//! Cookies store: list what a browser has, and merge an incoming set into it.
//!
//! Payload fields are (`host, name, path, value, expires_utc,
//! creation_utc, last_access_utc, is_secure, is_httponly, samesite`), with two optional
//! extras the reference ignores: `last_update_utc` and `top_frame_site_key`.
//!
//! Merge rule:
//! - Identity is (host, top_frame_site_key, name, path), so a partitioned cookie and the
//!   plain one never overwrite each other.
//! - Winner = the larger of (changed_at, creation_utc, last_access_utc, value), where
//!   changed_at is last_update_utc when > 0 else creation_utc. This is a total order on the
//!   record, so merging either direction lands on the same cookie: the result is the same on
//!   both devices after they trade boxes.
//! - Columns this engine does not model (priority, source_port, ...) are carried over from
//!   the existing newest row when one is replaced.

use std::path::Path;

use rusqlite::{params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::oscrypt::{linux_write_prefix, HostTag, LinuxPrefix, Lock};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cookie {
    pub host: String,
    pub name: String,
    pub path: String,
    pub value: String,
    pub expires_utc: i64,
    pub creation_utc: i64,
    pub last_access_utc: i64,
    pub is_secure: i64,
    pub is_httponly: i64,
    pub samesite: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update_utc: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub top_frame_site_key: String,
}

impl Cookie {
    fn rank(&self) -> (i64, i64, i64, &str, i64, i64, i64, i64) {
        let changed = self.last_update_utc.filter(|v| *v > 0).unwrap_or(self.creation_utc);
        // A total order: every field that can differ takes part, so no two distinct cookies tie
        // and both devices always pick the same winner.
        (
            changed,
            self.creation_utc,
            self.last_access_utc,
            self.value.as_str(),
            self.expires_utc,
            self.is_secure,
            self.is_httponly,
            self.samesite,
        )
    }

    /// True when `self` should win over `other` (same identity assumed). Total order, no ties.
    pub fn beats(&self, other: &Cookie) -> bool {
        self.rank() > other.rank()
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub imported: usize,
    pub kept_newer: usize,
}

/// A locked database means the browser is still open: a friendly, recoverable state.
pub(crate) fn sql(e: rusqlite::Error) -> Error {
    if let rusqlite::Error::SqliteFailure(f, _) = &e {
        if matches!(f.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) {
            return Error::BrowserOpen;
        }
    }
    Error::Io(format!("database error: {e}"))
}

pub(crate) fn table_columns(con: &Connection, table: &str) -> Result<Vec<String>> {
    let mut st = con.prepare(&format!("PRAGMA table_info({table})")).map_err(sql)?;
    let rows = st.query_map([], |r| r.get::<_, String>(1)).map_err(sql)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(sql)
}

/// One row of PRAGMA table_info: name, declared type, NOT NULL, has a default,
/// and part of the primary key.
pub(crate) struct ColumnInfo {
    pub name: String,
    pub type_name: String,
    pub notnull: bool,
    pub has_default: bool,
    pub pk: bool,
}

pub(crate) fn table_info(con: &Connection, table: &str) -> Result<Vec<ColumnInfo>> {
    let mut st = con.prepare(&format!("PRAGMA table_info({table})")).map_err(sql)?;
    let rows = st
        .query_map([], |r| {
            Ok(ColumnInfo {
                name: r.get(1)?,
                type_name: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                notnull: r.get::<_, i64>(3)? != 0,
                has_default: !matches!(r.get_ref(4)?, rusqlite::types::ValueRef::Null),
                pk: r.get::<_, i64>(5)? != 0,
            })
        })
        .map_err(sql)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(sql)
}

/// A neutral value for a declared column type, used only to satisfy a NOT NULL
/// constraint on a column the engine does not model.
fn fill_for_type(decl: &str) -> SqlValue {
    let t = decl.to_ascii_uppercase();
    if t.contains("INT") {
        SqlValue::Integer(0)
    } else if t.contains("CHAR") || t.contains("CLOB") || t.contains("TEXT") {
        SqlValue::Text(String::new())
    } else if t.contains("REAL") || t.contains("FLOA") || t.contains("DOUB") {
        SqlValue::Real(0.0)
    } else if t.contains("BLOB") || t.is_empty() {
        SqlValue::Blob(Vec::new())
    } else {
        SqlValue::Text(String::new())
    }
}

/// Values for every column that is NOT NULL with no default, is not a primary
/// key, and is not already in `present`. The next schema bump adds a column
/// like that, imports keep working instead of failing on the constraint.
/// Columns with a default are left out: SQLite fills those itself.
pub(crate) fn missing_notnull_defaults(
    con: &Connection,
    table: &str,
    present: &[String],
) -> Result<Vec<(String, SqlValue)>> {
    let mut out = Vec::new();
    for col in table_info(con, table)? {
        if col.pk || !col.notnull || col.has_default || present.iter().any(|n| n == &col.name) {
            continue;
        }
        out.push((col.name.clone(), fill_for_type(&col.type_name)));
    }
    Ok(out)
}

/// What decrypts a cookie value on read / locks it on write, chosen per platform.
pub enum Keys {
    /// Linux and Mac derive one AES key; `from_libsecret_v2` decides the label for an empty store.
    Cbc { lock: Lock, from_libsecret_v2: bool },
    /// Windows uses the DPAPI master key.
    Gcm { lock: Lock },
}

impl Keys {
    fn lock(&self) -> &Lock {
        match self {
            Keys::Cbc { lock, .. } | Keys::Gcm { lock } => lock,
        }
    }
}

fn open(path: &Path) -> Result<Connection> {
    let con = Connection::open(path).map_err(sql)?;
    con.busy_timeout(std::time::Duration::from_secs(5)).map_err(sql)?;
    Ok(con)
}

/// Read and decrypt every cookie. `value` is used when `encrypted_value` is empty (old rows).
pub fn export(path: &Path, keys: &Keys) -> Result<Vec<Cookie>> {
    let (_scratch, copy) = crate::util::snapshot_db(path)?;
    let con = open(&copy)?;
    let mut st = con
        .prepare(
            "SELECT host_key, name, path, value, encrypted_value, expires_utc, creation_utc, \
             last_access_utc, is_secure, is_httponly, samesite, last_update_utc, top_frame_site_key \
             FROM cookies ORDER BY host_key, name, path",
        )
        .map_err(sql)?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, i64>(10)?,
                r.get::<_, Option<i64>>(11).unwrap_or(None),
                r.get::<_, Option<String>>(12).unwrap_or(None).unwrap_or_default(),
            ))
        })
        .map_err(sql)?;
    let mut out = Vec::new();
    for row in rows {
        let (host, name, path, value, enc, exp, cre, acc, sec, http, ss, upd, tfs) = row.map_err(sql)?;
        let value = if enc.is_empty() { value } else { keys.lock().decrypt(&host, &enc)? };
        out.push(Cookie {
            host,
            name,
            path,
            value,
            expires_utc: exp,
            creation_utc: cre,
            last_access_utc: acc,
            is_secure: sec,
            is_httponly: http,
            samesite: ss,
            last_update_utc: upd,
            top_frame_site_key: tfs,
        });
    }
    Ok(out)
}

/// For Linux, sample the store's existing values to pick the write label before any row changes.
fn resolve_write_prefix(con: &Connection, keys: &Keys) -> Result<Option<LinuxPrefix>> {
    let Keys::Cbc { from_libsecret_v2, .. } = keys else { return Ok(None) };
    let mut st = con.prepare("SELECT encrypted_value FROM cookies").map_err(sql)?;
    let vals = st
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(sql)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql)?;
    Ok(Some(linux_write_prefix(vals.iter().map(|v| v.as_slice()), *from_libsecret_v2)))
}

fn default_for(col: &str, c: &Cookie) -> SqlValue {
    let on = |b: bool| SqlValue::Integer(b as i64);
    match col {
        "top_frame_site_key" => SqlValue::Text(c.top_frame_site_key.clone()),
        "has_expires" | "is_persistent" => on(c.expires_utc != 0),
        "priority" => SqlValue::Integer(1),
        "source_scheme" => on(c.is_secure != 0),
        "source_port" => SqlValue::Integer(-1),
        "source_type" => SqlValue::Integer(0),
        "has_cross_site_ancestor" => SqlValue::Integer(1),
        "last_update_utc" => SqlValue::Integer(c.last_update_utc.unwrap_or(c.last_access_utc)),
        _ => SqlValue::Null,
    }
}

/// Merge `incoming` into the cookies at `path`, inside one transaction. The caller takes the
/// atomic journal (txn.rs) around the whole move; this owns only the SQLite transaction so a
/// locked database (browser open) changes nothing.
pub fn import(path: &Path, incoming: &[Cookie], keys: &Keys) -> Result<Stats> {
    let mut con = open(path)?;
    let cols = table_columns(&con, "cookies")?;
    if cols.is_empty() {
        return Err(Error::Corrupt("the Cookies database has no cookies table".into()));
    }
    if !cols.iter().any(|c| c == "top_frame_site_key") {
        return Err(Error::Corrupt("this Cookies database predates partition keys; it is too old to write".into()));
    }
    let write_prefix = resolve_write_prefix(&con, keys)?;
    let tx = con.transaction().map_err(sql)?;
    let mut stats = Stats::default();
    // Modeled columns and their value for this cookie, if the column exists in this schema.
    let modeled = |c: &Cookie, enc: Vec<u8>| -> Vec<(&'static str, SqlValue)> {
        let on = |b: bool| SqlValue::Integer(b as i64);
        vec![
            ("creation_utc", SqlValue::Integer(c.creation_utc)),
            ("value", SqlValue::Text(String::new())),
            ("encrypted_value", SqlValue::Blob(enc)),
            ("expires_utc", SqlValue::Integer(c.expires_utc)),
            ("is_secure", SqlValue::Integer(c.is_secure)),
            ("is_httponly", SqlValue::Integer(c.is_httponly)),
            ("last_access_utc", SqlValue::Integer(c.last_access_utc)),
            ("samesite", SqlValue::Integer(c.samesite)),
            ("has_expires", on(c.expires_utc != 0)),
            ("is_persistent", on(c.expires_utc != 0)),
            ("last_update_utc", SqlValue::Integer(c.last_update_utc.unwrap_or(c.last_access_utc))),
        ]
    };
    let have = |col: &str| cols.iter().any(|x| x == col);

    for c in incoming {
        // The newest existing row with this identity (host, tfs, name, path). We key the match
        // on exactly the fields the box carries, and address a single row by rowid so sibling
        // rows that differ only in columns we do not model (source_scheme, partition flags) are
        // never touched.
        let existing: Option<(i64, i64, i64, i64, Option<i64>, String, Vec<u8>)> = tx
            .query_row(
                "SELECT rowid, creation_utc, last_access_utc, expires_utc, last_update_utc, value, encrypted_value \
                 FROM cookies WHERE host_key=?1 AND top_frame_site_key=?2 AND name=?3 AND path=?4 \
                 ORDER BY creation_utc DESC, rowid DESC LIMIT 1",
                (&c.host, &c.top_frame_site_key, &c.name, &c.path),
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(sql)?;

        let encrypted = match (keys, write_prefix) {
            (Keys::Cbc { .. }, Some(p)) => lock_with_prefix(keys, &c.host, &c.value, p)?,
            _ => keys.lock().encrypt(&c.host, &c.value, HostTag::With)?,
        };

        if let Some((rowid, cre, acc, exp, upd, val, enc)) = &existing {
            let value = if enc.is_empty() { val.clone() } else { keys.lock().decrypt(&c.host, enc)? };
            let cur = Cookie {
                host: c.host.clone(),
                name: c.name.clone(),
                path: c.path.clone(),
                value,
                expires_utc: *exp,
                creation_utc: *cre,
                last_access_utc: *acc,
                is_secure: c.is_secure,
                is_httponly: c.is_httponly,
                samesite: c.samesite,
                last_update_utc: *upd,
                top_frame_site_key: c.top_frame_site_key.clone(),
            };
            if !c.beats(&cur) {
                stats.kept_newer += 1;
                continue;
            }
            // Replace that one row in place. UPDATE keeps every column we do not set, so the
            // partition and source columns survive untouched.
            let sets: Vec<(&str, SqlValue)> = modeled(c, encrypted).into_iter().filter(|(n, _)| have(n)).collect();
            let assign = sets.iter().enumerate().map(|(i, (n, _))| format!("{n}=?{}", i + 1)).collect::<Vec<_>>().join(", ");
            let mut vals: Vec<SqlValue> = sets.into_iter().map(|(_, v)| v).collect();
            vals.push(SqlValue::Integer(*rowid));
            let stmt = format!("UPDATE cookies SET {assign} WHERE rowid=?{}", vals.len());
            tx.execute(&stmt, params_from_iter(vals.iter())).map_err(sql)?;
            stats.imported += 1;
            continue;
        }

        // A fresh row. Modeled columns plus the identity, and a sensible default for every other
        // NOT NULL column. Column names come from PRAGMA (owned Strings, no leak, not box data).
        let mut names: Vec<String> = vec!["host_key".into(), "name".into(), "path".into(), "top_frame_site_key".into()];
        let mut vals: Vec<SqlValue> = vec![
            SqlValue::Text(c.host.clone()),
            SqlValue::Text(c.name.clone()),
            SqlValue::Text(c.path.clone()),
            SqlValue::Text(c.top_frame_site_key.clone()),
        ];
        for (n, v) in modeled(c, encrypted) {
            if have(n) {
                names.push(n.to_string());
                vals.push(v);
            }
        }
        for col in &cols {
            if !names.iter().any(|n| n == col) {
                let v = default_for(col, c);
                if v != SqlValue::Null {
                    names.push(col.clone());
                    vals.push(v);
                }
            }
        }
        // Any NOT NULL column with no default that nothing above named yet
        // (a column a newer browser schema added) gets a neutral value here,
        // so the insert does not fail on the constraint.
        for (n, v) in missing_notnull_defaults(&tx, "cookies", &names)? {
            names.push(n);
            vals.push(v);
        }
        let placeholders = (1..=names.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
        let stmt = format!("INSERT INTO cookies ({}) VALUES ({})", names.join(", "), placeholders);
        tx.execute(&stmt, params_from_iter(vals.iter())).map_err(sql)?;
        stats.imported += 1;
    }
    tx.commit().map_err(sql)?;
    Ok(stats)
}

fn lock_with_prefix(keys: &Keys, host: &str, value: &str, prefix: LinuxPrefix) -> Result<Vec<u8>> {
    let Keys::Cbc { lock, .. } = keys else { unreachable!() };
    // Re-key is unnecessary: only the 3-byte label differs between v10 and v11.
    let mut enc = lock.encrypt(host, value, HostTag::With)?;
    enc[..3].copy_from_slice(match prefix {
        LinuxPrefix::V10 => b"v10",
        LinuxPrefix::V11 => b"v11",
    });
    Ok(enc)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "CREATE TABLE cookies (
        creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL,
        top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL,
        value TEXT NOT NULL DEFAULT '', encrypted_value BLOB NOT NULL DEFAULT '',
        path TEXT NOT NULL, expires_utc INTEGER NOT NULL DEFAULT 0,
        is_secure INTEGER NOT NULL DEFAULT 0, is_httponly INTEGER NOT NULL DEFAULT 0,
        last_access_utc INTEGER NOT NULL DEFAULT 0, has_expires INTEGER NOT NULL DEFAULT 1,
        is_persistent INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 1,
        samesite INTEGER NOT NULL DEFAULT -1, source_scheme INTEGER NOT NULL DEFAULT 0,
        source_port INTEGER NOT NULL DEFAULT -1, last_update_utc INTEGER NOT NULL DEFAULT 0,
        source_type INTEGER NOT NULL DEFAULT 0, has_cross_site_ancestor INTEGER NOT NULL DEFAULT 1);
        CREATE UNIQUE INDEX cookies_unique_index ON cookies (host_key, top_frame_site_key, name, path);";

    fn keys() -> Keys {
        Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
    }

    fn db() -> (tempfile::TempDir, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Cookies");
        let con = Connection::open(&p).unwrap();
        con.execute_batch(SCHEMA).unwrap();
        (t, p)
    }

    fn cookie(host: &str, name: &str, value: &str, cre: i64) -> Cookie {
        Cookie {
            host: host.into(),
            name: name.into(),
            path: "/".into(),
            value: value.into(),
            expires_utc: 0,
            creation_utc: cre,
            last_access_utc: cre,
            is_secure: 1,
            is_httponly: 0,
            samesite: -1,
            last_update_utc: None,
            top_frame_site_key: String::new(),
        }
    }

    #[test]
    fn round_trip_through_a_real_db() {
        let (_t, p) = db();
        let c = vec![cookie(".a.com", "sid", "hello", 100), cookie(".b.com", "t", "world", 200)];
        let s = import(&p, &c, &keys()).unwrap();
        assert_eq!(s.imported, 2);
        let back = export(&p, &keys()).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].value, "hello");
        assert_eq!(back[1].value, "world");
        // Stored encrypted, never in the clear.
        let raw: Vec<u8> = Connection::open(&p)
            .unwrap()
            .query_row("SELECT encrypted_value FROM cookies WHERE host_key='.a.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(&raw[..3], b"v10");
    }

    #[test]
    fn newer_wins_older_is_kept() {
        let (_t, p) = db();
        import(&p, &[cookie(".a.com", "sid", "v2", 200)], &keys()).unwrap();
        // Older creation loses.
        let s = import(&p, &[cookie(".a.com", "sid", "v1", 100)], &keys()).unwrap();
        assert_eq!(s, Stats { imported: 0, kept_newer: 1 });
        // Newer creation wins.
        let s = import(&p, &[cookie(".a.com", "sid", "v3", 300)], &keys()).unwrap();
        assert_eq!(s, Stats { imported: 1, kept_newer: 0 });
        assert_eq!(export(&p, &keys()).unwrap()[0].value, "v3");
    }

    #[test]
    fn equal_timestamps_break_the_tie_the_same_way_both_directions() {
        // Two cookies, identical identity and times, different values. The result must not
        // depend on which side imports which.
        let mut a = cookie(".a.com", "sid", "alpha", 100);
        let mut b = cookie(".a.com", "sid", "bravo", 100);
        a.last_update_utc = Some(100);
        b.last_update_utc = Some(100);
        assert_ne!(a.beats(&b), b.beats(&a), "exactly one wins");
        assert!(b.beats(&a), "bravo > alpha by value");

        let (_t1, p1) = db();
        import(&p1, std::slice::from_ref(&a), &keys()).unwrap();
        import(&p1, std::slice::from_ref(&b), &keys()).unwrap();
        let (_t2, p2) = db();
        import(&p2, std::slice::from_ref(&b), &keys()).unwrap();
        import(&p2, std::slice::from_ref(&a), &keys()).unwrap();
        assert_eq!(export(&p1, &keys()).unwrap()[0].value, export(&p2, &keys()).unwrap()[0].value);
        assert_eq!(export(&p1, &keys()).unwrap()[0].value, "bravo");
    }

    #[test]
    fn partitioned_and_plain_cookies_do_not_collide() {
        let (_t, p) = db();
        let plain = cookie(".a.com", "sid", "plain", 100);
        let mut part = cookie(".a.com", "sid", "partitioned", 50);
        part.top_frame_site_key = "https://top.example".into();
        import(&p, &[plain, part], &keys()).unwrap();
        let back = export(&p, &keys()).unwrap();
        assert_eq!(back.len(), 2, "both survive; different identity");
    }

    #[test]
    fn sibling_rows_on_the_real_index_are_not_clobbered() {
        // Modern Chrome's unique index includes source_scheme/port/has_cross_site_ancestor, so
        // two rows can share (host, tfs, name, path). An import must replace exactly one and
        // leave the other, and must keep columns we do not model.
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Cookies");
        let con = Connection::open(&p).unwrap();
        con.execute_batch(
            "CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL,
             top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value TEXT NOT NULL DEFAULT '',
             encrypted_value BLOB NOT NULL DEFAULT '', path TEXT NOT NULL, expires_utc INTEGER NOT NULL DEFAULT 0,
             is_secure INTEGER NOT NULL DEFAULT 0, is_httponly INTEGER NOT NULL DEFAULT 0,
             last_access_utc INTEGER NOT NULL DEFAULT 0, has_expires INTEGER NOT NULL DEFAULT 1,
             is_persistent INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 1,
             samesite INTEGER NOT NULL DEFAULT -1, source_scheme INTEGER NOT NULL DEFAULT 0,
             source_port INTEGER NOT NULL DEFAULT -1, last_update_utc INTEGER NOT NULL DEFAULT 0,
             source_type INTEGER NOT NULL DEFAULT 0, has_cross_site_ancestor INTEGER NOT NULL DEFAULT 1);
             CREATE UNIQUE INDEX cookies_unique_index ON cookies
             (host_key, top_frame_site_key, name, path, source_scheme, source_port, has_cross_site_ancestor);",
        )
        .unwrap();
        // Two siblings for .a.com/sid, differing only in source_port (443 vs 8443); plant with priority 7.
        let enc = Lock::linux("peanuts", LinuxPrefix::V10).encrypt(".a.com", "old", HostTag::With).unwrap();
        for port in [443, 8443] {
            con.execute(
                "INSERT INTO cookies (creation_utc,host_key,top_frame_site_key,name,value,encrypted_value,path,\
                 source_port,priority) VALUES (100,'.a.com','','sid','',?1,'/',?2,7)",
                rusqlite::params![enc, port],
            )
            .unwrap();
        }
        // A newer .a.com/sid arrives.
        let s = import(&p, &[cookie(".a.com", "sid", "new", 200)], &keys()).unwrap();
        assert_eq!(s.imported, 1);
        let con = Connection::open(&p).unwrap();
        let rows: i64 = con.query_row("SELECT COUNT(*) FROM cookies", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 2, "both siblings must survive; only one replaced");
        // The surviving rows keep priority 7 (an unmodeled column we must not reset).
        let kept7: i64 = con.query_row("SELECT COUNT(*) FROM cookies WHERE priority=7", [], |r| r.get(0)).unwrap();
        assert_eq!(kept7, 2, "priority preserved on the replaced row too");
        let got = export(&p, &keys()).unwrap();
        assert!(got.iter().any(|c| c.value == "new"), "the newer value landed");
    }

    #[test]
    fn unknown_notnull_columns_get_neutral_values() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Cookies");
        let schema = SCHEMA.replace(
            "source_type INTEGER NOT NULL DEFAULT 0, has_cross_site_ancestor INTEGER NOT NULL DEFAULT 1",
            "source_type INTEGER NOT NULL DEFAULT 0, has_cross_site_ancestor INTEGER NOT NULL DEFAULT 1, \
             future_flag INTEGER NOT NULL, future_note TEXT NOT NULL, future_blob BLOB NOT NULL",
        );
        Connection::open(&p).unwrap().execute_batch(&schema).unwrap();
        let s = import(&p, &[cookie(".a.com", "sid", "hello", 100)], &keys()).unwrap();
        assert_eq!(s.imported, 1);
        let con = Connection::open(&p).unwrap();
        let (flag, note, blob): (i64, String, Vec<u8>) = con
            .query_row(
                "SELECT future_flag, future_note, future_blob FROM cookies WHERE host_key='.a.com'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(flag, 0);
        assert_eq!(note, "");
        assert!(blob.is_empty());
    }

    #[test]
    fn a_locked_database_is_a_friendly_browser_open_error() {
        let (_t, p) = db();
        let hold = Connection::open(&p).unwrap();
        hold.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let other = open(&p).unwrap();
        // busy_timeout is short in test via a direct lock; force the conflict.
        other.busy_timeout(std::time::Duration::from_millis(50)).unwrap();
        let err = (|| -> Result<Stats> {
            let mut c = other;
            let tx = c.transaction().map_err(sql)?;
            tx.execute("INSERT INTO cookies (creation_utc, host_key, name, path) VALUES (1,'x','y','/')", [])
                .map_err(sql)?;
            tx.commit().map_err(sql)?;
            Ok(Stats::default())
        })()
        .unwrap_err();
        assert_eq!(err, Error::BrowserOpen);
    }
}
