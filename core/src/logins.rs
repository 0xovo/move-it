//! Saved-logins store: list what a browser has, and merge an incoming set into it.
//!
//! Payload fields match the reference engine's "passwords" list exactly (`origin_url,
//! action_url, username_value, password_value, date_created, date_last_used, times_used,
//! signon_realm`), so boxes stay compatible both ways.
//!
//! Merge rule (reference: `_merge_logins`), made deterministic:
//! - Identity is (origin_url, username_value). A missing login is inserted.
//! - For an existing one the winner is the larger of (date_created, date_last_used, times_used,
//!   action_url, signon_realm, password_value). The reference let the incoming row win every
//!   `date_created` tie, so two devices trading boxes could swap values forever; this order is
//!   total, so both devices land on the same login whichever box they merge first.
//! - A winning row only replaces the portable columns; the local row keeps its id and every
//!   column this engine does not model (form element names, form_data, scheme, ...).
//! - One SQLite transaction (BEGIN IMMEDIATE), no backups: a locked database means the browser
//!   is open and nothing changes; a value that will not unlock is `WrongBrowserPassword` and
//!   the whole import rolls back. We never retry with a guessed password.

use std::path::Path;
use std::time::Duration;

use rusqlite::{params_from_iter, types::Value as SqlValue, Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::cookies::{sql, table_columns, Keys};
use crate::oscrypt::{linux_write_prefix, login_prefix_host, HostTag, LinuxPrefix};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub origin_url: String,
    pub action_url: String,
    pub username_value: String,
    pub password_value: String,
    pub date_created: i64,
    pub date_last_used: i64,
    pub times_used: i64,
    pub signon_realm: String,
    /// When the password itself last changed. Ranked first, so a device that changed the
    /// password wins over one that merely kept using the old one (older boxes default it to 0).
    #[serde(default)]
    pub date_password_modified: i64,
}

impl Login {
    fn rank(&self) -> (i64, i64, i64, i64, &str, &str, &str) {
        (
            self.date_password_modified,
            self.date_created,
            self.date_last_used,
            self.times_used,
            &self.action_url,
            &self.signon_realm,
            &self.password_value,
        )
    }

    /// True when `self` should win over `other` (same identity assumed). Total order.
    pub fn beats(&self, other: &Login) -> bool {
        self.rank() > other.rank()
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub inserted: usize,
    pub updated: usize,
    pub skipped: usize,
}

fn open(path: &Path, wait: Duration) -> Result<Connection> {
    let con = Connection::open(path).map_err(sql)?;
    con.busy_timeout(wait).map_err(sql)?;
    Ok(con)
}

fn unlock(keys: &Keys, origin: &str, realm: &str, blob: &[u8]) -> Result<String> {
    if blob.is_empty() {
        return Ok(String::new());
    }
    let lock = match keys {
        Keys::Cbc { lock, .. } | Keys::Gcm { lock } => lock,
    };
    lock.decrypt(&login_prefix_host(origin, realm), blob)
}

/// Read and decrypt every saved login. A profile without a Login Data file exports nothing; a
/// file that exists but cannot be read fails.
pub fn export(path: &Path, keys: &Keys) -> Result<Vec<Login>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let (_scratch, copy) = crate::util::snapshot_db(path)?;
    let con = open(&copy, Duration::from_secs(5))?;
    let mut st = con
        .prepare(
            "SELECT origin_url, action_url, username_value, password_value, date_created, \
             date_last_used, times_used, signon_realm, COALESCE(date_password_modified,0) FROM logins \
             ORDER BY origin_url, username_value, signon_realm, date_created",
        )
        .map_err(sql)?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                r.get::<_, String>(7)?,
                r.get::<_, Option<i64>>(8)?.unwrap_or(0),
            ))
        })
        .map_err(sql)?;
    let mut out = Vec::new();
    for row in rows {
        let (origin, action, user, blob, created, used, times, realm, pwmod) = row.map_err(sql)?;
        let password_value = unlock(keys, &origin, &realm, &blob)?;
        out.push(Login {
            origin_url: origin,
            action_url: action,
            username_value: user,
            password_value,
            date_created: created,
            date_last_used: used,
            times_used: times,
            signon_realm: realm,
            date_password_modified: pwmod,
        });
    }
    Ok(out)
}

/// The label Linux values are written with: a vote over the store's existing password blobs,
/// taken before any row changes.
fn resolve_write_prefix(con: &Connection, keys: &Keys) -> Result<Option<LinuxPrefix>> {
    let Keys::Cbc { from_libsecret_v2, .. } = keys else { return Ok(None) };
    let mut st = con.prepare("SELECT password_value FROM logins").map_err(sql)?;
    let vals = st
        .query_map([], |r| r.get::<_, Option<Vec<u8>>>(0))
        .map_err(sql)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql)?;
    Ok(Some(linux_write_prefix(vals.iter().flatten().map(|v| v.as_slice()), *from_libsecret_v2)))
}

fn lock_value(keys: &Keys, l: &Login, tag: HostTag, prefix: Option<LinuxPrefix>) -> Result<Vec<u8>> {
    // An empty password is stored as an empty blob, which every reader takes as "no password".
    if l.password_value.is_empty() {
        return Ok(Vec::new());
    }
    let host = login_prefix_host(&l.origin_url, &l.signon_realm);
    match (keys, prefix) {
        (Keys::Cbc { lock, .. }, Some(p)) => {
            // Only the 3-byte label differs between v10 and v11.
            let mut enc = lock.encrypt(&host, &l.password_value, tag)?;
            enc[..3].copy_from_slice(if p == LinuxPrefix::V10 { b"v10" } else { b"v11" });
            Ok(enc)
        }
        (Keys::Cbc { lock, .. } | Keys::Gcm { lock }, _) => lock.encrypt(&host, &l.password_value, tag),
    }
}

/// The local row for one identity, as the merge needs it.
struct Local {
    id: i64,
    action_url: String,
    realm: String,
    created: i64,
    used: i64,
    times: i64,
    pwmod: i64,
    blob: Vec<u8>,
}

impl Local {
    fn key(&self) -> (i64, i64, i64, i64, &str, &str) {
        (self.pwmod, self.created, self.used, self.times, &self.action_url, &self.realm)
    }
}

/// Which existing row the incoming login is measured against, and whether it beats it. Decrypts
/// only when everything else ties, so an unrelated unreadable value never blocks a clear win.
fn incoming_wins(rows: &[Local], l: &Login, keys: &Keys) -> Result<(i64, bool)> {
    let top = rows.iter().map(Local::key).max().expect("at least one row");
    let tied: Vec<&Local> = rows.iter().filter(|r| r.key() == top).collect();
    let inc =
        (l.date_password_modified, l.date_created, l.date_last_used, l.times_used, l.action_url.as_str(), l.signon_realm.as_str());
    if tied.len() == 1 && inc != top {
        return Ok((tied[0].id, inc > top));
    }
    if inc < top {
        return Ok((tied.iter().map(|r| r.id).min().unwrap(), false));
    }
    // Full tie on the visible fields: the password decides. Several equal rows -> highest
    // password, lowest id, so the pick never depends on row order.
    let mut best: Option<(String, i64)> = None;
    for r in tied {
        let pw = unlock(keys, &l.origin_url, &r.realm, &r.blob)?;
        best = match best {
            Some((bp, bid)) if (bp.as_str(), std::cmp::Reverse(bid)) >= (pw.as_str(), std::cmp::Reverse(r.id)) => Some((bp, bid)),
            _ => Some((pw, r.id)),
        };
    }
    let (pw, id) = best.expect("tied is not empty");
    Ok((id, inc > top || l.password_value > pw))
}

/// Merge `incoming` into the Login Data at `path`, inside one transaction. `tag` says whether
/// new values are written with SHA256(host) in front of the password (the reference does;
/// callers default to `HostTag::Without`). A missing file is left alone.
pub fn import(path: &Path, incoming: &[Login], keys: &Keys, tag: HostTag) -> Result<Stats> {
    import_waiting(path, incoming, keys, tag, Duration::from_secs(5))
}

fn import_waiting(path: &Path, incoming: &[Login], keys: &Keys, tag: HostTag, wait: Duration) -> Result<Stats> {
    let mut stats = Stats::default();
    if !path.exists() {
        return Ok(stats);
    }
    let mut con = open(path, wait)?;
    let cols = table_columns(&con, "logins")?;
    if cols.is_empty() {
        return Err(Error::Corrupt("the Login Data database has no logins table".into()));
    }
    let tx = con.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
    let prefix = resolve_write_prefix(&tx, keys)?;
    let has = |c: &str| cols.iter().any(|x| x == c);

    for l in incoming {
        let mut st = tx
            .prepare(
                "SELECT id, COALESCE(action_url,''), signon_realm, COALESCE(date_created,0), \
                 COALESCE(date_last_used,0), COALESCE(times_used,0), COALESCE(password_value,x''), \
                 COALESCE(date_password_modified,0) \
                 FROM logins WHERE origin_url=?1 AND COALESCE(username_value,'')=?2",
            )
            .map_err(sql)?;
        let rows = st
            .query_map((&l.origin_url, &l.username_value), |r| {
                Ok(Local {
                    id: r.get(0)?,
                    action_url: r.get(1)?,
                    realm: r.get(2)?,
                    created: r.get(3)?,
                    used: r.get(4)?,
                    times: r.get(5)?,
                    blob: r.get(6)?,
                    pwmod: r.get(7)?,
                })
            })
            .map_err(sql)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql)?;
        drop(st);

        let blob = lock_value(keys, l, tag, prefix)?;
        let int = SqlValue::Integer;
        let text = |s: &str| SqlValue::Text(s.to_string());

        if !rows.is_empty() {
            let (id, wins) = incoming_wins(&rows, l, keys)?;
            if !wins {
                stats.skipped += 1;
                continue;
            }
            let pwmod = if l.date_password_modified > 0 { l.date_password_modified } else { l.date_created };
            let portable: [(&str, SqlValue); 7] = [
                ("action_url", text(&l.action_url)),
                ("password_value", SqlValue::Blob(blob)),
                ("date_created", int(l.date_created)),
                ("date_last_used", int(l.date_last_used)),
                ("times_used", int(l.times_used)),
                ("signon_realm", text(&l.signon_realm)),
                ("date_password_modified", int(pwmod)),
            ];
            let set: Vec<(&str, &SqlValue)> = portable.iter().filter(|(c, _)| has(c)).map(|(c, v)| (*c, v)).collect();
            let sets = set.iter().enumerate().map(|(i, (c, _))| format!("{c}=?{}", i + 1)).collect::<Vec<_>>().join(", ");
            let stmt = format!("UPDATE logins SET {sets} WHERE id=?{}", set.len() + 1);
            let mut vals: Vec<&SqlValue> = set.iter().map(|(_, v)| *v).collect();
            let idv = int(id);
            vals.push(&idv);
            // Rewriting signon_realm can collide with Chromium's UNIQUE index against ANOTHER
            // row. That is one login we cannot place, not a reason to fail the whole box, so a
            // constraint violation becomes a skip and the transaction continues.
            match tx.execute(&stmt, params_from_iter(vals)) {
                Ok(_) => stats.updated += 1,
                Err(e) if is_constraint(&e) => stats.skipped += 1,
                Err(e) => return Err(sql(e)),
            }
            continue;
        }

        // Columns the payload does not model but the schema wants: what a freshly saved login has.
        let row: [(&str, SqlValue); 21] = [
            ("origin_url", text(&l.origin_url)),
            ("action_url", text(&l.action_url)),
            ("username_value", text(&l.username_value)),
            ("password_value", SqlValue::Blob(blob)),
            ("date_created", int(l.date_created)),
            ("date_last_used", int(l.date_last_used)),
            ("times_used", int(l.times_used)),
            ("signon_realm", text(&l.signon_realm)),
            ("username_element", text("")),
            ("password_element", text("")),
            ("date_password_modified", int(if l.date_password_modified > 0 { l.date_password_modified } else { l.date_created })),
            ("form_data", SqlValue::Null),
            ("date_received", int(l.date_created)),
            ("shared_preference", int(0)),
            ("submission_event", int(0)),
            ("sender_email", text("")),
            ("sender_name", text("")),
            ("date_sender_notice_sent", int(0)),
            ("keychain_identifier", text("")),
            ("scheme", int(0)),
            ("version", int(0)),
        ];
        let extra: [(&str, SqlValue); 2] = [("federation_url", text("")), ("generation_upload_status", int(0))];
        // Insert in the table's own column order.
        let put: Vec<(&str, &SqlValue)> = cols
            .iter()
            .filter_map(|c| row.iter().chain(extra.iter()).find(|(n, _)| n == c).map(|(n, v)| (*n, v)))
            .collect();
        let names = put.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ");
        let ph = (1..=put.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
        match tx.execute(
            &format!("INSERT INTO logins ({names}) VALUES ({ph})"),
            params_from_iter(put.iter().map(|(_, v)| *v)),
        ) {
            Ok(_) => stats.inserted += 1,
            Err(e) if is_constraint(&e) => stats.skipped += 1,
            Err(e) => return Err(sql(e)),
        }
    }
    tx.commit().map_err(sql)?;
    Ok(stats)
}

/// A UNIQUE/constraint violation on one row: skip that login, do not fail the whole import.
fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oscrypt::Lock;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use sha2::{Digest, Sha256};

    // The real Chromium logins table, as in the reference test_passwords.py.
    const SCHEMA: &str = "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        INSERT INTO meta (key, value) VALUES ('version', '35');
        CREATE TABLE logins (
        origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR,
        password_element VARCHAR, password_value BLOB DEFAULT '', date_created INTEGER NOT NULL,
        date_last_used INTEGER NOT NULL, date_password_modified INTEGER NOT NULL, signon_realm VARCHAR NOT NULL,
        times_used INTEGER NOT NULL, form_data BLOB, date_received INTEGER,
        shared_preference INTEGER NOT NULL DEFAULT 0, submission_event INTEGER NOT NULL DEFAULT 0,
        sender_email VARCHAR, sender_name VARCHAR, date_sender_notice_sent INTEGER DEFAULT 0,
        keychain_identifier VARCHAR DEFAULT '', id INTEGER PRIMARY KEY AUTOINCREMENT,
        scheme INTEGER DEFAULT 0 NOT NULL, possible_username_pairs BLOB, moving_blocked_for BLOB,
        version INTEGER NOT NULL DEFAULT 0, encrypted_date_created BLOB DEFAULT '',
        encrypted_date_last_used BLOB DEFAULT '', encrypted_date_password_modified BLOB DEFAULT '',
        federation_url VARCHAR DEFAULT '', skip_zero_click INTEGER, generation_upload_status INTEGER DEFAULT 0,
        form_fetcher_path VARCHAR, date_received_is_readonly INTEGER NOT NULL DEFAULT 0,
        date_created_is_readonly INTEGER NOT NULL DEFAULT 0, possible_observer_handles BLOB);
        CREATE INDEX logins_signon ON logins (signon_realm);";

    const D1: i64 = 13350001000000000;
    const D2: i64 = 13350002000000000;
    const ORIGIN: &str = "https://mail.example.com/login";
    const REALM: &str = "https://mail.example.com";

    fn linux() -> Keys {
        Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
    }

    fn windows() -> Keys {
        Keys::Gcm { lock: Lock::windows(core::array::from_fn(|i| i as u8)) }
    }

    fn db() -> (tempfile::TempDir, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Login Data");
        Connection::open(&p).unwrap().execute_batch(SCHEMA).unwrap();
        (t, p)
    }

    fn login(user: &str, pw: &str, created: i64) -> Login {
        Login {
            origin_url: ORIGIN.into(),
            action_url: "https://mail.example.com/auth".into(),
            username_value: user.into(),
            password_value: pw.into(),
            date_created: created,
            date_last_used: created + 500,
            times_used: 3,
            signon_realm: REALM.into(),
            date_password_modified: created,
        }
    }

    fn blob(p: &Path, user: &str) -> Vec<u8> {
        Connection::open(p)
            .unwrap()
            .query_row("SELECT password_value FROM logins WHERE username_value=?1", [user], |r| r.get(0))
            .unwrap()
    }

    fn count(p: &Path) -> i64 {
        Connection::open(p).unwrap().query_row("SELECT count(*) FROM logins", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn payload_json_matches_the_reference_fields() {
        let v = serde_json::to_value(login("u", "p", D1)).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "action_url",
                "date_created",
                "date_last_used",
                "date_password_modified",
                "origin_url",
                "password_value",
                "signon_realm",
                "times_used",
                "username_value"
            ]
        );
        assert_eq!(v["date_created"], D1);
    }

    #[test]
    fn round_trip_with_both_tag_choices() {
        for tag in [HostTag::Without, HostTag::With] {
            let (_t, p) = db();
            let s = import(&p, &[login("u", "dummy-pw", D1)], &linux(), tag).unwrap();
            assert_eq!(s, Stats { inserted: 1, updated: 0, skipped: 0 });
            let back = export(&p, &linux()).unwrap();
            assert_eq!(back, vec![login("u", "dummy-pw", D1)]);
            let raw = blob(&p, "u");
            assert_eq!(&raw[..3], b"v10");
            // 8 plain bytes pad to 16; with the 32-byte tag 40 bytes pad to 48.
            assert_eq!(raw.len() - 3, if tag == HostTag::With { 48 } else { 16 });
        }
    }

    #[test]
    fn tag_with_hashes_the_realm_host_not_the_whole_origin() {
        let (_t, p) = db();
        import(&p, &[login("u", "dummy-pw", D1)], &windows(), HostTag::With).unwrap();
        let raw = blob(&p, "u");
        let Keys::Gcm { lock: crate::oscrypt::Lock::Gcm { master_key } } = windows() else { unreachable!() };
        let plain = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key))
            .decrypt(Nonce::from_slice(&raw[3..15]), &raw[15..])
            .unwrap();
        assert_eq!(plain[..32], Sha256::digest(b"mail.example.com")[..]);
        assert_eq!(&plain[32..], b"dummy-pw");
        // Without the tag the plaintext is just the password.
        let (_t2, p2) = db();
        import(&p2, &[login("u", "dummy-pw", D1)], &windows(), HostTag::Without).unwrap();
        let raw = blob(&p2, "u");
        let plain = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key))
            .decrypt(Nonce::from_slice(&raw[3..15]), &raw[15..])
            .unwrap();
        assert_eq!(plain, b"dummy-pw");
    }

    #[test]
    fn two_devices_converge_to_the_newer_shared_password() {
        let second = login("second-user", "dummy-second", D1 + 100);
        let mut a_only = login("user-a", "dummy-a-only", D1 + 200);
        a_only.origin_url = "https://a-only.example.com/".into();
        a_only.signon_realm = "https://a-only.example.com".into();
        let a = vec![login("shared-user", "dummy-shared-old", D1), second, a_only];
        let mut b_only = login("user-b", "dummy-b-only", D1 + 300);
        b_only.origin_url = "https://b-only.example.org/login".into();
        b_only.signon_realm = "https://b-only.example.org".into();
        let b = vec![login("shared-user", "dummy-shared-new", D2), b_only];

        let (_ta, pa) = db();
        let (_tb, pb) = db();
        import(&pa, &a, &windows(), HostTag::Without).unwrap();
        import(&pb, &b, &linux(), HostTag::Without).unwrap();
        let (ea, eb) = (export(&pa, &windows()).unwrap(), export(&pb, &linux()).unwrap());
        import(&pa, &eb, &windows(), HostTag::Without).unwrap();
        import(&pb, &ea, &linux(), HostTag::Without).unwrap();
        let (fa, fb) = (export(&pa, &windows()).unwrap(), export(&pb, &linux()).unwrap());
        assert_eq!(fa, fb);
        assert_eq!(fa.len(), 4);
        let shared = fa.iter().find(|l| l.username_value == "shared-user").unwrap();
        assert_eq!((shared.password_value.as_str(), shared.times_used, shared.date_created), ("dummy-shared-new", 3, D2));
    }

    #[test]
    fn an_older_login_is_skipped() {
        let (_t, p) = db();
        import(&p, &[login("u", "new", D2)], &linux(), HostTag::Without).unwrap();
        let s = import(&p, &[login("u", "old", D1)], &linux(), HostTag::Without).unwrap();
        assert_eq!(s, Stats { inserted: 0, updated: 0, skipped: 1 });
        assert_eq!(export(&p, &linux()).unwrap()[0].password_value, "new");
    }

    #[test]
    fn merge_is_commutative_even_on_full_ties() {
        // Same identity, same date_created, everything else differs: the reference let the
        // incoming row win, so order mattered. Here every order lands on the same login.
        let mut a = login("u", "alpha", D1);
        let mut b = login("u", "bravo", D1);
        let mut c = login("u", "bravo", D1);
        c.times_used = 9;
        let mut d = login("u", "bravo", D1);
        d.action_url = "https://zzz.example.com/".into();
        a.date_last_used = D1 + 1;
        b.date_last_used = D1 + 1;
        c.date_last_used = D1 + 1;
        d.date_last_used = D1 + 1;
        let all = [a, b, c, d];
        let mut results = Vec::new();
        for order in [[0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]] {
            let (_t, p) = db();
            for i in order {
                import(&p, std::slice::from_ref(&all[i]), &linux(), HostTag::Without).unwrap();
            }
            assert_eq!(count(&p), 1);
            results.push(export(&p, &linux()).unwrap());
        }
        assert!(results.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(results[0][0].times_used, 9);
        // Pure password tie: highest password wins both ways, and an identical re-import is skipped.
        let (x, y) = (login("u", "alpha", D1), login("u", "bravo", D1));
        let (_t1, p1) = db();
        let (_t2, p2) = db();
        for l in [&x, &y] {
            import(&p1, std::slice::from_ref(l), &linux(), HostTag::With).unwrap();
        }
        for l in [&y, &x] {
            import(&p2, std::slice::from_ref(l), &linux(), HostTag::With).unwrap();
        }
        assert_eq!(export(&p1, &linux()).unwrap(), export(&p2, &linux()).unwrap());
        assert_eq!(export(&p1, &linux()).unwrap()[0].password_value, "bravo");
        let s = import(&p1, &[y], &linux(), HostTag::With).unwrap();
        assert_eq!(s, Stats { inserted: 0, updated: 0, skipped: 1 });
    }

    #[test]
    fn update_keeps_the_row_id_and_unmodeled_columns() {
        let (_t, p) = db();
        let con = Connection::open(&p).unwrap();
        con.execute(
            "INSERT INTO logins (origin_url, username_value, username_element, password_element, password_value, \
             date_created, date_last_used, date_password_modified, signon_realm, times_used, scheme, form_data) \
             VALUES (?1, 'u', 'email', 'pass', x'', ?2, ?2, ?2, ?3, 1, 7, x'0102')",
            (ORIGIN, D1, REALM),
        )
        .unwrap();
        drop(con);
        let s = import(&p, &[login("u", "fresh", D2)], &linux(), HostTag::Without).unwrap();
        assert_eq!(s.updated, 1);
        let con = Connection::open(&p).unwrap();
        let (id, ue, pe, scheme, fd): (i64, String, String, i64, Vec<u8>) = con
            .query_row("SELECT id, username_element, password_element, scheme, form_data FROM logins", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap();
        assert_eq!((id, ue.as_str(), pe.as_str(), scheme, fd), (1, "email", "pass", 7, vec![1, 2]));
        assert_eq!(export(&p, &linux()).unwrap()[0].password_value, "fresh");
    }

    #[test]
    fn a_new_row_gets_fresh_login_defaults() {
        let (_t, p) = db();
        import(&p, &[login("u", "pw", D1)], &linux(), HostTag::Without).unwrap();
        let (dpm, recv, ue, scheme, ver): (i64, i64, String, i64, i64) = Connection::open(&p)
            .unwrap()
            .query_row(
                "SELECT date_password_modified, date_received, username_element, scheme, version FROM logins",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!((dpm, recv, ue.as_str(), scheme, ver), (D1, D1, "", 0, 0));
    }

    #[test]
    fn a_value_that_will_not_unlock_changes_nothing() {
        let (_t, p) = db();
        import(&p, &[login("keep", "pw", D1)], &linux(), HostTag::Without).unwrap();
        let before = std::fs::read(&p).unwrap();
        let wrong = Keys::Cbc { lock: Lock::linux("not-peanuts", LinuxPrefix::V10), from_libsecret_v2: false };
        // Export refuses.
        assert_eq!(export(&p, &wrong).unwrap_err(), Error::WrongBrowserPassword);
        // A full tie forces a read of the local value: refused, and the earlier new row rolls back.
        let batch = [login("brand-new", "x", D1), login("keep", "pw", D1)];
        assert_eq!(import(&p, &batch, &wrong, HostTag::Without).unwrap_err(), Error::WrongBrowserPassword);
        assert_eq!(count(&p), 1);
        assert_eq!(std::fs::read(&p).unwrap(), before);
    }

    #[test]
    fn a_locked_database_is_browser_open_and_untouched() {
        let (_t, p) = db();
        import(&p, &[login("u", "pw", D1)], &linux(), HostTag::Without).unwrap();
        let before = std::fs::read(&p).unwrap();
        let hold = Connection::open(&p).unwrap();
        hold.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let err = import_waiting(&p, &[login("v", "pw", D2)], &linux(), HostTag::Without, Duration::from_millis(50)).unwrap_err();
        assert_eq!(err, Error::BrowserOpen);
        hold.execute_batch("ROLLBACK").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), before);
    }

    #[test]
    fn linux_keeps_the_stores_v11_label() {
        let (_t, p) = db();
        let k11 = Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V11), from_libsecret_v2: true };
        import(&p, &[login("a", "one", D1)], &k11, HostTag::Without).unwrap();
        assert_eq!(&blob(&p, "a")[..3], b"v11");
        // A v10-writing Lock still follows the store's own majority.
        import(&p, &[login("b", "two", D1)], &linux(), HostTag::Without).unwrap();
        assert_eq!(&blob(&p, "b")[..3], b"v11");
        assert_eq!(export(&p, &linux()).unwrap().len(), 2);
    }

    #[test]
    fn empty_password_and_null_columns_round_trip() {
        let (_t, p) = db();
        Connection::open(&p)
            .unwrap()
            .execute(
                "INSERT INTO logins (origin_url, action_url, username_value, password_value, date_created, \
                 date_last_used, date_password_modified, signon_realm, times_used) \
                 VALUES (?1, NULL, NULL, NULL, 5, 5, 5, ?2, 0)",
                (ORIGIN, REALM),
            )
            .unwrap();
        let back = export(&p, &linux()).unwrap();
        assert_eq!((back[0].action_url.as_str(), back[0].username_value.as_str(), back[0].password_value.as_str()), ("", "", ""));
        // Importing an empty password (even tagged) must stay readable.
        let (_t2, p2) = db();
        import(&p2, &[login("u", "", D1)], &windows(), HostTag::With).unwrap();
        assert_eq!(export(&p2, &windows()).unwrap()[0].password_value, "");
        // The NULL-username row matches an incoming "" username instead of duplicating.
        let mut l = login("", "pw", D2);
        l.action_url = String::new();
        let s = import(&p, &[l], &linux(), HostTag::Without).unwrap();
        assert_eq!(s, Stats { inserted: 0, updated: 1, skipped: 0 });
        assert_eq!(count(&p), 1);
    }

    #[test]
    fn missing_file_is_empty_and_stays_missing() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Login Data");
        assert!(export(&p, &linux()).unwrap().is_empty());
        assert_eq!(import(&p, &[login("u", "pw", D1)], &linux(), HostTag::Without).unwrap(), Stats::default());
        assert!(!p.exists());
    }

    #[test]
    fn a_changed_password_beats_a_more_used_old_one() {
        // Device B changed the password (recent date_password_modified); device A just kept using
        // the old one (higher times_used, later date_last_used). B must win on both.
        let mut old = login("u", "oldpw", D1);
        old.date_last_used = D2;
        old.times_used = 99;
        old.date_password_modified = D1;
        let mut changed = login("u", "newpw", D1);
        changed.date_last_used = D1;
        changed.times_used = 1;
        changed.date_password_modified = D2;
        assert!(changed.beats(&old) && !old.beats(&changed), "the changed password wins");
    }

    #[test]
    fn a_unique_index_collision_skips_one_login_not_the_whole_box() {
        // A table with Chromium's real UNIQUE index and two rows for the same (origin, user) that
        // differ only by realm. An incoming row that would rewrite one realm onto the other's must
        // be skipped, the other logins must still import, and the DB must stay intact.
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Login Data");
        let con = Connection::open(&p).unwrap();
        con.execute_batch(
            "CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR DEFAULT '',
             username_value VARCHAR, password_element VARCHAR DEFAULT '', password_value BLOB DEFAULT '',
             date_created INTEGER NOT NULL, date_last_used INTEGER NOT NULL, date_password_modified INTEGER NOT NULL,
             signon_realm VARCHAR NOT NULL, times_used INTEGER NOT NULL, scheme INTEGER NOT NULL DEFAULT 0,
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             UNIQUE (origin_url, username_element, username_value, password_element, signon_realm));",
        )
        .unwrap();
        let enc = |realm: &str, pw: &str| Lock::linux("peanuts", LinuxPrefix::V10).encrypt(realm, pw, HostTag::Without).unwrap();
        for (realm, created) in [("https://a.example", 5i64), ("https://b.example", 4)] {
            con.execute(
                "INSERT INTO logins (origin_url,username_value,signon_realm,password_value,date_created,\
                 date_last_used,date_password_modified,times_used) VALUES ('https://x/l','bob',?1,?2,?3,?3,?3,1)",
                rusqlite::params![realm, enc(realm, "p"), created],
            )
            .unwrap();
        }
        // Incoming bob@b.example, newer: beats the a.example row, whose realm would be set to
        // b.example and collide with the existing b.example row.
        let mut collide = Login {
            origin_url: "https://x/l".into(),
            action_url: String::new(),
            username_value: "bob".into(),
            password_value: "new".into(),
            date_created: 9,
            date_last_used: 9,
            times_used: 9,
            signon_realm: "https://b.example".into(),
            date_password_modified: 9,
        };
        // Also a clean, unrelated login that must still import.
        let fine = Login { username_value: "carol".into(), ..collide.clone() };
        collide.password_value = "new".into();
        let s = import(&p, &[collide, fine], &linux(), HostTag::Without).unwrap();
        assert_eq!(s.skipped, 1, "the colliding login is skipped");
        assert!(s.inserted + s.updated >= 1, "the clean login still lands");
        let rows: i64 = Connection::open(&p).unwrap().query_row("SELECT COUNT(*) FROM logins", [], |r| r.get(0)).unwrap();
        assert!(rows >= 2, "nothing was lost; the DB is intact");
    }
}
