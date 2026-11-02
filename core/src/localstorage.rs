//! Extension localStorage: the entries of each `chrome-extension://<id>` origin in the Local
//! Storage store the extension pages SHARE with websites. Website rows are never read into a
//! box and never touched on import.
//!
//! Port of the reference's `ext_localstorage` section: a list of `{extension_id, key, value}`
//! string triples. Two store shapes, same as the reference:
//! - SQLite (current builds): `Default/LocalStorage`, tables `maps` / `map_entries`.
//! - Classic LevelDB (older builds): `Default/Local Storage/leveldb`, read and written with
//!   rusty-leveldb (the reference used plyvel). Keys are `_` + origin + NUL + tagged key.
//!
//! Strings are stored tagged: 0x01 + Latin-1 when every char fits a byte, else 0x00 + UTF-16LE.
//! Browser-compressed SQLite values (type 1, zstd) are read through ruzstd and written back
//! uncompressed.
//!
//! Merge rule, deterministic and commutative: keys are unioned; when both sides hold a key
//! with different values the larger value (by code point order) wins. It does not depend on
//! which side is "local", so two devices trading boxes end up with the same store. (The
//! reference let the incoming value overwrite, which converges nowhere: each device keeps the
//! other's value.) There are no per-key timestamps to do better.
//!
//! Atomicity is the caller's `Txn` over [`store_path`]; a SQLite merge is additionally one
//! transaction, a LevelDB merge one write batch.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use rusty_leveldb::{LdbIterator, Options, StatusCode, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cookies::sql;
use crate::extstate::extension_id_candidates;
use crate::{Error, Result};

const CHROME_EPOCH_OFFSET_US: i64 = 11_644_473_600_000_000;
/// Largest value we will inflate; the browser's own per-origin quota is far below this.
const MAX_INFLATED: u64 = 64 * 1024 * 1024;

/// One localStorage entry of one extension.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Triple {
    pub extension_id: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Shape {
    Sqlite,
    Leveldb,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub present: bool,
    pub shape: Option<Shape>,
    pub entries: usize,
    pub inserted: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub maps_touched: usize,
}

pub fn sqlite_path(profile: &Path) -> PathBuf {
    profile.join("Default").join("LocalStorage")
}

pub fn leveldb_path(profile: &Path) -> PathBuf {
    profile.join("Default").join("Local Storage").join("leveldb")
}

/// Now as a Chromium timestamp: microseconds since 1601-01-01.
pub fn chrome_now_us() -> i64 {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);
    unix + CHROME_EPOCH_OFFSET_US
}

fn io(e: std::io::Error, what: &str, p: &Path) -> Error {
    Error::Io(format!("{what} {}: {e}", p.display()))
}

fn refuse_link(p: &Path) -> Error {
    Error::Refused(format!("{} is a symbolic link; Move It never follows links", p.display()))
}

#[derive(PartialEq)]
enum Found {
    No,
    File,
    Dir,
}

fn probe(p: &Path) -> Result<Found> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => Err(refuse_link(p)),
        Ok(m) if m.is_dir() => Ok(Found::Dir),
        Ok(m) if m.is_file() => Ok(Found::File),
        Ok(_) => Ok(Found::No),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Found::No),
        Err(e) => Err(io(e, "cannot inspect", p)),
    }
}

/// The store that exists in this profile and its shape, if any. SQLite wins over LevelDB.
pub fn store(profile: &Path) -> Result<Option<(Shape, PathBuf)>> {
    let sq = sqlite_path(profile);
    if probe(&sq)? == Found::File {
        return Ok(Some((Shape::Sqlite, sq)));
    }
    let ld = leveldb_path(profile);
    if probe(&ld)? == Found::Dir {
        return Ok(Some((Shape::Leveldb, ld)));
    }
    Ok(None)
}

/// Path to hand to `Txn::begin` before [`import`].
pub fn store_path(profile: &Path) -> Result<Option<PathBuf>> {
    Ok(store(profile)?.map(|(_, p)| p))
}

// ---- string blobs ----------------------------------------------------------------------

/// Decode one stored key/value blob. An empty blob is the empty string.
pub fn decode_blob(blob: &[u8], what: &str) -> Result<String> {
    let Some((tag, rest)) = blob.split_first() else { return Ok(String::new()) };
    match tag {
        1 => Ok(rest.iter().map(|&b| b as char).collect()),
        0 => {
            if rest.len() % 2 != 0 {
                return Err(Error::Corrupt(format!("cannot decode a {what}: odd UTF-16 length")));
            }
            // localStorage can legitimately hold a lone (unpaired) UTF-16 surrogate, which a Rust
            // String cannot represent. Rather than abort the whole store's import over one such
            // value, substitute the replacement character. Both devices decode it the same way,
            // so the merge stays deterministic and convergent.
            let units = rest.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
            Ok(char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect())
        }
        t => Err(Error::Corrupt(format!("cannot decode a {what}: unknown encoding tag {t}"))),
    }
}

/// 0x01 + Latin-1 when possible, else 0x00 + UTF-16LE.
pub fn encode_str(text: &str) -> Vec<u8> {
    if text.chars().all(|c| (c as u32) < 256) {
        let mut out = vec![1u8];
        out.extend(text.chars().map(|c| c as u8));
        out
    } else {
        let mut out = vec![0u8];
        for u in text.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }
}

/// Effective tagged bytes of a SQLite value: type 0 as is, type 1 zstd-inflated, else refuse.
fn value_bytes(blob: &[u8], ctype: i64) -> Result<Vec<u8>> {
    match ctype {
        0 => Ok(blob.to_vec()),
        1 => {
            let dec = ruzstd::decoding::StreamingDecoder::new(blob)
                .map_err(|e| Error::Corrupt(format!("cannot decompress a localStorage value: {e}")))?;
            let mut out = Vec::new();
            dec.take(MAX_INFLATED + 1)
                .read_to_end(&mut out)
                .map_err(|e| Error::Corrupt(format!("cannot decompress a localStorage value: {e}")))?;
            if out.len() as u64 > MAX_INFLATED {
                return Err(Error::Corrupt("a compressed localStorage value inflates beyond the safety limit".into()));
            }
            Ok(out)
        }
        t => Err(Error::Corrupt(format!("unknown localStorage value compression type {t}"))),
    }
}

// ---- protobuf bits for META / METAACCESS ------------------------------------------------

fn read_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let (mut result, mut shift) = (0u64, 0u32);
    loop {
        let byte = *data.get(pos).ok_or_else(|| Error::Corrupt("truncated varint in a Local Storage META record".into()))?;
        pos += 1;
        if shift < 64 {
            result |= u64::from(byte & 0x7F) << shift;
        }
        if byte & 0x80 == 0 {
            return Ok((result, pos));
        }
        shift += 7;
    }
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            return out;
        }
    }
}

fn varint_field(number: u64, value: u64) -> Vec<u8> {
    let mut out = varint(number << 3);
    out.extend(varint(value));
    out
}

/// Rebuild a META / METAACCESS value: field 1 = time (Chrome microseconds), field 2 (META only)
/// = area size. Unknown fields of an existing record are preserved byte for byte.
pub fn meta_value(existing: Option<&[u8]>, now: u64, size: Option<u64>) -> Result<Vec<u8>> {
    let truncated = || Error::Corrupt("truncated Local Storage META record".into());
    let mut fields: Vec<(u64, &[u8])> = Vec::new();
    if let Some(data) = existing {
        let mut pos = 0;
        while pos < data.len() {
            let start = pos;
            let (tag, p) = read_varint(data, pos)?;
            pos = p;
            match tag & 7 {
                0 => pos = read_varint(data, pos)?.1,
                2 => {
                    let (len, p) = read_varint(data, pos)?;
                    pos = usize::try_from(len).ok().and_then(|l| p.checked_add(l)).ok_or_else(truncated)?;
                }
                1 => pos += 8,
                5 => pos += 4,
                w => return Err(Error::Corrupt(format!("cannot parse a Local Storage META record (wire type {w})"))),
            }
            if pos > data.len() {
                return Err(truncated());
            }
            fields.push((tag >> 3, &data[start..pos]));
        }
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    let (mut wrote_time, mut wrote_size) = (false, false);
    for (number, raw) in fields {
        if number == 1 {
            out.push(varint_field(1, now));
            wrote_time = true;
        } else if number == 2 && size.is_some() {
            out.push(varint_field(2, size.unwrap_or(0)));
            wrote_size = true;
        } else {
            out.push(raw.to_vec());
        }
    }
    if !wrote_time {
        out.insert(0, varint_field(1, now));
    }
    if let (Some(s), false) = (size, wrote_size) {
        out.push(varint_field(2, s));
    }
    Ok(out.concat())
}

/// The size field (2) of a META value, for callers that want to check upkeep.
pub fn meta_size(meta: &[u8]) -> Result<Option<u64>> {
    let (mut pos, mut size) = (0, None);
    while pos < meta.len() {
        let (tag, p) = read_varint(meta, pos)?;
        if tag & 7 != 0 {
            return Err(Error::Corrupt("unexpected wire type in a META record".into()));
        }
        let (v, p) = read_varint(meta, p)?;
        pos = p;
        if tag >> 3 == 2 {
            size = Some(v);
        }
    }
    Ok(size)
}

// ---- reading ---------------------------------------------------------------------------

/// Copy a database (plus -wal/-shm) into a temp dir so reading never fights a running browser.
fn snapshot_db(db: &Path) -> Result<(tempfile::TempDir, PathBuf)> {
    let tmp = tempfile::Builder::new().prefix("moveit-ls-").tempdir().map_err(|e| Error::Io(e.to_string()))?;
    let name = db.file_name().ok_or_else(|| Error::Io("store has no file name".into()))?;
    let target = tmp.path().join(name);
    for suffix in ["", "-wal", "-shm"] {
        let mut os = db.as_os_str().to_owned();
        os.push(suffix);
        let src = PathBuf::from(os);
        if probe(&src)? == Found::File {
            let mut dst = target.as_os_str().to_owned();
            dst.push(suffix);
            fs::copy(&src, PathBuf::from(dst)).map_err(|e| io(e, "cannot copy", &src))?;
        }
    }
    Ok((tmp, target))
}

fn has_ls_schema(con: &Connection) -> Result<bool> {
    let mut st = con.prepare("SELECT name FROM sqlite_master WHERE type='table'").map_err(sql)?;
    let names: Vec<String> = st
        .query_map([], |r| r.get(0))
        .map_err(sql)?
        .collect::<rusqlite::Result<_>>()
        .map_err(sql)?;
    Ok(["maps", "map_entries"].iter().all(|t| names.iter().any(|n| n == t)))
}

fn bad_schema(path: &Path) -> Error {
    Error::Corrupt(format!(
        "the LocalStorage file at {} does not have the expected SQLite Local Storage schema; refusing to guess at it",
        path.display()
    ))
}

fn sqlite_storage_key(id: &str) -> Vec<u8> {
    format!("chrome-extension://{id}/").into_bytes()
}

fn read_sqlite(db: &Path, ext_ids: &[String]) -> Result<Vec<Triple>> {
    let (_tmp, copy) = snapshot_db(db)?;
    let con = Connection::open(&copy).map_err(sql)?;
    if !has_ls_schema(&con)? {
        return Err(bad_schema(db));
    }
    let mut out = Vec::new();
    for id in ext_ids {
        let row: Option<i64> = con
            .query_row("SELECT row_id FROM maps WHERE storage_key=?", [sqlite_storage_key(id)], |r| r.get(0))
            .optional()
            .map_err(sql)?;
        let Some(map_id) = row else { continue };
        let mut st = con
            .prepare("SELECT key, value, value_compression_type FROM map_entries WHERE map_id=?")
            .map_err(sql)?;
        let rows = st
            .query_map([map_id], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, i64>(2)?)))
            .map_err(sql)?;
        for row in rows {
            let (k, v, ct) = row.map_err(sql)?;
            out.push(Triple {
                extension_id: id.clone(),
                key: decode_blob(&k, "localStorage key")?,
                value: decode_blob(&value_bytes(&v, ct)?, "localStorage value")?,
            });
        }
    }
    Ok(out)
}

fn ldb(e: rusty_leveldb::Status) -> Error {
    if e.code == StatusCode::LockError {
        return Error::BrowserOpen;
    }
    Error::Io(format!("Local Storage leveldb error: {e}"))
}

/// Every (key, value) whose key passes `keep`, in key order.
fn scan(db: &mut DB, keep: impl Fn(&[u8]) -> bool) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut it = db.new_iter().map_err(ldb)?;
    let mut out = Vec::new();
    while let Some((k, v)) = LdbIterator::next(&mut it) {
        if keep(&k) {
            out.push((k, v));
        }
    }
    Ok(out)
}

fn check_version(db: &mut DB) -> Result<()> {
    match db.get(b"VERSION") {
        Some(v) if &v[..] != b"1" => {
            Err(Error::Refused(format!("unsupported classic Local Storage version {:?}", String::from_utf8_lossy(&v))))
        }
        _ => Ok(()),
    }
}

fn copy_tree_no_links(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).map_err(|e| io(e, "cannot create", dst))?;
    for ent in fs::read_dir(src).map_err(|e| io(e, "cannot list", src))? {
        let ent = ent.map_err(|e| io(e, "cannot list", src))?;
        let from = ent.path();
        let ft = ent.file_type().map_err(|e| io(e, "cannot inspect", &from))?;
        if ft.is_symlink() {
            return Err(refuse_link(&from));
        }
        if ent.file_name() == "LOCK" {
            continue; // a copied lock is stale; leveldb recreates it
        }
        let to = dst.join(ent.file_name());
        if ft.is_dir() {
            copy_tree_no_links(&from, &to)?;
        } else if ft.is_file() {
            fs::copy(&from, &to).map_err(|e| io(e, "cannot copy", &from))?;
        }
    }
    Ok(())
}

fn leveldb_origin(id: &str) -> Vec<u8> {
    format!("chrome-extension://{id}").into_bytes()
}

fn read_leveldb(dir: &Path, ext_ids: &[String]) -> Result<Vec<Triple>> {
    let tmp = tempfile::Builder::new().prefix("moveit-ls-").tempdir().map_err(|e| Error::Io(e.to_string()))?;
    let copy = tmp.path().join("db");
    copy_tree_no_links(dir, &copy)?;
    let by_origin: BTreeMap<Vec<u8>, &String> = ext_ids.iter().map(|id| (leveldb_origin(id), id)).collect();
    let mut db = DB::open(&copy, Options::default()).map_err(|e| {
        Error::Corrupt(format!("cannot open the classic Local Storage leveldb at {}: {e}", dir.display()))
    })?;
    check_version(&mut db)?;
    let rows = scan(&mut db, |k| k.first() == Some(&b'_'))?;
    let _ = db.close();
    let mut out = Vec::new();
    for (k, v) in rows {
        let rest = &k[1..];
        let Some(sep) = rest.iter().position(|&b| b == 0) else { continue };
        let Some(id) = by_origin.get(&rest[..sep]) else { continue };
        out.push(Triple {
            extension_id: (*id).clone(),
            key: decode_blob(&rest[sep + 1..], "localStorage key")?,
            value: decode_blob(&v, "localStorage value")?,
        });
    }
    Ok(out)
}

/// The extension localStorage triples of a profile, sorted by (extension id, key). A profile
/// with no store (or no extension state) exports an empty list; a store that exists but cannot
/// be parsed fails closed.
pub fn export(profile: &Path) -> Result<Vec<Triple>> {
    let ids = extension_id_candidates(profile)?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut entries = match store(profile)? {
        Some((Shape::Sqlite, p)) => read_sqlite(&p, &ids)?,
        Some((Shape::Leveldb, p)) => read_leveldb(&p, &ids)?,
        None => return Ok(Vec::new()),
    };
    entries.sort_by(|a, b| (&a.extension_id, &a.key).cmp(&(&b.extension_id, &b.key)));
    Ok(entries)
}

/// Validate a box's `ext_localstorage` section: bundle content is data, not truth, so anything
/// that is not a list of `{extension_id, key, value}` string triples fails closed.
pub fn parse_section(section: &Value) -> Result<Vec<Triple>> {
    let list = match section {
        Value::Null => return Ok(Vec::new()),
        Value::Array(a) => a,
        _ => return Err(Error::Corrupt("bundle ext_localstorage is not a list".into())),
    };
    list.iter()
        .map(|e| {
            let field = |f: &str| e.get(f).and_then(Value::as_str).map(str::to_string);
            match (field("extension_id"), field("key"), field("value")) {
                (Some(extension_id), Some(key), Some(value)) => Ok(Triple { extension_id, key, value }),
                _ => Err(Error::Corrupt(format!("bundle ext_localstorage entry is not a string triple: {e}"))),
            }
        })
        .collect()
}

// ---- merging ---------------------------------------------------------------------------

/// Group by extension, reducing repeated keys to their winning (largest) value.
fn group(section: &[Triple]) -> BTreeMap<&str, BTreeMap<&str, &str>> {
    let mut groups: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();
    for t in section {
        let slot = groups.entry(&t.extension_id).or_default().entry(&t.key).or_insert(&t.value);
        if t.value.as_str() > *slot {
            *slot = &t.value;
        }
    }
    groups
}

fn count_entries(section: &[Triple], id: &str) -> usize {
    section.iter().filter(|t| t.extension_id == id).count()
}

fn merge_sqlite(con: &Connection, section: &[Triple], now: i64, report: &mut Report) -> Result<()> {
    for (id, items) in group(section) {
        let storage_key = sqlite_storage_key(id);
        let row: Option<(i64, Option<i64>)> = con
            .query_row("SELECT row_id, total_size FROM maps WHERE storage_key=?", [&storage_key], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .map_err(sql)?;
        let (map_id, mut total) = match row {
            Some((id, total)) => (id, total.unwrap_or(0)),
            None => {
                con.execute(
                    "INSERT INTO maps (storage_key, last_accessed, last_modified, total_size) VALUES (?, ?, ?, 0)",
                    rusqlite::params![storage_key, now, now],
                )
                .map_err(sql)?;
                report.maps_touched += 1;
                (con.last_insert_rowid(), 0)
            }
        };
        for (key, value) in items {
            let (kb, vb) = (encode_str(key), encode_str(value));
            let old: Option<(Vec<u8>, i64)> = con
                .query_row(
                    "SELECT value, value_compression_type FROM map_entries WHERE map_id=? AND key=?",
                    rusqlite::params![map_id, kb],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(sql)?;
            let Some((old_blob, old_ct)) = old else {
                con.execute(
                    "INSERT INTO map_entries (map_id, value_compression_type, key, value) VALUES (?, 0, ?, ?)",
                    rusqlite::params![map_id, kb, vb],
                )
                .map_err(sql)?;
                total += (kb.len() + vb.len()) as i64;
                report.inserted += 1;
                continue;
            };
            let old_bytes = value_bytes(&old_blob, old_ct)?;
            let old_value = decode_blob(&old_bytes, "localStorage value")?;
            if value <= old_value.as_str() {
                report.unchanged += 1;
                continue;
            }
            con.execute(
                "UPDATE map_entries SET value=?, value_compression_type=0 WHERE map_id=? AND key=?",
                rusqlite::params![vb, map_id, kb],
            )
            .map_err(sql)?;
            total += vb.len() as i64 - old_bytes.len() as i64;
            report.updated += 1;
        }
        con.execute(
            "UPDATE maps SET total_size=?, last_modified=? WHERE row_id=?",
            rusqlite::params![total, now, map_id],
        )
        .map_err(sql)?;
        report.entries += count_entries(section, id);
    }
    Ok(())
}

fn import_sqlite(path: &Path, section: &[Triple], now: i64, report: &mut Report, wait: Duration) -> Result<()> {
    let mut con = Connection::open(path).map_err(sql)?;
    con.busy_timeout(wait).map_err(sql)?;
    let tx = con.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
    if !has_ls_schema(&tx)? {
        return Err(bad_schema(path));
    }
    merge_sqlite(&tx, section, now, report)?;
    tx.commit().map_err(sql)
}

fn import_leveldb(dir: &Path, section: &[Triple], now: i64, report: &mut Report) -> Result<()> {
    let mut db = DB::open(dir, Options::default()).map_err(ldb)?;
    let result = (|| {
        check_version(&mut db)?;
        let mut batch = WriteBatch::default();
        for (id, items) in group(section) {
            let origin = leveldb_origin(id);
            let mut prefix = vec![b'_'];
            prefix.extend(&origin);
            prefix.push(0);
            let mut area: BTreeMap<Vec<u8>, Vec<u8>> = scan(&mut db, |k| k.starts_with(&prefix))?
                .into_iter()
                .map(|(k, v)| (k[prefix.len()..].to_vec(), v))
                .collect();
            for (key, value) in items {
                let (kb, vb) = (encode_str(key), encode_str(value));
                match area.get(&kb) {
                    None => report.inserted += 1,
                    Some(old) => {
                        if value <= decode_blob(old, "localStorage value")?.as_str() {
                            report.unchanged += 1;
                            continue;
                        }
                        report.updated += 1;
                    }
                }
                let mut full = prefix.clone();
                full.extend(&kb);
                batch.put(&full, &vb);
                area.insert(kb, vb);
            }
            let total: u64 = area.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum();
            let mut meta_key = b"META:".to_vec();
            meta_key.extend(&origin);
            let mut access_key = b"METAACCESS:".to_vec();
            access_key.extend(&origin);
            let t = now.max(0) as u64;
            batch.put(&meta_key, &meta_value(db.get(&meta_key).as_deref(), t, Some(total))?);
            batch.put(&access_key, &meta_value(db.get(&access_key).as_deref(), t, None)?);
            report.maps_touched += 1;
            report.entries += count_entries(section, id);
        }
        db.write(batch, true).map_err(ldb)
    })();
    let closed = db.close().map_err(ldb);
    result.and(closed)
}

/// Merge a box's triples into the profile's Local Storage store. A profile with no store yet
/// reports `present = false` and changes nothing (the browser creates it on its own schedule).
/// `now` is the Chromium-microsecond stamp written into the touched records; passing it in
/// keeps the merge deterministic. A locked store is `Error::BrowserOpen` with nothing changed.
pub fn import(profile: &Path, section: &[Triple], now: i64) -> Result<Report> {
    let mut report = Report::default();
    if section.is_empty() {
        return Ok(report);
    }
    match store(profile)? {
        Some((Shape::Sqlite, p)) => {
            report.shape = Some(Shape::Sqlite);
            report.present = true;
            import_sqlite(&p, section, now, &mut report, Duration::from_secs(5))?;
        }
        Some((Shape::Leveldb, p)) => {
            report.shape = Some(Shape::Leveldb);
            report.present = true;
            import_leveldb(&p, section, now, &mut report)?;
        }
        None => {}
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_C: &str = "cccccccccccccccccccccccccccccccc";
    const SITE: &str = "http://127.0.0.1:8931";
    const TS: i64 = 13_438_000_000_000_000;
    const NOW: i64 = 13_440_000_000_000_000;

    const SCHEMA: &str = "
        CREATE TABLE maps(row_id INTEGER PRIMARY KEY AUTOINCREMENT, storage_key BLOB NOT NULL,
                          last_accessed INTEGER, last_modified INTEGER, total_size INTEGER);
        CREATE UNIQUE INDEX maps_by_storage_key ON maps(storage_key);
        CREATE TABLE map_entries(map_id INTEGER NOT NULL, value_compression_type INTEGER NOT NULL,
                                 key BLOB NOT NULL, value BLOB NOT NULL,
                                 PRIMARY KEY(map_id, key)) WITHOUT ROWID;
        CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        INSERT INTO meta VALUES ('mmap_status', '-1'), ('version', '1'), ('last_compatible_version', '1');";

    fn t(id: &str, k: &str, v: &str) -> Triple {
        Triple { extension_id: id.into(), key: k.into(), value: v.into() }
    }

    fn register(profile: &Path, id: &str) {
        let p = profile.join("Default/Extensions").join(id).join("1.0_0");
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("manifest.json"), b"{}").unwrap();
    }

    /// areas: storage key (with trailing slash) -> [(key, value)]. A value prefixed "zstd:" is
    /// stored compressed the way the browser stores large values.
    fn make_sqlite(profile: &Path, areas: &[(&str, Vec<(&str, &str)>)]) {
        let path = sqlite_path(profile);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let con = Connection::open(&path).unwrap();
        con.execute_batch(SCHEMA).unwrap();
        for (sk, items) in areas {
            con.execute(
                "INSERT INTO maps (storage_key, last_accessed, last_modified, total_size) VALUES (?, ?, ?, 0)",
                rusqlite::params![sk.as_bytes(), TS, TS],
            )
            .unwrap();
            let map_id = con.last_insert_rowid();
            let mut total = 0usize;
            for (k, v) in items {
                let kb = encode_str(k);
                if let Some(plain) = v.strip_prefix("zstd:") {
                    let raw = encode_str(plain);
                    let blob = ruzstd::encoding::compress_to_vec(&raw[..], ruzstd::encoding::CompressionLevel::Fastest);
                    con.execute("INSERT INTO map_entries VALUES (?, 1, ?, ?)", rusqlite::params![map_id, kb, blob]).unwrap();
                    total += kb.len() + raw.len();
                } else {
                    let vb = encode_str(v);
                    con.execute("INSERT INTO map_entries VALUES (?, 0, ?, ?)", rusqlite::params![map_id, kb, vb]).unwrap();
                    total += kb.len() + vb.len();
                }
            }
            con.execute("UPDATE maps SET total_size=? WHERE row_id=?", rusqlite::params![total as i64, map_id]).unwrap();
        }
    }

    type RawArea = (i64, BTreeMap<Vec<u8>, (Vec<u8>, i64)>);

    fn raw_sqlite(profile: &Path) -> BTreeMap<String, RawArea> {
        let con = Connection::open(sqlite_path(profile)).unwrap();
        let mut out = BTreeMap::new();
        let mut st = con.prepare("SELECT row_id, storage_key, total_size FROM maps").unwrap();
        let maps: Vec<(i64, Vec<u8>, i64)> =
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(|r| r.unwrap()).collect();
        for (id, sk, total) in maps {
            let mut st = con.prepare("SELECT key, value, value_compression_type FROM map_entries WHERE map_id=?").unwrap();
            let entries = st
                .query_map([id], |r| Ok((r.get::<_, Vec<u8>>(0)?, (r.get::<_, Vec<u8>>(1)?, r.get::<_, i64>(2)?))))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            out.insert(String::from_utf8(sk).unwrap(), (total, entries));
        }
        out
    }

    fn make_leveldb(profile: &Path, areas: &[(&str, Vec<(&str, &str)>)]) {
        let path = leveldb_path(profile);
        fs::create_dir_all(&path).unwrap();
        let mut opt = Options::default();
        opt.create_if_missing = true;
        let mut db = DB::open(&path, opt).unwrap();
        db.put(b"VERSION", b"1").unwrap();
        for (origin, items) in areas {
            let mut prefix = format!("_{origin}").into_bytes();
            prefix.push(0);
            let mut total = 0u64;
            for (k, v) in items {
                let (kb, vb) = (encode_str(k), encode_str(v));
                db.put(&[&prefix[..], &kb].concat(), &vb).unwrap();
                total += (kb.len() + vb.len()) as u64;
            }
            db.put(format!("META:{origin}").as_bytes(), &meta_value(None, TS as u64, Some(total)).unwrap()).unwrap();
            db.put(format!("METAACCESS:{origin}").as_bytes(), &meta_value(None, TS as u64, None).unwrap()).unwrap();
        }
        db.close().unwrap();
    }

    fn raw_leveldb(profile: &Path) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut db = DB::open(leveldb_path(profile), Options::default()).unwrap();
        let out = scan(&mut db, |_| true).unwrap().into_iter().collect();
        db.close().unwrap();
        out
    }

    fn ext_origin(id: &str) -> String {
        format!("chrome-extension://{id}")
    }

    fn sqlite_profile(areas: &[(&str, Vec<(&str, &str)>)]) -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        register(p.path(), ID_A);
        register(p.path(), ID_C);
        make_sqlite(p.path(), areas);
        p
    }

    fn a_side() -> tempfile::TempDir {
        sqlite_profile(&[
            (&format!("{}/", ext_origin(ID_A)), vec![
                ("shared", "ls-A-value"),
                ("a_only", "alpha"),
                ("uni\u{2603}key", "v\u{2713}lue\u{2603}"),
                ("big", &format!("zstd:{}", "x".repeat(5000))),
            ]),
            (&format!("{SITE}/"), vec![("site_marker", "website-A-MUST-NOT-TRAVEL")]),
        ])
    }

    fn b_side() -> tempfile::TempDir {
        sqlite_profile(&[
            (&format!("{}/", ext_origin(ID_A)), vec![("shared", "ls-B-value"), ("b_only", "bravo")]),
            (&format!("{}/", ext_origin(ID_C)), vec![("c_key", "charlie")]),
            (&format!("{SITE}/"), vec![("site_marker", "website-B-must-survive")]),
        ])
    }

    fn triples(profile: &Path) -> Vec<Triple> {
        export(profile).unwrap()
    }

    #[test]
    fn string_encoding_matches_the_reference() {
        assert_eq!(encode_str("caf\u{e9}"), [1, b'c', b'a', b'f', 0xe9]);
        assert_eq!(encode_str("uni\u{2603}"), hex("0075006e0069000326"));
        for s in ["", "plain", "caf\u{e9}", "snow\u{2603}man", "astral \u{1F600}"] {
            assert_eq!(decode_blob(&encode_str(s), "t").unwrap(), s);
        }
        assert_eq!(decode_blob(b"", "t").unwrap(), "");
        assert!(matches!(decode_blob(&[7, 1], "t"), Err(Error::Corrupt(_)))); // unknown tag
        // A lone UTF-16 surrogate can't live in a Rust String; we substitute U+FFFD rather than
        // abort the whole store's import over one odd value.
        assert_eq!(decode_blob(&[0, 0x00, 0xd8], "t").unwrap(), "\u{FFFD}");
        assert!(matches!(decode_blob(&[0, 1], "t"), Err(Error::Corrupt(_)))); // odd length still fails
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn meta_values_match_the_reference_bytes() {
        let now = TS as u64;
        assert_eq!(meta_value(None, now, Some(7)).unwrap(), hex("0880c0f783a3b9ef171007"));
        let existing = [meta_value(None, 5, Some(9)).unwrap(), vec![0x18, 0x07]].concat();
        assert_eq!(meta_value(Some(&existing), now, None).unwrap(), hex("0880c0f783a3b9ef1710091807"));
        assert_eq!(meta_value(Some(&existing), now, Some(11)).unwrap(), hex("0880c0f783a3b9ef17100b1807"));
        assert_eq!(meta_size(&meta_value(None, now, Some(7)).unwrap()).unwrap(), Some(7));
        assert!(matches!(meta_value(Some(&[0x08]), now, None), Err(Error::Corrupt(_))));
        assert!(matches!(meta_value(Some(&[0x12, 0x05, 1]), now, None), Err(Error::Corrupt(_))));
        assert!(matches!(meta_value(Some(&[0x0b]), now, None), Err(Error::Corrupt(_))));
    }

    #[test]
    fn sqlite_export_carries_only_extension_origins_and_inflates_compressed_values() {
        let a = a_side();
        let got = triples(a.path());
        assert_eq!(
            got,
            vec![
                t(ID_A, "a_only", "alpha"),
                t(ID_A, "big", &"x".repeat(5000)),
                t(ID_A, "shared", "ls-A-value"),
                t(ID_A, "uni\u{2603}key", "v\u{2713}lue\u{2603}"),
            ]
        );
        let json = serde_json::to_string(&got).unwrap();
        assert!(!json.contains("website") && !json.contains("8931"));
        assert!(json.starts_with(r#"[{"extension_id":"aaaa"#));
    }

    #[test]
    fn sqlite_merge_is_a_key_level_union_and_keeps_everything_else_byte_for_byte() {
        let (a, b) = (a_side(), b_side());
        let before = raw_sqlite(b.path());
        let report = import(b.path(), &triples(a.path()), NOW).unwrap();
        assert!(report.present && report.shape == Some(Shape::Sqlite));
        // shared: "ls-B-value" > "ls-A-value", so B's value stays.
        assert_eq!((report.inserted, report.updated, report.unchanged, report.entries, report.maps_touched), (3, 0, 1, 4, 0));
        let area: BTreeMap<_, _> = triples(b.path()).into_iter().filter(|x| x.extension_id == ID_A).map(|x| (x.key, x.value)).collect();
        assert_eq!(area["shared"], "ls-B-value");
        assert_eq!(area["a_only"], "alpha");
        assert_eq!(area["b_only"], "bravo");
        assert_eq!(area["big"], "x".repeat(5000));
        assert_eq!(area["uni\u{2603}key"], "v\u{2713}lue\u{2603}");
        let after = raw_sqlite(b.path());
        assert_eq!(after[&format!("{SITE}/")], before[&format!("{SITE}/")]);
        assert_eq!(after[&format!("{}/", ext_origin(ID_C))], before[&format!("{}/", ext_origin(ID_C))]);
        let (total, entries) = &after[&format!("{}/", ext_origin(ID_A))];
        let sum: usize = entries.iter().map(|(k, (v, ct))| k.len() + value_bytes(v, *ct).unwrap().len()).sum();
        assert_eq!(*total, sum as i64);
    }

    #[test]
    fn the_larger_value_wins_and_a_compressed_loser_is_rewritten_plain() {
        let b = sqlite_profile(&[(&format!("{}/", ext_origin(ID_A)), vec![("k", "zstd:aaa"), ("j", "zstd:zzz")])]);
        let rep = import(b.path(), &[t(ID_A, "k", "bbb"), t(ID_A, "j", "yyy"), t(ID_A, "j", "aaa")], NOW).unwrap();
        assert_eq!((rep.updated, rep.unchanged, rep.inserted), (1, 1, 0));
        let m = raw_sqlite(b.path());
        let (total, entries) = &m[&format!("{}/", ext_origin(ID_A))];
        assert_eq!(entries[&encode_str("k")], (encode_str("bbb"), 0));
        assert_eq!(entries[&encode_str("j")].1, 1); // untouched: still the browser's own compressed row
        let sum: usize = entries.iter().map(|(k, (v, ct))| k.len() + value_bytes(v, *ct).unwrap().len()).sum();
        assert_eq!(*total, sum as i64);
    }

    #[test]
    fn merging_is_commutative_idempotent_and_deterministic() {
        let (a1, b1) = (a_side(), b_side());
        let (a2, b2) = (a_side(), b_side());
        // A <- B  and  B <- A, then compare.
        import(a1.path(), &triples(b1.path()), NOW).unwrap();
        import(b2.path(), &triples(a2.path()), NOW).unwrap();
        // b1 still has its own original; a2 too. Now both sides hold the same set.
        assert_eq!(triples(a1.path()), triples(b2.path()));
        // Same stored content and same total_size for the extension area (a row the browser
        // compressed and one we wrote plain hold the same bytes once inflated).
        let key = format!("{}/", ext_origin(ID_A));
        let eff = |p: &Path| {
            let (total, rows) = raw_sqlite(p).remove(&key).unwrap();
            let rows: BTreeMap<_, _> = rows.into_iter().map(|(k, (v, ct))| (k, value_bytes(&v, ct).unwrap())).collect();
            (total, rows)
        };
        assert_eq!(eff(a1.path()), eff(b2.path()));
        // Idempotent: merging the other side's box again changes nothing.
        let settled = triples(b2.path());
        let rep = import(b2.path(), &triples(a1.path()), NOW).unwrap();
        assert_eq!((rep.inserted, rep.updated), (0, 0));
        assert_eq!(triples(b2.path()), settled);
        // Order of the box does not matter either.
        let mut rev = triples(a2.path());
        rev.reverse();
        let b3 = b_side();
        import(b3.path(), &rev, NOW).unwrap();
        assert_eq!(triples(b3.path()), settled);
    }

    #[test]
    fn a_profile_without_a_store_reports_not_present_and_creates_nothing() {
        let p = tempfile::tempdir().unwrap();
        register(p.path(), ID_A);
        let rep = import(p.path(), &[t(ID_A, "k", "v")], NOW).unwrap();
        assert!(!rep.present && rep.shape.is_none());
        assert!(!sqlite_path(p.path()).exists() && !leveldb_path(p.path()).exists());
        assert!(export(p.path()).unwrap().is_empty());
        assert!(store_path(p.path()).unwrap().is_none());
        let nothing = import(p.path(), &[], NOW).unwrap();
        assert_eq!(nothing, Report::default());
    }

    #[test]
    fn a_locked_sqlite_store_is_browser_open_and_nothing_changes() {
        let b = b_side();
        let before = raw_sqlite(b.path());
        let hold = Connection::open(sqlite_path(b.path())).unwrap();
        hold.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let mut report = Report::default();
        let err = import_sqlite(&sqlite_path(b.path()), &[t(ID_A, "k", "v")], NOW, &mut report, Duration::from_millis(50))
            .unwrap_err();
        assert_eq!(err, Error::BrowserOpen);
        hold.execute_batch("ROLLBACK").unwrap();
        assert_eq!(raw_sqlite(b.path()), before);
    }

    #[test]
    fn a_store_with_the_wrong_schema_is_refused() {
        let p = tempfile::tempdir().unwrap();
        register(p.path(), ID_A);
        let path = sqlite_path(p.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        Connection::open(&path).unwrap().execute_batch("CREATE TABLE other(x)").unwrap();
        assert!(matches!(export(p.path()), Err(Error::Corrupt(_))));
        assert!(matches!(import(p.path(), &[t(ID_A, "k", "v")], NOW), Err(Error::Corrupt(_))));
    }

    #[test]
    fn section_validation_fails_closed() {
        let ok = json!([{"extension_id": "a", "key": "k", "value": "v"}]);
        assert_eq!(parse_section(&ok).unwrap(), vec![t("a", "k", "v")]);
        assert!(parse_section(&Value::Null).unwrap().is_empty());
        for bad in [
            json!({"extension_id": "a"}),
            json!([{"extension_id": "a", "key": "k"}]),
            json!([{"extension_id": "a", "key": "k", "value": 5}]),
            json!(["x"]),
        ] {
            assert!(matches!(parse_section(&bad), Err(Error::Corrupt(_))), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_store_is_refused() {
        let p = tempfile::tempdir().unwrap();
        register(p.path(), ID_A);
        let real = tempfile::tempdir().unwrap();
        fs::create_dir_all(p.path().join("Default")).unwrap();
        std::os::unix::fs::symlink(real.path().join("LocalStorage"), sqlite_path(p.path())).unwrap();
        assert!(matches!(export(p.path()), Err(Error::Refused(_))));
        let q = tempfile::tempdir().unwrap();
        register(q.path(), ID_A);
        make_leveldb(q.path(), &[(&ext_origin(ID_A), vec![("k", "v")])]);
        std::os::unix::fs::symlink(real.path(), leveldb_path(q.path()).join("evil")).unwrap();
        assert!(matches!(export(q.path()), Err(Error::Refused(_))));
    }

    fn classic_a() -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        register(p.path(), ID_A);
        make_leveldb(p.path(), &[
            (&ext_origin(ID_A), vec![("shared", "classic-A"), ("ca_only", "x")]),
            (SITE, vec![("site_marker", "website-classic-A")]),
        ]);
        p
    }

    fn classic_b() -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        register(p.path(), ID_A);
        make_leveldb(p.path(), &[
            (&ext_origin(ID_A), vec![("shared", "classic-B"), ("cb_only", "y")]),
            (SITE, vec![("site_marker", "website-classic-B")]),
        ]);
        p
    }

    #[test]
    fn leveldb_export_carries_only_the_extension_origin() {
        let a = classic_a();
        assert_eq!(triples(a.path()), vec![t(ID_A, "ca_only", "x"), t(ID_A, "shared", "classic-A")]);
    }

    #[test]
    fn leveldb_merge_unions_keys_keeps_websites_and_maintains_meta() {
        let (a, b) = (classic_a(), classic_b());
        let before = raw_leveldb(b.path());
        let rep = import(b.path(), &triples(a.path()), NOW).unwrap();
        assert!(rep.present && rep.shape == Some(Shape::Leveldb));
        assert_eq!((rep.inserted, rep.updated, rep.unchanged, rep.entries, rep.maps_touched), (1, 0, 1, 2, 1));
        let after = raw_leveldb(b.path());
        let prefix = [b"_".as_slice(), ext_origin(ID_A).as_bytes(), &[0]].concat();
        let area: BTreeMap<String, String> = after
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| (decode_blob(&k[prefix.len()..], "k").unwrap(), decode_blob(v, "v").unwrap()))
            .collect();
        // "classic-B" > "classic-A": B keeps its value; both sides' keys survive.
        assert_eq!(area, BTreeMap::from([("shared".into(), "classic-B".into()), ("ca_only".into(), "x".into()), ("cb_only".into(), "y".into())]));
        for (k, v) in &before {
            if k.starts_with(b"_http") || k.ends_with(SITE.as_bytes()) {
                assert_eq!(after.get(k), Some(v), "website record {:?}", String::from_utf8_lossy(k));
            }
        }
        let expect: u64 = after.iter().filter(|(k, _)| k.starts_with(&prefix)).map(|(k, v)| (k.len() - prefix.len() + v.len()) as u64).sum();
        let meta = &after[format!("META:{}", ext_origin(ID_A)).as_bytes()];
        assert_eq!(meta_size(meta).unwrap(), Some(expect));
        assert_eq!(meta_value(Some(meta), NOW as u64, Some(expect)).unwrap(), *meta);
        assert!(!after[format!("METAACCESS:{}", ext_origin(ID_A)).as_bytes()].is_empty());
    }

    #[test]
    fn leveldb_merge_is_commutative() {
        let (a1, b1) = (classic_a(), classic_b());
        let (a2, b2) = (classic_a(), classic_b());
        import(a1.path(), &triples(b1.path()), NOW).unwrap();
        import(b2.path(), &triples(a2.path()), NOW).unwrap();
        assert_eq!(triples(a1.path()), triples(b2.path()));
        // Website records differ by design; everything of the extension origin is identical.
        let ext_only = |p: &Path| -> BTreeMap<Vec<u8>, Vec<u8>> {
            raw_leveldb(p).into_iter().filter(|(k, _)| k.windows(ID_A.len()).any(|w| w == ID_A.as_bytes())).collect()
        };
        assert_eq!(ext_only(a1.path()), ext_only(b2.path()));
        assert_eq!(ext_only(a1.path()).len(), 3 + 2);
    }

    #[test]
    fn a_newer_leveldb_version_is_refused_and_a_held_lock_is_browser_open() {
        let b = classic_b();
        let held = DB::open(leveldb_path(b.path()), Options::default()).unwrap();
        assert_eq!(import(b.path(), &[t(ID_A, "k", "v")], NOW).unwrap_err(), Error::BrowserOpen);
        drop(held);
        let mut db = DB::open(leveldb_path(b.path()), Options::default()).unwrap();
        db.put(b"VERSION", b"2").unwrap();
        db.close().unwrap();
        assert!(matches!(import(b.path(), &[t(ID_A, "k", "v")], NOW), Err(Error::Refused(_))));
        assert!(matches!(export(b.path()), Err(Error::Refused(_))));
    }
}
