//! Bookmarks store: the Bookmarks file travels in the box as bytes.
//!
//! Manifest JSON is: `{"present": false}` or
//! `{"present": true, "size": N, "sha256": "..."}`; the bytes travel separately in the box.
//!
//! Keep-both rule on import: the person ends up with both sets of bookmarks in the one
//! file the browser actually reads.
//! - no local file: write the incoming bytes as they are.
//! - local file with the same hash: nothing to do.
//! - both files parse as bookmark trees: merge the incoming tree into the local one and
//!   write the merged tree back. Folders matched by name merge; a bookmark that is
//!   already there (same name, same address, same folder) is not duplicated; a different
//!   bookmark that reuses a name is kept as `Name (1)`. The stale `checksum` is dropped
//!   from the merged file; browsers recompute it when they next save.
//! - local file exists but does not parse as a bookmark tree: it is left untouched and
//!   the incoming bytes are written beside it as `Bookmarks.moveit-incoming-<UTC stamp>`
//!   for a person to reconcile. We never destroy what we cannot read.
//!
//! The merge replaces the local file. That is safe where `import` is meant to be called:
//! the engine applies a whole box inside its journal (txn.rs), which snapshots the
//! original file before any write, so it stays recoverable through rollback and Undo.
//! A sibling left by the fallback is never consumed automatically; it is a person's copy.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const SIBLING_MARK: &str = ".moveit-incoming-";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Written,
    Identical,
    Merged,
    Conflict,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub carried: bool,
    pub action: Option<Action>,
    pub path: Option<PathBuf>,
}

fn io(e: std::io::Error) -> Error {
    Error::Io(format!("bookmarks file error: {e}"))
}

fn ser(e: serde_json::Error) -> Error {
    Error::Io(format!("cannot shape the merged Bookmarks file: {e}"))
}

fn hex_sha256(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the Bookmarks file for the box. A missing file is `{"present": false}` and no bytes.
pub fn export(path: &Path) -> Result<(Manifest, Option<Vec<u8>>)> {
    match fs::read(path) {
        Ok(data) => Ok((
            Manifest { present: true, size: Some(data.len() as u64), sha256: Some(hex_sha256(&data)) },
            Some(data),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((Manifest::default(), None)),
        Err(e) => Err(io(e)),
    }
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time (civil-from-days, proleptic Gregorian).
fn utc_stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io)?;
    }
    fs::write(path, data).map_err(io)
}

/// A bookmark tree is a JSON object with an object at `roots`. Anything else is not a
/// Bookmarks file we can merge into or out of.
fn parse_tree(data: &[u8]) -> Result<Value> {
    let v: Value = serde_json::from_slice(data)
        .map_err(|e| Error::Corrupt(format!("a Bookmarks file is not readable as JSON: {e}")))?;
    match v.get("roots") {
        Some(Value::Object(_)) => Ok(v),
        _ => Err(Error::Corrupt("a Bookmarks file has no bookmark roots".into())),
    }
}

fn node_kind(node: &Value) -> &str {
    match node.get("type").and_then(Value::as_str) {
        Some(t) => t,
        None if node.get("children").is_some() => "folder",
        None if node.get("url").is_some() => "url",
        None => "",
    }
}

fn node_name(node: &Value) -> &str {
    node.get("name").and_then(Value::as_str).unwrap_or("")
}

fn children_of(node: &Value) -> Vec<Value> {
    node.get("children").and_then(Value::as_array).cloned().unwrap_or_default()
}

/// Bookkeeping for one merge: the ids and guids already present in the merged tree, and
/// how much the incoming tree actually added. Zero additions means the local tree already
/// held everything, so the local file is left exactly as it was.
struct Merger {
    used_ids: HashSet<String>,
    next_id: u64,
    used_guids: HashSet<String>,
    guid_salt: u64,
    added: usize,
}

impl Merger {
    fn from_tree(tree: &Value) -> Merger {
        let mut m = Merger {
            used_ids: HashSet::new(),
            next_id: 1,
            used_guids: HashSet::new(),
            guid_salt: 0,
            added: 0,
        };
        m.collect(tree);
        m
    }

    fn collect(&mut self, v: &Value) {
        match v {
            Value::Object(map) => {
                if let Some(id) = map.get("id").and_then(Value::as_str) {
                    if let Ok(n) = id.parse::<u64>() {
                        self.next_id = self.next_id.max(n.checked_add(1).unwrap_or(1));
                    }
                    self.used_ids.insert(id.to_string());
                }
                if let Some(g) = map.get("guid").and_then(Value::as_str) {
                    self.used_guids.insert(g.to_string());
                }
                for val in map.values() {
                    self.collect(val);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.collect(item);
                }
            }
            _ => {}
        }
    }

    /// A fresh guid that is not in the merged tree. Derived from a hash of a per-merge
    /// counter: uniqueness is what matters here, and the used-set check enforces it.
    fn fresh_guid(&mut self) -> String {
        loop {
            self.guid_salt += 1;
            let digest = Sha256::digest(self.guid_salt.to_le_bytes());
            let b = &digest[..16];
            let guid = format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                b[0], b[1], b[2], b[3], b[4], b[5], (b[6] & 0x0f) | 0x40, b[7],
                (b[8] & 0x3f) | 0x80, b[9], b[10], b[11], b[12], b[13], b[14], b[15]
            );
            if self.used_guids.insert(guid.clone()) {
                return guid;
            }
        }
    }

    /// Give an appended subtree ids and guids that are unique in the merged tree.
    fn fix_up(&mut self, v: &mut Value) {
        match v {
            Value::Object(map) => {
                if map.contains_key("id") {
                    let mut n = self.next_id;
                    while self.used_ids.contains(&n.to_string()) {
                        n = n.checked_add(1).unwrap_or(1);
                    }
                    self.next_id = n.checked_add(1).unwrap_or(1);
                    self.used_ids.insert(n.to_string());
                    map.insert("id".into(), Value::String(n.to_string()));
                }
                let clash = match map.get("guid") {
                    Some(Value::String(g)) => !self.used_guids.insert(g.clone()),
                    _ => false,
                };
                if clash {
                    let fresh = self.fresh_guid();
                    map.insert("guid".into(), Value::String(fresh));
                }
                for val in map.values_mut() {
                    self.fix_up(val);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.fix_up(item);
                }
            }
            _ => {}
        }
    }
}

/// Ignore clash suffixes on both sides, including names from older repeated merges.
fn base_name(mut name: &str) -> &str {
    while let Some((base, suffix)) = name.strip_suffix(')').and_then(|s| s.rsplit_once(" (")) {
        if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
            break;
        }
        name = base;
    }
    name
}

/// The first `Name (1)`, `Name (2)`, ... not already taken in the folder.
fn free_name(base: &str, taken: &HashSet<&str>) -> String {
    let mut n = 1;
    loop {
        let cand = format!("{base} ({n})");
        if !taken.contains(cand.as_str()) {
            return cand;
        }
        n += 1;
    }
}

fn merge_folder_children(target_node: &mut Value, inc_kids: &[Value], m: &mut Merger) {
    if !matches!(target_node.get("children"), Some(Value::Array(_))) {
        match target_node.as_object_mut() {
            Some(map) => {
                map.insert("children".into(), Value::Array(Vec::new()));
            }
            None => return,
        }
    }
    if let Some(Value::Array(kids)) = target_node.get_mut("children") {
        merge_children(kids, inc_kids, m);
    }
}

/// Union `incoming` into `target`, folder by folder. Appended nodes keep their incoming
/// order and land after the target's own children.
fn merge_children(target: &mut Vec<Value>, incoming: &[Value], m: &mut Merger) {
    for inc in incoming {
        match node_kind(inc) {
            "folder" => {
                let name = node_name(inc).to_string();
                let inc_kids = children_of(inc);
                let found = target
                    .iter()
                    .position(|c| node_kind(c) == "folder" && node_name(c) == name);
                match found {
                    Some(i) => merge_folder_children(&mut target[i], &inc_kids, m),
                    None => {
                        let mut c = inc.clone();
                        m.fix_up(&mut c);
                        target.push(c);
                        m.added += 1;
                    }
                }
            }
            "url" => {
                let name = node_name(inc);
                let url = inc.get("url").and_then(Value::as_str).unwrap_or("");
                let duplicate = target.iter().any(|c| {
                    node_kind(c) == "url"
                        && base_name(name) == base_name(node_name(c))
                        && c.get("url").and_then(Value::as_str).unwrap_or("") == url
                });
                if duplicate {
                    continue;
                }
                let mut c = inc.clone();
                let name_taken = target
                    .iter()
                    .any(|x| node_kind(x) == "url" && node_name(x) == name);
                if name_taken {
                    let taken: HashSet<&str> = target
                        .iter()
                        .filter(|x| node_kind(x) == "url")
                        .map(node_name)
                        .collect();
                    let renamed = free_name(base_name(name), &taken);
                    if let Some(map) = c.as_object_mut() {
                        map.insert("name".into(), Value::String(renamed));
                    }
                }
                m.fix_up(&mut c);
                target.push(c);
                m.added += 1;
            }
            _ => {
                // A leaf we do not know how to compare: keep it unless the exact same
                // node is already in this folder.
                if target.iter().any(|c| c == inc) {
                    continue;
                }
                let mut c = inc.clone();
                m.fix_up(&mut c);
                target.push(c);
                m.added += 1;
            }
        }
    }
}

/// Merge the incoming tree into the local tree in place. Returns how many nodes the
/// incoming tree added; the caller owns the `checksum` field and the write.
fn merge_trees(local: &mut Value, incoming: &Value) -> usize {
    let mut m = Merger::from_tree(local);
    let inc_roots = match incoming.get("roots").and_then(Value::as_object) {
        Some(r) => r.clone(),
        None => return 0,
    };
    let local_roots = match local.get_mut("roots").and_then(Value::as_object_mut) {
        Some(r) => r,
        None => return 0,
    };
    for (key, inc_root) in &inc_roots {
        if !inc_root.is_object() {
            continue;
        }
        match local_roots.get_mut(key) {
            Some(t) if t.is_object() => {
                let inc_kids = children_of(inc_root);
                merge_folder_children(t, &inc_kids, &mut m);
            }
            _ => {
                let mut c = inc_root.clone();
                m.fix_up(&mut c);
                local_roots.insert(key.clone(), c);
                m.added += 1;
            }
        }
    }
    m.added
}

/// The original keep-both fallback for a local file we cannot read as a tree: leave it
/// untouched and place the incoming bytes beside it for a person to reconcile.
fn import_as_sibling(target: &Path, data: &[u8], report: &mut Report) -> Result<Report> {
    report.action = Some(Action::Conflict);
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let base = target.file_name().and_then(|n| n.to_str()).unwrap_or("Bookmarks").to_string();
    let prefix = format!("{base}{SIBLING_MARK}");
    // A sibling that already holds exactly these bytes is reused (sorted so the pick is stable).
    let mut siblings: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(io)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect();
    siblings.sort();
    for s in siblings {
        if s.is_file() && fs::read(&s).map(|b| b == data).unwrap_or(false) {
            report.path = Some(s);
            return Ok(std::mem::take(report));
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let stamp = utc_stamp(now);
    let mut incoming = dir.join(format!("{prefix}{stamp}"));
    let mut counter = 1;
    while incoming.exists() {
        incoming = dir.join(format!("{prefix}{stamp}-{counter}"));
        counter += 1;
    }
    write_file(&incoming, data)?;
    report.path = Some(incoming);
    Ok(std::mem::take(report))
}

/// Place the box's Bookmarks file under the keep-both rule. `data` must match `manifest`.
pub fn import(target: &Path, manifest: &Manifest, data: Option<&[u8]>) -> Result<Report> {
    let mut report = Report::default();
    if !manifest.present {
        return Ok(report);
    }
    let data = data.ok_or_else(|| Error::Corrupt("bundle payload is missing the bytes for its Bookmarks file".into()))?;
    let sha = hex_sha256(data);
    if manifest.size != Some(data.len() as u64) || manifest.sha256.as_deref() != Some(sha.as_str()) {
        return Err(Error::Corrupt("the Bookmarks file in the box does not match its manifest".into()));
    }
    report.carried = true;
    if !target.exists() {
        write_file(target, data)?;
        report.action = Some(Action::Written);
        report.path = Some(target.to_path_buf());
        return Ok(report);
    }
    let local = fs::read(target).map_err(io)?;
    if hex_sha256(&local) == sha {
        report.action = Some(Action::Identical);
        report.path = Some(target.to_path_buf());
        return Ok(report);
    }
    // The incoming bytes are the payload: if they are not a bookmark tree,
    // they are placed beside the local file (the keep-both fallback), and
    // the local file stays exactly as it is. One box's bad bookmarks never
    // fail the whole move.
    let incoming_tree = match parse_tree(data) {
        Ok(t) => t,
        Err(_) => return import_as_sibling(target, data, &mut report),
    };
    match parse_tree(&local) {
        Ok(mut local_tree) => {
            let added = merge_trees(&mut local_tree, &incoming_tree);
            if added == 0 {
                report.action = Some(Action::Identical);
                report.path = Some(target.to_path_buf());
                return Ok(report);
            }
            if let Some(map) = local_tree.as_object_mut() {
                map.remove("checksum");
            }
            let bytes = serde_json::to_vec(&local_tree).map_err(ser)?;
            write_file(target, &bytes)?;
            report.action = Some(Action::Merged);
            report.path = Some(target.to_path_buf());
            Ok(report)
        }
        Err(_) => import_as_sibling(target, data, &mut report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BM_D: &[u8] = br#"{"checksum": "dummy-d", "roots": {"bookmark_bar": {"children": [], "name": "D"}}}"#;
    const BM_LOCAL: &[u8] = br#"{"checksum": "dummy-local", "roots": {"bookmark_bar": {"children": [], "name": "L"}}}"#;

    /// A used profile's file, the harness scenario: the target already has its own
    /// bookmark and a folder with a bookmark in it.
    const BM_TARGET: &[u8] = br#"{"checksum": "target-checksum", "roots": {
        "bookmark_bar": {"children": [
            {"date_added": "13370000000000000", "guid": "11111111-1111-4111-8111-111111111111", "id": "5", "name": "Opera Welcome", "type": "url", "url": "https://www.opera.com/welcome"},
            {"children": [
                {"date_added": "13370000000000001", "guid": "22222222-2222-4222-8222-222222222222", "id": "7", "name": "News One", "type": "url", "url": "https://news.example/one"}],
             "date_added": "13370000000000000", "date_modified": "13370000000000001", "guid": "33333333-3333-4333-8333-333333333333", "id": "6", "name": "News", "type": "folder"}],
         "date_added": "13370000000000000", "guid": "44444444-4444-4444-8444-444444444444", "id": "1", "name": "Bookmarks bar", "type": "folder"},
        "other": {"children": [], "guid": "55555555-5555-4555-8555-555555555555", "id": "2", "name": "Other bookmarks", "type": "folder"},
        "synced": {"children": [], "guid": "66666666-6666-4666-8666-666666666666", "id": "3", "name": "Mobile bookmarks", "type": "folder"}},
     "version": 1}"#;

    /// The source profile's file: the planted proof page, a same-named folder holding a
    /// second story, an exact copy of one of the target's bookmarks, one for Other.
    const BM_INCOMING: &[u8] = br#"{"roots": {
        "bookmark_bar": {"children": [
            {"guid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "id": "5", "name": "Move It proof page", "type": "url", "url": "http://127.0.0.1:8933/page2"},
            {"children": [
                {"guid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "id": "9", "name": "News Two", "type": "url", "url": "https://news.example/two"}],
             "guid": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "id": "8", "name": "News", "type": "folder"},
            {"guid": "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "id": "10", "name": "Opera Welcome", "type": "url", "url": "https://www.opera.com/welcome"}],
         "guid": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "id": "1", "name": "Bookmarks bar", "type": "folder"},
        "other": {"children": [
            {"guid": "ffffffff-ffff-4fff-8fff-ffffffffffff", "id": "4", "name": "Other One", "type": "url", "url": "https://other.example/"}],
         "guid": "12121212-1212-4212-8212-121212121212", "id": "2", "name": "Other bookmarks", "type": "folder"}},
     "version": 1}"#;

    fn manifest_for(data: &[u8]) -> Manifest {
        Manifest { present: true, size: Some(data.len() as u64), sha256: Some(hex_sha256(data)) }
    }

    fn siblings(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().contains(SIBLING_MARK))
            .collect();
        v.sort();
        v
    }

    fn read_tree(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn urls_in(node: &Value, out: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                if let Some(u) = map.get("url").and_then(Value::as_str) {
                    out.push(u.to_string());
                }
                for v in map.values() {
                    urls_in(v, out);
                }
            }
            Value::Array(items) => {
                for i in items {
                    urls_in(i, out);
                }
            }
            _ => {}
        }
    }

    fn all_urls(tree: &Value) -> Vec<String> {
        let mut v = Vec::new();
        urls_in(tree, &mut v);
        v.sort();
        v
    }

    fn strings(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    fn ids_and_guids(tree: &Value) -> (Vec<String>, Vec<String>) {
        fn walk(v: &Value, ids: &mut Vec<String>, guids: &mut Vec<String>) {
            match v {
                Value::Object(map) => {
                    if let Some(id) = map.get("id").and_then(Value::as_str) {
                        ids.push(id.to_string());
                    }
                    if let Some(g) = map.get("guid").and_then(Value::as_str) {
                        guids.push(g.to_string());
                    }
                    for val in map.values() {
                        walk(val, ids, guids);
                    }
                }
                Value::Array(items) => {
                    for i in items {
                        walk(i, ids, guids);
                    }
                }
                _ => {}
            }
        }
        let (mut ids, mut guids) = (Vec::new(), Vec::new());
        walk(tree, &mut ids, &mut guids);
        (ids, guids)
    }

    #[test]
    fn maximum_bookmark_ids_allocate_unused_ids_without_overflow() {
        let mut tree = serde_json::json!({"roots": {"bookmark_bar": {"type": "folder", "children": [
            {"type": "url", "id": (u64::MAX - 1).to_string(), "name": "a", "url": "https://a.test"},
            {"type": "url", "id": u64::MAX.to_string(), "name": "b", "url": "https://b.test"},
            {"type": "url", "id": "1", "name": "c", "url": "https://c.test"}
        ]}}});
        let incoming = serde_json::json!({"roots": {"bookmark_bar": {"type": "folder", "children": [
            {"type": "url", "id": u64::MAX.to_string(), "name": "new", "url": "https://new.test"}
        ]}}});
        assert_eq!(merge_trees(&mut tree, &incoming), 1);
        let kids = tree["roots"]["bookmark_bar"]["children"].as_array().unwrap();
        let ids: HashSet<_> = kids.iter().map(|n| n["id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), 4);
        assert!(ids.contains("2"));
    }

    #[test]
    fn five_rounds_of_trading_clashing_bookmarks_stay_stable() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("a");
        let b = t.path().join("b");
        for (path, url) in [(&a, "https://a.test"), (&b, "https://b.test")] {
            fs::write(path, serde_json::to_vec(&serde_json::json!({"roots": {"bookmark_bar": {
                "type": "folder", "children": [{"type": "url", "name": "Foo", "url": url}]
            }}})).unwrap()).unwrap();
        }
        let mut stable = None;
        for _ in 0..5 {
            for (src, dst) in [(&a, &b), (&b, &a)] {
                let (m, data) = export(src).unwrap();
                import(dst, &m, data.as_deref()).unwrap();
            }
            let bytes = (fs::read(&a).unwrap(), fs::read(&b).unwrap());
            for data in [&bytes.0, &bytes.1] {
                let tree: Value = serde_json::from_slice(data).unwrap();
                assert_eq!(tree["roots"]["bookmark_bar"]["children"].as_array().unwrap().len(), 2);
            }
            if let Some(previous) = &stable { assert_eq!(&bytes, previous); }
            stable = Some(bytes);
        }
        assert_eq!(base_name("Foo (1) (12)"), "Foo");
        assert_eq!(base_name("Foo (draft)"), "Foo (draft)");
    }

    #[test]
    fn export_missing_and_present() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Default").join("Bookmarks");
        assert_eq!(export(&p).unwrap(), (Manifest { present: false, size: None, sha256: None }, None));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, BM_D).unwrap();
        let (m, data) = export(&p).unwrap();
        assert!(m.present);
        assert_eq!(m.size, Some(BM_D.len() as u64));
        assert_eq!(m.sha256.as_deref(), Some(hex_sha256(BM_D).as_str()));
        assert_eq!(data.unwrap(), BM_D);
    }

    #[test]
    fn manifest_json_shape_matches_the_reference() {
        assert_eq!(serde_json::to_string(&Manifest::default()).unwrap(), r#"{"present":false}"#);
        let m: Manifest = serde_json::from_str(r#"{"present": true, "size": 3, "sha256": "ab"}"#).unwrap();
        assert_eq!(m, Manifest { present: true, size: Some(3), sha256: Some("ab".into()) });
        assert_eq!(serde_json::to_string(&m).unwrap(), r#"{"present":true,"size":3,"sha256":"ab"}"#);
    }

    #[test]
    fn missing_local_file_is_written() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        fs::write(&src, BM_D).unwrap();
        let (m, data) = export(&src).unwrap();
        let target = t.path().join("Default").join("Bookmarks");
        let r = import(&target, &m, data.as_deref()).unwrap();
        assert_eq!(r.action, Some(Action::Written));
        assert_eq!(fs::read(&target).unwrap(), BM_D);
    }

    #[test]
    fn identical_local_file_is_a_no_op() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        fs::write(&target, BM_D).unwrap();
        let (m, data) = export(&target).unwrap();
        let r = import(&target, &m, data.as_deref()).unwrap();
        assert_eq!(r.action, Some(Action::Identical));
        assert!(siblings(t.path()).is_empty());
    }

    #[test]
    fn conflict_merges_both_trees_into_the_one_file() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        fs::write(&target, BM_TARGET).unwrap();
        let r = import(&target, &manifest_for(BM_INCOMING), Some(BM_INCOMING)).unwrap();
        assert_eq!(r.action, Some(Action::Merged));
        assert_eq!(r.path.as_deref(), Some(target.as_path()));
        assert!(siblings(t.path()).is_empty(), "no sidecar: the browser must see the merge");

        let tree = read_tree(&target);
        // Both sets, in the one file: target's own plus the incoming's, the duplicate once.
        assert_eq!(
            all_urls(&tree),
            strings(&[
                "http://127.0.0.1:8933/page2",
                "https://news.example/one",
                "https://news.example/two",
                "https://other.example/",
                "https://www.opera.com/welcome",
            ])
        );
        // The bar holds target's bookmark, the merged folder, then the proof page.
        let bar = &tree["roots"]["bookmark_bar"]["children"];
        let bar_names: Vec<&str> = bar.as_array().unwrap().iter().map(node_name).collect();
        assert_eq!(bar_names, vec!["Opera Welcome", "News", "Move It proof page"]);
        // The same-named folders merged: both stories are inside the one News folder.
        let news = &bar[1]["children"];
        let news_names: Vec<&str> = news.as_array().unwrap().iter().map(node_name).collect();
        assert_eq!(news_names, vec!["News One", "News Two"]);
        // The root only the target had survives untouched.
        assert_eq!(tree["roots"]["synced"]["name"], "Mobile bookmarks");
        // The stale checksum does not ride along on a tree it no longer matches.
        assert!(tree.get("checksum").is_none());
        // Ids and guids stayed unique across the merged tree.
        let (ids, guids) = ids_and_guids(&tree);
        let id_set: HashSet<&String> = ids.iter().collect();
        let guid_set: HashSet<&String> = guids.iter().collect();
        assert_eq!(ids.len(), id_set.len(), "ids unique: {ids:?}");
        assert_eq!(guids.len(), guid_set.len(), "guids unique: {guids:?}");

        // Merging the same box again adds nothing and leaves the file alone.
        let before = fs::read(&target).unwrap();
        let r2 = import(&target, &manifest_for(BM_INCOMING), Some(BM_INCOMING)).unwrap();
        assert_eq!(r2.action, Some(Action::Identical));
        assert_eq!(fs::read(&target).unwrap(), before);
    }

    #[test]
    fn resync_does_not_grow_numbered_copies() {
        // The folder already holds Foo (url A) and the clash-renamed
        // Foo (1) (url B). The same box arriving again, still calling its
        // url-B bookmark Foo, must add nothing: no Foo (2).
        let local: &[u8] = br#"{"roots": {"bookmark_bar": {"children": [
            {"name": "Foo", "type": "url", "url": "https://a.example"},
            {"name": "Foo (1)", "type": "url", "url": "https://b.example"}],
            "name": "Bookmarks bar", "type": "folder"}}}"#;
        let incoming: &[u8] = br#"{"roots": {"bookmark_bar": {"children": [
            {"name": "Foo", "type": "url", "url": "https://b.example"}],
            "name": "Bookmarks bar", "type": "folder"}}}"#;
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        fs::write(&target, local).unwrap();
        let r = import(&target, &manifest_for(incoming), Some(incoming)).unwrap();
        assert_eq!(r.action, Some(Action::Identical));
        assert_eq!(fs::read(&target).unwrap(), local, "nothing was added or renamed");
    }

    #[test]
    fn merge_renames_a_different_bookmark_that_reuses_a_name() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        let local = br#"{"roots": {"bookmark_bar": {"children": [
            {"guid": "11111111-1111-4111-8111-111111111111", "id": "5", "name": "Example", "type": "url", "url": "https://a.example/"}],
         "type": "folder"}}, "version": 1}"#;
        let incoming = br#"{"roots": {"bookmark_bar": {"children": [
            {"guid": "22222222-2222-4222-8222-222222222222", "id": "5", "name": "Example", "type": "url", "url": "https://b.example/"},
            {"guid": "33333333-3333-4333-8333-333333333333", "id": "6", "name": "Example", "type": "url", "url": "https://a.example/"}],
         "type": "folder"}}, "version": 1}"#;
        fs::write(&target, local).unwrap();
        let r = import(&target, &manifest_for(incoming), Some(incoming)).unwrap();
        assert_eq!(r.action, Some(Action::Merged));
        let tree = read_tree(&target);
        let bar = tree["roots"]["bookmark_bar"]["children"].as_array().unwrap();
        let names: Vec<&str> = bar.iter().map(node_name).collect();
        assert_eq!(names, vec!["Example", "Example (1)"]);
        assert_eq!(all_urls(&tree), strings(&["https://a.example/", "https://b.example/"]));
    }

    #[test]
    fn merge_into_a_fresh_browser_file_with_empty_roots() {
        // The shape a first-run browser writes (and the harness plants into): roots with
        // empty children and no ids on the roots themselves.
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        let fresh = br#"{"checksum": "fresh", "roots": {
            "bookmark_bar": {"children": [], "type": "folder"},
            "other": {"children": [], "type": "folder"},
            "synced": {"children": [], "type": "folder"}}, "version": 1}"#;
        fs::write(&target, fresh).unwrap();
        let r = import(&target, &manifest_for(BM_INCOMING), Some(BM_INCOMING)).unwrap();
        assert_eq!(r.action, Some(Action::Merged));
        let tree = read_tree(&target);
        assert!(all_urls(&tree).contains(&"http://127.0.0.1:8933/page2".to_string()));
        assert!(tree.get("checksum").is_none());
        assert!(siblings(t.path()).is_empty());
    }

    #[test]
    fn malformed_incoming_becomes_a_sibling_and_the_target_is_untouched() {
        for bad in [b"not json".as_slice(), b"{\"roots\": 5}".as_slice(), b"[1,2]".as_slice()] {
            let t = tempfile::tempdir().unwrap();
            let target = t.path().join("Bookmarks");
            fs::write(&target, BM_LOCAL).unwrap();
            let m = manifest_for(bad);
            let r = import(&target, &m, Some(bad)).unwrap();
            assert_eq!(r.action, Some(Action::Conflict), "sibling fallback: {bad:?}");
            assert_eq!(fs::read(&target).unwrap(), BM_LOCAL, "target untouched");
            let sib = r.path.expect("a sibling path is reported");
            assert_eq!(fs::read(&sib).unwrap(), bad, "the incoming bytes are kept whole");
        }
    }

    #[test]
    fn unparseable_local_file_falls_back_to_the_sibling() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        fs::write(&target, b"\x00\x01 not a bookmarks file").unwrap();
        let r = import(&target, &manifest_for(BM_INCOMING), Some(BM_INCOMING)).unwrap();
        assert_eq!(r.action, Some(Action::Conflict));
        assert_eq!(fs::read(&target).unwrap(), b"\x00\x01 not a bookmarks file", "local untouched");
        let sib = r.path.unwrap();
        assert_eq!(fs::read(&sib).unwrap(), BM_INCOMING);
        // Same bytes again: the same sibling is pointed at, no second copy piles up.
        let r2 = import(&target, &manifest_for(BM_INCOMING), Some(BM_INCOMING)).unwrap();
        assert_eq!(r2.path.unwrap(), sib);
        assert_eq!(siblings(t.path()).len(), 1);
    }

    #[test]
    fn merge_is_symmetric_and_converges() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        let tree_a = br#"{"roots": {"bookmark_bar": {"children": [
            {"guid": "11111111-1111-4111-8111-111111111111", "id": "5", "name": "A page", "type": "url", "url": "https://a.example/"}],
         "type": "folder"}}, "version": 1}"#;
        let tree_b = br#"{"roots": {"bookmark_bar": {"children": [
            {"guid": "22222222-2222-4222-8222-222222222222", "id": "5", "name": "B page", "type": "url", "url": "https://b.example/"}],
         "type": "folder"}}, "version": 1}"#;
        fs::write(a.join("Bookmarks"), tree_a).unwrap();
        fs::write(b.join("Bookmarks"), tree_b).unwrap();
        // A into B, then the merged B back into A: both end with the union.
        let (ma, da) = export(&a.join("Bookmarks")).unwrap();
        import(&b.join("Bookmarks"), &ma, da.as_deref()).unwrap();
        let (mb2, db2) = export(&b.join("Bookmarks")).unwrap();
        import(&a.join("Bookmarks"), &mb2, db2.as_deref()).unwrap();
        let want = strings(&["https://a.example/", "https://b.example/"]);
        assert_eq!(all_urls(&read_tree(&a.join("Bookmarks"))), want);
        assert_eq!(all_urls(&read_tree(&b.join("Bookmarks"))), want);
        // One more pass changes nothing on either side.
        let a_bytes = fs::read(a.join("Bookmarks")).unwrap();
        let (mb3, db3) = export(&b.join("Bookmarks")).unwrap();
        let r = import(&a.join("Bookmarks"), &mb3, db3.as_deref()).unwrap();
        assert_eq!(r.action, Some(Action::Identical));
        assert_eq!(fs::read(a.join("Bookmarks")).unwrap(), a_bytes);
    }

    #[test]
    fn absent_in_box_changes_nothing_and_missing_bytes_or_bad_hash_refuse() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        let r = import(&target, &Manifest::default(), None).unwrap();
        assert_eq!(r, Report::default());
        assert!(!target.exists());
        let m = Manifest { present: true, size: Some(BM_D.len() as u64), sha256: Some(hex_sha256(BM_D)) };
        assert!(matches!(import(&target, &m, None), Err(Error::Corrupt(_))));
        assert!(matches!(import(&target, &m, Some(BM_LOCAL)), Err(Error::Corrupt(_))));
        assert!(!target.exists());
    }

    #[test]
    fn stamp_formats_utc() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(1_709_210_096), "20240229T123456Z");
    }
}
