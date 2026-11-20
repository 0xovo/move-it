//! Extension state: which extensions a profile carries, and the per-extension folders that
//! travel with them (the two settings stores and the per-extension IndexedDB units).
//!
//! Port of `installed_extension_ids` / `_collect_extension_state` / `_import_extension_state`.
//! JSON shape of the `"extensions"` manifest is identical:
//! `{installed_ids, folders, files: [{path, size, sha256}], total_bytes}`.
//!
//! Merge unit = one extension's state folder. Every (folder, id-or-unit) the box carries
//! replaces the local folder wholesale; folders the box does not mention are untouched. The
//! reference took its own backups; here the caller wraps [`import`] in a [`crate::txn::Txn`]
//! over [`target_dirs`], so the snapshot and rollback live in one place.
//!
//! Symlinks are never followed: one anywhere in a state tree or on the way to a target is
//! `Error::Refused`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::sealed::{validate_ext_logical_path, EXT_STATE_FOLDERS, INDEXEDDB_STATE_FOLDER};
use crate::{Error, Result};

fn io(e: std::io::Error, what: &str, p: &Path) -> Error {
    Error::Io(format!("{what} {}: {e}", p.display()))
}

fn refuse_link(p: &Path) -> Error {
    Error::Refused(format!("{} is a symbolic link; Move It never follows links", p.display()))
}

/// lstat that tolerates absence.
fn meta(p: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(p) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(e, "cannot inspect", p)),
    }
}

/// True for a real directory, false when absent or a plain file, `Refused` for a symlink.
fn real_dir(p: &Path) -> Result<bool> {
    match meta(p)? {
        None => Ok(false),
        Some(m) if m.file_type().is_symlink() => Err(refuse_link(p)),
        Some(m) => Ok(m.is_dir()),
    }
}

/// Names of the real subdirectories of `dir`, sorted. Empty when `dir` is not a directory.
fn subdir_names(dir: &Path) -> Result<Vec<String>> {
    if !real_dir(dir)? {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for ent in fs::read_dir(dir).map_err(|e| io(e, "cannot list", dir))? {
        let ent = ent.map_err(|e| io(e, "cannot list", dir))?;
        let ft = ent.file_type().map_err(|e| io(e, "cannot inspect", &ent.path()))?;
        if ft.is_symlink() {
            return Err(refuse_link(&ent.path()));
        }
        if ft.is_dir() {
            out.push(ent.file_name().to_string_lossy().into_owned());
        }
    }
    out.sort();
    Ok(out)
}

fn default_dir(profile: &Path) -> PathBuf {
    profile.join("Default")
}

fn slot_dir(profile: &Path, slot: &str) -> PathBuf {
    crate::paths::slot_dir(profile, slot)
}

fn ids_at(default: &Path) -> Result<Vec<String>> {
    subdir_names(&default.join("Extensions"))
}

/// Extension IDs installed in the profile: the subfolder names of `Default/Extensions`.
pub fn installed_extension_ids(profile: &Path) -> Result<Vec<String>> {
    ids_at(&default_dir(profile))
}

/// The same, for a named profile slot inside the browser folder.
pub fn installed_extension_ids_in(profile: &Path, slot: &str) -> Result<Vec<String>> {
    ids_at(&slot_dir(profile, slot))
}

fn candidates_at(default: &Path) -> Result<Vec<String>> {
    let mut ids: BTreeSet<String> = ids_at(default)?.into_iter().collect();
    for folder in EXT_STATE_FOLDERS {
        ids.extend(subdir_names(&default.join(folder))?);
    }
    Ok(ids.into_iter().collect())
}

/// Extension IDs whose state this profile carries: installed folders plus the per-ID subfolders
/// of the two settings stores (an unpacked extension has settings state but no Extensions
/// entry). IndexedDB units are only taken for IDs on this list, so a website origin sharing the
/// IndexedDB folder can never be mistaken for extension state.
pub fn extension_id_candidates(profile: &Path) -> Result<Vec<String>> {
    candidates_at(&default_dir(profile))
}

/// The same, for a named profile slot inside the browser folder.
pub fn extension_id_candidates_in(profile: &Path, slot: &str) -> Result<Vec<String>> {
    candidates_at(&slot_dir(profile, slot))
}

fn units_at(default: &Path) -> Result<Vec<(String, PathBuf)>> {
    let idb = default.join(INDEXEDDB_STATE_FOLDER);
    if !real_dir(&idb)? {
        return Ok(Vec::new());
    }
    let mut units = Vec::new();
    for id in candidates_at(default)? {
        for suffix in ["_0.indexeddb.leveldb", "_0"] {
            let name = format!("chrome-extension_{id}{suffix}");
            let path = idb.join(&name);
            if real_dir(&path)? {
                units.push((name, path));
            }
        }
    }
    Ok(units)
}

/// The per-extension IndexedDB units present: (unit directory name, path), both shapes
/// (`chrome-extension_<id>_0.indexeddb.leveldb` and `chrome-extension_<id>_0`).
pub fn indexeddb_units(profile: &Path) -> Result<Vec<(String, PathBuf)>> {
    units_at(&default_dir(profile))
}

/// What a profile's extension state looks like: the manifest object and the file bytes by
/// logical path (`<State Folder>/<id>/<inner>` or `IndexedDB/<unit>/<inner>`).
#[derive(Debug, Clone, PartialEq)]
pub struct Collected {
    pub manifest: Map<String, Value>,
    pub files: BTreeMap<String, Vec<u8>>,
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Depth-first, names sorted per directory: the order Python's `sorted(rglob)` gives.
fn take(prefix: &str, dir: &Path, rel: &str, files: &mut BTreeMap<String, Vec<u8>>, entries: &mut Vec<Value>) -> Result<()> {
    let mut names: Vec<(String, fs::FileType)> = Vec::new();
    for ent in fs::read_dir(dir).map_err(|e| io(e, "cannot list", dir))? {
        let ent = ent.map_err(|e| io(e, "cannot list", dir))?;
        let ft = ent.file_type().map_err(|e| io(e, "cannot inspect", &ent.path()))?;
        if ft.is_symlink() {
            return Err(refuse_link(&ent.path()));
        }
        names.push((ent.file_name().to_string_lossy().into_owned(), ft));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, ft) in names {
        let path = dir.join(&name);
        let rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        if ft.is_dir() {
            // Cache folders never travel, wherever they sit in a carried
            // tree (see `crate::paths::PROFILE_CACHE_DIRS`).
            if crate::paths::is_cache_dir_name(&name) {
                continue;
            }
            take(prefix, &path, &rel, files, entries)?;
        } else if ft.is_file() {
            let data = fs::read(&path).map_err(|e| io(e, "cannot read", &path))?;
            let logical = format!("{prefix}/{rel}");
            entries.push(json!({"path": logical, "size": data.len(), "sha256": sha256_hex(&data)}));
            files.insert(logical, data);
        }
    }
    Ok(())
}

/// Read every extension state file under `Default`. No file inside a collected folder is
/// excluded, cache folders aside (a leveldb store is only coherent whole); the manifest
/// records size + SHA-256 per file so the receiving side can verify before writing anything.
pub fn collect(profile: &Path) -> Result<Collected> {
    collect_in(profile, "Default")
}

/// The same, for a named profile slot inside the browser folder.
pub fn collect_in(profile: &Path, slot: &str) -> Result<Collected> {
    let default = slot_dir(profile, slot);
    let mut files = BTreeMap::new();
    let mut entries = Vec::new();
    let mut folders: Vec<String> = Vec::new();
    for folder in EXT_STATE_FOLDERS {
        let base = default.join(folder);
        if !real_dir(&base)? {
            continue;
        }
        folders.push(folder.to_string());
        take(folder, &base, "", &mut files, &mut entries)?;
    }
    for (name, dir) in units_at(&default)? {
        if !folders.iter().any(|f| f == INDEXEDDB_STATE_FOLDER) {
            folders.push(INDEXEDDB_STATE_FOLDER.to_string());
        }
        take(&format!("{INDEXEDDB_STATE_FOLDER}/{name}"), &dir, "", &mut files, &mut entries)?;
    }
    let total: usize = files.values().map(Vec::len).sum();
    let mut manifest = Map::new();
    manifest.insert("installed_ids".into(), json!(ids_at(&default)?));
    manifest.insert("folders".into(), json!(folders));
    manifest.insert("files".into(), Value::Array(entries));
    manifest.insert("total_bytes".into(), json!(total));
    Ok(Collected { manifest, files })
}

/// What an import wrote.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub folders: usize,
    pub files: usize,
    pub ids: Vec<String>,
}

/// (state folder, extension id or IndexedDB unit name) -> logical paths.
type Targets = BTreeMap<(String, String), Vec<String>>;

fn plan(ext_manifest: &Value, files: &BTreeMap<String, Vec<u8>>) -> Result<Targets> {
    let mut by_target: Targets = BTreeMap::new();
    let list = match ext_manifest.get("files") {
        None | Some(Value::Null) => return Ok(by_target),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(Error::Corrupt("extensions manifest \"files\" is not a list".into())),
    };
    for entry in list {
        let logical = entry
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Corrupt("extensions manifest entry has no path".into()))?;
        validate_ext_logical_path(logical)?;
        // A box from anywhere else can still name cache files; they are
        // excluded on this side too, never written into the profile.
        if crate::paths::logical_path_has_cache_dir(logical) {
            continue;
        }
        if !files.contains_key(logical) {
            return Err(Error::Corrupt(format!("bundle payload is missing the bytes for extension file {logical}")));
        }
        let mut parts = logical.split('/');
        let (folder, id) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let paths = by_target.entry((folder.to_string(), id.to_string())).or_default();
        if !paths.iter().any(|p| p == logical) {
            paths.push(logical.to_string());
        }
    }
    Ok(by_target)
}

/// The folders an import would replace, for the caller to snapshot (`Txn::begin`) first.
/// Validates the manifest the same way [`import`] does.
pub fn target_dirs(profile: &Path, ext_manifest: &Value, files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<PathBuf>> {
    target_dirs_in(profile, "Default", ext_manifest, files)
}

/// The same, for a named profile slot inside the browser folder.
pub fn target_dirs_in(profile: &Path, slot: &str, ext_manifest: &Value, files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<PathBuf>> {
    Ok(plan(ext_manifest, files)?
        .keys()
        .map(|(folder, id)| slot_dir(profile, slot).join(folder).join(id))
        .collect())
}

/// Refuse a symlink at the slot folder itself, at `default/<folder>`, or at
/// the target itself.
fn check_way(default: &Path, folder: &str, target: &Path) -> Result<()> {
    if let Some(m) = meta(default)? {
        if m.file_type().is_symlink() {
            return Err(refuse_link(default));
        }
    }
    let mut p = default.to_path_buf();
    for seg in folder.split('/') {
        p.push(seg);
        if let Some(m) = meta(&p)? {
            if m.file_type().is_symlink() {
                return Err(refuse_link(&p));
            }
        }
    }
    match meta(target)? {
        Some(m) if m.file_type().is_symlink() => Err(refuse_link(target)),
        _ => Ok(()),
    }
}

/// Replace each carried extension folder with the box's copy. Everything is validated before
/// the first byte is written. Atomicity is the caller's `Txn`.
pub fn import(profile: &Path, ext_manifest: &Value, files: &BTreeMap<String, Vec<u8>>) -> Result<Stats> {
    import_in(profile, "Default", ext_manifest, files)
}

/// The same, for a named profile slot inside the browser folder.
pub fn import_in(profile: &Path, slot: &str, ext_manifest: &Value, files: &BTreeMap<String, Vec<u8>>) -> Result<Stats> {
    let by_target = plan(ext_manifest, files)?;
    let default = slot_dir(profile, slot);
    for ((folder, id), _) in &by_target {
        check_way(&default, folder, &default.join(folder).join(id))?;
    }
    let mut written = 0;
    for ((folder, id), logicals) in &by_target {
        let target = default.join(folder).join(id);
        match meta(&target)? {
            Some(m) if m.is_dir() => fs::remove_dir_all(&target).map_err(|e| io(e, "cannot clear", &target))?,
            Some(_) => fs::remove_file(&target).map_err(|e| io(e, "cannot clear", &target))?,
            None => {}
        }
        fs::create_dir_all(&target).map_err(|e| io(e, "cannot create", &target))?;
        let skip = folder.split('/').count() + 1; // folder segments + id
        for logical in logicals {
            let inner: Vec<&str> = logical.split('/').skip(skip).collect();
            let dest = target.join(inner.join("/"));
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| io(e, "cannot create", parent))?;
            }
            fs::write(&dest, &files[logical]).map_err(|e| io(e, "cannot write", &dest))?;
            written += 1;
        }
    }
    let ids: BTreeSet<String> = by_target.keys().map(|(_, id)| id.clone()).collect();
    Ok(Stats { folders: by_target.len(), files: written, ids: ids.into_iter().collect() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txn::Txn;

    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ID_C: &str = "cccccccccccccccccccccccccccccccc";

    fn put(profile: &Path, rel: &str, data: &[u8]) {
        let p = profile.join("Default").join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }

    fn get(profile: &Path, rel: &str) -> Option<Vec<u8>> {
        fs::read(profile.join("Default").join(rel)).ok()
    }

    /// Installed A and B, unpacked C (settings only), classic + current IndexedDB units for A,
    /// a website origin and a stranger's unit that must never travel.
    fn profile_a() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let p = t.path();
        put(p, &format!("Extensions/{ID_A}/1.0_0/manifest.json"), b"{}");
        put(p, &format!("Extensions/{ID_B}/1.0_0/manifest.json"), b"{}");
        put(p, &format!("Local Extension Settings/{ID_A}/000003.log"), b"A-log");
        put(p, &format!("Local Extension Settings/{ID_A}/CURRENT"), b"MANIFEST-1\n");
        put(p, &format!("Sync Extension Settings/{ID_B}/000005.ldb"), b"B-sync");
        put(p, &format!("Local Extension Settings/{ID_C}/000001.log"), b"C-log");
        let classic = format!("IndexedDB/chrome-extension_{ID_A}_0.indexeddb.leveldb");
        for f in ["000003.log", "CURRENT", "LOCK", "LOG", "MANIFEST-000001"] {
            put(p, &format!("{classic}/{f}"), format!("idb-{f}").as_bytes());
        }
        put(p, &format!("IndexedDB/chrome-extension_{ID_B}_0/blobs/ab/abcdef"), b"hashed");
        put(p, "IndexedDB/https_example.com_0.indexeddb.leveldb/CURRENT", b"WEBSITE");
        put(p, &format!("IndexedDB/chrome-extension_{}_0.indexeddb.leveldb/CURRENT", "z".repeat(32)), b"STRANGER");
        t
    }

    #[test]
    fn ids_and_candidates() {
        let t = profile_a();
        assert_eq!(installed_extension_ids(t.path()).unwrap(), vec![ID_A, ID_B]);
        assert_eq!(extension_id_candidates(t.path()).unwrap(), vec![ID_A, ID_B, ID_C]);
        let empty = tempfile::tempdir().unwrap();
        assert!(installed_extension_ids(empty.path()).unwrap().is_empty());
        assert!(collect(empty.path()).unwrap().files.is_empty());
    }

    #[test]
    fn collect_takes_only_extension_state_and_describes_it() {
        let t = profile_a();
        let c = collect(t.path()).unwrap();
        assert_eq!(c.manifest["installed_ids"], json!([ID_A, ID_B]));
        assert_eq!(c.manifest["folders"], json!(["Local Extension Settings", "Sync Extension Settings", "IndexedDB"]));
        // 3 + 1 settings, 5 classic IndexedDB, 1 current-shape IndexedDB
        assert_eq!(c.files.len(), 4 + 5 + 1);
        assert_eq!(c.manifest["files"].as_array().unwrap().len(), 10);
        let total: usize = c.files.values().map(Vec::len).sum();
        assert_eq!(c.manifest["total_bytes"], json!(total));
        assert!(c.files.keys().all(|k| !k.contains("example.com") && !k.contains("zzzz")));
        assert!(c.files.keys().any(|k| k.ends_with("blobs/ab/abcdef")));
        let e = &c.manifest["files"][0];
        let path = e["path"].as_str().unwrap();
        assert_eq!(e["size"], json!(c.files[path].len()));
        assert_eq!(e["sha256"], json!(sha256_hex(&c.files[path])));
        // Every path the manifest lists is one the box would accept.
        for k in c.files.keys() {
            validate_ext_logical_path(k).unwrap();
        }
    }

    #[test]
    fn import_replaces_wholesale_and_leaves_the_rest_alone() {
        let a = profile_a();
        let c = collect(a.path()).unwrap();
        let b = tempfile::tempdir().unwrap();
        let bp = b.path();
        put(bp, &format!("Local Extension Settings/{ID_A}/stale.log"), b"B-old");
        put(bp, &format!("Local Extension Settings/{ID_B}/keep.log"), b"B-local-only");
        put(bp, "IndexedDB/https_example.com_0.indexeddb.leveldb/CURRENT", b"B-website");
        let m = Value::Object(c.manifest.clone());
        let stats = import(bp, &m, &c.files).unwrap();
        assert_eq!(stats.folders, 5); // A and C local, B sync, A classic unit, B current unit
        assert_eq!(stats.files, 10);
        assert_eq!(stats.ids.len(), 5);
        assert_eq!(get(bp, &format!("Local Extension Settings/{ID_A}/000003.log")).unwrap(), b"A-log");
        assert!(get(bp, &format!("Local Extension Settings/{ID_A}/stale.log")).is_none());
        assert_eq!(get(bp, &format!("Local Extension Settings/{ID_B}/keep.log")).unwrap(), b"B-local-only");
        assert_eq!(get(bp, "IndexedDB/https_example.com_0.indexeddb.leveldb/CURRENT").unwrap(), b"B-website");
        assert_eq!(get(bp, &format!("IndexedDB/chrome-extension_{ID_B}_0/blobs/ab/abcdef")).unwrap(), b"hashed");
        // Round trip: what B now collects (A's state plus its own leftovers) contains everything A sent.
        let back = collect(bp).unwrap();
        for (k, v) in &c.files {
            assert_eq!(back.files.get(k), Some(v), "{k}");
        }
    }

    #[test]
    fn a_stray_file_where_a_folder_belongs_is_replaced() {
        let a = profile_a();
        let c = collect(a.path()).unwrap();
        let b = tempfile::tempdir().unwrap();
        put(b.path(), &format!("Local Extension Settings/{ID_A}"), b"i am a file");
        import(b.path(), &Value::Object(c.manifest), &c.files).unwrap();
        assert_eq!(get(b.path(), &format!("Local Extension Settings/{ID_A}/CURRENT")).unwrap(), b"MANIFEST-1\n");
    }

    #[test]
    fn bad_manifests_fail_closed_before_anything_is_written() {
        let b = tempfile::tempdir().unwrap();
        put(b.path(), &format!("Local Extension Settings/{ID_A}/old"), b"old");
        let ok = format!("Local Extension Settings/{ID_A}/new");
        let files: BTreeMap<String, Vec<u8>> = [(ok.clone(), b"x".to_vec())].into();
        for (bad, why) in [
            ("IndexedDB/https_example.com_0.indexeddb.leveldb/x", "website IndexedDB"),
            ("Local Extension Settings/../../escape", "traversal"),
            ("Cookies", "outside known folders"),
        ] {
            let m = json!({"files": [{"path": ok}, {"path": bad}]});
            let mut f = files.clone();
            f.insert(bad.to_string(), b"y".to_vec());
            assert!(matches!(import(b.path(), &m, &f), Err(Error::Corrupt(_))), "{why}");
        }
        let missing = json!({"files": [{"path": ok}, {"path": format!("Sync Extension Settings/{ID_B}/gone")}]});
        assert!(matches!(import(b.path(), &missing, &files), Err(Error::Corrupt(_))));
        assert_eq!(get(b.path(), &format!("Local Extension Settings/{ID_A}/old")).unwrap(), b"old");
        assert!(get(b.path(), &format!("Local Extension Settings/{ID_A}/new")).is_none());
        // An empty or absent manifest is a no-op.
        assert_eq!(import(b.path(), &json!({}), &files).unwrap(), Stats::default());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused_everywhere() {
        use std::os::unix::fs::symlink;
        // inside a collected tree
        let a = profile_a();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"s").unwrap();
        symlink(outside.path().join("secret"), a.path().join(format!("Default/Local Extension Settings/{ID_A}/link"))).unwrap();
        assert!(matches!(collect(a.path()), Err(Error::Refused(_))));
        // a state folder that is itself a link
        let l = tempfile::tempdir().unwrap();
        fs::create_dir_all(l.path().join("Default")).unwrap();
        symlink(outside.path(), l.path().join("Default/Local Extension Settings")).unwrap();
        assert!(matches!(collect(l.path()), Err(Error::Refused(_))));
        // import onto a link, and through a linked parent
        let files: BTreeMap<String, Vec<u8>> = [(format!("Local Extension Settings/{ID_A}/f"), b"x".to_vec())].into();
        let m = json!({"files": [{"path": format!("Local Extension Settings/{ID_A}/f")}]});
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("Default/Local Extension Settings")).unwrap();
        symlink(outside.path(), t.path().join(format!("Default/Local Extension Settings/{ID_A}"))).unwrap();
        assert!(matches!(import(t.path(), &m, &files), Err(Error::Refused(_))));
        let t2 = tempfile::tempdir().unwrap();
        fs::create_dir_all(t2.path().join("Default")).unwrap();
        symlink(outside.path(), t2.path().join("Default/Local Extension Settings")).unwrap();
        assert!(matches!(import(t2.path(), &m, &files), Err(Error::Refused(_))));
        assert!(!outside.path().join(ID_A).exists());
        // the slot folder itself as a link redirects every state folder at once
        let t3 = tempfile::tempdir().unwrap();
        fs::create_dir_all(outside.path().join("Local Extension Settings")).unwrap();
        symlink(outside.path(), t3.path().join("Default")).unwrap();
        assert!(matches!(import(t3.path(), &m, &files), Err(Error::Refused(_))));
        assert!(!outside.path().join(format!("Local Extension Settings/{ID_A}")).exists());
    }

    #[test]
    fn a_txn_over_the_targets_rolls_the_whole_import_back() {
        let a = profile_a();
        let c = collect(a.path()).unwrap();
        let m = Value::Object(c.manifest.clone());
        let b = tempfile::tempdir().unwrap();
        put(b.path(), &format!("Local Extension Settings/{ID_A}/old"), b"old");
        let dirs = target_dirs(b.path(), &m, &c.files).unwrap();
        assert_eq!(dirs.len(), 5);
        let named: Vec<(String, &Path)> = dirs.iter().enumerate().map(|(i, d)| (format!("ext{i}"), d.as_path())).collect();
        let stores: Vec<(&str, &Path)> = named.iter().map(|(n, d)| (n.as_str(), *d)).collect();
        let txn = Txn::begin(&b.path().join("Default"), &stores).unwrap();
        import(b.path(), &m, &c.files).unwrap();
        assert!(get(b.path(), &format!("Local Extension Settings/{ID_A}/old")).is_none());
        txn.rollback().unwrap();
        assert_eq!(get(b.path(), &format!("Local Extension Settings/{ID_A}/old")).unwrap(), b"old");
        assert!(get(b.path(), &format!("Sync Extension Settings/{ID_B}/000005.ldb")).is_none());
    }
}
