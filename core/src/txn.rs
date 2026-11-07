//! All or nothing: the journal that makes a multi-store import atomic.
//!
//! Before any write, every store the payload touches is copied into one folder
//! `.moveit-txn-<stamp>/` beside the browser's data, with a `manifest.json` listing
//! (store, original path, snapshot path, kind, size, sha256). The manifest is written
//! last and fsynced, so a folder with a manifest is a complete snapshot.
//!
//! - Any failure while applying: [`Txn::rollback`] puts every snapshot back and verifies it.
//! - A crash: on the next start [`recover`] finds a manifest with no `COMMITTED` marker
//!   and restores it before anything else runs.
//! - Success: [`Txn::commit`] writes `COMMITTED`; that folder is now the Undo point
//!   ([`undo_last`]). Only the newest committed folder is kept.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const TXN_PREFIX: &str = ".moveit-txn-";
const MANIFEST: &str = "manifest.json";
const COMMITTED: &str = "COMMITTED";
const UNDO_MANIFEST: &str = "undo.json";
const UNDONE: &str = "UNDONE";
const UNDOING: &str = "UNDOING";
const LOCK_FILE: &str = ".moveit.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Dir,
    /// The store did not exist before; restoring means removing it.
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub store: String,
    pub original: PathBuf,
    /// Relative to the txn folder.
    pub snapshot: PathBuf,
    pub kind: Kind,
    /// sha256 over the file, or over the sorted (relative path, bytes) of a dir.
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub created_unix: u64,
    pub entries: Vec<Entry>,
}

fn io(e: std::io::Error, what: &str, p: &Path) -> Error {
    Error::Io(format!("{what} {}: {e}", p.display()))
}

fn fsync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(f) = fs::File::open(dir) {
        let _ = f.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Refuses symlinks anywhere in a store: we never follow them.
fn walk(root: &Path, rel: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let dir = root.join(rel);
    let mut names: Vec<_> = fs::read_dir(&dir)
        .map_err(|e| io(e, "cannot list", &dir))?
        .collect::<std::io::Result<_>>()
        .map_err(|e| io(e, "cannot list", &dir))?;
    names.sort_by_key(|e| e.file_name());
    for e in names {
        let ft = e.file_type().map_err(|err| io(err, "cannot stat", &e.path()))?;
        let r = rel.join(e.file_name());
        if ft.is_symlink() {
            return Err(Error::Refused(format!("refusing to follow a link inside a store: {}", e.path().display())));
        } else if ft.is_dir() {
            out.push(r.clone());
            walk(root, &r, out)?;
        } else {
            out.push(r);
        }
    }
    Ok(())
}

fn hash_file_into(h: &mut Sha256, p: &Path) -> Result<()> {
    let mut f = fs::File::open(p).map_err(|e| io(e, "cannot read", p))?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| io(e, "cannot read", p))?;
        if n == 0 {
            return Ok(());
        }
        h.update(&buf[..n]);
    }
}

/// Digest of what is at `p` now, in the same form a snapshot records.
pub fn digest(p: &Path) -> Result<(Kind, String)> {
    let meta = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Kind::Absent, String::new())),
        Err(e) => return Err(io(e, "cannot stat", p)),
    };
    let mut h = Sha256::new();
    if meta.file_type().is_symlink() {
        return Err(Error::Refused(format!("refusing to follow a link: {}", p.display())));
    }
    let kind = if meta.is_dir() {
        let mut items = Vec::new();
        walk(p, Path::new(""), &mut items)?;
        for rel in items {
            let full = p.join(&rel);
            let tag = if full.is_dir() { "d" } else { "f" };
            h.update(format!("{tag}:{}\0", rel.to_string_lossy().replace('\\', "/")).as_bytes());
            if tag == "f" {
                hash_file_into(&mut h, &full)?;
                h.update(b"\0");
            }
        }
        Kind::Dir
    } else {
        hash_file_into(&mut h, p)?;
        Kind::File
    };
    Ok((kind, h.finalize().iter().map(|b| format!("{b:02x}")).collect()))
}

fn copy_file_synced(from: &Path, to: &Path) -> Result<()> {
    fs::copy(from, to).map_err(|e| io(e, "cannot copy", from))?;
    // The flush needs a writable handle: Windows refuses FlushFileBuffers
    // on a read-only handle (access denied) where Linux fsync does not
    // care, and every other sync in the engine uses a write handle for
    // the same reason. A store file copied with read-only bits keeps the
    // old behaviour through the read-only fallback, which still flushes
    // fine on Linux.
    let f = fs::OpenOptions::new().write(true).open(to).or_else(|_| fs::File::open(to));
    f.and_then(|f| f.sync_all()).map_err(|e| io(e, "cannot sync", to))
}

/// Copy `from`'s own permission bits onto `to` (unix). Preserves modes like 0700 on directories,
/// which `create_dir_all` would otherwise reset to the umask default and widen access to the data.
fn copy_mode(from: &Path, to: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = fs::metadata(from) {
            let _ = fs::set_permissions(to, fs::Permissions::from_mode(m.permissions().mode()));
        }
    }
    #[cfg(not(unix))]
    let _ = (from, to);
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to).map_err(|e| io(e, "cannot create", to))?;
    copy_mode(from, to);
    let mut items = Vec::new();
    walk(from, Path::new(""), &mut items)?;
    for rel in items {
        let (s, d) = (from.join(&rel), to.join(&rel));
        if s.is_dir() {
            fs::create_dir_all(&d).map_err(|e| io(e, "cannot create", &d))?;
            copy_mode(&s, &d);
        } else {
            copy_file_synced(&s, &d)?;
        }
    }
    fsync_dir(to);
    Ok(())
}

fn remove_any(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p).map_err(|e| io(e, "cannot remove", p)),
        Ok(_) => fs::remove_file(p).map_err(|e| io(e, "cannot remove", p)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(e, "cannot stat", p)),
    }
}

/// Put one snapshot back: copy beside the original, then swap, so a crash mid-restore
/// leaves either the old or the restored store, and a re-run finishes the job.
fn restore_entry(txn_dir: &Path, e: &Entry) -> Result<()> {
    if e.kind == Kind::Absent {
        remove_any(&e.original)?;
    } else {
        let snap = txn_dir.join(&e.snapshot);
        let staged = e.original.with_file_name(format!(
            "{}.moveit-restore",
            e.original.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
        ));
        remove_any(&staged)?;
        match e.kind {
            Kind::Dir => copy_tree(&snap, &staged)?,
            _ => copy_file_synced(&snap, &staged)?,
        }
        remove_any(&e.original)?;
        fs::rename(&staged, &e.original).map_err(|err| io(err, "cannot put back", &e.original))?;
    }
    if let Some(parent) = e.original.parent() {
        fsync_dir(parent);
    }
    let (kind, now) = digest(&e.original)?;
    if kind != e.kind || now != e.digest {
        return Err(Error::Io(format!("restore of {} did not verify", e.store)));
    }
    Ok(())
}

fn read_manifest(txn_dir: &Path) -> Result<Manifest> {
    let p = txn_dir.join(MANIFEST);
    let raw = fs::read(&p).map_err(|e| io(e, "cannot read", &p))?;
    serde_json::from_slice(&raw).map_err(|_| Error::Corrupt(format!("journal {} is unreadable", p.display())))
}

fn read_undo_manifest(dir: &Path) -> Result<Manifest> {
    if dir.join(UNDO_MANIFEST).exists() {
        let raw = fs::read(dir.join(UNDO_MANIFEST)).map_err(|e| io(e, "cannot read undo", dir))?;
        serde_json::from_slice(&raw).map_err(|_| Error::Corrupt("the undo manifest is unreadable".into()))
    } else {
        read_manifest(dir)
    }
}

fn restore_all(txn_dir: &Path) -> Result<()> {
    let m = if txn_dir.join(COMMITTED).exists() {
        read_undo_manifest(txn_dir)?
    } else {
        read_manifest(txn_dir)?
    };
    // Restore everything we can, then report the first failure.
    let mut first_err = None;
    for e in &m.entries {
        if let Err(err) = restore_entry(txn_dir, e) {
            first_err.get_or_insert(err);
        }
    }
    first_err.map_or(Ok(()), Err)
}

fn txn_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = match fs::read_dir(root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(TXN_PREFIX))
            .map(|e| e.path())
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(e) => return Err(io(e, "cannot list", root)),
    };
    v.sort();
    Ok(v)
}

/// What [`recover`] did, so the app can say it plainly.
#[derive(Debug, PartialEq)]
pub enum Recovery {
    Nothing,
    /// An unfinished move (or an unfinished undo) was found and finished safely:
    /// your browsers are exactly as they were before it.
    PutBack,
}

/// One running Move It per browser folder. The OS drops the lock if we crash.
/// The lock file itself is never deleted. It has to keep a single stable inode:
/// if the path were unlinked on drop, a waiter that had already opened the old
/// file could lock it while a newcomer created and locked a fresh one, and two
/// owners would hold an "exclusive" lock on the same folder.
struct FolderLock(#[allow(dead_code)] fs::File);

fn lock_folder(root: &Path) -> Result<FolderLock> {
    let p = root.join(LOCK_FILE);
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&p)
        .map_err(|e| io(e, "cannot open", &p))?;
    // A child process that is starting (git) holds a copy of the lock for an instant between
    // fork and exec; retry briefly so that is not mistaken for a second Move It.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(FolderLock(f)),
            Err(fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            Err(fs::TryLockError::WouldBlock) => return Err(Error::Busy),
            Err(fs::TryLockError::Error(e)) => return Err(io(e, "cannot lock", &p)),
        }
    }
}

/// Run on every start, before anything else touches the stores in `root`.
/// True when a journal in `root` was left unfinished: a move (or an undo) was
/// cut short there, so [`recover`] has something to put back. Read-only: it
/// lists the folder but takes no lock and creates nothing.
pub fn has_unfinished(root: &Path) -> bool {
    let Ok(dirs) = txn_dirs(root) else { return false };
    dirs.iter().any(|d| !d.join(COMMITTED).exists() || (d.join(UNDOING).exists() && !d.join(UNDONE).exists()))
}

pub fn recover(root: &Path) -> Result<Recovery> {
    let _lock = lock_folder(root)?;
    recover_locked(root)
}

fn recover_locked(root: &Path) -> Result<Recovery> {
    let mut did = Recovery::Nothing;
    for d in txn_dirs(root)? {
        if d.join(COMMITTED).exists() {
            // A committed move whose undo was cut short: finish the undo.
            if d.join(UNDOING).exists() && !d.join(UNDONE).exists() {
                restore_all(&d)?;
                mark(&d, UNDONE, b"")?;
                did = Recovery::PutBack;
            }
            continue;
        }
        if d.join(MANIFEST).exists() {
            restore_all(&d)?;
            did = Recovery::PutBack;
        }
        // No manifest: the snapshot never finished, so no store was written yet.
        remove_any(&d)?;
    }
    Ok(did)
}

fn mark(dir: &Path, name: &str, body: &[u8]) -> Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = fs::File::create(&tmp).map_err(|e| io(e, "cannot mark", &tmp))?;
    f.write_all(body).and_then(|_| f.sync_all()).map_err(|e| io(e, "cannot mark", &tmp))?;
    fs::rename(&tmp, dir.join(name)).map_err(|e| io(e, "cannot mark", &tmp))?;
    fsync_dir(dir);
    Ok(())
}

fn undo_point(root: &Path) -> Result<Option<PathBuf>> {
    Ok(txn_dirs(root)?.into_iter().rev().find(|d| d.join(COMMITTED).exists() && !d.join(UNDONE).exists()))
}

/// What [`undo_last`] did.
#[derive(Debug, PartialEq)]
pub enum Undo {
    /// There is no finished move to undo.
    Nothing,
    /// Your browsers are back to how they were before the last move.
    Done,
    /// Your browsers changed since the last move (new logins, history...). Nothing was
    /// changed; undoing now would lose that, so the app must ask first and pass `force`.
    ChangedSince,
}

/// Undo the last finished move: put every store back to how it was before it.
pub fn undo_last(root: &Path, force: bool) -> Result<Undo> {
    let _lock = lock_folder(root)?;
    // An unfinished move must be put back first, never undone over.
    recover_locked(root)?;
    let Some(d) = undo_point(root)? else { return Ok(Undo::Nothing) };
    if !force {
        let post: Vec<String> = serde_json::from_slice(&fs::read(d.join(COMMITTED)).unwrap_or_default())
            .map_err(|_| Error::Corrupt("the undo point is unreadable".into()))?;
        let m = read_undo_manifest(&d)?;
        let now: Result<Vec<String>> = m.entries.iter().map(|e| digest(&e.original).map(|x| x.1)).collect();
        if now? != post {
            return Ok(Undo::ChangedSince);
        }
    }
    mark(&d, UNDOING, b"")?;
    restore_all(&d)?;
    mark(&d, UNDONE, b"")?;
    Ok(Undo::Done)
}

/// True when there is a finished move that can still be undone.
pub fn can_undo(root: &Path) -> Result<bool> {
    Ok(undo_point(root)?.is_some())
}

/// SQLite keeps unfinished writes in files beside the database; they are part of the store.
const SQLITE_SIDECARS: [&str; 3] = ["-journal", "-wal", "-shm"];

pub struct Txn {
    root: PathBuf,
    dir: PathBuf,
    manifest: Manifest,
    done: bool,
    _lock: FolderLock,
}

impl Txn {
    /// Snapshot every store, then write the manifest last. Refuses to start while an
    /// unfinished journal exists (call [`recover`] first) or another Move It holds the folder.
    /// `stores` = (name, path). A file store also covers its SQLite sidecar files.
    pub fn begin(root: &Path, stores: &[(&str, &Path)]) -> Result<Txn> {
        let lock = lock_folder(root)?;
        let existing = txn_dirs(root)?;
        for d in &existing {
            if !d.join(COMMITTED).exists() {
                return Err(Error::Refused("an earlier move did not finish; recover first".into()));
            }
        }
        // Names must sort in creation order even if the clock steps back.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let last = existing
            .iter()
            .filter_map(|d| d.file_name()?.to_str()?.strip_prefix(TXN_PREFIX)?.parse::<u128>().ok())
            .max()
            .unwrap_or(0);
        let stamp = now.max(last + 1);
        let dir = root.join(format!("{TXN_PREFIX}{stamp:024}"));
        fs::create_dir(&dir).map_err(|e| io(e, "cannot create", &dir))?;
        // Persist the journal's directory entry before any store is touched, so a crash can't
        // leave half-written stores with no journal for `recover` to roll back from.
        fsync_dir(&root);
        let built = (|| {
            let mut all: Vec<(String, PathBuf)> = Vec::new();
            for (name, path) in stores {
                all.push((name.to_string(), path.to_path_buf()));
                if !path.is_dir() {
                    for sc in SQLITE_SIDECARS {
                        let mut os = path.as_os_str().to_owned();
                        os.push(sc);
                        all.push((format!("{name}{sc}"), PathBuf::from(os)));
                    }
                }
            }
            let mut entries = Vec::new();
            for (i, (name, path)) in all.iter().enumerate() {
                let (kind, dg) = digest(path)?;
                let snapshot = PathBuf::from(format!("s{i}"));
                match kind {
                    Kind::Dir => copy_tree(path, &dir.join(&snapshot))?,
                    Kind::File => copy_file_synced(path, &dir.join(&snapshot))?,
                    Kind::Absent => {}
                }
                // The snapshot must match what we hashed; a browser writing meanwhile fails here.
                if kind != Kind::Absent && digest(&dir.join(&snapshot))?.1 != dg {
                    return Err(Error::Refused(format!("{name} changed while it was being saved; is the browser open?")));
                }
                entries.push(Entry { store: name.clone(), original: path.clone(), snapshot, kind, digest: dg });
            }
            let created_unix = (now / 1_000_000_000) as u64;
            let manifest = Manifest { version: 1, created_unix, entries };
            mark(&dir, MANIFEST, &serde_json::to_vec_pretty(&manifest).map_err(|e| Error::Io(e.to_string()))?)?;
            Ok(manifest)
        })();
        match built {
            Ok(manifest) => Ok(Txn { root: root.to_path_buf(), dir, manifest, done: false, _lock: lock }),
            Err(e) => {
                let _ = remove_any(&dir);
                Err(e)
            }
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Put every store back and drop the journal.
    pub fn rollback(mut self) -> Result<()> {
        self.done = true;
        restore_all(&self.dir)?;
        remove_any(&self.dir)
    }

    /// Mark the move finished; this folder becomes the Undo point and older ones go.
    /// The marker records how the stores look now, so a later undo can tell if they changed.
    /// If the marker cannot be written, the move is rolled back and the error returned,
    /// so the user is never told "failed" while the data stays changed.
    pub fn commit(self) -> Result<()> {
        self.commit_preserving(None)
    }

    /// A retry keeps the first round's snapshots as this move's undo baseline.
    /// The ordinary manifest still rolls back just this round if it fails or crashes.
    pub(crate) fn commit_preserving(mut self, previous: Option<&str>) -> Result<()> {
        let marked = (|| {
            let mut undo = self.manifest.clone();
            if let Some(name) = previous {
                let prior = undo_point(&self.root)?.ok_or_else(|| Error::Refused("the move's undo point disappeared".into()))?;
                if prior.file_name().and_then(|n| n.to_str()) != Some(name) {
                    return Err(Error::Refused("the move's undo point changed".into()));
                }
                let mut baseline = read_undo_manifest(&prior)?;
                for (i, entry) in baseline.entries.iter_mut().enumerate() {
                    let snapshot = PathBuf::from(format!("previous{i}"));
                    match entry.kind {
                        Kind::File => copy_file_synced(&prior.join(&entry.snapshot), &self.dir.join(&snapshot))?,
                        Kind::Dir => copy_tree(&prior.join(&entry.snapshot), &self.dir.join(&snapshot))?,
                        Kind::Absent => {}
                    }
                    entry.snapshot = snapshot;
                }
                for entry in &self.manifest.entries {
                    if !baseline.entries.iter().any(|e| entry.original == e.original
                        || (matches!(e.kind, Kind::Dir | Kind::Absent) && entry.original.starts_with(&e.original))) {
                        baseline.entries.push(entry.clone());
                    }
                }
                undo = baseline;
                mark(&self.dir, UNDO_MANIFEST, &serde_json::to_vec(&undo).map_err(|e| Error::Io(e.to_string()))?)?;
            }
            let post: Result<Vec<String>> =
                undo.entries.iter().map(|e| digest(&e.original).map(|x| x.1)).collect();
            mark(&self.dir, COMMITTED, &serde_json::to_vec(&post?).map_err(|e| Error::Io(e.to_string()))?)
        })();
        self.done = true;
        if let Err(e) = marked {
            let _ = fs::remove_file(self.dir.join(COMMITTED));
            restore_all(&self.dir)?;
            let _ = remove_any(&self.dir);
            return Err(e);
        }
        for d in txn_dirs(&self.root)? {
            if d != self.dir && d.join(COMMITTED).exists() {
                let _ = remove_any(&d);
            }
        }
        Ok(())
    }
}

impl Drop for Txn {
    /// Dropped without commit or rollback (an early return or a panic): roll back.
    /// If that fails the journal stays, and the next start's [`recover`] finishes it.
    fn drop(&mut self) {
        if !self.done {
            let _ = restore_all(&self.dir).and_then(|_| remove_any(&self.dir));
        }
    }
}

#[cfg(test)]
impl Txn {
    /// Simulate a crash: leave the journal on disk exactly as a killed process would.
    pub fn forget_as_crash(mut self) {
        self.done = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fx {
        _t: tempfile::TempDir,
        root: PathBuf,
    }

    /// A fake browser data folder with 5 stores: 3 files, 1 leveldb-like dir, 1 absent.
    fn fx() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("Default");
        fs::create_dir_all(root.join("Local Storage/leveldb")).unwrap();
        fs::write(root.join("Cookies"), b"cookies v0").unwrap();
        fs::write(root.join("History"), b"history v0").unwrap();
        fs::write(root.join("Login Data"), b"logins v0").unwrap();
        fs::write(root.join("Local Storage/leveldb/000003.log"), b"ls v0").unwrap();
        fs::write(root.join("Local Storage/leveldb/CURRENT"), b"MANIFEST-1").unwrap();
        Fx { _t: t, root }
    }

    fn stores(r: &Path) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("cookies", r.join("Cookies")),
            ("history", r.join("History")),
            ("logins", r.join("Login Data")),
            ("localstorage", r.join("Local Storage/leveldb")),
            ("bookmarks", r.join("Bookmarks")),
        ]
    }

    fn snap(r: &Path) -> Vec<(Kind, String)> {
        stores(r).iter().map(|(_, p)| digest(p).unwrap()).collect()
    }

    fn begin(r: &Path) -> Txn {
        let s = stores(r);
        let refs: Vec<(&str, &Path)> = s.iter().map(|(n, p)| (*n, p.as_path())).collect();
        Txn::begin(r, &refs).unwrap()
    }

    fn write_all_stores(r: &Path, upto: usize) {
        let writes: [&dyn Fn(); 5] = [
            &|| fs::write(r.join("Cookies"), b"cookies v1").unwrap(),
            &|| fs::write(r.join("History"), b"history v1").unwrap(),
            &|| fs::write(r.join("Login Data"), b"logins v1").unwrap(),
            &|| {
                fs::write(r.join("Local Storage/leveldb/000004.log"), b"new").unwrap();
                fs::remove_file(r.join("Local Storage/leveldb/000003.log")).unwrap();
            },
            &|| fs::write(r.join("Bookmarks"), b"{}").unwrap(),
        ];
        for w in writes.iter().take(upto) {
            w();
        }
    }

    #[test]
    fn retry_keeps_the_first_round_undo_and_adds_new_stores() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("a");
        let b = t.path().join("b");
        fs::write(&a, b"before").unwrap();
        let first = Txn::begin(t.path(), &[("a", &a)]).unwrap();
        let point = first.dir().file_name().unwrap().to_str().unwrap().to_string();
        fs::write(&a, b"round one").unwrap();
        first.commit().unwrap();
        let second = Txn::begin(t.path(), &[("a", &a), ("b", &b)]).unwrap();
        fs::write(&a, b"round two").unwrap();
        fs::write(&b, b"new").unwrap();
        second.commit_preserving(Some(&point)).unwrap();
        assert_eq!(txn_dirs(t.path()).unwrap().len(), 1);
        assert_eq!(undo_last(t.path(), false).unwrap(), Undo::Done);
        assert_eq!(fs::read(&a).unwrap(), b"before");
        assert!(!b.exists());
    }

    #[test]
    fn failure_mid_import_rolls_every_store_back() {
        let f = fx();
        let before = snap(&f.root);
        let t = begin(&f.root);
        write_all_stores(&f.root, 3);
        t.rollback().unwrap();
        assert_eq!(snap(&f.root), before);
        assert!(txn_dirs(&f.root).unwrap().is_empty());
    }

    #[test]
    fn crash_after_two_of_five_is_put_back_on_next_start() {
        let f = fx();
        let before = snap(&f.root);
        let t = begin(&f.root);
        write_all_stores(&f.root, 2);
        t.forget_as_crash();
        assert!(Txn::begin(&f.root, &[]).is_err(), "must refuse a new move before recovery");
        assert_eq!(recover(&f.root).unwrap(), Recovery::PutBack);
        assert_eq!(snap(&f.root), before);
        assert_eq!(recover(&f.root).unwrap(), Recovery::Nothing);
    }

    #[test]
    fn crash_during_snapshot_leaves_stores_untouched() {
        let f = fx();
        let before = snap(&f.root);
        // A txn folder with no manifest = the snapshot never finished.
        fs::create_dir(f.root.join(format!("{TXN_PREFIX}000"))).unwrap();
        fs::write(f.root.join(format!("{TXN_PREFIX}000/s0")), b"partial").unwrap();
        assert_eq!(recover(&f.root).unwrap(), Recovery::Nothing);
        assert_eq!(snap(&f.root), before);
        assert!(txn_dirs(&f.root).unwrap().is_empty());
    }

    #[test]
    fn undo_restores_byte_identical_and_only_once() {
        let f = fx();
        let before = snap(&f.root);
        let t = begin(&f.root);
        write_all_stores(&f.root, 5);
        t.commit().unwrap();
        assert_ne!(snap(&f.root), before);
        assert!(can_undo(&f.root).unwrap());
        assert_eq!(undo_last(&f.root, false).unwrap(), Undo::Done);
        assert_eq!(snap(&f.root), before);
        assert!(!can_undo(&f.root).unwrap());
        assert_eq!(undo_last(&f.root, false).unwrap(), Undo::Nothing);
    }

    #[test]
    fn only_the_newest_undo_point_is_kept() {
        let f = fx();
        begin(&f.root).commit().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        begin(&f.root).commit().unwrap();
        assert_eq!(txn_dirs(&f.root).unwrap().len(), 1);
    }

    #[test]
    fn crash_mid_undo_is_finished_on_next_start() {
        let f = fx();
        let before = snap(&f.root);
        let t = begin(&f.root);
        write_all_stores(&f.root, 5);
        t.commit().unwrap();
        let d = undo_point(&f.root).unwrap().unwrap();
        // Undo started, restored only the first store, then the power went.
        mark(&d, UNDOING, b"").unwrap();
        let m = read_manifest(&d).unwrap();
        restore_entry(&d, &m.entries[0]).unwrap();
        assert_ne!(snap(&f.root), before, "mixed state before recovery");
        assert_eq!(recover(&f.root).unwrap(), Recovery::PutBack);
        assert_eq!(snap(&f.root), before);
        assert!(!can_undo(&f.root).unwrap());
    }

    #[test]
    fn undo_asks_first_when_browsers_changed_since() {
        let f = fx();
        let t = begin(&f.root);
        write_all_stores(&f.root, 5);
        t.commit().unwrap();
        fs::write(f.root.join("History"), b"a week of browsing").unwrap();
        assert_eq!(undo_last(&f.root, false).unwrap(), Undo::ChangedSince);
        assert_eq!(fs::read(f.root.join("History")).unwrap(), b"a week of browsing", "nothing changed");
        assert!(can_undo(&f.root).unwrap());
        assert_eq!(undo_last(&f.root, true).unwrap(), Undo::Done);
        assert_eq!(fs::read(f.root.join("History")).unwrap(), b"history v0");
    }

    #[test]
    fn sqlite_sidecars_are_part_of_the_store() {
        let f = fx();
        fs::write(f.root.join("Cookies-wal"), b"wal v0").unwrap();
        let before = snap(&f.root);
        let t = begin(&f.root);
        fs::write(f.root.join("Cookies-wal"), b"wal v1").unwrap();
        fs::write(f.root.join("History-journal"), b"hot journal").unwrap();
        t.rollback().unwrap();
        assert_eq!(snap(&f.root), before);
        assert_eq!(fs::read(f.root.join("Cookies-wal")).unwrap(), b"wal v0");
        assert!(!f.root.join("History-journal").exists(), "a new hot journal must not survive rollback");
    }

    #[test]
    fn a_second_move_it_is_turned_away() {
        let f = fx();
        let t = begin(&f.root);
        assert!(matches!(recover(&f.root), Err(Error::Busy)));
        assert!(matches!(undo_last(&f.root, true), Err(Error::Busy)));
        assert!(matches!(Txn::begin(&f.root, &[]), Err(Error::Busy)));
        t.rollback().unwrap();
        assert_eq!(recover(&f.root).unwrap(), Recovery::Nothing);
    }

    #[test]
    fn journal_names_keep_order_when_the_clock_steps_back() {
        let f = fx();
        fs::create_dir(f.root.join(format!("{TXN_PREFIX}{:024}", u128::MAX / 2))).unwrap();
        fs::write(f.root.join(format!("{TXN_PREFIX}{:024}/{COMMITTED}", u128::MAX / 2)), b"[]").unwrap();
        let t = begin(&f.root);
        let newest = txn_dirs(&f.root).unwrap().pop().unwrap();
        assert_eq!(newest, t.dir());
        t.commit().unwrap();
    }

    #[test]
    fn dropping_without_commit_rolls_back() {
        let f = fx();
        let before = snap(&f.root);
        {
            let _t = begin(&f.root);
            write_all_stores(&f.root, 4);
        }
        assert_eq!(snap(&f.root), before);
    }

    #[test]
    fn a_dropped_lock_never_lets_two_owners_in() {
        // Ported from a review reproducer. A waiter opens the lock file
        // while the holder still owns it; when the holder lets go, the waiter
        // takes the lock, and a newcomer arriving after that must be refused.
        // This only holds while the lock file keeps one stable inode.
        let f = fx();
        let lock_path = f.root.join(LOCK_FILE);
        let a = lock_folder(&f.root).unwrap();
        let b = fs::OpenOptions::new().write(true).open(&lock_path).unwrap();
        assert!(matches!(b.try_lock(), Err(fs::TryLockError::WouldBlock)));
        drop(a);
        b.try_lock().unwrap();
        match lock_folder(&f.root) {
            Err(Error::Busy) => {}
            Ok(_) => panic!("newcomer locked the folder while the waiter still holds it"),
            Err(e) => panic!("unexpected error from the newcomer attempt: {e:?}"),
        }
        assert!(lock_path.exists(), "dropping a lock guard must not delete the lock file");
        drop(b);
        let _c = lock_folder(&f.root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_links_inside_a_store() {
        let f = fx();
        std::os::unix::fs::symlink("/etc", f.root.join("Local Storage/leveldb/evil")).unwrap();
        let s = stores(&f.root);
        let refs: Vec<(&str, &Path)> = s.iter().map(|(n, p)| (*n, p.as_path())).collect();
        assert!(matches!(Txn::begin(&f.root, &refs), Err(Error::Refused(_))));
        assert!(txn_dirs(&f.root).unwrap().is_empty(), "no journal left behind on refusal");
    }
}
