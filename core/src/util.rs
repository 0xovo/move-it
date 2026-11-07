//! Small shared helpers.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Copy a browser database (plus its -wal and -shm files) into a private temp folder, so
/// reading never fights a running browser's locks and never changes the original.
/// The folder is removed when the returned guard drops.
pub(crate) fn snapshot_db(path: &Path) -> Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix("moveit-read-")
        .tempdir()
        .map_err(|e| Error::Io(format!("cannot make a scratch folder: {e}")))?;
    let name = path.file_name().ok_or_else(|| Error::Corrupt(format!("bad database path {}", path.display())))?;
    let copy = dir.path().join(name);
    for suffix in ["", "-wal", "-shm"] {
        let mut src = path.as_os_str().to_owned();
        src.push(suffix);
        let src = PathBuf::from(src);
        if src.exists() {
            let mut dst = copy.as_os_str().to_owned();
            dst.push(suffix);
            std::fs::copy(&src, PathBuf::from(dst))
                .map_err(|e| Error::Io(format!("cannot copy {}: {e}", src.display())))?;
        }
    }
    Ok((dir, copy))
}

/// Write `bytes` to `path` so a crash never leaves a torn file: a unique
/// temp file in the same folder, fsynced, renamed over the target, and the
/// folder fsynced after it (where the platform allows). The temp name is
/// unique per process and call, so two writers never share one.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "moveit".to_string());
    let tmp = path.with_file_name(format!(".{name}.tmp-{}-{seq}", std::process::id()));
    let write = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(io_err)?;
        f.write_all(bytes).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_err(e));
    }
    #[cfg(unix)]
    {
        if let Some(dir) = path.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
    }
    Ok(())
}

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}
