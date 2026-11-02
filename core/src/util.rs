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
