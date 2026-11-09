//! Which staging files cloud pipes move (boxes + pairing notes).

use std::io::Write;
use std::path::Path;

use crate::pairing;
use crate::pipe::{allowed_box_file_name, BOX_FILE};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudFileKind {
    Unrelated,
    Pairing,
    Box,
    RejectedBox,
}

pub fn classify_cloud_file_name(name: &str) -> CloudFileKind {
    if name == pairing::OFFER_FILE || name == pairing::PAIRED_FILE {
        return CloudFileKind::Pairing;
    }
    if name.starts_with("moveit-box") && name.ends_with(".json") {
        if allowed_box_file_name(name) {
            CloudFileKind::Box
        } else {
            CloudFileKind::RejectedBox
        }
    } else {
        CloudFileKind::Unrelated
    }
}

pub fn is_cloud_file(name: &str) -> bool {
    matches!(
        classify_cloud_file_name(name),
        CloudFileKind::Pairing | CloudFileKind::Box
    )
}

pub fn skip_rejected_remote_name(name: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "moveit: skipped remote cloud file (invalid name): {name}"
    );
}

pub fn local_cloud_files(place: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    if !place.is_dir() {
        return Ok(names);
    }
    for entry in std::fs::read_dir(place).map_err(|e| Error::Io(e.to_string()))? {
        let entry = entry.map_err(|e| Error::Io(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_cloud_file(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

pub fn write_cloud_file(place: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    match classify_cloud_file_name(name) {
        CloudFileKind::Box => {
            let _ = crate::pipe::write_named_box(place, name, bytes)?;
            Ok(())
        }
        CloudFileKind::Pairing => {
            std::fs::write(place.join(name), bytes).map_err(|e| Error::Io(e.to_string()))
        }
        CloudFileKind::RejectedBox | CloudFileKind::Unrelated => {
            Err(Error::Refused("box file name is not allowed".into()))
        }
    }
}

/// Store one remote cloud file during refresh; invalid box names are skipped, not fatal.
pub fn ingest_remote_cloud_file(place: &Path, name: &str, bytes: &[u8]) -> Result<bool> {
    match classify_cloud_file_name(name) {
        CloudFileKind::Unrelated => Ok(false),
        CloudFileKind::RejectedBox => {
            skip_rejected_remote_name(name);
            Ok(false)
        }
        CloudFileKind::Pairing | CloudFileKind::Box => {
            write_cloud_file(place, name, bytes)?;
            Ok(true)
        }
    }
}

pub fn remove_stale_locals(place: &Path, keep: &[String]) -> Result<()> {
    let keep: std::collections::BTreeSet<&str> = keep.iter().map(String::as_str).collect();
    for entry in std::fs::read_dir(place).map_err(|e| Error::Io(e.to_string()))? {
        let entry = entry.map_err(|e| Error::Io(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_cloud_file(&name) && !keep.iter().any(|k| k == &name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}
