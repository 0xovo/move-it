//! Which staging files cloud pipes move (boxes + pairing notes).

use std::path::Path;

use crate::pairing;
use crate::pipe::BOX_FILE;
use crate::{Error, Result};

pub fn is_cloud_file(name: &str) -> bool {
    name == BOX_FILE
        || (name.starts_with("moveit-box") && name.ends_with(".json"))
        || name == pairing::OFFER_FILE
        || name == pairing::PAIRED_FILE
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
    if name == BOX_FILE || (name.starts_with("moveit-box") && name.ends_with(".json")) {
        let _ = crate::pipe::write_named_box(place, name, bytes)?;
        Ok(())
    } else {
        std::fs::write(place.join(name), bytes).map_err(|e| Error::Io(e.to_string()))
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
