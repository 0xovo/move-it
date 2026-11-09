use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const INDEX_FILE: &str = ".moveit-cloud-index.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteIndex {
    #[serde(default)]
    pub files: BTreeMap<String, RemoteFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteFile {
    pub id: String,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub rev: Option<String>,
}

pub fn index_path(place: &Path) -> PathBuf {
    place.parent().unwrap_or(place).join(INDEX_FILE)
}

pub fn load_index(place: &Path) -> Result<RemoteIndex> {
    let path = index_path(place);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| Error::Corrupt(format!("cloud index is damaged: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RemoteIndex::default()),
        Err(e) => Err(Error::Io(e.to_string())),
    }
}

pub fn save_index(place: &Path, index: &RemoteIndex) -> Result<()> {
    let path = index_path(place);
    let bytes = serde_json::to_vec_pretty(index).map_err(|e| Error::Io(e.to_string()))?;
    std::fs::write(path, bytes).map_err(|e| Error::Io(e.to_string()))
}
