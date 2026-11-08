use std::path::{Path, PathBuf};
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct Candidate {
    pub label: String,
    pub kind: String,
    pub path: Option<PathBuf>,
}

/// Inspect only known provider folders and metadata; never initiate OAuth or sync.
pub fn candidates(home: &Path, local: Option<&Path>, roaming: Option<&Path>) -> Vec<Candidate> {
    let mut found = Vec::new();
    let mut add = |label: &str, path: PathBuf| {
        if path.is_dir() && !found.iter().any(|c: &Candidate| c.path.as_ref() == Some(&path)) {
            found.push(Candidate { label: label.into(), kind: "folder".into(), path: Some(path) });
        }
    };
    for (label, relative) in [
        ("Dropbox", "Dropbox"), ("Google Drive", "Google Drive"),
        ("Google Drive", "My Drive"), ("iCloud Drive", "iCloudDrive"),
        ("iCloud Drive", "iCloud Drive"),
        ("iCloud Drive", "Library/Mobile Documents/com~apple~CloudDocs"),
    ] { add(label, home.join(relative)); }
    let mut metadata = vec![home.join(".dropbox/info.json")];
    for base in [local, roaming].into_iter().flatten() { metadata.push(base.join("Dropbox/info.json")); }
    for path in metadata {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                for account in ["personal", "business"] {
                    if let Some(path) = value[account]["path"].as_str() { add("Dropbox", PathBuf::from(path)); }
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(home.join("Library/CloudStorage")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("GoogleDrive-") { add("Google Drive", entry.path()); }
            if name.starts_with("Dropbox") { add("Dropbox", entry.path()); }
        }
    }
    found.sort_by(|a, b| a.label.cmp(&b.label).then(a.path.cmp(&b.path)));
    found.extend([
        Candidate { label: "Git repository".into(), kind: "git".into(), path: None },
        Candidate { label: "Another folder".into(), kind: "folder".into(), path: None },
    ]);
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_real_provider_folders_and_custom_dropbox_without_inventing_paths() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        for dir in ["Dropbox", "custom-dropbox", ".dropbox", "Library/CloudStorage/GoogleDrive-test", "Library/Mobile Documents/com~apple~CloudDocs"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::write(home.join(".dropbox/info.json"), serde_json::to_vec(&serde_json::json!({"personal":{"path":home.join("custom-dropbox")}})).unwrap()).unwrap();
        let list = candidates(home, None, None);
        assert_eq!(list.iter().filter(|c| c.path.is_some()).count(), 4);
        assert_eq!(list.iter().filter(|c| c.path.is_none()).count(), 2);
    }
}
