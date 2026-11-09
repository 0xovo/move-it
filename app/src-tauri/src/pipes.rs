//! Pipe picker: local folders, git, and cloud sign-in rows (Google Drive / Dropbox).

use std::path::{Path, PathBuf};
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct Candidate {
    pub label: String,
    pub kind: String,
    pub path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud: Option<bool>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CloudStatus {
    pub google_connected: bool,
    pub dropbox_connected: bool,
    pub byok_installed: bool,
}

pub fn candidates(
    home: &Path,
    local: Option<&Path>,
    roaming: Option<&Path>,
    cloud: CloudStatus,
) -> Vec<Candidate> {
    let mut found = Vec::new();
    let mut add = |label: &str, path: PathBuf| {
        if path.is_dir() && !found.iter().any(|c: &Candidate| c.path.as_ref() == Some(&path)) {
            found.push(Candidate {
                label: label.into(),
                kind: "folder".into(),
                path: Some(path),
                connected: None,
                cloud: None,
            });
        }
    };
    for (label, relative) in [
        ("Dropbox", "Dropbox"),
        ("Google Drive", "Google Drive"),
        ("Google Drive", "My Drive"),
        ("iCloud Drive", "iCloudDrive"),
        ("iCloud Drive", "iCloud Drive"),
        ("iCloud Drive", "Library/Mobile Documents/com~apple~CloudDocs"),
    ] {
        add(label, home.join(relative));
    }
    let mut metadata = vec![home.join(".dropbox/info.json")];
    for base in [local, roaming].into_iter().flatten() {
        metadata.push(base.join("Dropbox/info.json"));
    }
    for path in metadata {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                for account in ["personal", "business"] {
                    if let Some(path) = value[account]["path"].as_str() {
                        add("Dropbox", PathBuf::from(path));
                    }
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(home.join("Library/CloudStorage")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("GoogleDrive-") {
                add("Google Drive", entry.path());
            }
            if name.starts_with("Dropbox") {
                add("Dropbox", entry.path());
            }
        }
    }
    found.sort_by(|a, b| a.label.cmp(&b.label).then(a.path.cmp(&b.path)));

    let google_label = if cloud.google_connected {
        "Google Drive (connected)"
    } else {
        "Sign in with Google Drive"
    };
    let dropbox_label = if cloud.dropbox_connected {
        "Dropbox (connected)"
    } else {
        "Sign in with Dropbox"
    };
    let mut list = found;
    list.push(Candidate {
        label: google_label.into(),
        kind: "google".into(),
        path: None,
        connected: Some(cloud.google_connected),
        cloud: Some(true),
    });
    list.push(Candidate {
        label: dropbox_label.into(),
        kind: "dropbox".into(),
        path: None,
        connected: Some(cloud.dropbox_connected),
        cloud: Some(true),
    });
    list.push(Candidate {
        label: "Git repository".into(),
        kind: "git".into(),
        path: None,
        connected: None,
        cloud: None,
    });
    list.push(Candidate {
        label: "Another folder".into(),
        kind: "folder".into(),
        path: None,
        connected: None,
        cloud: None,
    });
  list.push(Candidate {
        label: "Advanced".into(),
        kind: "group".into(),
        path: None,
        connected: None,
        cloud: None,
    });
    list.push(Candidate {
        label: if cloud.byok_installed {
            "Use my own app keys (configured)".into()
        } else {
            "Use my own app keys".into()
        },
        kind: "byok".into(),
        path: None,
        connected: None,
        cloud: Some(true),
    });
    list
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn includes_cloud_sign_in_rows() {
        let temp = tempfile::tempdir().unwrap();
        let list = candidates(
            temp.path(),
            None,
            None,
            CloudStatus {
                google_connected: false,
                dropbox_connected: true,
                byok_installed: false,
            },
        );
        assert!(list.iter().any(|c| c.kind == "google" && c.connected == Some(false)));
        assert!(list.iter().any(|c| c.kind == "dropbox" && c.connected == Some(true)));
    }
}
