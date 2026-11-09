use std::path::{Path, PathBuf};

use crate::cloud::http::{HttpClient, HttpRequest, Method, SharedHttp};
use crate::cloud::index::{load_index, save_index, RemoteFile, RemoteIndex};
use crate::cloud::sync_files::{
    classify_cloud_file_name, ingest_remote_cloud_file, is_cloud_file, local_cloud_files,
    remove_stale_locals, skip_rejected_remote_name, CloudFileKind,
};
use crate::pipe::Pipe;
use crate::{Error, Result};

pub struct DropboxPipe {
    place: PathBuf,
    http: SharedHttp,
    access: String,
}

impl DropboxPipe {
    pub fn new(place: PathBuf, http: SharedHttp, access: String) -> Result<Self> {
        std::fs::create_dir_all(&place).map_err(|e| Error::Io(e.to_string()))?;
        Ok(Self { place, http, access })
    }
}

impl Pipe for DropboxPipe {
    fn place(&self) -> &Path {
        &self.place
    }

    fn refresh(&self) -> Result<()> {
        let mut index = RemoteIndex::default();
        let mut kept = Vec::new();
        for item in self.list_folder()? {
            match classify_cloud_file_name(&item.name) {
                CloudFileKind::Unrelated => continue,
                CloudFileKind::RejectedBox => {
                    skip_rejected_remote_name(&item.name);
                    continue;
                }
                CloudFileKind::Pairing | CloudFileKind::Box => {}
            }
            let bytes = self.download(&format!("/{}", item.name))?;
            if ingest_remote_cloud_file(&self.place, &item.name, &bytes)? {
                kept.push(item.name.clone());
            }
            index.files.insert(
                item.name.clone(),
                RemoteFile {
                    id: item.id.clone(),
                    etag: item.content_hash.clone(),
                    modified: None,
                    rev: item.rev.clone(),
                },
            );
            save_index(&self.place, &index)?;
        }
        remove_stale_locals(&self.place, &kept)?;
        save_index(&self.place, &index)?;
        Ok(())
    }

    fn publish(&self, _note: &str) -> Result<()> {
        let mut index = load_index(&self.place)?;
        let local_names = local_cloud_files(&self.place)?;
        self.guard_remote_quiet(&index, &local_names)?;
        let remote = self.list_folder()?;

        for name in &local_names {
            let bytes =
                std::fs::read(self.place.join(name)).map_err(|e| Error::Io(e.to_string()))?;
            let path = format!("/{name}");
            if let Some(existing) = remote.iter().find(|f| f.name == *name) {
                if let Some(saved) = index.files.get(name) {
                    if saved.rev.as_deref() != existing.rev.as_deref() {
                        return Err(Error::Busy);
                    }
                } else {
                    return Err(Error::Busy);
                }
                self.upload_update(&path, &bytes, existing.rev.as_deref())?;
            } else {
                if index.files.contains_key(name) {
                    return Err(Error::Busy);
                }
                self.upload_add(&path, &bytes)?;
            }
            if let Some(item) = self.list_folder()?.into_iter().find(|f| f.name == *name) {
                index.files.insert(
                    name.clone(),
                    RemoteFile {
                        id: item.id,
                        etag: item.content_hash,
                        modified: None,
                        rev: item.rev,
                    },
                );
            }
            save_index(&self.place, &index)?;
        }

        for item in remote {
            if !is_cloud_file(&item.name) {
                continue;
            }
            if local_names.iter().any(|n| n == &item.name) {
                continue;
            }
            if index.files.contains_key(&item.name) {
                self.delete(&format!("/{}", item.name))?;
                index.files.remove(&item.name);
                save_index(&self.place, &index)?;
            }
        }
        Ok(())
    }
}

impl DropboxPipe {
    fn guard_remote_quiet(&self, index: &RemoteIndex, local: &[String]) -> Result<()> {
        for item in self.list_folder()? {
            if !is_cloud_file(&item.name) {
                continue;
            }
            if local.iter().any(|n| n == &item.name) {
                continue;
            }
            if !index.files.contains_key(&item.name) {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }

    fn api_headers(&self, json: bool) -> Vec<(String, String)> {
        let mut h = vec![("Authorization".into(), format!("Bearer {}", self.access))];
        if json {
            h.push(("Content-Type".into(), "application/json".into()));
        }
        h
    }

    fn list_folder(&self) -> Result<Vec<DropboxMeta>> {
        let resp = self.http.request(HttpRequest {
            method: Method::Post,
            url: "https://api.dropboxapi.com/2/files/list_folder".into(),
            headers: self.api_headers(true),
            body: Some(r#"{"path":"","recursive":false,"include_deleted":false}"#.as_bytes().to_vec()),
        })?;
        let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| Error::Io(e.to_string()))?;
        let mut out = Vec::new();
        if let Some(entries) = v.get("entries").and_then(|e| e.as_array()) {
            for e in entries {
                if e.get(".tag").and_then(|t| t.as_str()) != Some("file") {
                    continue;
                }
                out.push(DropboxMeta {
                    id: e.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    name: e.get("name").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    rev: e.get("rev").and_then(|x| x.as_str()).map(str::to_string),
                    content_hash: e.get("content_hash").and_then(|x| x.as_str()).map(str::to_string),
                });
            }
        }
        Ok(out)
    }

    fn download(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self.http.request(HttpRequest {
            method: Method::Post,
            url: "https://content.dropboxapi.com/2/files/download".into(),
            headers: vec![
                ("Authorization".into(), format!("Bearer {}", self.access)),
                ("Dropbox-API-Arg".into(), format!(r#"{{"path":"{path}"}}"#)),
            ],
            body: None,
        })?;
        Ok(resp.body)
    }

    fn upload_add(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let _ = self.http.request(HttpRequest {
            method: Method::Post,
            url: "https://content.dropboxapi.com/2/files/upload".into(),
            headers: vec![
                ("Authorization".into(), format!("Bearer {}", self.access)),
                ("Content-Type".into(), "application/octet-stream".into()),
                (
                    "Dropbox-API-Arg".into(),
                    format!(r#"{{"path":"{path}","mode":"add","autorename":false,"mute":true}}"#),
                ),
            ],
            body: Some(bytes.to_vec()),
        })?;
        Ok(())
    }

    fn upload_update(&self, path: &str, bytes: &[u8], rev: Option<&str>) -> Result<()> {
        let mode = match rev {
            Some(r) => format!(r#"{{".tag":"update","update_rev":"{r}"}}"#),
            None => r#"{".tag":"add"}"#.to_string(),
        };
        let _ = self.http.request(HttpRequest {
            method: Method::Post,
            url: "https://content.dropboxapi.com/2/files/upload".into(),
            headers: vec![
                ("Authorization".into(), format!("Bearer {}", self.access)),
                ("Content-Type".into(), "application/octet-stream".into()),
                (
                    "Dropbox-API-Arg".into(),
                    format!(r#"{{"path":"{path}","mode":{mode},"autorename":false,"mute":true}}"#),
                ),
            ],
            body: Some(bytes.to_vec()),
        })?;
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<()> {
        let _ = self.http.request(HttpRequest {
            method: Method::Post,
            url: "https://api.dropboxapi.com/2/files/delete_v2".into(),
            headers: self.api_headers(true),
            body: Some(format!(r#"{{"path":"{path}"}}"#).into_bytes()),
        })?;
        Ok(())
    }
}

struct DropboxMeta {
    id: String,
    name: String,
    rev: Option<String>,
    content_hash: Option<String>,
}
