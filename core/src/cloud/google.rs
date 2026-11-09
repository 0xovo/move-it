use std::path::{Path, PathBuf};

use crate::cloud::http::{HttpClient, HttpRequest, Method, SharedHttp};
use crate::cloud::index::{load_index, save_index, RemoteFile, RemoteIndex};
use crate::cloud::sync_files::{is_cloud_file, local_cloud_files, remove_stale_locals, write_cloud_file};
use crate::pairing;
use crate::pipe::{Pipe, BOX_FILE};
use crate::{Error, Result};

pub struct GoogleDrivePipe {
    place: PathBuf,
    http: SharedHttp,
    access: String,
}

impl GoogleDrivePipe {
    pub fn new(place: PathBuf, http: SharedHttp, access: String) -> Result<Self> {
        std::fs::create_dir_all(&place).map_err(|e| Error::Io(e.to_string()))?;
        Ok(Self { place, http, access })
    }
}

impl Pipe for GoogleDrivePipe {
    fn place(&self) -> &Path {
        &self.place
    }

    fn refresh(&self) -> Result<()> {
        let mut index = RemoteIndex::default();
        let mut kept = Vec::new();
        for remote in self.list_remote()? {
            if !is_cloud_file(&remote.name) {
                continue;
            }
            let bytes = self.download(&remote.id)?;
            write_cloud_file(&self.place, &remote.name, &bytes)?;
            kept.push(remote.name.clone());
            index.files.insert(
                remote.name,
                RemoteFile {
                    id: remote.id,
                    etag: remote.etag,
                    modified: remote.modified,
                    rev: None,
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

        for name in &local_names {
            let bytes =
                std::fs::read(self.place.join(name)).map_err(|e| Error::Io(e.to_string()))?;
            match index.files.get(name) {
                Some(remote) => {
                    let current = self.find_remote(name)?;
                    if let (Some(old), Some(now)) =
                        (remote.etag.as_ref(), current.as_ref().and_then(|c| c.etag.as_ref()))
                    {
                        if old != now {
                            return Err(Error::Busy);
                        }
                    }
                    self.update_file(&remote.id, &bytes)?;
                    if let Some(updated) = self.find_remote(name)? {
                        index.files.insert(name.clone(), updated);
                    }
                }
                None => {
                    if self.find_remote(name)?.is_some() {
                        return Err(Error::Busy);
                    }
                    let created = self.create_file(name, &bytes)?;
                    index.files.insert(name.clone(), created);
                }
            }
            save_index(&self.place, &index)?;
        }

        let remote = self.list_remote()?;
        for item in remote {
            if !is_cloud_file(&item.name) {
                continue;
            }
            if local_names.iter().any(|n| n == &item.name) {
                continue;
            }
            if let Some(remote) = index.files.get(&item.name) {
                self.delete_file(&remote.id)?;
                index.files.remove(&item.name);
                save_index(&self.place, &index)?;
            }
        }
        Ok(())
    }
}

impl GoogleDrivePipe {
    fn guard_remote_quiet(&self, index: &RemoteIndex, local: &[String]) -> Result<()> {
        for remote in self.list_remote()? {
            if !is_cloud_file(&remote.name) {
                continue;
            }
            if local.iter().any(|n| n == &remote.name) {
                continue;
            }
            if !index.files.contains_key(&remote.name) {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }

    fn auth_headers(&self) -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bearer {}", self.access))]
    }

    fn list_remote(&self) -> Result<Vec<DriveListItem>> {
        let q = format!(
            "trashed=false and (name='{BOX_FILE}' or name contains 'moveit-box-' or name='{}' or name='{}')",
            pairing::OFFER_FILE,
            pairing::PAIRED_FILE
        );
        let url = format!(
            "https://www.googleapis.com/drive/v3/files?q={}&fields=files(id,name,modifiedTime,md5Checksum)",
            pct_encode(&q)
        );
        let resp = self.http.request(HttpRequest {
            method: Method::Get,
            url,
            headers: self.auth_headers(),
            body: None,
        })?;
        let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| Error::Io(e.to_string()))?;
        let mut out = Vec::new();
        if let Some(files) = v.get("files").and_then(|f| f.as_array()) {
            for f in files {
                out.push(DriveListItem {
                    id: f.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    name: f.get("name").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    modified: f.get("modifiedTime").and_then(|x| x.as_str()).map(str::to_string),
                    etag: f.get("md5Checksum").and_then(|x| x.as_str()).map(str::to_string),
                });
            }
        }
        Ok(out)
    }

    fn find_remote(&self, name: &str) -> Result<Option<RemoteFile>> {
        Ok(self
            .list_remote()?
            .into_iter()
            .find(|f| f.name == name)
            .map(|f| RemoteFile {
                id: f.id,
                etag: f.etag,
                modified: f.modified,
                rev: None,
            }))
    }

    fn download(&self, id: &str) -> Result<Vec<u8>> {
        let url = format!("https://www.googleapis.com/drive/v3/files/{id}?alt=media");
        let resp = self.http.request(HttpRequest {
            method: Method::Get,
            url,
            headers: self.auth_headers(),
            body: None,
        })?;
        Ok(resp.body)
    }

    fn create_file(&self, name: &str, bytes: &[u8]) -> Result<RemoteFile> {
        let meta = format!(r#"{{"name":"{}"}}"#, name.replace('"', ""));
        let boundary = "moveit_upload_boundary";
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n").as_bytes());
        body.extend_from_slice(format!("--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let resp = self.http.request(HttpRequest {
            method: Method::Post,
            url: "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart".into(),
            headers: [
                self.auth_headers(),
                vec![("Content-Type".into(), format!("multipart/related; boundary={boundary}"))],
            ]
            .concat(),
            body: Some(body),
        })?;
        parse_drive_file(&resp.body)
    }

    fn update_file(&self, id: &str, bytes: &[u8]) -> Result<()> {
        let _ = self.http.request(HttpRequest {
            method: Method::Patch,
            url: format!("https://www.googleapis.com/upload/drive/v3/files/{id}?uploadType=media"),
            headers: [
                self.auth_headers(),
                vec![("Content-Type".into(), "application/octet-stream".into())],
            ]
            .concat(),
            body: Some(bytes.to_vec()),
        })?;
        Ok(())
    }

    fn delete_file(&self, id: &str) -> Result<()> {
        let _ = self.http.request(HttpRequest {
            method: Method::Delete,
            url: format!("https://www.googleapis.com/drive/v3/files/{id}"),
            headers: self.auth_headers(),
            body: None,
        })?;
        Ok(())
    }
}

struct DriveListItem {
    id: String,
    name: String,
    modified: Option<String>,
    etag: Option<String>,
}

fn parse_drive_file(body: &[u8]) -> Result<RemoteFile> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| Error::Io(e.to_string()))?;
    Ok(RemoteFile {
        id: v.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
        etag: v.get("md5Checksum").and_then(|x| x.as_str()).map(str::to_string),
        modified: v.get("modifiedTime").and_then(|x| x.as_str()).map(str::to_string),
        rev: None,
    })
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
