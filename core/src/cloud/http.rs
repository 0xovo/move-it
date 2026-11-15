use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait HttpClient: Send + Sync {
    fn request(&self, req: HttpRequest) -> Result<HttpResponse>;
}

fn shared_agent() -> &'static ureq::Agent {
    use std::sync::OnceLock;
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_recv_body(Some(Duration::from_secs(120)))
            .timeout_global(Some(Duration::from_secs(120)))
            .build();
        ureq::Agent::new_with_config(config)
    })
}

fn read_body(response: &mut ureq::http::Response<ureq::Body>) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    response
        .body_mut()
        .with_config()
        .limit(512 * 1024 * 1024)
        .reader()
        .read_to_end(&mut body)
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(body)
}

pub fn map_http_status(status: u16, body: &[u8]) -> Result<()> {
    if status < 400 {
        return Ok(());
    }
    if status == 409 {
        return Err(Error::Busy);
    }
    if status == 429 || status >= 500 {
        return Err(Error::Refused(format!("network is busy ({status}); try again later")));
    }
    if status == 400 || status == 401 {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
            if v.get("error").and_then(|x| x.as_str()) == Some("invalid_grant") {
                return Err(Error::Refused("sign-in expired; sign in again".into()));
            }
        }
        if status == 401 {
            return Err(Error::Refused("sign-in expired; sign in again".into()));
        }
    }
    if status == 403 {
        let reasons = provider_reasons(body);
        let has = |r: &str| reasons.iter().any(|x| x.eq_ignore_ascii_case(r));
        if has("accessNotConfigured") || has("SERVICE_DISABLED") {
            return Err(Error::Refused(
                "Google Drive is not switched on for this app yet (Drive API disabled in the Google Cloud project)".into(),
            ));
        }
        if has("insufficientPermissions") || has("ACCESS_TOKEN_SCOPE_INSUFFICIENT") {
            return Err(Error::Refused(
                "Move It was not given Drive access. Sign in again and tick the box that lets Move It use the files it creates".into(),
            ));
        }
    }
    match provider_message(body) {
        Some(msg) => Err(Error::Refused(format!("request failed ({status}): {msg}"))),
        None => Err(Error::Refused(format!("request failed ({status})"))),
    }
}

/// Machine reasons from a Google or Dropbox error body (never tokens).
fn provider_reasons(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return out };
    let err = &v["error"];
    for list in [&err["errors"], &err["details"]] {
        if let Some(items) = list.as_array() {
            for item in items {
                if let Some(r) = item["reason"].as_str() {
                    out.push(r.to_string());
                }
            }
        }
    }
    if let Some(s) = err["status"].as_str() {
        out.push(s.to_string());
    }
    out
}

/// A short, safe provider message: Google error.message or Dropbox error_summary.
fn provider_message(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let raw = v["error"]["message"]
        .as_str()
        .or_else(|| v["error_summary"].as_str())
        .or_else(|| v["error_description"].as_str())?;
    let clean: String = raw
        .split_whitespace()
        .filter(|w| !w.starts_with("ya29.") && !w.starts_with("sl.") && w.len() < 80)
        .collect::<Vec<_>>()
        .join(" ");
    let short: String = clean.chars().take(200).collect();
    (!short.is_empty()).then_some(short)
}

/// Blocking ureq client. License: MIT/Apache-2.0 (GPL-3.0-compatible).
pub struct UreqClient;

impl HttpClient for UreqClient {
    fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let agent = shared_agent();
        let response = match (req.method, req.body.as_deref()) {
            (Method::Get, None) => {
                let mut builder = agent.get(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.call()
            }
            (Method::Delete, None) => {
                let mut builder = agent.delete(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.call()
            }
            (Method::Post, Some(b)) => {
                let mut builder = agent.post(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send(b)
            }
            (Method::Post, None) => {
                let mut builder = agent.post(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send_empty()
            }
            (Method::Put, Some(b)) => {
                let mut builder = agent.put(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send(b)
            }
            (Method::Put, None) => {
                let mut builder = agent.put(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send_empty()
            }
            (Method::Patch, Some(b)) => {
                let mut builder = agent.patch(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send(b)
            }
            (Method::Patch, None) => {
                let mut builder = agent.patch(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send_empty()
            }
            (Method::Get, Some(_)) | (Method::Delete, Some(_)) => {
                return Err(Error::Refused("http get/delete cannot carry a body".into()));
            }
        }
        .map_err(|e| Error::Io(format!("network request failed: {e}")))?;
        let mut response = response;
        let status = response.status().as_u16();
        let body = read_body(&mut response)?;
        map_http_status(status, &body)?;
        Ok(HttpResponse { status, body })
    }
}

#[derive(Default)]
pub struct MockHttp {
    pub requests: Mutex<Vec<HttpRequest>>,
    responses: Mutex<Vec<std::result::Result<HttpResponse, String>>>,
}

impl MockHttp {
    pub fn push_ok_json(&self, json: &str) {
        self.responses.lock().unwrap().push(std::result::Result::Ok(HttpResponse {
            status: 200,
            body: json.as_bytes().to_vec(),
        }));
    }

    pub fn push_status_body(&self, status: u16, body: &str) {
        self.responses.lock().unwrap().push(std::result::Result::Ok(HttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        }));
    }

    pub fn push_bytes(&self, status: u16, body: Vec<u8>) {
        self.responses.lock().unwrap().push(std::result::Result::Ok(HttpResponse { status, body }));
    }

    pub fn recorded(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn clear_recorded(&self) {
        self.requests.lock().unwrap().clear();
        self.responses.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn google_403_reasons_are_explained() {
        let disabled = br#"{"error":{"code":403,"message":"Google Drive API has not been used in project 1 before or it is disabled.","errors":[{"reason":"accessNotConfigured"}],"status":"PERMISSION_DENIED"}}"#;
        let msg = map_http_status(403, disabled).unwrap_err().to_string();
        assert!(msg.contains("Drive API disabled"), "{msg}");
        let scope = br#"{"error":{"code":403,"message":"Request had insufficient authentication scopes.","errors":[{"reason":"insufficientPermissions"}],"status":"PERMISSION_DENIED"}}"#;
        let msg = map_http_status(403, scope).unwrap_err().to_string();
        assert!(msg.contains("Sign in again"), "{msg}");
        let other = br#"{"error_summary":"path/not_found/..","error":{".tag":"path"}}"#;
        let msg = map_http_status(404, other).unwrap_err().to_string();
        assert!(msg.contains("path/not_found"), "{msg}");
        let leak = br#"{"error":{"message":"bad ya29.SECRETTOKEN value"}}"#;
        let msg = map_http_status(403, leak).unwrap_err().to_string();
        assert!(!msg.contains("ya29"), "{msg}");
    }

    #[test]
    fn map_http_status_rejects_other_4xx() {
        assert!(matches!(
            map_http_status(403, b"{}"),
            Err(Error::Refused(_))
        ));
        assert!(matches!(
            map_http_status(404, b"{}"),
            Err(Error::Refused(_))
        ));
    }
}

impl HttpClient for MockHttp {
    fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        self.requests.lock().unwrap().push(req);
        let mut queue = self.responses.lock().unwrap();
        if queue.is_empty() {
            return Err(Error::Refused("mock http has no queued response".into()));
        }
        match queue.remove(0) {
            Ok(r) => {
                map_http_status(r.status, &r.body)?;
                Ok(r)
            }
            Err(m) => Err(Error::Refused(m)),
        }
    }
}

pub type SharedHttp = Arc<dyn HttpClient>;
