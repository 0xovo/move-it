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
    Ok(())
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
