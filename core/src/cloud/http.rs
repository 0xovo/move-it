use std::io::Read;
use std::sync::{Arc, Mutex};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
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

/// Blocking ureq client. License: MIT/Apache-2.0 (GPL-3.0-compatible).
pub struct UreqClient;

impl HttpClient for UreqClient {
    fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let mut response = match (req.method, req.body.as_deref()) {
            (Method::Get, None) => {
                let mut builder = ureq::get(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.call()
            }
            (Method::Delete, None) => {
                let mut builder = ureq::delete(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.call()
            }
            (Method::Post, Some(b)) => {
                let mut builder = ureq::post(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send(b)
            }
            (Method::Post, None) => {
                let mut builder = ureq::post(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send_empty()
            }
            (Method::Put, Some(b)) => {
                let mut builder = ureq::put(&req.url);
                for (k, v) in &req.headers {
                    builder = builder.header(k, v);
                }
                builder.send(b)
            }
            (Method::Put, None) => {
                let mut builder = ureq::put(&req.url);
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
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .read_to_vec()
            .map_err(|e| Error::Io(e.to_string()))?;
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
            Ok(r) => Ok(r),
            Err(m) => Err(Error::Refused(m)),
        }
    }
}

pub type SharedHttp = Arc<dyn HttpClient>;
