use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::{Error, Result};

const SUCCESS_HTML: &str = "<!doctype html><title>Move It</title><p>Sign-in finished. You can close this tab.</p>";

pub struct LoopbackRedirect {
    listener: TcpListener,
    pub redirect_uri: String,
}

impl LoopbackRedirect {
    pub fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| Error::Io(e.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::Io(e.to_string()))?;
        let port = listener.local_addr().map_err(|e| Error::Io(e.to_string()))?.port();
        Ok(Self {
            listener,
            redirect_uri: format!("http://127.0.0.1:{port}"),
        })
    }

    /// Wait for one redirect, verify `state`, return the authorization `code`.
    pub fn wait_for_code(self, expected_state: &str, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Refused("sign-in did not finish; try again".into()));
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => match read_redirect(&mut stream, expected_state) {
                    Ok(code) => {
                        let _ = respond_ok(&mut stream);
                        return Ok(code);
                    }
                    Err(_) => {
                        let _ = respond_err(&mut stream);
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(Error::Io(e.to_string())),
            }
        }
    }
}

fn read_redirect(stream: &mut TcpStream, expected_state: &str) -> Result<String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| Error::Io(e.to_string()))?;
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).map_err(|e| Error::Io(e.to_string()))?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
    if !first.starts_with("GET ") {
        return Err(Error::Refused("sign-in redirect was not recognized".into()));
    }
    let path = first.split_whitespace().nth(1).unwrap_or("");
    let query = path.split('?').nth(1).unwrap_or("");
    let params: std::collections::HashMap<_, _> = query
        .split('&')
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k, percent_decode(v)))
        })
        .collect();
    if let Some(err) = params.get("error") {
        return Err(Error::Refused(format!("sign-in was declined ({err})")));
    }
    let state = params.get("state").ok_or_else(|| Error::Refused("sign-in response missing state".into()))?;
    if state != expected_state {
        return Err(Error::Refused("sign-in response did not match; try again".into()));
    }
    let code = params
        .get("code")
        .ok_or_else(|| Error::Refused("sign-in response missing code".into()))?
        .clone();
    if code.is_empty() {
        return Err(Error::Refused("sign-in response missing code".into()));
    }
    Ok(code)
}

fn respond_ok(stream: &mut TcpStream) -> std::io::Result<()> {
    let body = SUCCESS_HTML.as_bytes();
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn respond_err(stream: &mut TcpStream) -> std::io::Result<()> {
    let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    stream.write_all(resp.as_bytes())
}

fn percent_decode(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"), 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(' ');
        } else {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}
