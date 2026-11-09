use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cloud::http::{HttpClient, HttpRequest, Method};
use crate::keychain::TokenStore;
use crate::oauth::config::{resolve_google_secret, OAuthFile};
use crate::oauth::tokens::{access_from_stored, load_provider_token, store_provider_token, Provider, ProviderToken};
use crate::{Error, Result};

pub struct CloudSession {
    pub access: String,
    pub refreshed: Option<ProviderToken>,
}

pub fn open_session(
    store: &dyn TokenStore,
    provider: Provider,
    byok: bool,
    oauth: &OAuthFile,
    oauth_dir: &Path,
    http: &dyn HttpClient,
) -> Result<CloudSession> {
    let mut stored = load_provider_token(store, provider, byok)?
        .ok_or_else(|| Error::Refused("this cloud provider is not signed in".into()))?;
    if let Some(access) = access_from_stored(&stored)? {
        return Ok(CloudSession { access, refreshed: None });
    }
    let updated = refresh_access(provider, http, oauth, oauth_dir, &stored)?;
    stored.access_token = Some(updated.access.clone());
    stored.expires_at_unix = updated.expires_at_unix;
    store_provider_token(store, provider, byok, &stored)?;
    Ok(CloudSession {
        access: updated.access,
        refreshed: Some(stored),
    })
}

struct AccessMint {
    access: String,
    expires_at_unix: Option<u64>,
}

fn refresh_access(
    provider: Provider,
    http: &dyn HttpClient,
    oauth: &OAuthFile,
    oauth_dir: &Path,
    stored: &ProviderToken,
) -> Result<AccessMint> {
    let body = match provider {
        Provider::Google => {
            let (client_id, client_secret) = resolve_google_secret(oauth, oauth_dir)?;
            format!(
                "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
                pct_encode(&stored.refresh_token),
                pct_encode(&client_id),
                pct_encode(&client_secret),
            )
        }
        Provider::Dropbox => {
            let d = oauth
                .dropbox
                .as_ref()
                .ok_or_else(|| Error::Refused("dropbox is not configured".into()))?;
            format!(
                "grant_type=refresh_token&refresh_token={}&client_id={}",
                pct_encode(&stored.refresh_token),
                pct_encode(&d.app_key),
            )
        }
    };
    let url = match provider {
        Provider::Google => "https://oauth2.googleapis.com/token",
        Provider::Dropbox => "https://api.dropboxapi.com/oauth2/token",
    };
    let resp = http.request(HttpRequest {
        method: Method::Post,
        url: url.into(),
        headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into())],
        body: Some(body.into_bytes()),
    })?;
    let v: serde_json::Value = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Refused(format!("provider token refresh failed: {e}")))?;
    if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
        if err == "invalid_grant" {
            return Err(Error::Refused("sign-in expired; sign in again".into()));
        }
        return Err(Error::Refused(format!("provider token refresh failed ({err})")));
    }
    let access = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::Refused("provider token refresh returned no access token".into()))?
        .to_string();
    let expires_at_unix = v.get("expires_in").and_then(|x| x.as_u64()).map(|secs| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() + secs)
            .unwrap_or(0)
    });
    Ok(AccessMint { access, expires_at_unix })
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
