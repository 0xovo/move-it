use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::keychain::TokenStore;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    Dropbox,
}

impl Provider {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "google" => Ok(Self::Google),
            "dropbox" => Ok(Self::Dropbox),
            _ => Err(Error::Refused(format!("unknown cloud provider: {s}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Dropbox => "dropbox",
        }
    }
}

pub fn token_account(provider: Provider, byok: bool) -> &'static str {
    match (provider, byok) {
        (Provider::Google, false) => "google-drive",
        (Provider::Dropbox, false) => "dropbox",
        (Provider::Google, true) => "google-drive-byok",
        (Provider::Dropbox, true) => "dropbox-byok",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderToken {
    pub refresh_token: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
}

pub fn store_provider_token(store: &dyn TokenStore, provider: Provider, byok: bool, token: &ProviderToken) -> Result<()> {
    let text = serde_json::to_string(token).map_err(|e| Error::Corrupt(e.to_string()))?;
    store.store_token(token_account(provider, byok), &text)
}

pub fn load_provider_token(store: &dyn TokenStore, provider: Provider, byok: bool) -> Result<Option<ProviderToken>> {
    match store.load_token(token_account(provider, byok))? {
        Some(text) => Ok(Some(
            serde_json::from_str(&text).map_err(|e| Error::Corrupt(format!("stored provider token is damaged: {e}")))?,
        )),
        None => Ok(None),
    }
}

pub fn delete_provider_token(store: &dyn TokenStore, provider: Provider, byok: bool) -> Result<()> {
    store.delete_token(token_account(provider, byok))
}

pub fn access_from_stored(token: &ProviderToken) -> Result<Option<String>> {
    if let (Some(access), Some(exp)) = (&token.access_token, token.expires_at_unix) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if now + 60 < exp {
            return Ok(Some(access.clone()));
        }
    }
    Ok(None)
}

pub fn redact_token_err(msg: &str) -> String {
    let mut s = msg.to_string();
    for needle in ["refresh_token", "access_token", "client_secret"] {
        if let Some(i) = s.find(needle) {
            s.truncate(i.saturating_add(needle.len()));
            s.push_str("=…");
        }
    }
    s
}
