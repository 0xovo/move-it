use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::tokens::Provider;

/// In-memory OAuth access tokens for one app session (not shared across `App` instances).
#[derive(Default)]
pub struct AccessCache {
    inner: Mutex<HashMap<(Provider, bool), (String, u64)>>,
}

impl AccessCache {
    pub fn put(&self, provider: Provider, byok: bool, access: String, expires_at_unix: Option<u64>) {
        let exp = expires_at_unix.unwrap_or(0);
        if let Ok(mut g) = self.inner.lock() {
            g.insert((provider, byok), (access, exp));
        }
    }

    pub fn get(&self, provider: Provider, byok: bool) -> Option<String> {
        let g = self.inner.lock().ok()?;
        let (access, exp) = g.get(&(provider, byok))?;
        if *exp > 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now + 60 >= *exp {
                return None;
            }
        }
        Some(access.clone())
    }

    pub fn clear_provider(&self, provider: Provider) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(&(provider, false));
            g.remove(&(provider, true));
        }
    }

    pub fn clear_variant(&self, provider: Provider, byok: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(&(provider, byok));
        }
    }
}
