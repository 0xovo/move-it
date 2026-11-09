use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::tokens::Provider;

static CACHE: LazyLock<Mutex<HashMap<(Provider, bool), (String, u64)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn put(provider: Provider, byok: bool, access: String, expires_at_unix: Option<u64>) {
    let exp = expires_at_unix.unwrap_or(0);
    if let Ok(mut g) = CACHE.lock() {
        g.insert((provider, byok), (access, exp));
    }
}

pub fn get(provider: Provider, byok: bool) -> Option<String> {
    let g = CACHE.lock().ok()?;
    let (access, exp) = g.get(&(provider, byok))?;
    if *exp > 0 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if now + 60 >= *exp {
            return None;
        }
    }
    Some(access.clone())
}

pub fn clear_provider(provider: Provider) {
    if let Ok(mut g) = CACHE.lock() {
        g.remove(&(provider, false));
        g.remove(&(provider, true));
    }
}
