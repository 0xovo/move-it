//! Where the sync key lives on a device: the OS keychain, never a file.
//!
//! The key file helpers on [`SyncKey`] predate this module and stay for tests and
//! scratch work, but a paired device keeps its key here instead: service scoped to
//! this app, account scoped to the device's stable id. Linux reaches the Secret
//! Service, macOS the login Keychain, Windows the Credential Manager, all
//! through the keyring crate behind the one [`KeyStore`] trait. Every call
//! runs under a hard time budget: a wedged keychain daemon must surface as
//! "unavailable", never as a hang.
//!
//! Flow, matching [`crate::pairing`]: the offering device calls [`ensure_key`]
//! (an existing key is loaded back, a first run generates one and stores it), the
//! accepting device stores the key it just unwrapped, and every later seal or open
//! loads the key back with [`load_key`].

use crate::sealed::SyncKey;
use crate::Result;

/// Secret Service service name: this app, nothing else.
pub const SERVICE: &str = "moveit-sync";

/// Storing and loading one device's sync key.
pub trait KeyStore {
    /// Store `key` as `device`'s sync key, replacing any previous one.
    fn store(&self, device: &str, key: &SyncKey) -> Result<()>;
    /// The stored key, or `None` when this device has none yet.
    fn load(&self, device: &str) -> Result<Option<SyncKey>>;
    /// Remove the stored key; removing an absent one is not an error.
    fn delete(&self, device: &str) -> Result<()>;
}

/// The real store: the OS keychain.
pub struct OsKeychain;

/// How long one keychain call may take before it counts as unavailable.
/// A locked store that would prompt forever, or a daemon that never
/// answers, must become a plain error, not a frozen app.
const KEYCHAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn timed<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(KEYCHAIN_TIMEOUT) {
        Ok(r) => r,
        Err(_) => Err(crate::Error::KeychainUnavailable(format!(
            "the system keychain did not answer the {what} request in time; it may be locked"
        ))),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod os {
    use super::{timed, KeyStore, TokenStore, SERVICE};
    use crate::sealed::SyncKey;
    use crate::{Error, Result};

    fn entry(device: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, device)
            .map_err(|e| Error::KeychainUnavailable(format!("keychain: {e}")))
    }

    impl KeyStore for super::OsKeychain {
        fn store(&self, device: &str, key: &SyncKey) -> Result<()> {
            let device = device.to_string();
            let text = key.to_key_file_text().trim().to_string();
            timed("store", move || {
                entry(&device)?
                    .set_password(&text)
                    .map_err(|e| Error::KeychainUnavailable(format!("keychain store: {e}")))
            })
        }

        fn load(&self, device: &str) -> Result<Option<SyncKey>> {
            let device = device.to_string();
            timed("load", move || match entry(&device)?.get_password() {
                Ok(text) => Ok(Some(SyncKey::from_key_file_text(&text)?)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(Error::KeychainUnavailable(format!("keychain load: {e}"))),
            })
        }

        fn delete(&self, device: &str) -> Result<()> {
            let device = device.to_string();
            timed("delete", move || match entry(&device)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(Error::KeychainUnavailable(format!("keychain delete: {e}"))),
            })
        }
    }

    impl TokenStore for super::OsKeychain {
        fn store_token(&self, account: &str, value: &str) -> Result<()> {
            let account = account.to_string();
            let value = value.to_string();
            timed("store token", move || {
                entry(&account)?
                    .set_password(&value)
                    .map_err(|e| Error::KeychainUnavailable(format!("keychain store: {e}")))
            })
        }

        fn load_token(&self, account: &str) -> Result<Option<String>> {
            let account = account.to_string();
            timed("load token", move || match entry(&account)?.get_password() {
                Ok(text) => Ok(Some(text)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(Error::KeychainUnavailable(format!("keychain load: {e}"))),
            })
        }

        fn delete_token(&self, account: &str) -> Result<()> {
            let account = account.to_string();
            timed("delete token", move || match entry(&account)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(Error::KeychainUnavailable(format!("keychain delete: {e}"))),
            })
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl TokenStore for OsKeychain {
    fn store_token(&self, _account: &str, _value: &str) -> Result<()> {
        Err(crate::Error::Refused("no keychain backend is built for this platform".into()))
    }
    fn load_token(&self, _account: &str) -> Result<Option<String>> {
        Err(crate::Error::Refused("no keychain backend is built for this platform".into()))
    }
    fn delete_token(&self, _account: &str) -> Result<()> {
        Err(crate::Error::Refused("no keychain backend is built for this platform".into()))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl KeyStore for OsKeychain {
    fn store(&self, _device: &str, _key: &SyncKey) -> Result<()> {
        Err(crate::Error::Refused("no keychain backend is built for this platform".into()))
    }
    fn load(&self, _device: &str) -> Result<Option<SyncKey>> {
        Err(crate::Error::Refused("no keychain backend is built for this platform".into()))
    }
    fn delete(&self, _device: &str) -> Result<()> {
        Err(crate::Error::Refused("no keychain backend is built for this platform".into()))
    }
}

/// An in-memory store: the stand-in for tests and CI, where no OS keychain
/// session exists. One store models one device's keychain.
#[derive(Default)]
pub struct MemoryStore(std::sync::Mutex<std::collections::HashMap<String, String>>);

impl MemoryStore {
    /// Every (account, key text) pair it holds. Test support: a test can
    /// recover a key even when the app's config file is damaged or gone.
    pub fn entries(&self) -> Vec<(String, String)> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl KeyStore for MemoryStore {
    fn store(&self, device: &str, key: &SyncKey) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert(device.to_string(), key.to_key_file_text());
        Ok(())
    }
    fn load(&self, device: &str) -> Result<Option<SyncKey>> {
        match self.0.lock().unwrap().get(device) {
            Some(t) => Ok(Some(SyncKey::from_key_file_text(t)?)),
            None => Ok(None),
        }
    }
    fn delete(&self, device: &str) -> Result<()> {
        self.0.lock().unwrap().remove(device);
        Ok(())
    }
}

/// Load `device`'s key from the OS keychain, or `None` when it has none.
pub fn load_key(device: &str) -> Result<Option<SyncKey>> {
    OsKeychain.load(device)
}

/// Store `key` as `device`'s sync key in the OS keychain.
pub fn store_key(device: &str, key: &SyncKey) -> Result<()> {
    OsKeychain.store(device, key)
}

/// Remove `device`'s sync key from the OS keychain.
pub fn delete_key(device: &str) -> Result<()> {
    OsKeychain.delete(device)
}

/// Provider OAuth tokens: same OS keychain service, different account names.
pub trait TokenStore {
    fn store_token(&self, account: &str, value: &str) -> Result<()>;
    fn load_token(&self, account: &str) -> Result<Option<String>>;
    fn delete_token(&self, account: &str) -> Result<()>;
}

impl TokenStore for MemoryStore {
    fn store_token(&self, account: &str, value: &str) -> Result<()> {
        self.0.lock().unwrap().insert(account.to_string(), value.to_string());
        Ok(())
    }
    fn load_token(&self, account: &str) -> Result<Option<String>> {
        Ok(self.0.lock().unwrap().get(account).cloned())
    }
    fn delete_token(&self, account: &str) -> Result<()> {
        self.0.lock().unwrap().remove(account);
        Ok(())
    }
}

/// The device's key, generating and storing a fresh one when it has none.
/// This is where a first device's secret is born: in the keychain, not on disk.
pub fn ensure_key<S: KeyStore>(store: &S, device: &str) -> Result<SyncKey> {
    if let Some(k) = store.load(device)? {
        return Ok(k);
    }
    let k = SyncKey::generate()?;
    store.store(device, &k)?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// In-memory store: the CI stand-in for the OS keychain.
    #[derive(Default)]
    struct MemStore(RefCell<HashMap<String, String>>);

    impl KeyStore for MemStore {
        fn store(&self, device: &str, key: &SyncKey) -> Result<()> {
            self.0
                .borrow_mut()
                .insert(device.to_string(), key.to_key_file_text());
            Ok(())
        }
        fn load(&self, device: &str) -> Result<Option<SyncKey>> {
            match self.0.borrow().get(device) {
                Some(t) => Ok(Some(SyncKey::from_key_file_text(t)?)),
                None => Ok(None),
            }
        }
        fn delete(&self, device: &str) -> Result<()> {
            self.0.borrow_mut().remove(device);
            Ok(())
        }
    }

    #[test]
    fn store_load_round_trip() {
        let s = MemStore::default();
        assert!(s.load("dev-a").unwrap().is_none(), "empty store loads as none");
        let k = SyncKey::generate().unwrap();
        s.store("dev-a", &k).unwrap();
        let back = s.load("dev-a").unwrap().expect("stored key loads");
        assert_eq!(back.to_key_file_text(), k.to_key_file_text());
        // Accounts are per device: another device still has nothing.
        assert!(s.load("dev-b").unwrap().is_none());
        // Sealing with the loaded key opens with the original, and the reverse.
        let sealed = back.seal_small(&[7u8; 12], b"hello").unwrap();
        assert_eq!(k.open_small(&[7u8; 12], &sealed).unwrap(), b"hello");
        // Overwrite replaces, delete removes.
        let k2 = SyncKey::generate().unwrap();
        s.store("dev-a", &k2).unwrap();
        assert_eq!(
            s.load("dev-a").unwrap().unwrap().to_key_file_text(),
            k2.to_key_file_text()
        );
        s.delete("dev-a").unwrap();
        assert!(s.load("dev-a").unwrap().is_none());
        s.delete("dev-a").unwrap();
    }

    #[test]
    fn ensure_key_generates_once_then_loads() {
        let s = MemStore::default();
        let a = ensure_key(&s, "dev-a").unwrap();
        let b = ensure_key(&s, "dev-a").unwrap();
        assert_eq!(a.to_key_file_text(), b.to_key_file_text(), "second run loads, not regenerates");
    }

    #[test]
    fn pairing_flow_through_a_store() {
        use crate::pairing::{accept, check_paired, offer, Accept, Tries};
        let shared = tempfile::tempdir().unwrap();
        let b_state = tempfile::tempdir().unwrap();
        let a_store = MemStore::default();
        let b_store = MemStore::default();
        // A: first run generates the secret straight into its store and offers it.
        let key_a = ensure_key(&a_store, "dev-a").unwrap();
        offer(shared.path(), &key_a, "482913", "dev-a").unwrap();
        // B: unwrap with the code, then keep the key in its own store.
        let tries = Tries { path: b_state.path().join("tries") };
        let Accept::Paired(key_b) = accept(shared.path(), "482913", "dev-b", &tries).unwrap()
        else {
            panic!("pairing should succeed")
        };
        b_store.store("dev-b", &key_b).unwrap();
        // The note is left only now that the key is stored (never before).
        crate::pairing::leave_paired_note(shared.path(), &key_b, "dev-b").unwrap();
        // Both sides now load back the same key from their stores.
        let la = a_store.load("dev-a").unwrap().unwrap();
        let lb = b_store.load("dev-b").unwrap().unwrap();
        assert_eq!(la.to_key_file_text(), lb.to_key_file_text());
        // And A confirms with the loaded key.
        assert_eq!(check_paired(shared.path(), &la).unwrap(), Some("dev-b".into()));
    }

    /// Live Secret Service round trip. Needs a real session keyring, so it is
    /// ignored in CI; run it by hand with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn live_keychain_round_trip() {
        let device = "moveit-test-device";
        let _ = delete_key(device);
        assert!(load_key(device).unwrap().is_none());
        let k = SyncKey::generate().unwrap();
        store_key(device, &k).unwrap();
        let back = load_key(device).unwrap().expect("key loads from the keychain");
        assert_eq!(back.to_key_file_text(), k.to_key_file_text());
        delete_key(device).unwrap();
        assert!(load_key(device).unwrap().is_none());
    }
}
