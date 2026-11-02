//! How Chromium browsers lock cookie and saved-login values at rest, per platform.
//! Ported from the Python prototype; Mac added from Chromium's os_crypt_mac.
//!
//! - Linux: `v10`/`v11` + AES-128-CBC, IV = 16 spaces, key = PBKDF2-HMAC-SHA1(password, "saltysalt", 1 round).
//! - Mac:   `v10` + the same CBC, key = PBKDF2-HMAC-SHA1(Keychain password, "saltysalt", 1003 rounds).
//! - Windows: `v10` + AES-256-GCM with the DPAPI-unwrapped master key from Local State.
//!   `v20` (App-Bound) is refused, never guessed.
//!
//! Cookies (Cookies db meta version >= 24) put SHA256(host_key) in front of the plaintext.
//! Saved logins do NOT, as far as Chromium's LoginDatabase goes; the Python prototype adds it.
//! Until a live probe settles it, writers here take [`HostTag`] explicitly, readers strip a
//! matching tag either way, so reading is always safe.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

type CbcEnc = cbc::Encryptor<aes::Aes128>;
type CbcDec = cbc::Decryptor<aes::Aes128>;

const SALT: &[u8] = b"saltysalt";
const IV: [u8; 16] = [b' '; 16];
pub const LINUX_FALLBACK_PASSWORD: &str = "peanuts";

/// The libsecret schema attribute Chromium stamps on its current Safe Storage items.
pub const LIBSECRET_V2_SCHEMA: &str = "chrome_libsecret_os_crypt_password_v2";

/// Environment variable that overrides Linux browser-password discovery.
pub const LINUX_PASSWORD_ENV: &str = "MOVEIT_LINUX_PASSWORD";

/// Which Chromium browser a Linux profile belongs to. The keyring item is looked
/// up for this browser only, never for the other browsers on the same machine:
/// on a machine with both Brave and Chrome, a Chrome profile must not pick up
/// Brave's password (it would only fail as WrongBrowserPassword, after a
/// wasted lookup, and a wrong-password attempt is never harmless).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxBrowser {
    Brave,
    Chrome,
    Chromium,
}

impl LinuxBrowser {
    /// The `application` attribute this browser stores its Safe Storage item under.
    pub fn keyring_app(self) -> &'static str {
        match self {
            LinuxBrowser::Brave => "brave",
            LinuxBrowser::Chrome => "chrome",
            LinuxBrowser::Chromium => "chromium",
        }
    }

    /// Parse a browser name as the caller spells it.
    pub fn from_name(name: &str) -> Option<LinuxBrowser> {
        match name {
            "brave" => Some(LinuxBrowser::Brave),
            "chrome" => Some(LinuxBrowser::Chrome),
            "chromium" => Some(LinuxBrowser::Chromium),
            _ => None,
        }
    }
}

/// Discover the Linux browser password for one browser: the
/// `MOVEIT_LINUX_PASSWORD` override, then the secret service, then the compiled-in
/// fallback. Returns the password and whether it came from a libsecret v2 item (the
/// provenance only matters when writing into an empty store). Never fails: a machine
/// with no keyring at all still gets the fallback, exactly like Chromium itself.
pub fn linux_browser_password_for(browser: LinuxBrowser) -> (String, bool) {
    linux_browser_password_from(browser, std::env::var(LINUX_PASSWORD_ENV).ok(), &secret_tool_lookup)
}

/// The ordering logic of [`linux_browser_password_for`], with the browser, the
/// environment value and the secret-service lookup injected so it can be tested
/// without a keyring.
fn linux_browser_password_from(
    browser: LinuxBrowser,
    env: Option<String>,
    lookup: &dyn Fn(&[(&str, &str)]) -> Option<String>,
) -> (String, bool) {
    if let Some(pw) = env {
        if !pw.is_empty() {
            return (pw, false);
        }
    }
    let app = browser.keyring_app();
    // The v2-schema item first: it is the one a current browser actually uses, and its
    // provenance decides the write label for an empty store.
    if let Some(pw) = lookup(&[("application", app), ("xdg:schema", LIBSECRET_V2_SCHEMA)]) {
        return (pw, true);
    }
    if let Some(pw) = lookup(&[("application", app)]) {
        return (pw, false);
    }
    (LINUX_FALLBACK_PASSWORD.to_string(), false)
}

/// One `secret-tool lookup` (the libsecret command line), with a timeout so a locked
/// keyring's prompt can never hang a sync. `None` on any failure: tool missing, no
/// match, empty secret, or too slow.
fn secret_tool_lookup(attrs: &[(&str, &str)]) -> Option<String> {
    let mut cmd = std::process::Command::new("secret-tool");
    cmd.arg("lookup");
    for (k, v) in attrs {
        cmd.arg(k).arg(v);
    }
    cmd.stdin(std::process::Stdio::null());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(cmd.output());
    });
    let out = rx.recv_timeout(std::time::Duration::from_secs(5)).ok()?.ok()?;
    if !out.status.success() {
        return None;
    }
    let pw = String::from_utf8(out.stdout).ok()?.trim_end_matches('\n').to_string();
    (!pw.is_empty()).then_some(pw)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Mac,
    Windows,
}

impl Platform {
    pub fn current() -> Platform {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::Mac
        } else {
            Platform::Linux
        }
    }
}

/// Which version label a Linux store uses; bodies are identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxPrefix {
    V10,
    V11,
}

impl LinuxPrefix {
    fn bytes(self) -> &'static [u8; 3] {
        match self {
            LinuxPrefix::V10 => b"v10",
            LinuxPrefix::V11 => b"v11",
        }
    }
}

/// Whether to put SHA256(host) in front of the plaintext when writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostTag {
    With,
    Without,
}

/// The unlocked secret for one browser on one machine.
#[derive(Clone)]
pub enum Lock {
    /// Linux or Mac: the derived 16-byte AES key, and the label to write.
    Cbc { key: [u8; 16], write_prefix: LinuxPrefix },
    /// Windows: the 32-byte master key.
    Gcm { master_key: [u8; 32] },
}

impl Lock {
    pub fn linux(password: &str, write_prefix: LinuxPrefix) -> Lock {
        Lock::Cbc { key: derive(password, 1), write_prefix }
    }

    pub fn mac(keychain_password: &str) -> Lock {
        Lock::Cbc { key: derive(keychain_password, 1003), write_prefix: LinuxPrefix::V10 }
    }

    pub fn windows(master_key: [u8; 32]) -> Lock {
        Lock::Gcm { master_key }
    }

    pub fn encrypt(&self, host: &str, value: &str, tag: HostTag) -> Result<Vec<u8>> {
        let mut plain = Vec::with_capacity(32 + value.len());
        if tag == HostTag::With {
            plain.extend_from_slice(&host_hash(host));
        }
        plain.extend_from_slice(value.as_bytes());
        match self {
            Lock::Cbc { key, write_prefix } => {
                let body = CbcEnc::new(key.into(), &IV.into()).encrypt_padded_vec_mut::<Pkcs7>(&plain);
                Ok([write_prefix.bytes().as_slice(), &body].concat())
            }
            Lock::Gcm { master_key } => {
                let mut nonce = [0u8; 12];
                getrandom::getrandom(&mut nonce).map_err(|e| Error::Io(format!("no randomness: {e}")))?;
                let body = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key))
                    .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
                    .map_err(|_| Error::Io("locking a value failed".into()))?;
                Ok([b"v10".as_slice(), &nonce, &body].concat())
            }
        }
    }

    /// Unlock one value; a matching SHA256(host) tag in front is removed.
    pub fn decrypt(&self, host: &str, data: &[u8]) -> Result<String> {
        let label = data.get(..3).unwrap_or(data);
        let plain = match self {
            Lock::Cbc { key, .. } => {
                if label != b"v10" && label != b"v11" {
                    return Err(Error::Refused(format!("value for {host} has unknown prefix {label:?}")));
                }
                CbcDec::new(key.into(), &IV.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(&data[3..])
                    .map_err(|_| Error::WrongBrowserPassword)?
            }
            Lock::Gcm { master_key } => {
                if label == b"v20" {
                    return Err(Error::AppBound);
                }
                if label != b"v10" || data.len() < 3 + 12 + 16 {
                    return Err(Error::Refused(format!("value for {host} has unknown prefix {label:?}")));
                }
                Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key))
                    .decrypt(Nonce::from_slice(&data[3..15]), &data[15..])
                    .map_err(|_| Error::WrongBrowserPassword)?
            }
        };
        let hh = host_hash(host);
        let body = if plain.len() >= 32 && plain[..32] == hh { &plain[32..] } else { &plain[..] };
        String::from_utf8(body.to_vec()).map_err(|_| Error::Corrupt(format!("value for {host} is not text")))
    }
}

fn derive(password: &str, rounds: u32) -> [u8; 16] {
    let mut k = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), SALT, rounds, &mut k);
    k
}

fn host_hash(host: &str) -> [u8; 32] {
    Sha256::digest(host.as_bytes()).into()
}

/// Pick the label for writing into an existing Linux store: strict majority of
/// recognised v10/v11 values wins; a tie (or none) falls back to the password's source.
pub fn linux_write_prefix<'a>(values: impl IntoIterator<Item = &'a [u8]>, from_libsecret_v2: bool) -> LinuxPrefix {
    let (mut v10, mut v11) = (0usize, 0usize);
    for v in values {
        match v.get(..3) {
            Some(b"v10") => v10 += 1,
            Some(b"v11") => v11 += 1,
            _ => {}
        }
    }
    match v10.cmp(&v11) {
        std::cmp::Ordering::Greater => LinuxPrefix::V10,
        std::cmp::Ordering::Less => LinuxPrefix::V11,
        std::cmp::Ordering::Equal if from_libsecret_v2 => LinuxPrefix::V11,
        std::cmp::Ordering::Equal => LinuxPrefix::V10,
    }
}

/// The string whose SHA256 may prefix a login: the realm's host, else origin's host, else the raw realm.
pub fn login_prefix_host(origin_url: &str, signon_realm: &str) -> String {
    for c in [signon_realm, origin_url] {
        if let Some(h) = url_host(c) {
            return h;
        }
    }
    if !signon_realm.is_empty() { signon_realm.to_string() } else { origin_url.to_string() }
}

/// Lowercased host of a `scheme://[user@]host[:port]/...` URL, like Python's urlparse().hostname.
fn url_host(s: &str) -> Option<String> {
    let rest = s.split_once("://")?.1;
    let auth = rest.split(['/', '?', '#']).next()?;
    let hostport = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        hostport.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Vectors written by the Python prototype.
    #[test]
    fn linux_key_is_chromiums_peanuts_key() {
        assert_eq!(derive("peanuts", 1).to_vec(), hex("fd621fe5a2b402539dfa147ca9272778"));
        assert_eq!(derive("keychainpw", 1003).to_vec(), hex("09f1e9836b8119c9ee8bc5bc00827898"));
    }

    #[test]
    fn linux_matches_reference_both_labels() {
        let v10 = hex("7631301bb654833fa6f8a731528db92d657dc37c87544a81ba7875d0681273543b4e4fdb2564a521be4183708cc9385502c208");
        let lock = Lock::linux("peanuts", LinuxPrefix::V10);
        assert_eq!(lock.decrypt(".example.com", &v10).unwrap(), "sid-value-1");
        // CBC with a fixed IV is deterministic: our bytes must equal the reference's.
        assert_eq!(lock.encrypt(".example.com", "sid-value-1", HostTag::With).unwrap(), v10);
        let v11 = hex("7631310414212dcd3868f07c6e6d34173d414ff984f8078a0728d505e2a221165e521f9111ea6ef913e7e9be2da906e3f588fc");
        let lock11 = Lock::linux("s3cret", LinuxPrefix::V11);
        assert_eq!(lock11.decrypt(".example.com", &v11).unwrap(), "x");
        assert_eq!(lock11.encrypt(".example.com", "x", HostTag::With).unwrap(), v11);
    }

    #[test]
    fn wrong_linux_password_is_an_error_never_a_guess() {
        let v10 = hex("7631301bb654833fa6f8a731528db92d657dc37c87544a81ba7875d0681273543b4e4fdb2564a521be4183708cc9385502c208");
        // Wrong key either fails the padding or yields non-text; both are refusals, neither re-locks.
        assert!(Lock::linux("not-peanuts", LinuxPrefix::V10).decrypt(".example.com", &v10).is_err());
    }

    #[test]
    fn windows_matches_reference_and_refuses_app_bound() {
        let mk: [u8; 32] = core::array::from_fn(|i| i as u8);
        let lock = Lock::windows(mk);
        let v10 = hex("763130ac4ca1ab3ecb63d8a3db01bc5c85eb4a7ef2c32e019b46063467825205fddfe893441c0eb8fc30b39e58afcdf6367a77e29386710607cfdc060c86888b3a369a76535ecd0561");
        assert_eq!(lock.decrypt(".example.com", &v10).unwrap(), "win-cookie");
        let mine = lock.encrypt(".example.com", "win-cookie", HostTag::With).unwrap();
        assert_eq!(lock.decrypt(".example.com", &mine).unwrap(), "win-cookie");
        let mut v20 = v10.clone();
        v20[1..3].copy_from_slice(b"20");
        assert_eq!(lock.decrypt(".example.com", &v20).unwrap_err(), Error::AppBound);
    }

    #[test]
    fn untagged_values_read_whole() {
        let lock = Lock::linux("peanuts", LinuxPrefix::V10);
        let enc = lock.encrypt("example.com", "bare-password", HostTag::Without).unwrap();
        assert_eq!(lock.decrypt("example.com", &enc).unwrap(), "bare-password");
    }

    #[test]
    fn discovery_order_env_then_v2_then_app_then_fallback() {
        let none = |_: &[(&str, &str)]| None;
        // Nothing anywhere: the compiled-in fallback, like Chromium itself.
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, None, &none),
            (LINUX_FALLBACK_PASSWORD.to_string(), false)
        );
        // The environment override wins over the keyring and is not a v2 item.
        let v2 = |_: &[(&str, &str)]| Some("from-keyring".to_string());
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, Some("from-env".to_string()), &v2),
            ("from-env".to_string(), false)
        );
        // An empty override counts as unset ("" means no override).
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, Some(String::new()), &v2),
            ("from-keyring".to_string(), true)
        );
        // A schema-scoped hit is a v2 item; an application-only hit is not.
        let app_only = |attrs: &[(&str, &str)]| {
            (attrs.len() == 1).then(|| "app-pw".to_string())
        };
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, None, &app_only),
            ("app-pw".to_string(), false)
        );
        // A Chrome item is found when Chrome is the browser asked for.
        let chrome_only = |attrs: &[(&str, &str)]| {
            attrs.iter().any(|(k, v)| *k == "application" && *v == "chrome")
                .then(|| "chrome-pw".to_string())
        };
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Chrome, None, &chrome_only),
            ("chrome-pw".to_string(), true)
        );
    }

    #[test]
    fn discovery_is_scoped_to_the_browser_asked_for() {
        // Both browsers have a keyring item; each lookup must return its own.
        let both = |attrs: &[(&str, &str)]| {
            attrs
                .iter()
                .find(|(k, _)| *k == "application")
                .and_then(|(_, v)| match *v {
                    "brave" => Some("brave-pw".to_string()),
                    "chrome" => Some("chrome-pw".to_string()),
                    _ => None,
                })
        };
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, None, &both),
            ("brave-pw".to_string(), true)
        );
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Chrome, None, &both),
            ("chrome-pw".to_string(), true)
        );
        // A Brave-only keyring must not serve a Chrome profile: it falls back
        // rather than returning Brave's password for a Chrome profile.
        let brave_only = |attrs: &[(&str, &str)]| {
            attrs
                .iter()
                .any(|(k, v)| *k == "application" && *v == "brave")
                .then(|| "brave-pw".to_string())
        };
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Chrome, None, &brave_only),
            (LINUX_FALLBACK_PASSWORD.to_string(), false)
        );
    }

    #[test]
    fn write_label_vote() {
        let v: Vec<&[u8]> = vec![b"v11aaa", b"v11bbb", b"v10ccc", b"djunk"];
        assert_eq!(linux_write_prefix(v, false), LinuxPrefix::V11);
        assert_eq!(linux_write_prefix(Vec::<&[u8]>::new(), false), LinuxPrefix::V10);
        assert_eq!(linux_write_prefix(Vec::<&[u8]>::new(), true), LinuxPrefix::V11);
        let tie: Vec<&[u8]> = vec![b"v10", b"v11"];
        assert_eq!(linux_write_prefix(tie, false), LinuxPrefix::V10);
    }

    #[test]
    fn login_host_matches_reference() {
        assert_eq!(login_prefix_host("https://Example.com:8443/login", "https://user@Example.com:8443/"), "example.com");
        assert_eq!(login_prefix_host("", "android://abc@com.app/"), "com.app");
        assert_eq!(login_prefix_host("", ""), "");
        assert_eq!(login_prefix_host("", "not a url"), "not a url");
    }
}
