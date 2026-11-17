//! How Chromium browsers lock cookie and saved-login values at rest, per platform.
//! Ported from the Python prototype; Mac added from Chromium's os_crypt_mac.
//!
//! - Linux: `v10`/`v11` + AES-128-CBC, IV = 16 spaces, key = PBKDF2-HMAC-SHA1(password, "saltysalt", 1 round).
//! - Mac:   `v10`/`v11` + the same CBC, key = PBKDF2-HMAC-SHA1(Keychain password, salt, 1003 rounds);
//!   the salt is "saltysalt" for `v10` and "pepper" for `v11`. Chrome 158 in a temp user
//!   data folder wrote `v11` (probe 2026-11-17: its own rows open under the pepper key,
//!   5/5 cookies and 9/9 `*_encrypted_hash` values); whether a default-directory profile
//!   also writes `v11` was not measured. The folder location therefore proves nothing:
//!   the store's own rows decide first, and for an empty store the folder's own
//!   `*_encrypted_hash` pref values do ([`mac_data_dir_speaks_v11`]): the browser seals those
//!   with the same key. No evidence writes `v10`.
//! - Windows: `v10` + AES-256-GCM with the DPAPI-unwrapped master key from Local State.
//!   `v20` (App-Bound) is refused, never guessed. On Linux, `v10` is Posix, `v11` is
//!   Freedesktop Secret, `v12` is portal-decrypt-only; `v20` is Windows App-Bound
//!   wherever it appears and is refused, never guessed.
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
const PEPPER: &[u8] = b"pepper";
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
    Edge,
    Opera,
}

impl LinuxBrowser {
    /// The `application` attribute this browser stores its Safe Storage item under.
    pub fn keyring_app(self) -> &'static str {
        match self {
            LinuxBrowser::Brave => "brave",
            LinuxBrowser::Chrome => "chrome",
            LinuxBrowser::Chromium => "chromium",
            // Edge brands the libsecret item with the product name, not "edge".
            LinuxBrowser::Edge => "Microsoft Edge",
            LinuxBrowser::Opera => "Opera",
        }
    }

    /// Whether an empty store may seed v11 when the password came from this
    /// browser's own unlocked backend item (libsecret v2 on Linux).
    pub fn empty_store_v11_from_trusted_item(self, from_trusted_item: bool) -> bool {
        matches!(self, LinuxBrowser::Chromium) && from_trusted_item
    }

    /// Parse a browser name as the caller spells it.
    pub fn from_name(name: &str) -> Option<LinuxBrowser> {
        match name {
            "brave" => Some(LinuxBrowser::Brave),
            "chrome" => Some(LinuxBrowser::Chrome),
            "chromium" => Some(LinuxBrowser::Chromium),
            "edge" => Some(LinuxBrowser::Edge),
            "opera" => Some(LinuxBrowser::Opera),
            _ => None,
        }
    }
}

/// Discover the Linux browser password for one browser: the
/// `MOVEIT_LINUX_PASSWORD` override, then the secret service, then the compiled-in
/// fallback. Returns the password and whether it came from a libsecret v2 item (the
/// provenance only matters when writing into an empty store). A confirmed missing
/// item permits the fallback, and so does no secret service at all: a machine with
/// no D-Bus session or no provider is a clean miss, and Chromium itself falls back
/// to its basic store ("peanuts") there, so v10 writes follow it. Locked, timed-out
/// or otherwise unusable keyrings still fail, and a fallback key never seeds v11
/// writes (see `verify_write_key` in cookies.rs and logins.rs).
pub fn linux_browser_password_for(browser: LinuxBrowser) -> Result<(String, bool)> {
    linux_browser_password_for_at(browser, None)
}

/// Like [`linux_browser_password_for`], with optional context from the profile
/// install root (Flatpak under `~/.var/app/<id>/config/...`).
pub fn linux_browser_password_for_at(
    browser: LinuxBrowser,
    install_root: Option<&std::path::Path>,
) -> Result<(String, bool)> {
    let lookup = &|attrs: &[(&str, &str)]| secret_service_lookup(attrs);
    linux_browser_password_from(browser, std::env::var(LINUX_PASSWORD_ENV).ok(), lookup, install_root)
}

/// The ordering logic of [`linux_browser_password_for`], with the browser, the
/// environment value and the secret-service lookup injected so it can be tested
/// without a keyring.
fn linux_browser_password_from(
    browser: LinuxBrowser,
    env: Option<String>,
    lookup: &dyn Fn(&[(&str, &str)]) -> Result<Option<String>>,
    install_root: Option<&std::path::Path>,
) -> Result<(String, bool)> {
    if let Some(pw) = env {
        if !pw.is_empty() {
            return Ok((pw, false));
        }
    }
    if let Some(root) = install_root {
        if let Some(_app_id) = flatpak_app_id_from_install(root) {
            // Flatpak browsers keep a host Secret Service item for the portal; when
            // that is locked away we still notice the sandbox layout below.
            let _flatpak_keyrings = flatpak_keyrings_dir(_app_id);
        }
    }
    let app = browser.keyring_app();
    let label = browser.keyring_label();
    // The v2-schema item first: it is the one a current browser actually uses, and its
    // provenance decides the write label for an empty store.
    if let Some(pw) = lookup(&[("application", app), ("xdg:schema", LIBSECRET_V2_SCHEMA)])? {
        return Ok((pw, true));
    }
    if let Some(pw) = lookup(&[("application", app)])? {
        return Ok((pw, false));
    }
    if let Some(pw) = lookup(&[("label", label)])? {
        return Ok((pw, true));
    }
    Ok((LINUX_FALLBACK_PASSWORD.to_string(), false))
}

/// Flatpak app id when `install_root` lives under `~/.var/app/<id>/config/`.
pub fn flatpak_app_id_from_install(install_root: &std::path::Path) -> Option<&'static str> {
    use std::path::Component;
    let comps: Vec<_> = install_root
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy()),
            _ => None,
        })
        .collect();
    for (i, c) in comps.iter().enumerate() {
        if c.as_ref() == ".var" && comps.get(i + 1).map(|x| x.as_ref()) == Some("app") {
            let id = comps.get(i + 2)?;
            return match id.as_ref() {
                "com.brave.Browser" => Some("com.brave.Browser"),
                "com.google.Chrome" => Some("com.google.Chrome"),
                "org.chromium.Chromium" => Some("org.chromium.Chromium"),
                "io.github.ungoogled_software.ungoogled_chromium" => {
                    Some("io.github.ungoogled_software.ungoogled_chromium")
                }
                "com.microsoft.Edge" => Some("com.microsoft.Edge"),
                "com.opera.Opera" => Some("com.opera.Opera"),
                "com.vivaldi.Vivaldi" => Some("com.vivaldi.Vivaldi"),
                _ => None,
            };
        }
    }
    None
}

fn flatpak_keyrings_dir(app_id: &str) -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from)?;
    let dir = home.join(".var/app").join(app_id).join("data/keyrings");
    dir.is_dir().then_some(dir)
}

impl LinuxBrowser {
    /// The Secret Service label Chromium stamps on its item (`secret-tool search label …`).
    pub fn keyring_label(self) -> &'static str {
        match self {
            LinuxBrowser::Brave => "Brave Safe Storage",
            LinuxBrowser::Chrome => "Chrome Safe Storage",
            LinuxBrowser::Chromium => "Chromium Safe Storage",
            LinuxBrowser::Edge => "Microsoft Edge Safe Storage",
            LinuxBrowser::Opera => "Opera Safe Storage",
        }
    }
}

/// App-Bound Encryption (`v20`): Windows-only writer, but the tag means App-Bound on every OS.
pub fn encryption_is_app_bound(prefix: &[u8]) -> bool {
    prefix.starts_with(b"v20")
}

/// Windows Chrome/Edge App-Bound (`v20`); elsewhere the same prefix is not that contract.
pub fn encryption_is_windows_app_bound(prefix: &[u8]) -> bool {
    Platform::current() == Platform::Windows && encryption_is_app_bound(prefix)
}

/// One secret-service lookup over D-Bus, with a timeout so a locked
/// keyring or a hung bus can never hang a sync. Only a clean miss is `None`;
/// locked items, unavailable buses and timeouts are errors.
/// Locked items are never unlocked here: unlocking would prompt the
/// user, which a background sync must not do. The lookup runs on a
/// thread so the timeout also bounds a hung D-Bus call; unlike the old
/// secret-tool child, there is no child process left running on timeout.
#[cfg(target_os = "linux")]
fn secret_service_lookup(attrs: &[(&str, &str)]) -> Result<Option<String>> {
    let owned: Vec<(String, String)> = attrs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(secret_service_lookup_inner(&owned));
    });
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| Error::KeychainUnavailable("browser keyring lookup timed out".into()))?
}

#[cfg(target_os = "linux")]
fn secret_service_lookup_inner(attrs: &[(String, String)]) -> Result<Option<String>> {
    use secret_service::{blocking::SecretService, EncryptionType};
    use std::collections::HashMap;
    let unavailable = |e| Error::KeychainUnavailable(format!("browser keyring: {e}"));
    let ss = match SecretService::connect(EncryptionType::Dh) {
        Ok(ss) => ss,
        // No bus to connect to, or a bus with no secret-service provider: there
        // is no keyring to read, so this is a clean miss, not an error.
        Err(e) if is_no_secret_service(&e) => return Ok(None),
        Err(e) => return Err(unavailable(e)),
    };
    let map: HashMap<&str, &str> = attrs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let found = ss.search_items(map).map_err(unavailable)?;
    if !found.locked.is_empty() {
        return Err(Error::KeychainUnavailable("browser keyring item is locked".into()));
    }
    let Some(item) = found.unlocked.first() else { return Ok(None) };
    let secret = item.get_secret().map_err(unavailable)?;
    let pw = String::from_utf8(secret)
        .map_err(|_| Error::KeychainUnavailable("browser keyring item is not text".into()))?
        .trim_end_matches(char::from(10)).to_string();
    if pw.is_empty() {
        return Err(Error::KeychainUnavailable("browser keyring item is empty".into()));
    }
    Ok(Some(pw))
}

/// True when a Secret Service failure means "there is no secret service here at
/// all": no D-Bus session to connect to (`Unavailable`), or a bus that knows no
/// provider for org.freedesktop.secrets. A locked item, a timeout, or a provider
/// that answered with an error is not this: those stay errors.
#[cfg(target_os = "linux")]
fn is_no_secret_service(e: &secret_service::Error) -> bool {
    match e {
        secret_service::Error::Unavailable => true,
        // OpenSession uses a zbus::Result, so missing-provider replies can
        // arrive as raw method errors rather than the typed FDO variant.
        secret_service::Error::Zbus(zbus::Error::MethodError(name, _, _)) => matches!(
            name.as_str(),
            "org.freedesktop.DBus.Error.ServiceUnknown" | "org.freedesktop.DBus.Error.NameHasNoOwner"
        ),
        secret_service::Error::ZbusFdo(zbus::fdo::Error::ServiceUnknown(_))
        | secret_service::Error::ZbusFdo(zbus::fdo::Error::NameHasNoOwner(_)) => true,
        _ => false,
    }
}

/// No Secret Service off Linux: discovery falls through to the fallback.
#[cfg(not(target_os = "linux"))]
fn secret_service_lookup(_attrs: &[(&str, &str)]) -> Result<Option<String>> {
    Ok(None)
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
    /// `v11_key` names the keyring key on Linux and the pepper-derived key on Mac.
    /// Linux's main key is always the compiled-in peanuts key.
    Cbc { key: [u8; 16], v11_key: Option<[u8; 16]>, write_prefix: LinuxPrefix },
    /// Windows: the 32-byte master key.
    Gcm { master_key: [u8; 32] },
}

impl Lock {
    pub fn linux(password: &str, write_prefix: LinuxPrefix) -> Lock {
        Lock::Cbc { key: derive(LINUX_FALLBACK_PASSWORD, 1), v11_key: Some(derive(password, 1)), write_prefix }
    }

    /// Whether this lock's v11 key is the compiled-in fallback key. That key
    /// comes from no keyring item, so it proves nothing about a store's real
    /// key; a keyring-derived key that matches no live row instead means the
    /// store's rows were written under a rotated-away password. Mac and
    /// Windows locks are never the fallback.
    pub fn v11_key_is_fallback(&self) -> bool {
        match self {
            Lock::Cbc { v11_key: Some(k), .. } => *k == derive(LINUX_FALLBACK_PASSWORD, 1),
            _ => false,
        }
    }

    pub fn mac(keychain_password: &str) -> Lock {
        Lock::Cbc {
            key: derive(keychain_password, 1003),
            v11_key: Some(derive_salted(keychain_password, PEPPER, 1003)),
            write_prefix: LinuxPrefix::V10,
        }
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
            Lock::Cbc { key, v11_key, write_prefix } => {
                let k = key_for(*write_prefix, key, v11_key);
                let body = CbcEnc::new((&k).into(), &IV.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(&plain);
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

    /// Encrypt for a label the caller picks (the store being written sets it), so the
    /// key and the label always agree. A Windows lock takes no label choice.
    pub fn encrypt_labelled(&self, host: &str, value: &str, tag: HostTag, prefix: LinuxPrefix) -> Result<Vec<u8>> {
        match self {
            Lock::Cbc { .. } => {
                let mut l = self.clone();
                if let Lock::Cbc { write_prefix, .. } = &mut l {
                    *write_prefix = prefix;
                }
                l.encrypt(host, value, tag)
            }
            Lock::Gcm { .. } => self.encrypt(host, value, tag),
        }
    }

    /// Unlock one value; a matching SHA256(host) tag in front is removed.
    pub fn decrypt(&self, host: &str, data: &[u8]) -> Result<String> {
        let label = data.get(..3).unwrap_or(data);
        let plain = match self {
            Lock::Cbc { key, v11_key, .. } => {
                if encryption_is_app_bound(label) {
                    return Err(Error::AppBound);
                }
                if label != b"v10" && label != b"v11" {
                    return Err(Error::Refused(format!("value for {host} has unknown prefix {label:?}")));
                }
                let k = if label == b"v11" { v11_key.as_ref().unwrap_or(key) } else { key };
                CbcDec::new(k.into(), &IV.into())
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
    derive_salted(password, SALT, rounds)
}

fn derive_salted(password: &str, salt: &[u8], rounds: u32) -> [u8; 16] {
    let mut k = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), salt, rounds, &mut k);
    k
}

/// The key a label names: `v11` takes the lock's second key when it carries one
/// and falls back to the main key for older caller-constructed locks.
fn key_for(label: LinuxPrefix, key: &[u8; 16], v11_key: &Option<[u8; 16]>) -> [u8; 16] {
    match (label, v11_key) {
        (LinuxPrefix::V11, Some(k)) => *k,
        _ => *key,
    }
}

fn host_hash(host: &str) -> [u8; 32] {
    Sha256::digest(host.as_bytes()).into()
}

/// Pick the label for writing into a store: strict majority of recognised
/// v10/v11 values wins; a tie (or no values at all) falls back to the
/// password's source when the caller sets `from_libsecret_v2` from
/// [`LinuxBrowser::empty_store_v11_from_trusted_item`] or
/// [`MacBrowser::empty_store_v11_from_trusted_item`] (Chromium with its own
/// unlocked item only; Chrome and Brave keep v10). The folder location never
/// decides: live proof showed Chrome 156 and Brave 1.98 writing v10 in
/// non-default dirs, and no Local State field records the scheme, so the store's
/// own rows are the evidence for v11, plus on macOS the folder's pref hashes
/// (see [`mac_data_dir_speaks_v11`]), which the caller folds into
/// `from_libsecret_v2`.
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


// ---------------- macOS: the Safe Storage password from the login Keychain ----------------

/// Which Chromium browser a macOS profile belongs to. The Keychain item is looked
/// up for this browser only, never for the other browsers on the same machine:
/// the same scoping rule as [`LinuxBrowser`], for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacBrowser {
    Brave,
    Chrome,
    Chromium,
    Edge,
    Opera,
}

impl MacBrowser {
    /// The `service` of this browser's Safe Storage item in the login Keychain.
    pub fn keychain_service(self) -> &'static str {
        match self {
            MacBrowser::Brave => "Brave Safe Storage",
            MacBrowser::Chrome => "Chrome Safe Storage",
            MacBrowser::Chromium => "Chromium Safe Storage",
            MacBrowser::Edge => "Microsoft Edge Safe Storage",
            MacBrowser::Opera => "Opera Safe Storage",
        }
    }

    /// The `account` of this browser's Safe Storage item.
    pub fn keychain_account(self) -> &'static str {
        match self {
            MacBrowser::Brave => "Brave",
            MacBrowser::Chrome => "Chrome",
            MacBrowser::Chromium => "Chromium",
            MacBrowser::Edge => "Microsoft Edge",
            MacBrowser::Opera => "Opera",
        }
    }

    /// Whether an empty store may seed v11 when the password came from this
    /// browser's own unlocked Keychain item.
    pub fn empty_store_v11_from_trusted_item(self, from_keychain: bool) -> bool {
        matches!(self, MacBrowser::Chromium) && from_keychain
    }

    /// Parse a browser name as the caller spells it.
    pub fn from_name(name: &str) -> Option<MacBrowser> {
        match name {
            "brave" => Some(MacBrowser::Brave),
            "chrome" => Some(MacBrowser::Chrome),
            "chromium" => Some(MacBrowser::Chromium),
            "edge" => Some(MacBrowser::Edge),
            "opera" => Some(MacBrowser::Opera),
            _ => None,
        }
    }
}

/// What one Keychain lookup came back with, before it becomes an engine error.
#[derive(Debug, PartialEq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // its variants are built by the macOS lookup
enum KeychainOutcome {
    /// The Safe Storage password itself.
    Found(String),
    /// No such item (or an empty one): the browser never stored a password here.
    Missing,
    /// The keychain refused: locked, or the read needs the person at the keyboard.
    Refused,
    /// The `security` tool is missing or failed in some other way.
    Unavailable,
}

/// Read one macOS browser's Safe Storage password from the login Keychain.
/// Unlike Linux there is no fallback password: a missing or refused read is a
/// clean error, because guessing would silently re-lock values wrong.
pub fn mac_browser_password(browser: MacBrowser) -> Result<String> {
    Ok(mac_browser_password_for(browser)?.0)
}

/// Like [`mac_browser_password`], plus whether the password came from the
/// Keychain (provenance only matters when writing into an empty store).
pub fn mac_browser_password_for(browser: MacBrowser) -> Result<(String, bool)> {
    mac_password_from(browser, &security_cli_lookup)
}

/// The error mapping of [`mac_browser_password_for`], with the lookup injected so it
/// can be tested without a keychain.
fn mac_password_from(
    browser: MacBrowser,
    lookup: &dyn Fn(MacBrowser) -> KeychainOutcome,
) -> Result<(String, bool)> {
    match lookup(browser) {
        KeychainOutcome::Found(pw) if !pw.is_empty() => Ok((pw, true)),
        KeychainOutcome::Found(_) | KeychainOutcome::Missing => Err(Error::Refused(format!(
            "no Safe Storage password for {} was found in the Keychain",
            browser.keychain_service()
        ))),
        KeychainOutcome::Refused => Err(Error::KeychainLocked),
        KeychainOutcome::Unavailable => Err(Error::Io(
            "the macOS security tool did not answer".into(),
        )),
    }
}

/// Whether the browser that owns this macOS user data folder seals with the
/// `v11` (pepper) key. The scheme is chosen per user data folder, so every
/// profile folder inside it is a witness. Evidence is the label on the
/// `*_encrypted_hash` values the browser itself wrote into `Preferences` and
/// `Secure Preferences` (tracked-pref hashes sealed with the same OSCrypt key
/// as cookies). A strict majority of `v11` labels says yes; no evidence, a tie
/// or a `v10` majority says no. Folders beside this one are not witnesses:
/// only this folder and the profile folders inside it. Reads only; never
/// touches the Keychain.
///
/// The argument is the user data folder (the harness `open`/`seal` root),
/// not one profile inside it: that is what the only caller passes.
pub fn mac_data_dir_speaks_v11(data_dir: &std::path::Path) -> bool {
    let mut dirs = vec![data_dir.to_path_buf()];
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            }
        }
    }
    let mut labels: Vec<Vec<u8>> = Vec::new();
    for d in &dirs {
        for name in ["Preferences", "Secure Preferences"] {
            let Ok(bytes) = std::fs::read(d.join(name)) else { continue };
            let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else { continue };
            collect_encrypted_hash_labels(&json, &mut labels);
        }
    }
    !labels.is_empty()
        && linux_write_prefix(labels.iter().map(|l| l.as_slice()), false) == LinuxPrefix::V11
}

/// Gather the 3-byte scheme label of every `*_encrypted_hash` string in a prefs tree.
/// An object-valued `*_encrypted_hash` (Chrome's per-extension
/// `protection.macs.extensions.settings_encrypted_hash`, extension id to sealed
/// hash) contributes one label per string value inside it.
fn collect_encrypted_hash_labels(v: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
    fn push_label(s: &str, out: &mut Vec<Vec<u8>>) {
        use base64::Engine;
        if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(s) {
            if let Some(label) = raw.get(..3) {
                out.push(label.to_vec());
            }
        }
    }
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                match val {
                    serde_json::Value::String(s) if k.ends_with("_encrypted_hash") => {
                        push_label(s, out);
                    }
                    serde_json::Value::Object(inner) if k.ends_with("_encrypted_hash") => {
                        for s in inner.values() {
                            if let serde_json::Value::String(s) = s {
                                push_label(s, out);
                            }
                        }
                    }
                    other => collect_encrypted_hash_labels(other, out),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_encrypted_hash_labels(item, out);
            }
        }
        _ => {}
    }
}

/// The lock for one macOS browser, built from its Keychain password.
pub fn mac_lock(browser: MacBrowser) -> Result<Lock> {
    Ok(Lock::mac(&mac_browser_password(browser)?))
}

/// Sort one `security find-generic-password` result into a [`KeychainOutcome`].
/// Pure, so the wording macOS answers with is pinned down by tests.
#[cfg(any(target_os = "macos", test))]
fn classify_security_output(success: bool, stdout: &[u8], stderr: &[u8]) -> KeychainOutcome {
    let err = String::from_utf8_lossy(stderr);
    // A locked keychain, or a session that may not prompt (SSH lands here):
    // macOS says the interaction is not allowed instead of asking.
    if err.contains("User interaction is not allowed") {
        return KeychainOutcome::Refused;
    }
    if success {
        let pw = String::from_utf8_lossy(stdout)
            .trim_end_matches(['\n', '\r'])
            .to_string();
        return if pw.is_empty() {
            KeychainOutcome::Missing
        } else {
            KeychainOutcome::Found(pw)
        };
    }
    if err.contains("could not be found") || err.contains("item was not found") {
        return KeychainOutcome::Missing;
    }
    KeychainOutcome::Unavailable
}

/// One Keychain lookup through the `security` tool that ships with macOS: the
/// same shell-out philosophy as the old Linux secret-tool path, and it keeps a
/// locked keychain a normal error instead of a hang or a prompt.
/// What one attribute-only `security` query came back with. An item's
/// attributes are readable without its secret, so this separates "there is
/// no item" from "the item is there but the secret read was refused", which
/// the secret read alone cannot always do: a read that may not prompt can
/// be refused at once with no wording at all to classify.
#[derive(Debug, PartialEq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // its variants are built by the macOS lookup
enum AttrOutcome {
    /// The item is in the Keychain.
    Exists,
    /// No such item.
    Missing,
    /// The `security` tool is missing or failed in some other way.
    Unavailable,
}

/// Sort one attribute-only `security find-generic-password` result into an
/// [`AttrOutcome`]. Pure, like [`classify_security_output`].
#[cfg(any(target_os = "macos", test))]
fn classify_attr_output(success: bool, stderr: &[u8]) -> AttrOutcome {
    if success {
        return AttrOutcome::Exists;
    }
    let err = String::from_utf8_lossy(stderr);
    if err.contains("could not be found") || err.contains("item was not found") {
        return AttrOutcome::Missing;
    }
    AttrOutcome::Unavailable
}

/// Combine the attribute answer with the secret-read answer. A read that
/// failed without a classifiable reason is a refusal when the item is
/// known to exist: the secret is there, this reader may not have it yet
/// (a locked Keychain, or the person's one-time OK still outstanding).
/// When the attribute query found nothing, the item is simply missing,
/// and answers that already know what happened pass through untouched.
#[cfg(any(target_os = "macos", test))]
fn resolve_keychain_outcome(attr: AttrOutcome, value: KeychainOutcome) -> KeychainOutcome {
    if matches!(value, KeychainOutcome::Found(_) | KeychainOutcome::Refused) {
        return value;
    }
    match attr {
        AttrOutcome::Exists => KeychainOutcome::Refused,
        AttrOutcome::Missing => KeychainOutcome::Missing,
        AttrOutcome::Unavailable => value,
    }
}

/// One `security` run under a hard time budget: the tool can stall on a
/// locked keychain or a prompt nobody will ever see (an SSH session), and
/// a stall must read as Unavailable, never as a hang. The worker thread is
/// left to finish on its own when the budget runs out.
#[cfg(target_os = "macos")]
fn security_output(args: &[&str]) -> Option<std::process::Output> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(std::process::Command::new("security").args(&args).output());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Ok(o)) => Some(o),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn security_cli_lookup(browser: MacBrowser) -> KeychainOutcome {
    // Attributes first: they answer even when the secret read below is
    // refused in silence, which is exactly the first-run case (the item is
    // there and the read waits on the person's OK).
    let attr = match security_output(&[
        "find-generic-password",
        "-s",
        browser.keychain_service(),
        "-a",
        browser.keychain_account(),
    ]) {
        Some(o) => classify_attr_output(o.status.success(), &o.stderr),
        None => AttrOutcome::Unavailable,
    };
    let value = match security_output(&[
        "find-generic-password",
        "-w",
        "-s",
        browser.keychain_service(),
        "-a",
        browser.keychain_account(),
    ]) {
        Some(o) => classify_security_output(o.status.success(), &o.stdout, &o.stderr),
        None => KeychainOutcome::Unavailable,
    };
    resolve_keychain_outcome(attr, value)
}

/// No Keychain off macOS: the lookup simply never finds anything.
#[cfg(not(target_os = "macos"))]
fn security_cli_lookup(_browser: MacBrowser) -> KeychainOutcome {
    KeychainOutcome::Unavailable
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
        let value = Lock::linux("secret", LinuxPrefix::V11)
            .encrypt(".example.com", "password", HostTag::With).unwrap();
        assert!(Lock::linux("wrong", LinuxPrefix::V11).decrypt(".example.com", &value).is_err());
    }

    #[test]
    fn linux_mixed_labels_use_independent_keys() {
        let lock = Lock::linux("keyring-secret", LinuxPrefix::V11);
        let v10 = lock.encrypt_labelled("host", "legacy", HostTag::With, LinuxPrefix::V10).unwrap();
        let v11 = lock.encrypt_labelled("host", "modern", HostTag::With, LinuxPrefix::V11).unwrap();
        assert_eq!(lock.decrypt("host", &v10).unwrap(), "legacy");
        assert_eq!(lock.decrypt("host", &v11).unwrap(), "modern");
        assert_eq!(v10, Lock::linux("peanuts", LinuxPrefix::V10).encrypt("host", "legacy", HostTag::With).unwrap());
        assert!(Lock::linux("peanuts", LinuxPrefix::V11).decrypt("host", &v11).is_err());
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
    #[ignore = "reads the host keyring; run on a live Linux machine"]
    fn live_linux_brave_password_is_not_the_fallback() {
        let (pw, from_v2) =
            linux_browser_password_for(LinuxBrowser::Brave).expect("brave keyring lookup");
        assert_ne!(pw, LINUX_FALLBACK_PASSWORD, "fell back to peanuts");
        assert!(from_v2, "expected a chrome_libsecret_os_crypt_password_v2 item");
    }

    #[test]
    fn discovery_order_env_then_v2_then_app_then_fallback() {
        let none = |_: &[(&str, &str)]| Ok(None);
        // Nothing anywhere: the compiled-in fallback, like Chromium itself.
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, None, &none, None).unwrap(),
            (LINUX_FALLBACK_PASSWORD.to_string(), false)
        );
        // The environment override wins over the keyring and is not a v2 item.
        let v2 = |_: &[(&str, &str)]| Ok(Some("from-keyring".to_string()));
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, Some("from-env".to_string()), &v2, None).unwrap(),
            ("from-env".to_string(), false)
        );
        // An empty override counts as unset ("" means no override).
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, Some(String::new()), &v2, None).unwrap(),
            ("from-keyring".to_string(), true)
        );
        // A schema-scoped hit is a v2 item; an application-only hit is not.
        let app_only = |attrs: &[(&str, &str)]| {
            Ok((attrs.len() == 1).then(|| "app-pw".to_string()))
        };
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, None, &app_only, None).unwrap(),
            ("app-pw".to_string(), false)
        );
        // A Chrome item is found when Chrome is the browser asked for.
        let chrome_only = |attrs: &[(&str, &str)]| {
            Ok(attrs.iter().any(|(k, v)| *k == "application" && *v == "chrome")
                .then(|| "chrome-pw".to_string()))
        };
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Chrome, None, &chrome_only, None).unwrap(),
            ("chrome-pw".to_string(), true)
        );
    }

    #[test]
    fn opera_is_a_linux_browser_with_its_own_keyring_app() {
        assert_eq!(
            LinuxBrowser::from_name("opera"),
            Some(LinuxBrowser::Opera)
        );
        assert_eq!(LinuxBrowser::Opera.keyring_app(), "Opera");
    }

    #[test]
    fn flatpak_install_root_is_recognized() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
        let root = std::path::PathBuf::from(home)
            .join(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser");
        assert_eq!(
            flatpak_app_id_from_install(&root),
            Some("com.brave.Browser")
        );
    }

    #[test]
    fn v20_is_app_bound_on_every_platform() {
        assert!(encryption_is_app_bound(b"v20"));
        assert!(!encryption_is_app_bound(b"v11"));
        // The windows classification is platform-designed: v20 is Windows
        // App-Bound, so it classifies that way only when running on Windows.
        assert_eq!(encryption_is_windows_app_bound(b"v20"), cfg!(windows));
    }

    #[test]
    fn edge_is_a_linux_browser_with_its_own_keyring_app() {
        assert_eq!(LinuxBrowser::from_name("edge"), Some(LinuxBrowser::Edge));
        assert_eq!(LinuxBrowser::Edge.keyring_app(), "Microsoft Edge");
    }

    #[test]
    fn discovery_is_scoped_to_the_browser_asked_for() {
        // Both browsers have a keyring item; each lookup must return its own.
        let both = |attrs: &[(&str, &str)]| {
            Ok(attrs
                .iter()
                .find(|(k, _)| *k == "application")
                .and_then(|(_, v)| match *v {
                    "brave" => Some("brave-pw".to_string()),
                    "chrome" => Some("chrome-pw".to_string()),
                    _ => None,
                }))
        };
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Brave, None, &both, None).unwrap(),
            ("brave-pw".to_string(), true)
        );
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Chrome, None, &both, None).unwrap(),
            ("chrome-pw".to_string(), true)
        );
        // A Brave-only keyring must not serve a Chrome profile: it falls back
        // rather than returning Brave's password for a Chrome profile.
        let brave_only = |attrs: &[(&str, &str)]| {
            Ok(attrs
                .iter()
                .any(|(k, v)| *k == "application" && *v == "brave")
                .then(|| "brave-pw".to_string()))
        };
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Chrome, None, &brave_only, None).unwrap(),
            (LINUX_FALLBACK_PASSWORD.to_string(), false)
        );
    }

    #[test]
    fn discovery_refuses_locked_or_timed_out_keyrings() {
        // "No bus" is not in this list: the real lookup turns a missing bus or
        // provider into a clean miss (see secret_service_lookup_inner), so the
        // password layer falls back to peanuts instead of erroring.
        for reason in ["locked", "timeout"] {
            let lookup = |_: &[(&str, &str)]| Err(Error::KeychainUnavailable(reason.into()));
            assert_eq!(linux_browser_password_from(LinuxBrowser::Chrome, None, &lookup, None).unwrap_err(),
                Error::KeychainUnavailable(reason.into()));
        }
    }

    #[test]
    fn no_secret_service_is_a_clean_miss_and_peanuts_for_v10() {
        // What the real lookup reports when there is no bus or no provider:
        // no item, so the compiled-in password is used, with no v2 provenance.
        // An empty store then writes v10; a v11 write still needs a verified key.
        let none = |_: &[(&str, &str)]| Ok(None);
        assert_eq!(
            linux_browser_password_from(LinuxBrowser::Chrome, None, &none, None).unwrap(),
            (LINUX_FALLBACK_PASSWORD.to_string(), false)
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn missing_provider_method_errors_are_clean_misses() {
        for (name, missing) in [
            ("org.freedesktop.DBus.Error.ServiceUnknown", true),
            ("org.freedesktop.DBus.Error.NameHasNoOwner", true),
            ("org.freedesktop.DBus.Error.AccessDenied", false),
            ("org.freedesktop.DBus.Error.NoReply", false),
            ("org.freedesktop.Secret.Error.IsLocked", false),
        ] {
            let message = zbus::Message::method("/org/freedesktop/secrets", "OpenSession")
                .unwrap().build(&()).unwrap();
            let error = secret_service::Error::Zbus(zbus::Error::MethodError(
                name.try_into().unwrap(), None, message,
            ));
            assert_eq!(is_no_secret_service(&error), missing, "{name}");
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn dead_bus_address_is_a_clean_miss() {
        // Point zbus at a socket that does not exist: connecting fails with
        // Unavailable, and the lookup reports a clean miss instead of an error.
        // The env var is process-global, so this test holds a lock while it
        // swaps it; no other test in this binary touches the bus.
        static BUS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = BUS_LOCK.lock().unwrap();
        let prev = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        std::env::set_var(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/tmp/moveit-no-such-bus/socket",
        );
        let found =
            secret_service_lookup_inner(&[("application".to_string(), "chrome".to_string())]);
        match prev {
            Some(v) => std::env::set_var("DBUS_SESSION_BUS_ADDRESS", v),
            None => std::env::remove_var("DBUS_SESSION_BUS_ADDRESS"),
        }
        assert_eq!(found.unwrap(), None);
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

    // Vectors written independently of this code (same inputs through the
    // reference stack): password "mac-test-safe-storage-pw", 1003 rounds.
    #[test]
    fn mac_key_matches_reference() {
        assert_eq!(
            derive("mac-test-safe-storage-pw", 1003).to_vec(),
            hex("898c526c68b52821575ea43265c8a36e")
        );
    }

    #[test]
    fn mac_decrypts_reference_vectors() {
        let lock = Lock::mac("mac-test-safe-storage-pw");
        // A cookie value: SHA256(host) in front of the plaintext.
        let tagged = hex("763130e209658513c1140173e31503b553c4769f91958473379ef733755af0f16ef1ef292b975402562acbe91e09ccbff4ddd1");
        assert_eq!(lock.decrypt(".example.com", &tagged).unwrap(), "mac-cookie-1");
        // CBC with a fixed IV is deterministic: our bytes must equal the reference's.
        assert_eq!(
            lock.encrypt(".example.com", "mac-cookie-1", HostTag::With).unwrap(),
            tagged
        );
        // A login value: no host tag.
        let untagged = hex("7631301b7193150c6caff72289b6d438daaafd");
        assert_eq!(lock.decrypt("example.com", &untagged).unwrap(), "mac-login-pw-9");
        assert_eq!(
            lock.encrypt("example.com", "mac-login-pw-9", HostTag::Without).unwrap(),
            untagged
        );
    }

    #[test]
    fn mac_round_trip_and_wrong_password() {
        let lock = Lock::mac("some safe storage password");
        let enc = lock
            .encrypt(".example.com", "round-trip-me", HostTag::With)
            .unwrap();
        assert_eq!(&enc[..3], b"v10", "a Mac lock's own label is v10; stores override it per target");
        assert_eq!(lock.decrypt(".example.com", &enc).unwrap(), "round-trip-me");
        assert!(
            Lock::mac("not the password")
                .decrypt(".example.com", &enc)
                .is_err()
        );
    }

    #[test]
    fn mac_pepper_key_matches_reference() {
        assert_eq!(
            derive_salted("mac-test-safe-storage-pw", PEPPER, 1003).to_vec(),
            hex("35584f68e84c13ed510c9cc713c644f6")
        );
    }

    #[test]
    fn mac_decrypts_v11_reference_vectors() {
        let lock = Lock::mac("mac-test-safe-storage-pw");
        // A cookie from a non-default user data dir: v11 label, pepper-derived key.
        let tagged = hex("76313155dce3512dff6139a14eff5e3894c0e08bd12491923810b0801bcb99d2fa7db2e4d55f2d60caacf284a64e2954866e6b");
        assert_eq!(lock.decrypt(".example.com", &tagged).unwrap(), "mac-cookie-1");
        // Writing for a v11 store must reproduce those bytes exactly, key included.
        assert_eq!(
            lock.encrypt_labelled(".example.com", "mac-cookie-1", HostTag::With, LinuxPrefix::V11).unwrap(),
            tagged
        );
        // A login value under the same scheme: no host tag.
        let untagged = hex("76313140bb3ccbf51abdc8845123f745e0c0b0");
        assert_eq!(lock.decrypt("example.com", &untagged).unwrap(), "mac-login-pw-9");
        assert_eq!(
            lock.encrypt_labelled("example.com", "mac-login-pw-9", HostTag::Without, LinuxPrefix::V11).unwrap(),
            untagged
        );
    }

    #[test]
    fn mac_dispatch_is_by_label_not_by_trying_keys() {
        let lock = Lock::mac("mac-test-safe-storage-pw");
        // The v11 body under a v10 label must fail: the label picks the key.
        let mut swapped = hex("76313155dce3512dff6139a14eff5e3894c0e08bd12491923810b0801bcb99d2fa7db2e4d55f2d60caacf284a64e2954866e6b");
        swapped[..3].copy_from_slice(b"v10");
        assert!(lock.decrypt(".example.com", &swapped).is_err());
    }

    #[test]
    fn mac_mislabeled_v11_from_before_the_fix_is_a_clean_error() {
        // Writes made before the pepper fix carried a v11 label over a salt-keyed
        // body; no browser ever accepted those, and the reader now refuses them
        // cleanly instead of handing back garbage.
        let lock = Lock::mac("mac-test-safe-storage-pw");
        let mut enc = lock.encrypt(".example.com", "secret", HostTag::With).unwrap();
        enc[..3].copy_from_slice(b"v11");
        assert!(matches!(lock.decrypt(".example.com", &enc), Err(Error::WrongBrowserPassword)));
    }

    #[test]
    fn write_label_vote_counts_labels_only() {
        // The vote reads the 3-byte label alone; even stub rows with no body count.
        let v: Vec<&[u8]> = vec![b"v10", b"v10", b"v11realbody"];
        assert_eq!(linux_write_prefix(v, false), LinuxPrefix::V10);
    }

    #[test]
    fn mac_keychain_names() {
        assert_eq!(MacBrowser::Brave.keychain_service(), "Brave Safe Storage");
        assert_eq!(MacBrowser::Brave.keychain_account(), "Brave");
        assert_eq!(MacBrowser::Chrome.keychain_service(), "Chrome Safe Storage");
        assert_eq!(MacBrowser::Chrome.keychain_account(), "Chrome");
        assert_eq!(
            MacBrowser::Chromium.keychain_service(),
            "Chromium Safe Storage"
        );
        assert_eq!(MacBrowser::Chromium.keychain_account(), "Chromium");
        assert_eq!(
            MacBrowser::Edge.keychain_service(),
            "Microsoft Edge Safe Storage"
        );
        assert_eq!(MacBrowser::Edge.keychain_account(), "Microsoft Edge");
        assert_eq!(MacBrowser::from_name("brave"), Some(MacBrowser::Brave));
        assert_eq!(MacBrowser::from_name("chrome"), Some(MacBrowser::Chrome));
        assert_eq!(MacBrowser::from_name("chromium"), Some(MacBrowser::Chromium));
        assert_eq!(MacBrowser::from_name("edge"), Some(MacBrowser::Edge));
        assert_eq!(MacBrowser::from_name("firefox"), None);
    }

    #[test]
    fn empty_store_v11_trust_is_chromium_only() {
        use LinuxBrowser::{Brave, Chrome, Chromium};
        use MacBrowser;
        assert!(!Brave.empty_store_v11_from_trusted_item(true));
        assert!(!Chrome.empty_store_v11_from_trusted_item(true));
        assert!(Chromium.empty_store_v11_from_trusted_item(true));
        assert!(!Chromium.empty_store_v11_from_trusted_item(false));
        assert!(!MacBrowser::Chrome.empty_store_v11_from_trusted_item(true));
        assert!(MacBrowser::Chromium.empty_store_v11_from_trusted_item(true));
    }

    #[test]
    fn mac_keychain_outcomes_map_to_engine_errors() {
        let found = |_: MacBrowser| KeychainOutcome::Found("pw-123".to_string());
        assert_eq!(
            mac_password_from(MacBrowser::Brave, &found).unwrap(),
            ("pw-123".to_string(), true)
        );
        // An empty secret counts as missing: no silent empty password.
        let empty = |_: MacBrowser| KeychainOutcome::Found(String::new());
        assert!(matches!(
            mac_password_from(MacBrowser::Brave, &empty),
            Err(Error::Refused(_))
        ));
        let missing = |_: MacBrowser| KeychainOutcome::Missing;
        assert!(matches!(
            mac_password_from(MacBrowser::Chrome, &missing),
            Err(Error::Refused(_))
        ));
        // The locked or non-interactive keychain gets its own friendly error.
        let refused = |_: MacBrowser| KeychainOutcome::Refused;
        assert_eq!(
            mac_password_from(MacBrowser::Brave, &refused).unwrap_err(),
            Error::KeychainLocked
        );
        let unavailable = |_: MacBrowser| KeychainOutcome::Unavailable;
        assert!(matches!(
            mac_password_from(MacBrowser::Brave, &unavailable),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn security_output_classification() {
        // Success prints the password, newline and all.
        assert_eq!(
            classify_security_output(true, b"hunter2\n", b""),
            KeychainOutcome::Found("hunter2".to_string())
        );
        // Success with nothing is a missing item, not an empty password.
        assert_eq!(
            classify_security_output(true, b"\n", b""),
            KeychainOutcome::Missing
        );
        // The SSH / locked case: macOS refuses instead of prompting.
        assert_eq!(
            classify_security_output(
                false,
                b"",
                b"security: SecKeychainSearchCopyNext: User interaction is not allowed."
            ),
            KeychainOutcome::Refused
        );
        assert_eq!(
            classify_security_output(
                false,
                b"",
                b"The specified item could not be found in the keychain."
            ),
            KeychainOutcome::Missing
        );
        assert_eq!(
            classify_security_output(false, b"", b"something else went wrong"),
            KeychainOutcome::Unavailable
        );
    }

    #[test]
    fn security_attr_classification() {
        // Attributes print for an existing item, secret or no secret.
        assert_eq!(classify_attr_output(true, b""), AttrOutcome::Exists);
        assert_eq!(
            classify_attr_output(
                false,
                b"The specified item could not be found in the keychain."
            ),
            AttrOutcome::Missing
        );
        assert_eq!(classify_attr_output(false, b""), AttrOutcome::Unavailable);
    }

    #[test]
    fn keychain_outcome_resolution() {
        // Measured on a real machine: the item exists (its attributes
        // answer) and the secret read fails at once with no wording at
        // all, because this reader has not been given the person's OK
        // yet. That is a refusal, not a broken tool.
        assert_eq!(
            resolve_keychain_outcome(
                AttrOutcome::Exists,
                classify_security_output(false, b"", b"")
            ),
            KeychainOutcome::Refused
        );
        // No item by either measure stays missing.
        assert_eq!(
            resolve_keychain_outcome(AttrOutcome::Missing, KeychainOutcome::Unavailable),
            KeychainOutcome::Missing
        );
        // Answers that already know what happened pass through untouched.
        assert_eq!(
            resolve_keychain_outcome(
                AttrOutcome::Missing,
                KeychainOutcome::Found("pw".to_string())
            ),
            KeychainOutcome::Found("pw".to_string())
        );
        assert_eq!(
            resolve_keychain_outcome(AttrOutcome::Unavailable, KeychainOutcome::Refused),
            KeychainOutcome::Refused
        );
        // Nothing classifiable anywhere is still Unavailable.
        assert_eq!(
            resolve_keychain_outcome(AttrOutcome::Unavailable, KeychainOutcome::Unavailable),
            KeychainOutcome::Unavailable
        );
    }

    #[test]
    fn mac_data_dir_scheme_follows_the_browsers_own_encrypted_hashes() {
        use base64::Engine;
        let b64 = |raw: &[u8]| base64::engine::general_purpose::STANDARD.encode(raw);
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("Chrome");
        let slot = root.join("Default");
        std::fs::create_dir_all(&slot).unwrap();
        // No prefs at all: no evidence, so v10.
        assert!(!mac_data_dir_speaks_v11(&root));
        // HMACs alone are not evidence.
        std::fs::write(
            slot.join("Secure Preferences"),
            "{\"protection\":{\"macs\":{\"homepage\":\"ABCDEF\"},\"super_mac\":\"0123\"}}",
        )
        .unwrap();
        assert!(!mac_data_dir_speaks_v11(&root));
        // The browser's own v11-sealed hashes, nested and top level.
        let prefs = serde_json::json!({"protection": {
            "macs": {"homepage": "ABCDEF", "homepage_encrypted_hash": b64(b"v11-sealed-bytes"),
                     "extensions": {"settings": {"abc_encrypted_hash": b64(b"v11-more")}}},
            "super_encrypted_hash": b64(b"v11-super"),
        }});
        std::fs::write(slot.join("Secure Preferences"), serde_json::to_vec(&prefs).unwrap()).unwrap();
        assert!(mac_data_dir_speaks_v11(&root));
        // A sibling profile in the same user data folder is a witness for a
        // folder whose Default profile has no prefs of its own.
        let sibling = root.join("Profile 1");
        std::fs::create_dir(&sibling).unwrap();
        std::fs::remove_file(slot.join("Secure Preferences")).unwrap();
        std::fs::write(sibling.join("Preferences"), serde_json::to_vec(&prefs).unwrap()).unwrap();
        assert!(mac_data_dir_speaks_v11(&root));
        // A v11 folder beside this user data folder is no witness for it:
        // only this folder and the profiles inside it count.
        std::fs::remove_file(sibling.join("Preferences")).unwrap();
        let other = t.path().join("OtherBrowser");
        std::fs::create_dir_all(other.join("Default")).unwrap();
        std::fs::write(other.join("Default").join("Preferences"), serde_json::to_vec(&prefs).unwrap()).unwrap();
        assert!(!mac_data_dir_speaks_v11(&root));
        // A v10 folder stays v10, and junk values prove nothing.
        let t10 = tempfile::tempdir().unwrap();
        let slot10 = t10.path().join("Chrome").join("Default");
        std::fs::create_dir_all(&slot10).unwrap();
        let prefs10 = serde_json::json!({"protection": {
            "super_encrypted_hash": b64(b"v10-super"),
            "macs": {"a_encrypted_hash": "not base64 !!", "b_encrypted_hash": 7},
        }});
        std::fs::write(slot10.join("Preferences"), serde_json::to_vec(&prefs10).unwrap()).unwrap();
        assert!(!mac_data_dir_speaks_v11(&t10.path().join("Chrome")));
    }

    #[test]
    fn mac_data_dir_scheme_counts_the_per_extension_hash_object() {
        use base64::Engine;
        let b64 = |raw: &[u8]| base64::engine::general_purpose::STANDARD.encode(raw);
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("Chrome");
        let slot = root.join("Default");
        std::fs::create_dir_all(&slot).unwrap();
        // The per-extension hashes live in an object, not a string:
        // protection.macs.extensions.settings_encrypted_hash maps each
        // extension id to its own sealed hash. With nothing else in the
        // file, those object entries are the only v11 evidence.
        let object_only = serde_json::json!({"protection": {"macs": {"extensions": {
            "settings_encrypted_hash": {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": b64(b"v11-ext-one"),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": b64(b"v11-ext-two"),
            },
        }}}});
        std::fs::write(slot.join("Preferences"), serde_json::to_vec(&object_only).unwrap()).unwrap();
        assert!(mac_data_dir_speaks_v11(&root));
        // Mixed case: the counted strings are a v10 majority (2 v10, 0 v11),
        // but the object holds the larger v11 set (3 v11), so the folder
        // still speaks v11.
        let mixed = serde_json::json!({"protection": {
            "super_encrypted_hash": b64(b"v10-super"),
            "macs": {
                "homepage_encrypted_hash": b64(b"v10-home"),
                "extensions": {"settings_encrypted_hash": {
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": b64(b"v11-ext-one"),
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": b64(b"v11-ext-two"),
                    "cccccccccccccccccccccccccccccccc": b64(b"v11-ext-three"),
                }},
            },
        }});
        std::fs::write(slot.join("Preferences"), serde_json::to_vec(&mixed).unwrap()).unwrap();
        assert!(mac_data_dir_speaks_v11(&root));
        // The object votes both ways: a v10 object majority stays v10.
        let object_v10 = serde_json::json!({"protection": {
            "super_encrypted_hash": b64(b"v11-super"),
            "macs": {"extensions": {"settings_encrypted_hash": {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": b64(b"v10-ext-one"),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": b64(b"v10-ext-two"),
            }}},
        }});
        std::fs::write(slot.join("Preferences"), serde_json::to_vec(&object_v10).unwrap()).unwrap();
        assert!(!mac_data_dir_speaks_v11(&root));
    }
}
