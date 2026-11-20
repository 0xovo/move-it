//! The app surface: one function per thing the shell can ask the engine to do.
//!
//! This is a thin, honest layer over the engine pieces (pairing, pipe, engine, txn). The
//! surface owns the app state folder: the config, the sync key file, the pairing tries
//! counter and the last-sync stamp. It owns no browser logic of its own; every store read
//! and write goes through the same modules the harness stress-test exercises.
//!
//! Sync key storage is isolated in [`App::load_key`] and [`App::store_key`]: today the key
//! lives in a file in the state folder (the same format the pairing offer carries). When
//! the keychain work lands, only those two bodies change.
//!
//! Browser password discovery is Linux-only for now (the same stance as
//! `logins::discover`); on other platforms the surface refuses plainly instead of guessing.
//!
//! Profiles are first-class: a device can hold several browsers, each with several
//! profiles. The preview lists every profile; a move can leave profiles out (the
//! excluded set). On the sending computer that is all it chooses. The receiving
//! computer picks which browser each incoming profile lands in (the route choices),
//! where it lands as that browser's own fresh profile, never over one the person
//! already has. Routes are per profile and per move. Nothing makes a route stick
//! beyond the move it was chosen in.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cookies::Keys;
use crate::oscrypt::{HostTag, LinuxBrowser, LinuxPrefix, Lock, Platform};
use crate::sealed::{Payload, SyncKey};
use crate::pipe::Pipe as _;
use crate::{bookmarks, engine, extstate, history, logins, pairing, paths, pipe, profiles, txn};
use crate::cloud::http::{SharedHttp, UreqClient};
use crate::keychain::TokenStore;
use crate::{Error, Result};

#[path = "api_cloud.rs"]
mod api_cloud;

const CONFIG_FILE: &str = "config.json";
const LEGACY_KEY_FILE: &str = "sync-key.txt";
const TRIES_FILE: &str = "pairing-tries";
const LAST_MOVE_FILE: &str = "last-move.json";
const LANDED_FILE: &str = "landed.json";

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn now_micros() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as i64).unwrap_or(0)
}

fn io(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}

/// The app state that persists between runs, in the state folder as plain JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub device_name: Option<String>,
    /// This device's stable id, made once and kept: two devices can share a
    /// name, but a box only ever belongs to the id that sealed it.
    #[serde(default)]
    pub device_id: Option<String>,
    /// "folder", "git", "google", or "dropbox".
    #[serde(default)]
    pub pipe_kind: Option<String>,
    #[serde(default)]
    pub pipe_byok: Option<bool>,
    /// The folder the person picked, or the git clone path.
    #[serde(default)]
    pub pipe_path: Option<String>,
    #[serde(default)]
    pub browser: Option<String>,
    #[serde(default)]
    pub profile_dir: Option<String>,
    #[serde(default)]
    pub other_device: Option<String>,
    #[serde(default)]
    pub last_sync_unix: Option<u64>,
    /// Profile ids seen in a finished move. A profile not in here yet is shown as
    /// new in the preview, so it is never absorbed invisibly.
    #[serde(default)]
    pub known_profiles: Vec<String>,
    /// The profiles left out of the last finished move, remembered per profile id.
    #[serde(default)]
    pub excluded_profiles: Vec<String>,
}

/// A browser profile found on this device: a user data folder with a `Default` inside.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedProfile {
    /// Short name the engine knows: brave, chrome, chromium, edge.
    pub browser: String,
    /// The name a person calls it: Brave, Google Chrome, ...
    pub display: String,
    pub dir: PathBuf,
}

fn validate_kinds(kinds: Option<&[String]>) -> Result<()> {
    if let Some(list) = kinds {
        for k in list {
            if !engine::MOVE_KINDS.contains(&k.as_str()) {
                return Err(Error::Refused(format!("unknown data kind: {k}")));
            }
        }
    }
    Ok(())
}

/// Per-profile partial-move selection. Keys are profile ids; omit a profile to move all kinds.
/// The legacy sentinel `*` applies one list to every profile (old global `kinds` argument).
pub type ProfileKinds = BTreeMap<String, Vec<String>>;

const LEGACY_KINDS_ALL: &str = "*";

pub fn normalize_profile_kinds(
    legacy: Option<&[String]>,
    by_profile: Option<&ProfileKinds>,
) -> Result<Option<ProfileKinds>> {
    if let Some(m) = by_profile {
        for list in m.values() {
            validate_kinds(Some(list.as_slice()))?;
        }
        return Ok(Some(m.clone()));
    }
    if let Some(list) = legacy {
        validate_kinds(Some(list))?;
        return Ok(Some(ProfileKinds::from([(
            LEGACY_KINDS_ALL.to_string(),
            list.to_vec(),
        )])));
    }
    Ok(None)
}

fn kinds_for_profile<'a>(map: Option<&'a ProfileKinds>, profile_id: &str) -> Option<&'a [String]> {
    let m = map?;
    if let Some(all) = m.get(LEGACY_KINDS_ALL) {
        return Some(all.as_slice());
    }
    m.get(profile_id).map(|v| v.as_slice())
}

fn browser_display(name: &str) -> String {
    crate::browsers::display_for(name)
        .map(str::to_string)
        .unwrap_or_else(|| name.to_string())
}

/// The browsers profiles can live in and be routed between: one store format
/// family (Chromium). Anything else (Firefox, Safari) keeps its own format and
/// is never a move target.
/// Every id here is a registry row in `crate::browsers`, in listing order
/// (a registry test pins the two lists to each other).
pub const FAMILY: [&str; 14] = [
    "brave",
    "chrome",
    "chromium",
    "edge",
    "opera",
    "vivaldi",
    "chrome-beta",
    "chrome-dev",
    "chrome-canary",
    "edge-beta",
    "edge-dev",
    "brave-beta",
    "brave-nightly",
    "opera-gx",
];

/// The folder one browser keeps its profiles in, under the config base
/// (the registry's Linux folder; this surface's non-Linux base has always
/// used the same folder names).
fn browser_subdir(name: &str) -> Option<&'static str> {
    crate::browsers::by_id(name).and_then(|d| d.linux_dir)
}

/// The base the browsers live under (Linux: `$XDG_CONFIG_HOME` or `~/.config`).
fn config_base() -> Option<PathBuf> {
    if Platform::current() != Platform::Linux {
        return None;
    }
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
}

/// The short slug a slot carries in a profile id: `Default` -> `default`,
/// `Profile 1` -> `profile-1`.
fn slot_slug(slot: &str) -> String {
    slot.to_lowercase().replace(' ', "-")
}

/// The id a profile is known by in this surface: `brave:profile-1`. Ids are only
/// ever matched against enumerated profiles, never used as paths.
pub fn profile_id(browser: &str, slot: &str) -> String {
    format!("{browser}:{}", slot_slug(slot))
}

/// One profile on this device, in the surface's terms.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceProfile {
    pub id: String,
    /// Short browser name: brave, chrome, ...
    pub browser: String,
    /// The browser's folder.
    pub root: PathBuf,
    /// The slot (folder name) inside it: Default, Profile 1, ...
    pub slot: String,
    /// What the person calls the profile.
    pub name: String,
}

/// Chromium profiles in their usual Linux places. Other platforms: no detection yet, so
/// the working profile must come from the config or an override.
pub fn detect_profiles() -> Vec<DetectedProfile> {
    if Platform::current() != Platform::Linux {
        return Vec::new();
    }
    from_profiles_detected(profiles::linux_chromium_install_roots(None))
}

fn from_profiles_detected(roots: Vec<profiles::ChromiumInstallRoot>) -> Vec<DetectedProfile> {
    roots
        .into_iter()
        .map(|r| DetectedProfile {
            browser: r.browser,
            display: r.display,
            dir: r.dir,
        })
        .collect()
}

fn default_device_name() -> String {
    if let Ok(n) = std::env::var("MOVEIT_DEVICE_NAME") {
        if !n.trim().is_empty() {
            return n.trim().to_string();
        }
    }
    #[cfg(unix)]
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    for var in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(n) = std::env::var(var) {
            if !n.trim().is_empty() {
                return n.trim().to_string();
            }
        }
    }
    "this device".to_string()
}

/// One running app: a state folder plus the config read from it.
pub struct App {
    state_dir: PathBuf,
    config: Config,
    key_store: std::sync::Arc<dyn crate::keychain::KeyStore + Send + Sync>,
    token_store: std::sync::Arc<dyn TokenStore + Send + Sync>,
    http: SharedHttp,
    app_config_dir: Option<PathBuf>,
    /// The app's own log, behind the Logs screen (see logbuf).
    logs: crate::logbuf::LogBuffer,
    profile_override: Option<(String, PathBuf)>,
    /// The browser base captured when the app opened: enumeration stays stable for
    /// the app's life even if the environment changes under it.
    base: Option<PathBuf>,
    local_profiles: Vec<DetectedProfile>,
    access_cache: crate::oauth::access_cache::AccessCache,
    /// Test harness: built-in OAuth files live here instead of the process default.
    builtin_oauth_dir: Option<PathBuf>,
}

/// One move at a time per device: a lock file in the state folder, held for
/// the length of a move and removed when it ends. A lock left by a crashed
/// move is taken over only when the process that made it is gone (or, where
/// that cannot be checked, when it is plainly stale).
struct MoveLock {
    path: PathBuf,
}

impl MoveLock {
    fn take(state_dir: &Path) -> Result<MoveLock> {
        let path = state_dir.join("move.lock");
        match Self::create(&path) {
            Ok(lock) => Ok(lock),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if Self::stale(&path) {
                    let _ = std::fs::remove_file(&path);
                    Self::create(&path).map_err(io)
                } else {
                    Err(Error::Refused(
                        "another move is already running on this device; wait for it to finish"
                            .into(),
                    ))
                }
            }
            Err(e) => Err(io(e)),
        }
    }

    fn create(path: &Path) -> std::io::Result<MoveLock> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        use std::io::Write;
        let _ = writeln!(f, "{}", std::process::id());
        Ok(MoveLock { path: path.to_path_buf() })
    }

    fn stale(path: &Path) -> bool {
        #[cfg(unix)]
        {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    return !process_live(pid);
                }
            }
        }
        let Ok(meta) = std::fs::metadata(path) else { return true };
        let Ok(mtime) = meta.modified() else { return true };
        mtime.elapsed().map(|d| d.as_secs() > 6 * 3600).unwrap_or(true)
    }
}

impl Drop for MoveLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl App {
    /// Open (or start) the app state in `state_dir`.
    pub fn open(state_dir: &Path) -> Result<App> {
        std::fs::create_dir_all(state_dir).map_err(io)?;
        let config = match std::fs::read(state_dir.join(CONFIG_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::Corrupt(format!("the app settings are damaged: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(io(e)),
        };
        Ok(App {
            state_dir: state_dir.to_path_buf(),
            config,
            key_store: std::sync::Arc::new(crate::keychain::OsKeychain),
            token_store: std::sync::Arc::new(crate::keychain::OsKeychain),
            http: std::sync::Arc::new(UreqClient),
            app_config_dir: None,
            logs: crate::logbuf::LogBuffer::default(),
            profile_override: None,
            base: config_base(),
            local_profiles: Vec::new(),
            access_cache: crate::oauth::access_cache::AccessCache::default(),
            builtin_oauth_dir: None,
        })
    }

    /// Pin the working profile for this session (the shell after a browser pick, the
    /// harness and tests always). Not written to the config.
    /// Swap the key store (tests and CI run against an in-memory store:
    /// no OS keychain session exists there).
    pub fn with_key_store(
        mut self,
        store: std::sync::Arc<dyn crate::keychain::KeyStore + Send + Sync>,
    ) -> App {
        self.key_store = store;
        self
    }

    pub fn with_token_store(mut self, store: std::sync::Arc<dyn TokenStore + Send + Sync>) -> App {
        self.token_store = store;
        self
    }

    pub fn with_http(mut self, http: SharedHttp) -> App {
        self.http = http;
        self
    }

    pub fn with_app_config_dir(mut self, dir: PathBuf) -> App {
        self.app_config_dir = Some(dir);
        self
    }

    pub fn with_builtin_oauth_dir(mut self, dir: PathBuf) -> App {
        self.builtin_oauth_dir = Some(dir);
        self
    }

    /// Override browser discovery for fixture callers such as the harness.
    pub fn with_browser_base(mut self, base: &Path) -> App {
        self.base = Some(base.to_path_buf());
        self
    }

    pub fn with_profile(mut self, browser: &str, dir: &Path) -> App {
        self.profile_override = Some((browser.to_string(), dir.to_path_buf()));
        self
    }

    /// Register one more profile this device has, for the same-device move. The
    /// shell normally finds these by detection; the harness and tests pin them here.
    /// Not written to the config.
    pub fn with_local_profile(mut self, browser: &str, dir: &Path) -> App {
        // One folder per name: registering a name again replaces the earlier
        // folder, so a later pin can never be silently shadowed by an old one.
        self.local_profiles.retain(|p| p.browser != browser);
        self.local_profiles.push(DetectedProfile {
            browser: browser.to_string(),
            display: browser_display(browser),
            dir: dir.to_path_buf(),
        });
        self
    }

    /// A browser this device has, by its short name: a pinned profile first, then
    /// the registered same-device profiles, then detection.
    fn find_profile(&self, browser: &str) -> Option<DetectedProfile> {
        if let Some((b, d)) = &self.profile_override {
            if b == browser {
                return Some(DetectedProfile {
                    browser: b.clone(),
                    display: browser_display(b),
                    dir: d.clone(),
                });
            }
        }
        if let Some(p) = self.local_profiles.iter().find(|p| p.browser == browser) {
            return Some(p.clone());
        }
        self.detected().into_iter().find(|p| p.browser == browser)
    }

    fn require_local_profile(&self, browser: &str) -> Result<DetectedProfile> {
        self.find_profile(browser).ok_or_else(|| {
            Error::Refused(format!("{} was not found on this device", browser_display(browser)))
        })
    }

    /// This device's stable id, generating and saving one on first use.
    pub fn device_id(&mut self) -> Result<String> {
        if let Some(id) = &self.config.device_id {
            return Ok(id.clone());
        }
        let mut b = [0u8; 16];
        getrandom::getrandom(&mut b).map_err(|e| Error::Io(format!("no randomness: {e}")))?;
        let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
        self.config.device_id = Some(id.clone());
        self.save_config()?;
        Ok(id)
    }

    /// The id if one has been made yet (read-only paths never force one).
    fn device_id_opt(&self) -> Option<&str> {
        self.config.device_id.as_deref()
    }

    pub fn device_name(&self) -> String {
        self.config
            .device_name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(default_device_name)
    }

    pub fn set_device_name(&mut self, name: &str) -> Result<()> {
        self.config.device_name = Some(name.to_string());
        self.save_config()
    }

    fn save_config(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.config).map_err(|e| Error::Io(e.to_string()))?;
        crate::util::atomic_write(&self.state_dir.join(CONFIG_FILE), &bytes)
    }

    // ---- the sync key (see the module note: these two bodies are the keychain seam) ----

    /// The keychain account for this device: its stable id once one
    /// exists, else its name (installs from before ids).
    fn key_account(&self) -> String {
        self.config
            .device_id
            .clone()
            .unwrap_or_else(|| self.device_name())
    }

    fn load_key(&mut self) -> Result<Option<SyncKey>> {
        // Persist the account before migrating a key into it.
        let account = self.device_id()?;
        if let Some(k) = self.key_store.load(&account)? {
            return Ok(Some(k));
        }
        // Older builds stored migrated keys under the device name.
        let old_account = self.device_name();
        if old_account != account {
            if let Some(k) = self.key_store.load(&old_account)? {
                self.key_store.store(&account, &k)?;
                self.key_store.delete(&old_account)?;
                return Ok(Some(k));
            }
        }
        // One-time migration: a device paired before the keychain kept its
        // key in a file in the state folder. Move it into the keychain and
        // delete the file; the file path is never used again after this.
        let p = self.state_dir.join(LEGACY_KEY_FILE);
        if p.exists() {
            let k = SyncKey::read_key_file(&p)?;
            self.key_store.store(&account, &k)?;
            let _ = std::fs::remove_file(&p);
            return Ok(Some(k));
        }
        Ok(None)
    }

    fn store_key(&self, key: &SyncKey) -> Result<()> {
        self.key_store.store(&self.key_account(), key)?;
        // A legacy key file must not outlive the keychain copy.
        let p = self.state_dir.join(LEGACY_KEY_FILE);
        if p.exists() {
            let _ = std::fs::remove_file(&p);
        }
        Ok(())
    }

    // ---- the pipe ----

    /// Where the box and pairing notes live, from the config alone (no side effects).
    fn place_path(&self) -> Option<PathBuf> {
        let path = self.config.pipe_path.as_ref()?;
        match self.config.pipe_kind.as_deref() {
            Some("git") | Some("google") | Some("dropbox") => Some(PathBuf::from(path)),
            _ => Some(PathBuf::from(path).join(pipe::FOLDER_NAME)),
        }
    }

    fn make_pipe(&self) -> Result<Option<Box<dyn pipe::Pipe>>> {
        let (Some(kind), Some(path)) = (self.config.pipe_kind.as_deref(), self.config.pipe_path.as_deref())
        else {
            return Ok(None);
        };
        let p: Box<dyn pipe::Pipe> = match kind {
            "git" => Box::new(pipe::GitPipe::new(Path::new(path))?),
            "google" | "dropbox" => self.build_cloud_pipe(kind, Path::new(path))?,
            _ => Box::new(pipe::FolderPipe::new(Path::new(path))?),
        };
        Ok(Some(p))
    }

    fn require_pipe(&self) -> Result<Box<dyn pipe::Pipe>> {
        self.make_pipe()?.ok_or_else(|| {
            Error::Refused("choose where Move It keeps your sealed box first".into())
        })
    }

    // ---- the working profile ----

    fn working_profile(&self) -> Option<DetectedProfile> {
        if let Some((b, d)) = &self.profile_override {
            return Some(DetectedProfile { browser: b.clone(), display: browser_display(b), dir: d.clone() });
        }
        if let Some(dir) = &self.config.profile_dir {
            let b = self.config.browser.clone().unwrap_or_else(|| "brave".to_string());
            return Some(DetectedProfile { display: browser_display(&b), browser: b, dir: PathBuf::from(dir) });
        }
        self.detected().into_iter().next()
    }

    /// The profiles detection finds under the base this app captured when
    /// it opened: the same world for the app's whole life, even if the
    /// environment changes under it.
    fn detected(&self) -> Vec<DetectedProfile> {
        if Platform::current() == Platform::Linux {
            return from_profiles_detected(profiles::linux_chromium_install_roots(self.base.as_deref()));
        }
        Vec::new()
    }

    fn require_profile(&self) -> Result<DetectedProfile> {
        self.working_profile()
            .ok_or_else(|| Error::Refused("no browser profile was found on this device".into()))
    }

    /// The per-profile store keys, from live password discovery (Linux).
    fn keys_for(&self, browser: &str) -> Result<Keys> {
        self.keys_for_at(browser, None)
    }

    fn keys_for_at(&self, browser: &str, install_root: Option<&Path>) -> Result<Keys> {
        // Integration tests plant Linux-style v10 stores and pin MOVEIT_LINUX_PASSWORD;
        // on macOS CI there is no Safe Storage item, so honour the pin without touching
        // the real Keychain. `cfg(test)` is off for integration-test builds, so a
        // test-only feature gates it; the desktop app never enables it.
        #[cfg(feature = "test-keys")]
        if std::env::var(crate::oscrypt::LINUX_PASSWORD_ENV)
            .ok()
            .is_some_and(|p| !p.is_empty())
        {
            let b = LinuxBrowser::from_name(browser).ok_or_else(|| {
                Error::Refused(format!("{} is not a browser Move It can read yet", browser_display(browser)))
            })?;
            let (password, from_trusted) =
                crate::oscrypt::linux_browser_password_for_at(b, install_root)?;
            let from_libsecret_v2 = b.empty_store_v11_from_trusted_item(from_trusted);
            return Ok(Keys::Cbc {
                lock: Lock::linux(&password, LinuxPrefix::V10),
                from_libsecret_v2,
            });
        }
        if Platform::current() != Platform::Linux {
            return Err(Error::Refused(
                "reading a browser's own password is implemented for Linux only so far".into(),
            ));
        }
        let b = LinuxBrowser::from_name(browser).ok_or_else(|| {
            Error::Refused(format!("{} is not a browser Move It can read yet", browser_display(browser)))
        })?;
        let (password, from_trusted) =
            crate::oscrypt::linux_browser_password_for_at(b, install_root)?;
        let from_libsecret_v2 = b.empty_store_v11_from_trusted_item(from_trusted);
        Ok(Keys::Cbc { lock: Lock::linux(&password, LinuxPrefix::V10), from_libsecret_v2 })
    }

    /// The destination keys for a same-device move: the destination
    /// browser's own keyring key, found through the validated probing
    /// (`oscrypt::linux_browser_password_validated_for`, the route the
    /// harness logins probe uses), never the single first candidate
    /// `keys_for` returns.
    ///
    /// Validation is evidence-based, and the only evidence is the
    /// destination's own v11 rows: v10 rows open under the compiled-in
    /// fallback whatever candidate is offered, so they prove nothing.
    /// Two cases:
    ///
    /// - The destination HAS v11 rows (in either store): a candidate
    ///   counts only when it decrypts at least one v11 row in each
    ///   store that carries them. A candidate that fails is refused;
    ///   there is no unvalidated path past live rows.
    /// - The destination has NO v11 rows (an empty store, or a legacy
    ///   v10-only one): no store evidence exists to validate against,
    ///   and refusing would break moves into fresh profiles, so the
    ///   move may proceed with the discovered key - the keyring item
    ///   the destination browser itself will use for its own v11
    ///   writes - but ONLY when that key is not the compiled-in
    ///   fallback. The fallback refuses absolutely, before any write:
    ///   sealing secrets under a publicly known key is never allowed.
    ///
    /// Provenance is carried truthfully: the returned keys keep the
    /// discovery provenance (the probe's own v2 flag, folded through
    /// `empty_store_v11_from_trusted_item` exactly as `keys_for`
    /// does), never a manufactured trust flag. The no-v11-rows case
    /// is NOT marked validated or trusted; its v11 seeding permission
    /// travels on the forced-prefix import path itself, named for
    /// what it is - no v11 rows contradict the discovered key - and
    /// the store-level check on that path still refuses the fallback
    /// key outright.
    fn keys_for_local_destination(&self, browser: &str, dir: &Path, slot: &str) -> Result<Keys> {
        let b = LinuxBrowser::from_name(browser).ok_or_else(|| {
            Error::Refused(format!("{} is not a browser Move It can read yet", browser_display(browser)))
        })?;
        let cookies_p = paths::cookies_in(dir, slot);
        let logins_p = paths::login_data_in(dir, slot);
        // (v11 rows, of those how many this candidate opens), per store.
        // The probe keys carry no trust flag: decryption is all that is
        // being measured, and a flag would say nothing about it.
        let v11_counts = |pw: &str| -> ((usize, usize), (usize, usize)) {
            let keys = Keys::Cbc {
                lock: Lock::linux(pw, LinuxPrefix::V10),
                from_libsecret_v2: false,
            };
            (
                crate::cookies::v11_decryption(&cookies_p, &keys),
                logins::v11_decryption(&logins_p, &keys),
            )
        };
        let has_v11_rows = |pw: &str| -> bool {
            let ((c_total, _), (l_total, _)) = v11_counts(pw);
            c_total + l_total > 0
        };
        let opens_destination = |pw: &str| -> bool {
            let ((c_total, c_opened), (l_total, l_opened)) = v11_counts(pw);
            (c_total == 0 || c_opened > 0) && (l_total == 0 || l_opened > 0)
        };
        let (password, from_v2) = crate::oscrypt::linux_browser_password_validated_for(
            b,
            &|pw, _from_trusted| opens_destination(pw),
        )?;
        if password == crate::oscrypt::LINUX_FALLBACK_PASSWORD {
            return Err(Error::Refused(format!(
                "no keyring key for {} was found on this device, so the move would have to seal \
                 secrets with the browser's public fallback key; Move It will not write those secrets",
                browser_display(browser)
            )));
        }
        if has_v11_rows(&password) && !opens_destination(&password) {
            return Err(Error::Refused(format!(
                "the keyring key found for {} does not open that browser's existing v11 cookies \
                 or logins, so it cannot be the key its profile was sealed with; the move is refused",
                browser_display(browser)
            )));
        }
        Ok(Keys::Cbc {
            lock: Lock::linux(&password, LinuxPrefix::V11),
            from_libsecret_v2: b.empty_store_v11_from_trusted_item(from_v2),
        })
    }

    /// All profiles on this device: every family browser folder under the config
    /// base, every slot the browser itself lists. A pinned working profile whose
    /// folder sits outside the usual places is listed too, so the shell's pick is
    /// never invisible to the surface.
    fn source_profiles(&self) -> Vec<SourceProfile> {
        let mut out: Vec<SourceProfile> = Vec::new();
        if Platform::current() == Platform::Linux {
            for install in profiles::linux_chromium_install_roots(self.base.as_deref()) {
                if !FAMILY.contains(&install.browser.as_str()) {
                    continue;
                }
                let name = install.browser.as_str();
                for slot in profiles::list_slots_for(&install.dir, install.layout) {
                    if out.iter().any(|s: &SourceProfile| s.id == profile_id(name, &slot.name)) {
                        continue; // two folder names, one id: the first keeps it
                    }
                    out.push(SourceProfile {
                        id: profile_id(name, &slot.name),
                        browser: name.to_string(),
                        root: install.dir.clone(),
                        slot: slot.name,
                        name: slot.display,
                    });
                }
            }
        } else if let Some(base) = &self.base {
            for name in FAMILY {
                let Some(sub) = browser_subdir(name) else { continue };
                let root = base.join(sub);
                if !root.is_dir() {
                    continue;
                }
                for slot in profiles::list_slots_for_browser(&root, name) {
                    if out.iter().any(|s: &SourceProfile| s.id == profile_id(name, &slot.name)) {
                        continue;
                    }
                    out.push(SourceProfile {
                        id: profile_id(name, &slot.name),
                        browser: name.to_string(),
                        root: root.clone(),
                        slot: slot.name,
                        name: slot.display,
                    });
                }
            }
        }
        if let Some(wp) = self.working_profile() {
            if !out.iter().any(|s| s.root == wp.dir) {
                // The pinned profile's folder was not under the detected
                // base: every slot in it is a source, not just Default.
                for slot in profiles::list_slots_for_browser(&wp.dir, &wp.browser) {
                    out.push(SourceProfile {
                        id: profile_id(&wp.browser, &slot.name),
                        browser: wp.browser.clone(),
                        root: wp.dir.clone(),
                        slot: slot.name,
                        name: slot.display,
                    });
                }
            }
        }
        out
    }

    /// Where profiles for `browser` live on this device: the working root when the
    /// pinned profile is that browser, else the folder under the config base
    /// (created by the move if it comes to that).
    fn dest_root(&self, browser: &str) -> Option<PathBuf> {
        if let Some(wp) = self.working_profile() {
            if wp.browser == browser {
                return Some(wp.dir);
            }
        }
        if Platform::current() == Platform::Linux {
            let root = profiles::linux_chromium_install_roots(self.base.as_deref())
                .into_iter()
                .find(|r| r.browser == browser)?;
            return root.dir.is_dir().then_some(root.dir);
        }
        let base = self.base.as_ref()?;
        let sub = browser_subdir(browser)?;
        let root = base.join(sub);
        root.is_dir().then_some(root)
    }

    // ---- the multi-profile undo record ----

    fn load_last_move(&self) -> Option<LastMove> {
        let text = std::fs::read_to_string(self.state_dir.join(LAST_MOVE_FILE)).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn save_last_move(&self, rec: &LastMove) -> Result<()> {
        let bytes = serde_json::to_vec(rec).map_err(|e| Error::Io(e.to_string()))?;
        crate::util::atomic_write(&self.state_dir.join(LAST_MOVE_FILE), &bytes)
    }

    fn record_landings(&mut self, roots: &BTreeSet<PathBuf>, book: &LandedBook) -> Result<()> {
        let roots = roots.iter().map(|r| {
            let txn = current_undo_point(r).ok_or_else(|| Error::Corrupt("a landing has no undo point".into()))?;
            Ok(LastMoveRoot { root: r.to_string_lossy().into_owned(), txn })
        }).collect::<Result<Vec<_>>>()?;
        self.save_last_move(&LastMove { roots })?;
        self.save_landed(book)?;
        self.config.last_sync_unix = Some(now_secs());
        self.save_config()
    }

    fn clear_last_move(&self) {
        let _ = std::fs::remove_file(self.state_dir.join(LAST_MOVE_FILE));
    }

    fn load_landed(&self) -> LandedBook {
        std::fs::read_to_string(self.state_dir.join(LANDED_FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save_landed(&self, book: &LandedBook) -> Result<()> {
        let bytes = serde_json::to_vec(book).map_err(|e| Error::Io(e.to_string()))?;
        crate::util::atomic_write(&self.state_dir.join(LANDED_FILE), &bytes)
    }

}

/// One box from the other device, with the identity its manifest carries. A box
/// sealed before profiles had identities (no profile keys in the manifest) is
/// the other device's working profile and lands in this device's matching one.
struct Incoming {
    /// The device that sealed the box.
    origin: String,
    /// The origin's stable key: its device id when the box carries one,
    /// else its name (boxes sealed before ids existed).
    origin_key: String,
    src_browser: String,
    src_slot: String,
    src_name: String,
    route: Option<String>,
    slot_ok: bool,
    payload: Payload,
}

impl Incoming {
    fn from_payload(mut payload: Payload, working: &Option<DetectedProfile>) -> Incoming {
        if !payload.manifest.contains_key("profile_browser") {
            let (b, disp) = working
                .as_ref()
                .map(|w| (w.browser.clone(), w.display.clone()))
                .unwrap_or_else(|| ("brave".to_string(), "Brave".to_string()));
            let origin = payload
                .manifest
                .get("origin")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let origin_key = payload
                .manifest
                .get("origin_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| origin.clone());
            payload
                .manifest
                .insert("profile_browser".into(), serde_json::json!(b));
            payload
                .manifest
                .insert("profile_slot".into(), serde_json::json!(paths::DEFAULT_SLOT));
            return Incoming {
                origin,
                origin_key,
                src_browser: b,
                src_slot: paths::DEFAULT_SLOT.to_string(),
                src_name: disp,
                route: None,
                slot_ok: true,
                payload,
            };
        }
        let get = |k: &str| {
            payload.manifest.get(k).and_then(|v| v.as_str()).map(str::to_string)
        };
        let b = get("profile_browser").expect("profile_browser checked");
        let slot = get("profile_slot").unwrap_or_else(|| paths::DEFAULT_SLOT.to_string());
        Incoming {
            origin: get("origin").unwrap_or_default(),
            origin_key: get("origin_id").unwrap_or_else(|| get("origin").unwrap_or_default()),
            slot_ok: profiles::is_slot_name_for_browser(&slot, &b.to_lowercase()),
            src_name: get("profile_name").unwrap_or_else(|| slot.clone()),
            // Browser names match case-insensitively; slot names do
            // not (they are folder names, and case is real there).
            src_browser: b.to_lowercase(),
            src_slot: slot,
            route: get("route_browser").map(|r| r.to_lowercase()),
            payload,
        }
    }

    fn id(&self) -> String {
        profile_id(&self.src_browser, &self.src_slot)
    }
}

/// Where a routed profile landed, remembered across moves. A routed profile
/// arrives as a fresh profile the first time; its box stays in the pipe (that is
/// how sync works), so without this memory the next move would land it again as
/// another fresh profile, forever. The entry names the landed home; later boxes
/// from the same source profile merge into it, the way an unrouted profile
/// merges into its own slot. An entry is only a hint: the landed profile must
/// still carry the landing marker its first landing stamped into it, naming
/// this exact source, before anything merges there. An entry whose folder is
/// gone, or whose marker does not match, is inert: the next arrival lands
/// fresh again and the entry is rewritten.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LandedRec {
    origin: String,
    browser: String,
    slot: String,
    root: String,
    landed_slot: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LandedBook {
    entries: Vec<LandedRec>,
}

impl LandedBook {
    /// The slot this source profile already landed in under `root`, when it did,
    /// the folder is still there, and the profile itself carries the landing
    /// marker naming this source.
    fn home(&self, origin: &str, browser: &str, slot: &str, root: &Path) -> Option<String> {
        let e = self.entries.iter().find(|e| {
            e.origin == origin
                && e.browser == browser
                && e.slot == slot
                && e.root == root.to_string_lossy()
                && root.join(&e.landed_slot).is_dir()
        })?;
        let text =
            std::fs::read_to_string(root.join(&e.landed_slot).join(engine::LANDING_MARKER))
                .ok()?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default();
        if field("origin") == origin && field("browser") == browser && field("slot") == slot {
            Some(e.landed_slot.clone())
        } else {
            None
        }
    }

    fn record(&mut self, origin: &str, browser: &str, slot: &str, root: &Path, landed_slot: &str) {
        let root = root.to_string_lossy().into_owned();
        if let Some(e) = self.entries.iter_mut().find(|e| {
            e.origin == origin && e.browser == browser && e.slot == slot && e.root == root
        }) {
            e.landed_slot = landed_slot.to_string();
        } else {
            self.entries.push(LandedRec {
                origin: origin.to_string(),
                browser: browser.to_string(),
                slot: slot.to_string(),
                root,
                landed_slot: landed_slot.to_string(),
            });
        }
    }
}

/// The undo record a move leaves behind when it landed profiles in more than the
/// working profile (or in several browsers at once): every profile root that took
/// profiles in, with the undo point the move created there. One move, one undo,
/// across however many browsers it touched. A later move replaces the record:
/// undo always means the last move. A move that tried to land profiles and
/// landed none leaves a record with no roots at all, which reads as "the last
/// move cannot be undone" and, unlike a missing record, does not fall through
/// to the working profile's own last transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LastMove {
    roots: Vec<LastMoveRoot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LastMoveRoot {
    root: String,
    /// The committed transaction folder name the move created in that root.
    txn: String,
}

/// The undo point a profile root currently offers: the newest committed,
/// not-yet-undone transaction folder, by name.
fn current_undo_point(root: &Path) -> Option<String> {
    let rd = std::fs::read_dir(root).ok()?;
    let mut best: Option<String> = None;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with(txn::TXN_PREFIX) || !e.path().is_dir() {
            continue;
        }
        if e.path().join("COMMITTED").exists() && !e.path().join("UNDONE").exists() {
            if best.as_deref().is_none_or(|b| name.as_str() > b) {
                best = Some(name);
            }
        }
    }
    best
}

/// Check a move's route choices against the profiles on this device, and return
/// the effective routes (profile id -> destination browser). A route to the
/// profile's own browser is the default path and drops out. Everything else that
/// is wrong refuses plainly, before anything is read or written: an unknown
/// profile, a profile routed twice, a route for a profile left out of the move,
/// a destination outside the Chromium family.
fn validate_routes(
    sources: &[SourceProfile],
    excluded: &[String],
    routes: &[RouteChoice],
) -> Result<BTreeMap<String, String>> {
    let by_id: BTreeMap<&str, &SourceProfile> =
        sources.iter().map(|s| (s.id.as_str(), s)).collect();
    // An id in `excluded` that names no profile here excludes nothing and is
    // not an error: the set can be a remembered one from an older shape of
    // this device, and a stale id must never brick every move.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for r in routes {
        let Some(sp) = by_id.get(r.profile.as_str()) else {
            return Err(Error::Refused(format!("{} is not a profile on this device", r.profile)));
        };
        if !seen.insert(r.profile.as_str()) {
            return Err(Error::Refused(format!("{} is routed twice in one move", r.profile)));
        }
        if excluded.iter().any(|e| e == &r.profile) {
            return Err(Error::Refused(format!(
                "{} is left out of this move, so it cannot be routed too",
                r.profile
            )));
        }
        // Browser names are matched case-insensitively everywhere in this
        // surface (a choice or a box saying "Chrome" means Chrome).
        let target = r.browser.to_lowercase();
        if !FAMILY.contains(&target.as_str()) {
            return Err(Error::Refused(format!(
                "profiles cannot be sent to {}: it is not one of the browsers Move It moves between",
                r.browser
            )));
        }
        if target != sp.browser {
            out.insert(r.profile.clone(), target);
        }
    }
    Ok(out)
}

/// Every browser this device can land a profile into: installed, and opened at
/// least once, with plain reasons for the rest.
fn route_targets(app: &App) -> Vec<RouteTarget> {
    FAMILY
        .iter()
        .map(|name| {
            let display = browser_display(name);
            let mut available = false;
            let mut reason = None;
            if Platform::current() == Platform::Linux && LinuxBrowser::from_name(name).is_some() {
                match app.dest_root(name) {
                    Some(root) if !browser_landing_ready(&root) => {
                        reason = Some(format!(
                            "Open {display} once on this computer so Move It can add a profile there"
                        ));
                    }
                    Some(_) => available = true,
                    None => reason = Some(format!("{display} is not installed on this computer")),
                }
            } else {
                reason = Some(format!(
                    "Move It cannot read {display}'s password on this system yet"
                ));
            }
            RouteTarget {
                name: name.to_string(),
                display: display.clone(),
                available,
                reason,
            }
        })
        .collect()
}

/// Check route choices for incoming profiles waiting in shared storage. Refuses
/// before anything is read or written: unknown id, routed twice, destination
/// outside the Chromium family, or a destination this device cannot use yet.
fn validate_incoming_routes(
    arriving: &[ArrivingProfile],
    routes: &[RouteChoice],
) -> Result<BTreeMap<String, String>> {
    let by_id: BTreeMap<&str, &ArrivingProfile> =
        arriving.iter().map(|a| (a.id.as_str(), a)).collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for r in routes {
        let Some(ap) = by_id.get(r.profile.as_str()) else {
            continue; // stale choice from an earlier preview; drop quietly
        };
        if !seen.insert(r.profile.as_str()) {
            return Err(Error::Refused(format!("{} is routed twice in one move", r.profile)));
        }
        let target = r.browser.to_lowercase();
        if !FAMILY.contains(&target.as_str()) {
            return Err(Error::Refused(format!(
                "profiles cannot be sent to {}: it is not one of the browsers Move It moves between",
                r.browser
            )));
        }
        if target != ap.from_browser {
            out.insert(r.profile.clone(), target);
        }
    }
    Ok(out)
}

fn default_incoming_destination(
    from_browser: &str,
    targets: &[RouteTarget],
) -> (String, Option<String>) {
    if targets
        .iter()
        .any(|t| t.name == from_browser && t.available)
    {
        return (from_browser.to_string(), None);
    }
    let first = targets.iter().find(|t| t.available);
    if let Some(t) = first {
        let note = format!(
            "{} is not on this computer; the first browser available here is {}",
            browser_display(from_browser),
            t.display
        );
        return (t.name.clone(), Some(note));
    }
    (from_browser.to_string(), None)
}

fn incoming_admits(
    inc: &Incoming,
    sources: &[SourceProfile],
    route_map: &BTreeMap<String, String>,
    app: &App,
) -> bool {
    let id = inc.id();
    let will_route = route_map.get(&id).is_some_and(|d| d != &inc.src_browser);
    if will_route {
        return true;
    }
    if sources
        .iter()
        .any(|s| s.browser == inc.src_browser && s.slot == inc.src_slot)
    {
        return true;
    }
    // Same browser, no local slot yet: land fresh when that browser is here.
    app.dest_root(&inc.src_browser).is_some()
}

fn incoming_landing_target(
    inc: &Incoming,
    routed: bool,
    root: &Path,
    landed_book: &LandedBook,
    single_profile: bool,
) -> (engine::Target, bool) {
    if single_profile {
        // The dest folder is the profile: every box for this browser
        // lands in its one slot, never in a created subfolder.
        return (engine::Target::Slot(paths::SINGLE_SLOT.to_string()), false);
    }
    if routed {
        match landed_book.home(&inc.origin_key, &inc.src_browser, &inc.src_slot, root) {
            Some(home) => (engine::Target::Slot(home), false),
            None => (engine::Target::Fresh { display: inc.src_name.clone() }, true),
        }
    } else if root.join(&inc.src_slot).is_dir() {
        (engine::Target::Slot(inc.src_slot.clone()), false)
    } else {
        match landed_book.home(&inc.origin_key, &inc.src_browser, &inc.src_slot, root) {
            Some(home) => (engine::Target::Slot(home), false),
            None => (engine::Target::Fresh { display: inc.src_name.clone() }, true),
        }
    }
}

/// True when at least one profile slot under this browser root has been opened once.
fn browser_landing_ready(root: &Path) -> bool {
    if crate::browsers::has_single_profile_markers(root)
        && !paths::never_launched(root, paths::SINGLE_SLOT)
    {
        return true;
    }
    for slot in profiles::list_slots(root) {
        if !paths::never_launched(root, &slot.name) {
            return true;
        }
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return false;
    };
    rd.flatten().any(|e| {
        let name = e.file_name().to_string_lossy().into_owned();
        e.path().is_dir() && profiles::is_slot_name(&name) && !paths::never_launched(root, &name)
    })
}

fn scan_incoming_boxes(
    app: &App,
    p: &dyn pipe::Pipe,
    key: &SyncKey,
    my_id: &str,
    device: &str,
) -> Result<Vec<Incoming>> {
    let working = app.working_profile();
    let mut out = Vec::new();
    for box_path in p.boxes()? {
        let fname = box_path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let opened = std::fs::read(&box_path)
            .map_err(io)
            .and_then(|bytes| engine::open_box(&bytes, key));
        let payload = match opened {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !box_name_matches(&fname, &payload, &working) {
            continue;
        }
        if is_own_box(&payload, Some(my_id), device) {
            continue;
        }
        out.push(Incoming::from_payload(payload, &working));
    }
    Ok(out)
}

/// What the shell learns when the app starts (the welcome and home screens route on it).
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartInfo {
    pub device: String,
    pub paired: bool,
    pub other_device: Option<String>,
    pub pipe_set: bool,
    pub pipe_kind: Option<String>,
    pub browser: Option<String>,
    pub profile_found: bool,
}

/// A progress beat during a move: `frac` runs 0 to 1, always in order within one move.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Progress {
    pub frac: f64,
    pub line: String,
    pub step: String,
}

/// The answer to "show me a code" on the device that starts pairing.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShowCode {
    pub code: String,
    pub this_device: String,
}

/// The outcome of typing a code on the other device.
#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PairOutcome {
    Success {
        #[serde(rename = "otherDevice")]
        other_device: String,
    },
    Wrong {
        #[serde(rename = "triesLeft")]
        tries_left: u32,
    },
    NeedNewCode,
    NoOffer,
}

/// The pipe after `use_pipe`: what kind it is and where the box actually lives.
#[derive(Debug, PartialEq, Serialize)]
pub struct PipeInfo {
    pub kind: String,
    pub place: String,
}

/// One thing that will not move, and why, named by browser.
#[derive(Debug, PartialEq, Serialize)]
pub struct Skipped {
    pub browser: String,
    pub reason: String,
}

/// One route choice for one move: this profile goes to that browser instead of
/// its own. Choosing the profile's own browser is the same as not choosing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteChoice {
    /// The source profile id, as the preview lists it.
    pub profile: String,
    /// The browser it should land in: brave, chrome, chromium, edge, opera.
    pub browser: String,
}

/// One profile in the preview: what would move, and where it would go.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfilePreview {
    pub id: String,
    /// The profile's slot (folder name) in its own browser: Default, Profile 1.
    pub slot: String,
    pub name: String,
    pub logins: u64,
    pub passwords: u64,
    pub cookies: u64,
    pub extensions: u64,
    pub bookmarks: u64,
    pub history: u64,
    /// Seen for the first time: not in any finished move yet.
    pub is_new: bool,
    /// Left out of the last finished move.
    pub remembered_excluded: bool,
    /// Left out of the move being previewed (the shell's current unticks):
    /// counted on its row, but out of the totals.
    pub excluded: bool,
    /// In the move being previewed: not left out by the shell now and not
    /// remembered as left out. The shell renders its tick from this.
    pub ticked: bool,
    /// The browser this profile is headed to in the previewed move (its own
    /// browser when no route is chosen).
    pub destination: String,
    /// True when `destination` is a chosen route, not the default.
    pub routed: bool,
}

/// One browser's part of the preview. Totals count its profiles only.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPreview {
    /// Short browser name.
    pub name: String,
    pub display: String,
    pub logins: u64,
    pub passwords: u64,
    pub cookies: u64,
    pub extensions: u64,
    pub bookmarks: u64,
    pub history: u64,
    /// What this browser holds that would not move, named plainly.
    pub skipped: Vec<Skipped>,
    pub profiles: Vec<ProfilePreview>,
}

/// A browser the person can send a profile to in this move.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteTarget {
    /// Short browser name.
    pub name: String,
    pub display: String,
    /// False when Move It cannot read that browser's password on this system yet:
    /// a profile sent there fails with the reason; the rest of the move still runs.
    pub available: bool,
    pub reason: Option<String>,
}

/// A profile waiting in shared storage from the other device.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArrivingProfile {
    pub id: String,
    pub name: String,
    pub from_browser: String,
    pub from_browser_display: String,
    pub from_device: String,
    /// Browser this profile will land in on this move (the receiver's choice).
    pub destination: String,
    pub routed: bool,
    /// When the default is not the browser the profile came from.
    pub destination_note: Option<String>,
}

/// The counts behind the "ready to move" screen: every profile on this device,
/// where each one is headed, and what would not move.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    /// The other device's name, when known.
    pub target: String,
    pub browsers: Vec<BrowserPreview>,
    pub targets: Vec<RouteTarget>,
    /// Profiles the other device left in shared storage, waiting to land here.
    #[serde(default)]
    pub arriving: Vec<ArrivingProfile>,
    /// What would not move anywhere (nothing readable on this device).
    pub skipped: Vec<Skipped>,
}

/// One incoming profile's landing, in a move report: where it went, or why not.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteLine {
    /// The profile's id on the device it came from.
    pub profile: String,
    pub from_browser: String,
    pub to_browser: String,
    /// The profile it landed in, when it landed.
    pub into_profile: Option<String>,
    /// True when the landing profile was created by this move.
    pub created: bool,
    /// "moved" or "failed".
    pub status: String,
    pub reason: Option<String>,
}

/// What one move did.
#[derive(Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveReport {
    pub boxes_read: u64,
    /// Boxes in the shared place that could not be read or opened, or whose
    /// name and contents disagreed: skipped, never fatal to the move.
    #[serde(default)]
    pub boxes_skipped: u64,
    pub cookies: u64,
    /// Existing target cookies no key could decrypt, preserved untouched.
    #[serde(default)]
    pub preserved_cookies: u64,
    pub logins: u64,
    pub history_urls: u64,
    /// Incoming cookies the target already had in a winning copy, kept
    /// rather than moved (the cookie store's `kept_newer`, summed over
    /// every landing). Same meaning as in `LocalMoveReport`.
    #[serde(default)]
    pub already_present_cookies: u64,
    /// Incoming logins the target already had in a winning copy (login
    /// merge skips only, never constraint skips).
    #[serde(default)]
    pub already_present_logins: u64,
    /// History visits that landed (`visits_inserted + visits_updated`),
    /// including visits on urls already present; see `LocalMoveReport`.
    #[serde(default)]
    pub history_visits_moved: u64,
    pub wrote_box: bool,
    /// What this device packed for the other one (including a box already
    /// waiting unchanged in the shared place).
    #[serde(default)]
    pub sent_profiles: u64,
    #[serde(default)]
    pub sent_cookies: u64,
    #[serde(default)]
    pub sent_logins: u64,
    #[serde(default)]
    pub sent_history_urls: u64,
    /// Where each incoming profile landed, or why it did not.
    #[serde(default)]
    pub routes: Vec<RouteLine>,
    /// This device's profiles that could not move, named plainly.
    #[serde(default)]
    pub skipped: Vec<Skipped>,
}

/// The home screen: when the last move finished, and whether it can still be undone.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeState {
    pub last_sync: Option<u64>,
    pub can_undo: bool,
}

/// What `undo_last` did.
#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum UndoOutcome {
    Done,
    Nothing,
    Changed,
}

/// The blocked-state check for the working profile's browser.
#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OpenCheck {
    Blocked { browser: String },
    Clear,
}

/// One browser the same-device move can pick, as the pick screen lists it.
#[derive(Debug, PartialEq, Serialize)]
pub struct BrowserChoice {
    pub browser: String,
    pub display: String,
}

/// One profile in a browser on this device, as the same-device pick screen
/// lists it: the slot (folder name) and what the person calls it.
#[derive(Debug, PartialEq, Serialize)]
pub struct LocalProfileChoice {
    pub slot: String,
    pub name: String,
}

/// The profiles one same-device browser holds, for the pick screen.
#[derive(Debug, PartialEq, Serialize)]
pub struct LocalBrowserProfiles {
    pub browser: String,
    pub display: String,
    pub profiles: Vec<LocalProfileChoice>,
}

/// The counts behind the same-device "ready to move" screen: what would move out
/// of the source browser into the picked target, on this device. `extensions`
/// counts installed extensions, the same count the sync preview shows; how many
/// of them have saved state to carry is only known once the move runs.
#[derive(Debug, PartialEq, Serialize)]
pub struct LocalPreview {
    pub source: String,
    pub target: String,
    pub logins: u64,
    pub passwords: u64,
    pub cookies: u64,
    pub extensions: u64,
    pub bookmarks: u64,
    pub history: u64,
    /// Cookies in the source that are locked to it (App-Bound) and stay behind.
    pub locked_cookies: u64,
    pub skipped: Vec<Skipped>,
}

/// What one same-device move did. `extensions` here counts the extensions whose
/// saved state was carried, which can be fewer than the preview's installed
/// count: an extension with no saved state has nothing to carry.
///
/// The `already_present_*` fields explain a low or zero moved count: they
/// count source rows the target already held in a copy that won the merge
/// (the cookie store's `kept_newer`, and the login store's merge skips
/// only; login constraint skips are a different outcome and are never
/// counted here). `history_urls` counts only urls inserted or updated, so
/// visits that landed on urls the target already had are counted
/// separately in `history_visits_moved` (`visits_inserted +
/// visits_updated`): a visit-only change is not hidden behind a zero
/// `history_urls`. `summary` is the one honest line core stands behind
/// for the whole move; the harness progress stream and the app shell both
/// surface it, so every surface agrees on what happened.
#[derive(Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMoveReport {
    pub source: String,
    pub target: String,
    pub cookies: u64,
    pub logins: u64,
    pub history_urls: u64,
    pub extensions: u64,
    pub locked_cookies: u64,
    /// Existing cookies in the target that no key could decrypt. They were
    /// left byte-for-byte untouched and did not block the move.
    #[serde(default)]
    pub preserved_cookies: u64,
    #[serde(default)]
    pub extension_installs: Vec<crate::extinstall::InstallReport>,
    /// Source cookies the target already had in a winning (newer or
    /// equal) copy, so they were kept rather than moved.
    #[serde(default)]
    pub already_present_cookies: u64,
    /// Source logins the target already had in a winning copy. Merge
    /// skips only: a login refused by a database constraint is not
    /// counted here, because it was not already present.
    #[serde(default)]
    pub already_present_logins: u64,
    /// History visits that landed (`visits_inserted + visits_updated`),
    /// including visits on urls that were already present and so do not
    /// show up in `history_urls`.
    #[serde(default)]
    pub history_visits_moved: u64,
    /// The one-line summary of the move, built by core (see
    /// `local_move_summary`): never an unconditional success line when
    /// nothing was applied to a non-empty source.
    #[serde(default)]
    pub summary: String,
}

/// The honest one-line summary of a same-device move, from the same
/// counts the report carries. A move that applied nothing while the
/// target already held the source rows is a converged success, not an
/// error and not an unexplained "everything moved": it says the target
/// already has all of this. A partial overlap says both halves.
fn local_move_summary(target: &str, moved: u64, already_present: u64) -> String {
    if moved == 0 && already_present > 0 {
        format!("Nothing new to move: {target} already has all of this")
    } else if moved > 0 && already_present > 0 {
        format!("Moved {moved}, already had {already_present}")
    } else if moved == 0 {
        "Nothing to move".to_string()
    } else {
        "Everything moved".to_string()
    }
}

/// The movable counts of one profile, before anyone decides where they go.
#[derive(Debug, Default)]
struct StoreCounts {
    logins: u64,
    passwords: u64,
    cookies: u64,
    extensions: u64,
    bookmarks: u64,
    history: u64,
}

fn skip_reason(browser: &str, e: &Error) -> String {
    match e {
        Error::AppBound => match Platform::current() {
            Platform::Windows => format!(
                "{browser} uses Windows App-Bound protection on some data — close {browser} and try again, or leave that data behind"
            ),
            _ => format!(
                "{browser} has cookies sealed by the browser on Windows (App-Bound, v20); only that Windows install can open them — you can still move the rest"
            ),
        },
        Error::WrongBrowserPassword => match Platform::current() {
            Platform::Linux => format!(
                "Could not unlock {browser} — unlock your login keyring, or open the Flatpak browser once so it can store its key"
            ),
            _ => format!(
                "Could not unlock {browser} — sign in to its system keychain, then try again"
            ),
        },
        Error::KeychainUnavailable(msg) => format!(
            "{browser} keyring is unavailable ({msg}) — unlock the keyring or use --password-store=basic"
        ),
        Error::BrowserOpen => {
            format!("Close {browser} completely, then try again")
        }
        Error::NeverLaunched { browser: name } => {
            format!("Open {name} once on this device, then come back")
        }
        other => format!("{browser}: {other}"),
    }
}

fn locked_logins_skip_message(browser: &str, locked: u64) -> String {
    if Platform::current() == Platform::Windows {
        format!("{locked} saved logins are App-Bound and cannot be moved")
    } else if locked == 1 {
        format!("{browser}: 1 saved password uses a protected format and will stay behind")
    } else {
        format!("{browser}: {locked} saved passwords use a protected format and will stay behind")
    }
}

fn count_cookie_rows(root: &Path, slot: &str) -> u64 {
    let db = paths::cookies_in(root, slot);
    if !db.exists() {
        return 0;
    }
    let Ok((_tmp, copy)) = crate::util::snapshot_db(&db) else { return 0 };
    let Ok(con) = rusqlite::Connection::open(&copy) else { return 0 };
    let Ok(n) = con.query_row("SELECT COUNT(*) FROM cookies", [], |r| r.get::<_, i64>(0)) else {
        return 0;
    };
    n.max(0) as u64
}

/// True when the profile's cookie store holds App-Bound (v20) values. Reads blob labels
/// only, from a snapshot copy, so a running browser is never disturbed.
fn has_app_bound_cookies_in(root: &Path, slot: &str) -> bool {
    let db = paths::cookies_in(root, slot);
    if !db.exists() {
        return false;
    }
    let Ok((_tmp, copy)) = crate::util::snapshot_db(&db) else { return false };
    let Ok(con) = rusqlite::Connection::open(&copy) else { return false };
    let Ok(mut st) = con.prepare("SELECT encrypted_value FROM cookies") else { return false };
    let Ok(rows) = st.query_map([], |r| r.get::<_, Vec<u8>>(0)) else { return false };
    for v in rows.flatten() {
        if crate::oscrypt::encryption_is_app_bound(&v) {
            return true;
        }
    }
    false
}

/// How many of the profile's cookies are locked to the browser itself (App-Bound,
/// v20). Reads blob labels only, from a snapshot copy, so a running browser is
/// never disturbed.
fn local_profile_slot(slot: Option<&str>) -> &str {
    slot.filter(|s| !s.is_empty()).unwrap_or(paths::DEFAULT_SLOT)
}

fn local_kind_id(slot: &str) -> String {
    profile_id("local", slot)
}

fn count_locked_cookies_in(profile_dir: &Path, slot: &str) -> u64 {
    let db = paths::cookies_in(profile_dir, slot);
    if !db.exists() {
        return 0;
    }
    let Ok((_tmp, copy)) = crate::util::snapshot_db(&db) else { return 0 };
    let Ok(con) = rusqlite::Connection::open(&copy) else { return 0 };
    let Ok(mut st) = con.prepare("SELECT encrypted_value FROM cookies") else { return 0 };
    let Ok(rows) = st.query_map([], |r| r.get::<_, Vec<u8>>(0)) else { return 0 };
    rows
        .flatten()
        .filter(|v| crate::oscrypt::encryption_is_app_bound(v))
        .count() as u64
}

/// True when the profile's cookie store holds App-Bound (v20) values.
fn has_app_bound_cookies(profile_dir: &Path) -> bool {
    has_app_bound_cookies_in(profile_dir, paths::DEFAULT_SLOT)
}

fn count_bookmark_urls(bytes: &[u8]) -> u64 {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else { return 0 };
    fn walk(v: &serde_json::Value) -> u64 {
        match v {
            serde_json::Value::Object(m) => {
                let here = u64::from(m.get("type").and_then(|t| t.as_str()) == Some("url"));
                here + m.values().map(walk).sum::<u64>()
            }
            serde_json::Value::Array(a) => a.iter().map(walk).sum(),
            _ => 0,
        }
    }
    walk(&v)
}

/// A box only ever describes the profile its file name names. A named box
/// whose manifest names a different browser or slot is not applied anywhere:
/// the name is the address, the manifest must agree with it. The main box is
/// the working profile's; a manifest that names a profile must name that one.
/// A box belongs to this device when its stable id matches, or (for boxes
/// sealed before ids existed) when it carries no id and the name matches.
/// A box with a different id is another device's, even a same-named one.
fn is_own_box(payload: &Payload, my_id: Option<&str>, my_name: &str) -> bool {
    match payload.manifest.get("origin_id").and_then(|v| v.as_str()) {
        Some(id) => my_id == Some(id),
        None => {
            payload.manifest.get("origin").and_then(|v| v.as_str()) == Some(my_name)
        }
    }
}

fn box_name_matches(
    fname: &str,
    payload: &Payload,
    working: &Option<DetectedProfile>,
) -> bool {
    let get = |k: &str| payload.manifest.get(k).and_then(|v| v.as_str());
    if fname == pipe::BOX_FILE {
        // The main box is the sender's working profile. Cross-device landings
        // are chosen on the receiving device, so the browser named in the
        // manifest need not be this device's working browser. The slot must
        // still agree: a main box naming a non-Default slot wears the working
        // profile's filename, and is refused.
        if let Some(s) = get("profile_slot") {
            if s != paths::DEFAULT_SLOT {
                return false;
            }
        }
        if get("profile_browser").is_some() || working.is_some() {
            return true;
        }
        return false;
    }
    if pipe::is_profile_box(fname) {
        let inner = fname
            .strip_prefix("moveit-box-")
            .and_then(|f| f.strip_suffix(".json"))
            .unwrap_or_default();
        let Some((browser, slug)) = inner.split_once('-') else { return false };
        return match (get("profile_browser"), get("profile_slot")) {
            (Some(b), Some(s)) => {
                b.to_lowercase() == browser && slot_slug(s) == slug
            }
            _ => false,
        };
    }
    true
}

fn payload_digest(p: &Payload) -> Result<String> {
    use sha2::{Digest, Sha256};
    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }
    let mut h = Sha256::new();
    h.update(
        serde_json::to_vec(&serde_json::Value::Object(p.manifest.clone()))
            .map_err(|e| Error::Io(e.to_string()))?,
    );
    for (name, bytes) in &p.ext_files {
        h.update(name.as_bytes());
        h.update(Sha256::digest(bytes));
    }
    if let Some(b) = &p.bookmarks {
        h.update(Sha256::digest(b));
    }
    Ok(hex(&h.finalize()))
}

impl App {
    /// The app is starting: finish any crashed move safely, learn whether the other
    /// device has paired since last time, and say what this device looks like.
    pub fn welcome_start(&mut self) -> Result<StartInfo> {
        let wp = self.working_profile();
        if let Some(p) = &wp {
            if !profile_open(p) { txn::recover(&p.dir)?; }
        }
        // A crashed multi-profile move can leave a half-applied transaction in any
        // browser's folder, not just the working one. Those recoveries are best
        // effort: one bad folder must not stop the app from opening.
        let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
        if let Some(p) = &wp {
            seen.insert(p.dir.clone());
        }
        for sp in self.source_profiles() {
            if seen.insert(sp.root.clone()) && !root_open(&sp.root) {
                let _ = txn::recover(&sp.root);
            }
        }
        if let Some(rec) = self.load_last_move() {
            for r in &rec.roots {
                if seen.insert(PathBuf::from(&r.root)) && !root_open(Path::new(&r.root)) {
                    let _ = txn::recover(Path::new(&r.root));
                }
            }
        }
        // A same-device move can leave an unfinished journal in any browser on
        // this device, not just the working one. Put those back too, best
        // effort: only a profile that actually has an unfinished journal is
        // touched, and only while its browser is closed. A running browser
        // keeps its stores; picking it for a move recovers it again, strictly.
        let mut extra: Vec<DetectedProfile> = Vec::new();
        for p in self.local_profiles.iter().chain(self.detected().iter()) {
            if wp.as_ref().map(|w| &w.dir) != Some(&p.dir) && !extra.iter().any(|e| e.dir == p.dir) {
                extra.push(p.clone());
            }
        }
        for p in extra {
            if txn::has_unfinished(&p.dir) && !profile_open(&p) {
                let _ = txn::recover(&p.dir);
            }
        }
        let mut other = self.config.other_device.clone();
        if let (Some(key), Some(place)) = (self.load_key()?, self.place_path()) {
            if let Some(name) = pairing::check_paired(&place, &key)? {
                other = Some(name);
            }
        }
        if other != self.config.other_device {
            self.config.other_device = other.clone();
            self.save_config()?;
        }
        Ok(StartInfo {
            device: self.device_name(),
            paired: self.load_key()?.is_some(),
            other_device: other,
            pipe_set: self.config.pipe_path.is_some(),
            pipe_kind: self.config.pipe_kind.clone(),
            browser: wp.as_ref().map(|p| p.display.clone()),
            profile_found: wp.is_some(),
        })
    }

    /// Start pairing from this device: make a sync key if there is none, show a code,
    /// and leave the offer where the other device will find it.
    pub fn pair_show_code(&mut self) -> Result<ShowCode> {
        let p = self.require_pipe()?;
        let _ = self.device_id()?;
        p.refresh()?;
        let key = match self.load_key()? {
            Some(k) => k,
            None => {
                let k = SyncKey::generate()?;
                self.store_key(&k)?;
                k
            }
        };
        let code = pairing::new_code(6)?;
        pairing::offer(p.place(), &key, &code, &self.device_name())?;
        p.publish(&self.device_name())?;
        Ok(ShowCode { code: pairing::display_code(&code), this_device: self.device_name() })
    }

    /// Type the code the other device is showing.
    pub fn pair_enter_code(&mut self, code: &str) -> Result<PairOutcome> {
        let p = self.require_pipe()?;
        p.refresh()?;
        let from = match pairing::look(p.place())? {
            pairing::Found::Nothing => return Ok(PairOutcome::NoOffer),
            pairing::Found::Expired => return Ok(PairOutcome::NeedNewCode),
            pairing::Found::Waiting { from } => from,
        };
        let tries = pairing::Tries { path: self.state_dir.join(TRIES_FILE) };
        let _ = self.device_id()?;
        match pairing::accept_and_store(p.place(), code, &self.device_name(), &tries, &|key| self.store_key(key))? {
            pairing::Accept::Paired(key) => {
                self.config.other_device = Some(from.clone());
                self.save_config()?;
                // The note is best-effort: losing it only means A learns
                // on its next start instead.
                let _ = pairing::leave_paired_note(p.place(), &key, &self.device_name());
                // Tell the other device right away; losing a race is fine, it learns on
                // its next start instead.
                let _ = p.publish(&self.device_name());
                Ok(PairOutcome::Success { other_device: from })
            }
            pairing::Accept::WrongCode { tries_left } => Ok(PairOutcome::Wrong { tries_left }),
            pairing::Accept::NeedNewCode => Ok(PairOutcome::NeedNewCode),
            pairing::Accept::Nothing => Ok(PairOutcome::NoOffer),
        }
    }

    /// Point Move It at the place both devices reach: a folder a sync app keeps in step,
    /// or a git clone. Validates the place and writes the config; the native folder
    /// dialog itself is the shell's job.
    pub fn use_pipe(&mut self, path: &Path) -> Result<PipeInfo> {
        let (kind, place) = if path.join(".git").exists() {
            let g = pipe::GitPipe::new(path)?;
            ("git".to_string(), g.place().to_path_buf())
        } else {
            let f = pipe::FolderPipe::new(path)?;
            ("folder".to_string(), f.place().to_path_buf())
        };
        self.config.pipe_kind = Some(kind.clone());
        self.config.pipe_path = Some(path.to_string_lossy().into_owned());
        self.config.pipe_byok = None;
        self.save_config()?;
        Ok(PipeInfo { kind, place: place.to_string_lossy().into_owned() })
    }

    /// Count what would move out of every profile on this device, and name honestly
    /// what would not. `excluded` and `routes` are the shell's current choices:
    /// the totals count only profiles that would actually move, each profile
    /// reports where it is headed, and the same invalid combinations `move_start`
    /// refuses (a route for a left-out profile, an unknown id) refuse here too,
    /// so the screen never promises a move the engine will not run. Read-only:
    /// nothing in any profile is changed.
    pub fn preview_counts(&mut self, excluded: &[String], routes: &[RouteChoice]) -> Result<Preview> {
        let sources = self.source_profiles();
        let targets = route_targets(self);
        let mut arriving = Vec::new();
        if let Ok(Some(key)) = self.load_key() {
            if let Ok(p) = self.require_pipe() {
                let my_id = self.device_id()?;
                let device = self.device_name();
                let peek = scan_incoming_boxes(self, p.as_ref(), &key, &my_id, &device)?;
                for inc in peek {
                    let (destination, destination_note) =
                        default_incoming_destination(&inc.src_browser, &targets);
                    arriving.push(ArrivingProfile {
                        id: inc.id(),
                        name: inc.src_name.clone(),
                        from_browser: inc.src_browser.clone(),
                        from_browser_display: browser_display(&inc.src_browser),
                        from_device: inc.origin.clone(),
                        destination,
                        routed: false,
                        destination_note,
                    });
                }
                let route_map = validate_incoming_routes(&arriving, routes)?;
                for ap in &mut arriving {
                    if let Some(d) = route_map.get(&ap.id) {
                        ap.destination = d.clone();
                        ap.routed = d != &ap.from_browser;
                        if ap.routed {
                            ap.destination_note = None;
                        }
                    }
                }
            }
        }
        let excluded_set: BTreeSet<&str> = excluded.iter().map(String::as_str).collect();
        // The remembered unticks apply on top of the shell's current set: a
        // profile left out of the last finished move starts this preview out
        // too, until a move runs with it back in.
        let remembered_set: BTreeSet<&str> =
            self.config.excluded_profiles.iter().map(String::as_str).collect();
        let no_profiles = sources.is_empty() && arriving.is_empty();
        let mut out = Preview {
            target: self.config.other_device.clone().unwrap_or_default(),
            browsers: Vec::new(),
            targets,
            arriving,
            skipped: Vec::new(),
        };
        if no_profiles {
            out.skipped.push(Skipped {
                browser: String::new(),
                reason: "no browser profile was found on this device".into(),
            });
            return Ok(out);
        }
        for name in FAMILY {
            let group: Vec<&SourceProfile> =
                sources.iter().filter(|s| s.browser == name).collect();
            if group.is_empty() {
                continue;
            }
            let display = browser_display(name);
            let mut bp = BrowserPreview {
                name: name.to_string(),
                display: display.clone(),
                logins: 0,
                passwords: 0,
                cookies: 0,
                extensions: 0,
                bookmarks: 0,
                history: 0,
                skipped: Vec::new(),
                profiles: Vec::new(),
            };
            for sp in group {
                let (mut pp, mut sk) = self.count_profile(sp);
                pp.destination = sp.browser.clone();
                pp.routed = false;
                pp.excluded = excluded_set.contains(sp.id.as_str());
                pp.ticked = !pp.excluded && !remembered_set.contains(sp.id.as_str());
                if pp.ticked {
                    bp.logins += pp.logins;
                    bp.passwords += pp.passwords;
                    bp.cookies += pp.cookies;
                    bp.extensions += pp.extensions;
                    bp.bookmarks += pp.bookmarks;
                    bp.history += pp.history;
                    bp.skipped.append(&mut sk);
                }
                bp.profiles.push(pp);
            }
            out.browsers.push(bp);
        }
        Ok(out)
    }

    /// One profile's preview counts, plus what in it would not move.
    fn count_profile(&self, sp: &SourceProfile) -> (ProfilePreview, Vec<Skipped>) {
        let display = browser_display(&sp.browser);
        let mut skipped: Vec<Skipped> = Vec::new();
        let mut pp = ProfilePreview {
            id: sp.id.clone(),
            slot: sp.slot.clone(),
            name: sp.name.clone(),
            logins: 0,
            passwords: 0,
            cookies: 0,
            extensions: 0,
            bookmarks: 0,
            history: 0,
            is_new: !self.config.known_profiles.contains(&sp.id),
            remembered_excluded: self.config.excluded_profiles.contains(&sp.id),
            excluded: false,
            ticked: true,
            destination: sp.browser.clone(),
            routed: false,
        };
        if paths::never_launched(&sp.root, &sp.slot) {
            skipped.push(Skipped {
                browser: display.clone(),
                reason: skip_reason(
                    &display,
                    &Error::NeverLaunched {
                        browser: display.clone(),
                    },
                ),
            });
            return (pp, skipped);
        }
        pp.cookies = count_cookie_rows(&sp.root, &sp.slot);
        match self.keys_for_at(&sp.browser, Some(&sp.root)) {
            Ok(keys) => {
                match logins::export_counted(&paths::login_data_in(&sp.root, &sp.slot), &keys) {
                    Ok((found, locked)) => {
                        if locked > 0 {
                            skipped.push(Skipped {
                                browser: display.clone(),
                                reason: locked_logins_skip_message(&display, locked as u64),
                            });
                        }
                        pp.logins = found.len() as u64;
                        pp.passwords =
                            found.iter().filter(|l| !l.password_value.is_empty()).count() as u64;
                    }
                    Err(e) => skipped.push(Skipped {
                        browser: display.clone(),
                        reason: skip_reason(&display, &e),
                    }),
                }
                if pp.cookies > 0 {
                    let cookie_path = paths::cookies_in(&sp.root, &sp.slot);
                    match crate::cookies::export(&cookie_path, &keys) {
                        Ok(moved) => pp.cookies = moved.len() as u64,
                        Err(e) => skipped.push(Skipped {
                            browser: display.clone(),
                            reason: skip_reason(&display, &e),
                        }),
                    }
                }
            }
            Err(e) => skipped.push(Skipped {
                browser: display.clone(),
                reason: skip_reason(&display, &e),
            }),
        }
        match history::export(&paths::history_in(&sp.root, &sp.slot)) {
            Ok(section) => pp.history = section.urls.len() as u64,
            Err(e) => skipped.push(Skipped {
                browser: display.clone(),
                reason: skip_reason(&display, &e),
            }),
        }
        match bookmarks::export(&paths::bookmarks_in(&sp.root, &sp.slot)) {
            Ok((_m, bytes)) => {
                pp.bookmarks = bytes.as_deref().map(count_bookmark_urls).unwrap_or(0);
            }
            Err(e) => skipped.push(Skipped {
                browser: display.clone(),
                reason: skip_reason(&display, &e),
            }),
        }
        match extstate::installed_extension_ids_in(&sp.root, &sp.slot) {
            Ok(ids) => pp.extensions = ids.len() as u64,
            Err(e) => skipped.push(Skipped {
                browser: display.clone(),
                reason: skip_reason(&display, &e),
            }),
        }
        // Cookies are not in the counts, but a profile whose cookies are locked to
        // its own browser belongs on the skipped list.
        if has_app_bound_cookies_in(&sp.root, &sp.slot) {
            skipped.push(Skipped {
                browser: display.clone(),
                reason: skip_reason(&display, &Error::AppBound),
            });
        }
        (pp, skipped)
    }

    /// One move: bring in what the other device sent, land each incoming profile
    /// where this move says it goes, seal this device's profiles and leave them in
    /// the shared place. `excluded` profiles sit the move out entirely: they are
    /// not sealed, and an incoming profile headed for one is not applied either.
    /// `routes` sends a profile to a different browser, where it lands as a fresh
    /// profile of that browser. A profile that fails (its destination browser is
    /// open, its password unreadable) fails on its own line in the report; the
    /// rest of the move still runs. Progress beats arrive in order; the last one
    /// is always the `done` step at 1.0.
    pub fn move_start(
        &mut self,
        excluded: Option<&[String]>,
        routes: &[RouteChoice],
        profile_kinds: Option<&ProfileKinds>,
        on: &mut dyn FnMut(Progress),
    ) -> Result<MoveReport> {
        if let Some(m) = profile_kinds {
            for list in m.values() {
                validate_kinds(Some(list.as_slice()))?;
            }
        }
        let key = self
            .load_key()?
            .ok_or_else(|| Error::Refused("this device is not paired yet".into()))?;
        let p = self.require_pipe()?;
        let my_id = self.device_id()?;
        let sources = self.source_profiles();
        // No explicit set: the remembered unticks are the set. An explicit
        // set is validated the same way the preview validates it.
        let effective: Vec<String> = match excluded {
            Some(list) => list.to_vec(),
            None => self.config.excluded_profiles.clone(),
        };
        let excluded_set: BTreeSet<&str> = effective.iter().map(String::as_str).collect();
        // Never-launched first among profile work: a profile with no Cookies and
        // no Login Data was never opened. Refuse before the move lock, browser
        // keys, recover, or any plant. (Pairing/sync key load above only touches
        // app state, not browser profile stores.)
        for sp in &sources {
            if excluded_set.contains(sp.id.as_str()) {
                continue;
            }
            if paths::never_launched(&sp.root, &sp.slot) {
                return Err(Error::NeverLaunched {
                    browser: browser_display(&sp.browser),
                });
            }
        }
        let _move_lock = MoveLock::take(&self.state_dir)?;
        // A move never runs against a browser that is open on this device:
        // every browser folder this move could seal from is checked before
        // anything is touched, and the folders it lands in are checked again
        // once the landings are planned.
        let mut checked_roots: BTreeSet<PathBuf> = BTreeSet::new();
        for sp in &sources {
            if checked_roots.insert(sp.root.clone()) && root_open(&sp.root) {
                return Err(Error::BrowserOpen);
            }
        }
        // A crashed earlier move may have left a transaction unfinished in
        // any of these folders; put it back before reading or writing. Best
        // effort: one bad folder must not stop the move.
        for root in &checked_roots {
            let _ = txn::recover(root);
        }
        let device = self.device_name();
        let working = self.working_profile();
        let mut report = MoveReport::default();
        let mut landed_roots: BTreeSet<PathBuf> = BTreeSet::new();
        let mut landed_book = self.load_landed();
        let mut landed_dirty = false;
        let mut publish_err: Option<Error> = None;
        let mut seal_err: Option<Error> = None;
        // Browsers this move actually read from (their password was
        // readable): only they take part, for what the move remembers.
        let mut took_part: BTreeSet<String> = BTreeSet::new();
        let landing_targets = route_targets(self);
        let mut incoming_route_map: Option<BTreeMap<String, String>> = None;

        // A push that loses a race earns exactly one more round (refresh, merge, send).
        for round in 0..2 {
            report = MoveReport::default();
            seal_err = None;
            took_part.clear();
            on(Progress { frac: 0.05, step: "refresh".into(), line: "Checking the place your devices share".into() });
            p.refresh()?;
            // The paired note is read exactly once, so a name learned here is saved at
            // once: a later failure in this move must not lose it.
            if let Some(name) = pairing::check_paired(p.place(), &key)? {
                if self.config.other_device.as_deref() != Some(name.as_str()) {
                    self.config.other_device = Some(name);
                    self.save_config()?;
                }
            }

            on(Progress { frac: 0.15, step: "read".into(), line: "Reading what your other device sent".into() });
            let mut digests: BTreeMap<String, String> = BTreeMap::new();
            let mut candidates: Vec<Incoming> = Vec::new();
            for box_path in p.boxes()? {
                let fname = box_path
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let opened = std::fs::read(&box_path)
                    .map_err(io)
                    .and_then(|bytes| engine::open_box(&bytes, &key));
                let payload = match opened {
                    Ok(p) => p,
                    Err(_) => {
                        report.boxes_skipped += 1;
                        continue;
                    }
                };
                if !box_name_matches(&fname, &payload, &working) {
                    report.boxes_skipped += 1;
                    continue;
                }
                match payload_digest(&payload) {
                    Ok(d) => {
                        digests.insert(fname, d);
                    }
                    Err(_) => {
                        report.boxes_skipped += 1;
                        continue;
                    }
                }
                if is_own_box(&payload, Some(&my_id), &device) {
                    continue; // our own box coming back around; nothing to apply
                }
                candidates.push(Incoming::from_payload(payload, &working));
            }
            if incoming_route_map.is_none() {
                let arriving: Vec<ArrivingProfile> = candidates
                    .iter()
                    .map(|inc| {
                        let (destination, destination_note) =
                            default_incoming_destination(&inc.src_browser, &landing_targets);
                        ArrivingProfile {
                            id: inc.id(),
                            name: inc.src_name.clone(),
                            from_browser: inc.src_browser.clone(),
                            from_browser_display: browser_display(&inc.src_browser),
                            from_device: inc.origin.clone(),
                            destination,
                            routed: false,
                            destination_note,
                        }
                    })
                    .collect();
                incoming_route_map = Some(validate_incoming_routes(&arriving, routes)?);
            }
            let route_map = incoming_route_map.as_ref().expect("incoming routes validated once");
            let mut incoming = Vec::new();
            let mut admit_failures: Vec<RouteLine> = Vec::new();
            for inc in candidates {
                if incoming_admits(&inc, &sources, route_map, self) {
                    incoming.push(inc);
                } else {
                    report.boxes_skipped += 1;
                    admit_failures.push(RouteLine {
                        profile: inc.id(),
                        from_browser: inc.src_browser.clone(),
                        to_browser: inc.src_browser.clone(),
                        into_profile: None,
                        created: false,
                        status: "failed".into(),
                        reason: Some(format!(
                            "{} is not on this computer",
                            browser_display(&inc.src_browser)
                        )),
                    });
                }
            }

            // Plan the landings: group the jobs by destination root, so each
            // browser's folder is written once, under one transaction.
            // Meta per job: (incoming index, profile id, source browser, origin
            // device, source slot, planned as a fresh landing).
            type JobMeta = (usize, String, String, String, String, bool);
            let mut groups: BTreeMap<String, (String, PathBuf, Vec<(JobMeta, engine::Job<'_>)>)> =
                BTreeMap::new();
            let mut lines: BTreeMap<usize, RouteLine> = BTreeMap::new();
            for (i, inc) in incoming.iter().enumerate() {
                let dest = route_map
                    .get(&inc.id())
                    .cloned()
                    .unwrap_or_else(|| inc.src_browser.clone());
                let routed = dest != inc.src_browser;
                let fail = |lines: &mut BTreeMap<usize, RouteLine>, reason: String| {
                    lines.insert(i, RouteLine {
                        profile: inc.id(),
                        from_browser: inc.src_browser.clone(),
                        to_browser: dest.clone(),
                        into_profile: None,
                        created: false,
                        status: "failed".into(),
                        reason: Some(reason),
                    });
                };
                if !inc.slot_ok {
                    fail(&mut lines, "the box names a profile Move It will not write to".into());
                    continue;
                }
                if !FAMILY.contains(&dest.as_str()) {
                    fail(&mut lines, format!("{dest} is not one of the browsers Move It moves between"));
                    continue;
                }
                let Some(root) = self.dest_root(&dest) else {
                    fail(&mut lines, format!("there is no {} folder on this device", browser_display(&dest)));
                    continue;
                };
                let (target, was_fresh) =
                    incoming_landing_target(
                        inc,
                        routed,
                        &root,
                        &landed_book,
                        crate::browsers::by_id(&dest)
                            .is_some_and(|d| d.layout == crate::browsers::LayoutKind::SingleProfile),
                    );
                if let engine::Target::Slot(slot) = &target {
                    if paths::slot_dir(&root, slot).is_dir() && paths::never_launched(&root, slot) {
                        fail(
                            &mut lines,
                            format!(
                                "Open {} once on this device, then try again",
                                browser_display(&dest)
                            ),
                        );
                        continue;
                    }
                }
                groups
                    .entry(root.to_string_lossy().into_owned())
                    .or_insert_with(|| (dest.clone(), root.clone(), Vec::new()))
                    .2
                    .push((
                        (i, inc.id(), inc.src_browser.clone(), inc.origin_key.clone(), inc.src_slot.clone(), was_fresh),
                        engine::Job { target, payload: &inc.payload },
                    ));
            }

            if !groups.is_empty() {
                for (_k, (_dest, root, _grouped)) in &groups {
                    let _ = txn::recover(root);
                }
                on(Progress { frac: 0.45, step: "apply".into(), line: "Moving your other device's profiles in".into() });
            }
            for (_k, (dest, root, grouped)) in groups {
                let display = browser_display(&dest);
                let (meta, job_list): (Vec<JobMeta>, Vec<engine::Job>) =
                    grouped.into_iter().unzip();
                let fail_all = |lines: &mut BTreeMap<usize, RouteLine>, reason: String| {
                    for (i, id, src, ..) in &meta {
                        lines.insert(*i, RouteLine {
                            profile: id.clone(),
                            from_browser: src.clone(),
                            to_browser: dest.clone(),
                            into_profile: None,
                            created: false,
                            status: "failed".into(),
                            reason: Some(reason.clone()),
                        });
                    }
                };
                // Never write into a running browser: it holds its databases
                // open and would overwrite or corrupt what we land. This
                // profile fails on its own line; the rest of the move runs.
                if root_open(&root) {
                    fail_all(&mut lines, format!("{display} is open on this device; close it and try again"));
                    continue;
                }
                let keys = match self.keys_for(&dest) {
                    Ok(k) => k,
                    Err(e) => {
                        fail_all(&mut lines, skip_reason(&display, &e));
                        continue;
                    }
                };
                let previous = if landed_roots.contains(&root) { current_undo_point(&root) } else { None };
                match engine::import_many_preserving(
                    &root,
                    &keys,
                    HostTag::Without,
                    &job_list,
                    now_micros(),
                    previous.as_deref(),
                    dest.as_str(),
                    &display,
                ) {
                    Ok(landed) => {
                        landed_roots.insert(root.clone());
                        for ((i, id, src, origin, src_slot, was_fresh), l) in
                            meta.iter().zip(landed.iter())
                        {
                            if *was_fresh && l.created {
                                landed_book.record(origin, src, src_slot, &root, &l.slot);
                                landed_dirty = true;
                            }
                            report.boxes_read += 1;
                            report.cookies += l.applied.cookies.imported as u64;
                            report.preserved_cookies +=
                                l.applied.cookies.preserved_undecryptable as u64;
                            report.already_present_cookies +=
                                l.applied.cookies.kept_newer as u64;
                            report.logins +=
                                (l.applied.logins.inserted + l.applied.logins.updated) as u64;
                            report.already_present_logins +=
                                l.applied.logins.already_present as u64;
                            if let Some(h) = &l.applied.history {
                                report.history_urls += (h.urls_inserted + h.urls_updated) as u64;
                                report.history_visits_moved +=
                                    (h.visits_inserted + h.visits_updated) as u64;
                            }
                            let into_profile = if l.slot == paths::SINGLE_SLOT {
                                // "Single" is the engine's name for the
                                // one profile a single-profile browser
                                // holds, not a profile name a person would
                                // recognise: report that profile's own
                                // name, as listed from the landed root.
                                profiles::list_slots_for(
                                    &root,
                                    crate::browsers::LayoutKind::SingleProfile,
                                )
                                .into_iter()
                                .next()
                                .map(|s| s.display)
                                .unwrap_or_else(|| display.clone())
                            } else {
                                l.slot.clone()
                            };
                            lines.insert(*i, RouteLine {
                                profile: id.clone(),
                                from_browser: src.clone(),
                                to_browser: dest.clone(),
                                into_profile: Some(into_profile),
                                created: l.created,
                                status: "moved".into(),
                                reason: None,
                            });
                        }
                        self.record_landings(&landed_roots, &landed_book)?;
                    }
                    Err(e) => fail_all(&mut lines, skip_reason(&display, &e)),
                }
            }
            admit_failures.extend(lines.into_values());
            report.routes = admit_failures;

            for sp in &sources {
                if excluded_set.contains(sp.id.as_str()) {
                    let is_working = working.as_ref().is_some_and(|w| {
                        w.browser == sp.browser
                            && w.dir == sp.root
                            && sp.slot == paths::DEFAULT_SLOT
                    });
                let fname = if is_working {
                        pipe::BOX_FILE.to_string()
                    } else {
                        pipe::profile_box_name(&sp.browser, &slot_slug(&sp.slot))
                    };
                    self.withdraw_box(p.place(), &fname, sp, &key, Some(&my_id), &device);
                }
            }
            self.withdraw_stale_boxes(p.place(), &key, &sources, Some(&my_id), &device);

            on(Progress { frac: 0.7, step: "seal".into(), line: "Sealing your browsers into the box".into() });
            let mut any_write = false;
            for sp in &sources {
                if excluded_set.contains(sp.id.as_str()) {
                    continue;
                }
                let display = browser_display(&sp.browser);
                let keys = match self.keys_for(&sp.browser) {
                    Ok(k) => k,
                    Err(e) => {
                        report.skipped.push(Skipped {
                            browser: display.clone(),
                            reason: skip_reason(&display, &e),
                        });
                        continue;
                    }
                };
                let prof = engine::Profile {
                    dir: &sp.root,
                    slot: &sp.slot,
                    keys: &keys,
                    login_tag: HostTag::Without,
                    browser: &sp.browser,
                    display: &display,
                };
                let pk = kinds_for_profile(profile_kinds, &sp.id);
                let mut payload = match engine::export(&prof, &device, pk) {
                    Ok(p) => {
                        took_part.insert(sp.browser.clone());
                        for source in sources.iter().filter(|s| s.browser == sp.browser) {
                            if !self.config.known_profiles.contains(&source.id) {
                                self.config.known_profiles.push(source.id.clone());
                            }
                        }
                        self.config.excluded_profiles.retain(|id| id.split(':').next() != Some(sp.browser.as_str()));
                        self.config.excluded_profiles.extend(effective.iter()
                            .filter(|id| id.split(':').next() == Some(sp.browser.as_str())).cloned());
                        self.save_config()?;
                        p
                    }
                    Err(e) => {
                        // The siblings still seal; the failure itself is
                        // reported as the move's error once the rest has run,
                        // never hidden behind a success.
                        report.skipped.push(Skipped {
                            browser: display.clone(),
                            reason: skip_reason(&display, &e),
                        });
                        if seal_err.is_none() {
                            seal_err = Some(e);
                        }
                        continue;
                    }
                };
                if let Some(locked) = payload.manifest.get("skipped_logins").and_then(serde_json::Value::as_u64).filter(|n| *n > 0) {
                    report.skipped.push(Skipped { browser: display.clone(), reason: format!("{locked} saved logins are App-Bound and cannot be moved") });
                }
                payload.manifest.insert("origin_id".into(), my_id.clone().into());
                payload.manifest.insert("profile_browser".into(), sp.browser.clone().into());
                payload.manifest.insert("profile_slot".into(), sp.slot.clone().into());
                payload.manifest.insert("profile_name".into(), sp.name.clone().into());
                // The working profile is its root's Default slot; a sibling slot
                // in the same folder is a different profile with its own box.
                let is_working = working.as_ref().is_some_and(|w| {
                    w.browser == sp.browser
                        && w.dir == sp.root
                        && sp.slot == paths::DEFAULT_SLOT
                });
                let fname = if is_working {
                    pipe::BOX_FILE.to_string()
                } else {
                    pipe::profile_box_name(&sp.browser, &slot_slug(&sp.slot))
                };
                let arr_len = |k: &str| payload.manifest.get(k).and_then(serde_json::Value::as_array).map_or(0, |a| a.len() as u64);
                report.sent_profiles += 1;
                report.sent_cookies += arr_len("cookies");
                report.sent_logins += arr_len("passwords");
                report.sent_history_urls += payload.manifest.get("history").and_then(|h| h.get("urls")).and_then(serde_json::Value::as_array).map_or(0, |a| a.len() as u64);
                let digest = payload_digest(&payload)?;
                if digests.get(&fname).is_some_and(|d| d == &digest) {
                    continue; // the pipe already holds exactly this profile
                }
                let env = crate::sealed::seal(&payload, &key)?;
                let bytes = serde_json::to_vec(&env).map_err(|e| Error::Io(e.to_string()))?;
                pipe::write_named_box(p.place(), &fname, &bytes)?;
                any_write = true;
            }
            if any_write {
                on(Progress { frac: 0.85, step: "send".into(), line: "Leaving the sealed boxes for your other device".into() });
                report.wrote_box = true;
            }

            match p.publish(&device) {
                Ok(()) => break,
                Err(Error::Busy) if round == 0 => continue,
                Err(e) => {
                    publish_err = Some(e);
                    break;
                }
            }
        }
        // The landings are committed in the browser folders whatever the pipe
        // did afterwards, so the records that describe them are written before
        // any error is reported: undo and the landed homes must be true even
        // when the move could not finish sending.
        // The undo record names THIS move's undo points: one move, one undo,
        // across every browser it landed profiles in. A move that tried to
        // land profiles and landed none leaves an empty record on purpose:
        // undo must never quietly reach back past it to an older move (and
        // the empty record, not a missing one, is what stops the legacy
        // working-profile path from doing exactly that). A move where
        // nothing arrived at all leaves the record as it was.
        if landed_roots.is_empty() {
            if report.routes.iter().any(|l| l.status == "failed") {
                self.save_last_move(&LastMove { roots: Vec::new() })?;
            }
        } else {
            let rec = LastMove {
                roots: landed_roots
                    .iter()
                    .filter_map(|r| {
                        current_undo_point(r).map(|t| LastMoveRoot {
                            root: r.to_string_lossy().into_owned(),
                            txn: t,
                        })
                    })
                    .collect(),
            };
            self.save_last_move(&rec)?;
        }
        if landed_dirty {
            self.save_landed(&landed_book)?;
        }
        let _ = pipe::clear_conflicts(p.place());
        self.config.last_sync_unix = Some(now_secs());
        // A browser this move could not read (its password was not found,
        // or every store failed to open) took no part: its profiles are
        // not absorbed as known, and its remembered unticks are not
        // replaced by this move's set. A browser that was read absorbs
        // all of its profiles, unticked ones included: is_new flags
        // profiles that appear later, not profiles that stayed home.
        for s in &sources {
            if took_part.contains(&s.browser) && !self.config.known_profiles.contains(&s.id) {
                self.config.known_profiles.push(s.id.clone());
            }
        }
        fn browser_of(id: &str) -> &str { id.split(':').next().unwrap_or_default() }
        let mut remembered: Vec<String> = self
            .config
            .excluded_profiles
            .iter()
            .filter(|id| !took_part.contains(browser_of(id)))
            .cloned()
            .collect();
        remembered.extend(
            effective.iter().filter(|id| took_part.contains(browser_of(id))).cloned(),
        );
        self.config.excluded_profiles = remembered;
        self.save_config()?;
        // The move's memory is saved above on purpose: the local work
        // happened even when the send or a seal failed afterwards, and an
        // untick the person made must not be lost with the error.
        if let Some(e) = seal_err {
            self.logs.push(now_secs(), crate::logbuf::Level::Error, &format!("move failed: {e}"));
            return Err(e);
        }
        if let Some(e) = publish_err {
            self.logs.push(now_secs(), crate::logbuf::Level::Error, &format!("move failed: {e}"));
            return Err(e);
        }
        let summary = format!(
            "move finished: {} logins, {} cookies, {} history pages, {} boxes read, {} skipped",
            report.logins, report.cookies, report.history_urls, report.boxes_read, report.boxes_skipped
        );
        self.logs.record_outcome(&summary);
        self.logs.push(now_secs(), crate::logbuf::Level::Info, &summary);
        on(Progress { frac: 1.0, step: "done".into(), line: "Everything is in sync".into() });
        Ok(report)
    }

    /// The home screen state: when the last move finished, and whether it can
    /// still be undone (in whichever browsers it landed profiles in).
    pub fn home_state(&self) -> Result<HomeState> {
        let can_undo = if let Some(rec) = self.load_last_move() {
            rec.roots.iter().any(|r| {
                current_undo_point(Path::new(&r.root)).as_deref() == Some(r.txn.as_str())
            })
        } else {
            match self.working_profile() {
                Some(wp) => txn::can_undo(&wp.dir)?,
                None => false,
            }
        };
        Ok(HomeState { last_sync: self.config.last_sync_unix, can_undo })
    }

    /// Undo the last finished move. A move that landed profiles in several
    /// browsers is undone in all of them, or (without `force`) in none of them
    /// when any of them changed since: the check runs everywhere before the
    /// first restore. A profile that changed anyway is left alone, named by the
    /// outcome, and stays undoable on its own.
    pub fn undo_last(&self, force: bool) -> Result<UndoOutcome> {
        if let Some(rec) = self.load_last_move() {
            // An empty record is a move that landed nothing: there is nothing
            // to undo, and the record stays so this answer does not change.
            if rec.roots.is_empty() {
                return Ok(UndoOutcome::Nothing);
            }
            if rec.roots.iter().any(|r| root_open(Path::new(&r.root))) {
                return Err(Error::BrowserOpen);
            }
            if !force {
                let intact = rec.roots.iter().all(|r| {
                    current_undo_point(Path::new(&r.root)).as_deref() == Some(r.txn.as_str())
                });
                if !intact {
                    return Ok(UndoOutcome::Changed);
                }
            }
            let mut remaining = rec.roots.clone();
            let mut any_done = false;
            let mut any_changed = false;
            for (i, r) in rec.roots.iter().enumerate().rev() {
                match txn::undo_last(Path::new(&r.root), force)? {
                    txn::Undo::Done => { any_done = true; remaining.remove(i); }
                    txn::Undo::Nothing => { remaining.remove(i); }
                    txn::Undo::ChangedSince => {
                        any_changed = true;
                    }
                }
                self.save_last_move(&LastMove { roots: remaining.clone() })?;
            }
            if remaining.is_empty() {
                self.clear_last_move();
            } else {
                self.save_last_move(&LastMove { roots: remaining })?;
            }
            return Ok(if any_changed {
                UndoOutcome::Changed
            } else if any_done {
                UndoOutcome::Done
            } else {
                UndoOutcome::Nothing
            });
        }
        let wp = self.require_profile()?;
        if root_open(&wp.dir) {
            return Err(Error::BrowserOpen);
        }
        Ok(match txn::undo_last(&wp.dir, force)? {
            txn::Undo::Done => UndoOutcome::Done,
            txn::Undo::Nothing => UndoOutcome::Nothing,
            txn::Undo::ChangedSince => UndoOutcome::Changed,
        })
    }

    /// Withdraw one profile's box from the shared place: the profile is left
    /// out of this move, so its shared copy goes away (the browser's own data
    /// is never touched). A file that positively belongs to a different
    /// profile is left alone, and a file that cannot be opened is left alone
    /// too: withdrawing is a courtesy, never a guess.
    fn withdraw_box(
        &self,
        place: &Path,
        file: &str,
        sp: &SourceProfile,
        key: &SyncKey,
        my_id: Option<&str>,
        device: &str,
    ) {
        let path = place.join(file);
        if !path.exists() {
            return;
        }
        let belongs = match std::fs::read(&path) {
            Ok(bytes) => match engine::open_box(&bytes, key) {
                Ok(payload) => {
                    is_own_box(&payload, my_id, device)
                        && match payload.manifest.get("profile_browser") {
                            Some(b) => {
                                b.as_str().map(str::to_lowercase)
                                    == Some(sp.browser.clone())
                                    && payload
                                        .manifest
                                        .get("profile_slot")
                                        .and_then(|v| v.as_str())
                                        == Some(sp.slot.as_str())
                            }
                            None => {
                                file == pipe::BOX_FILE
                                    && sp.slot == paths::DEFAULT_SLOT
                            }
                        }
                }
                Err(_) => false,
            },
            Err(_) => false,
        };
        if belongs {
            let _ = std::fs::remove_file(&path);
        }
    }

    /// Withdraw our own boxes for profiles that no longer exist on this
    /// device (the profile was deleted in the browser after an earlier
    /// move). A box whose last writer is the other device is theirs.
    fn withdraw_stale_boxes(
        &self,
        place: &Path,
        key: &SyncKey,
        sources: &[SourceProfile],
        my_id: Option<&str>,
        device: &str,
    ) {
        let Ok(boxes) = pipe::boxes_in(place) else { return };
        for box_path in boxes {
            let fname = box_path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            if fname == pipe::BOX_FILE || !pipe::is_profile_box(&fname) {
                continue;
            }
            let Ok(bytes) = std::fs::read(&box_path) else { continue };
            let Ok(payload) = engine::open_box(&bytes, key) else { continue };
            if !is_own_box(&payload, my_id, device) {
                continue;
            }
            let (Some(b), Some(s)) = (
                payload.manifest.get("profile_browser").and_then(|v| v.as_str()),
                payload.manifest.get("profile_slot").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let b = b.to_lowercase();
            if sources.iter().any(|sp| sp.browser == b)
                && !sources.iter().any(|sp| sp.browser == b && sp.slot == s)
            {
                let _ = std::fs::remove_file(&box_path);
            }
        }
    }

    /// Is the working profile's browser open right now? Two signals: the browser's own
    /// lock marker with a live process behind it (the recorded pid, or the browser's
    /// host processes when that pid is a sandbox pid), and the store lock canary (a
    /// write lock on the cookie store that only a running browser's database can
    /// refuse).
    /// The newest log lines, oldest first; the Logs screen renders them
    /// newest first.
    pub fn logs_recent(&self, n: usize) -> Vec<crate::logbuf::LogLine> {
        self.logs.recent(n)
    }

    /// The whole log as one text report, ready to save or share.
    pub fn export_logs(&self) -> String {
        self.logs.export(now_secs())
    }

    pub fn browser_open_check(
        &self,
        excluded: &[String],
        routes: &[RouteChoice],
    ) -> Result<OpenCheck> {
        let _ = excluded;
        let mut roots: Vec<PathBuf> = Vec::new();
        if let Some(wp) = self.working_profile() {
            roots.push(wp.dir.clone());
        }
        for r in routes {
            let browser = r.browser.to_lowercase();
            if let Some(root) = self.dest_root(&browser) {
                if !roots.contains(&root) {
                    roots.push(root);
                }
            }
        }
        for root in roots {
            if root_open(&root) {
                let display = self
                    .working_profile()
                    .filter(|w| w.dir == root)
                    .map(|w| w.display.clone())
                    .or_else(|| {
                        routes.iter().find_map(|r| {
                            self.dest_root(&r.browser.to_lowercase()).filter(|d| d == &root).map(|_| {
                                browser_display(&r.browser)
                            })
                        })
                    })
                    .unwrap_or_else(|| "your browser".into());
                return Ok(OpenCheck::Blocked { browser: display });
            }
        }
        Ok(OpenCheck::Clear)
    }

    /// The browser folders the same-device move can pick from, in pick order:
    /// the pinned override first, then registered and detected roots, each
    /// browser once.
    fn local_browser_roots(&self) -> Vec<DetectedProfile> {
        let mut found: Vec<DetectedProfile> = Vec::new();
        if let Some((b, d)) = &self.profile_override {
            found.push(DetectedProfile { browser: b.clone(), display: browser_display(b), dir: d.clone() });
        }
        for p in self.local_profiles.iter().chain(self.detected().iter()) {
            if !found.iter().any(|f| f.browser == p.browser) {
                found.push(p.clone());
            }
        }
        found
    }

    /// The browsers the same-device move can pick from: every profile this device
    /// has, each once, pinned and registered ones first, then detection order.
    pub fn local_browsers(&self) -> Vec<BrowserChoice> {
        self.local_browser_roots()
            .into_iter()
            .map(|p| BrowserChoice { browser: p.browser, display: p.display })
            .collect()
    }

    /// Every profile each same-device browser holds, in the browser's own
    /// order, so the pick screen can ask which profile to move when a
    /// browser has more than one.
    pub fn local_browser_profiles(&self) -> Vec<LocalBrowserProfiles> {
        self.local_browser_roots()
            .into_iter()
            .map(|p| LocalBrowserProfiles {
                profiles: profiles::list_slots_for_browser(&p.dir, &p.browser)
                    .into_iter()
                    .map(|s| LocalProfileChoice { slot: s.name, name: s.display })
                    .collect(),
                browser: p.browser,
                display: p.display,
            })
            .collect()
    }

    /// Count what would move from one of this device's browsers into another, and
    /// name honestly what would not. Read-only: nothing in any profile is changed.
    /// The movable counts of one same-device profile, with every store
    /// that would not read named in the skipped list.
    fn count_stores(&self, prof: &DetectedProfile, slot: &str) -> (StoreCounts, Vec<Skipped>) {
        let mut counts = StoreCounts::default();
        let mut skipped: Vec<Skipped> = Vec::new();
        counts.cookies = count_cookie_rows(&prof.dir, slot);
        match self.keys_for_at(&prof.browser, Some(&prof.dir)) {
            Ok(keys) => {
                match logins::export_counted(&paths::login_data_in(&prof.dir, slot), &keys) {
                    Ok((found, locked)) => {
                        if locked > 0 {
                            skipped.push(Skipped {
                                browser: prof.display.clone(),
                                reason: locked_logins_skip_message(&prof.display, locked as u64),
                            });
                        }
                        counts.logins = found.len() as u64;
                        counts.passwords =
                            found.iter().filter(|l| !l.password_value.is_empty()).count() as u64;
                    }
                    Err(e) => skipped.push(Skipped {
                        browser: prof.display.clone(),
                        reason: skip_reason(&prof.display, &e),
                    }),
                }
                if counts.cookies > 0 {
                    match crate::cookies::export(&paths::cookies_in(&prof.dir, slot), &keys) {
                        Ok(moved) => counts.cookies = moved.len() as u64,
                        Err(e) => skipped.push(Skipped {
                            browser: prof.display.clone(),
                            reason: skip_reason(&prof.display, &e),
                        }),
                    }
                }
            }
            Err(e) => skipped.push(Skipped {
                browser: prof.display.clone(),
                reason: skip_reason(&prof.display, &e),
            }),
        }
        match history::export(&paths::history_in(&prof.dir, slot)) {
            Ok(section) => counts.history = section.urls.len() as u64,
            Err(e) => skipped.push(Skipped {
                browser: prof.display.clone(),
                reason: skip_reason(&prof.display, &e),
            }),
        }
        match bookmarks::export(&paths::bookmarks_in(&prof.dir, slot)) {
            Ok((_m, bytes)) => {
                counts.bookmarks = bytes.as_deref().map(count_bookmark_urls).unwrap_or(0);
            }
            Err(e) => skipped.push(Skipped {
                browser: prof.display.clone(),
                reason: skip_reason(&prof.display, &e),
            }),
        }
        match extstate::installed_extension_ids_in(&prof.dir, slot) {
            Ok(ids) => counts.extensions = ids.len() as u64,
            Err(e) => skipped.push(Skipped {
                browser: prof.display.clone(),
                reason: skip_reason(&prof.display, &e),
            }),
        }
        (counts, skipped)
    }

    pub fn local_preview(
        &self,
        source: &str,
        target: &str,
        source_slot: Option<&str>,
        target_slot: Option<&str>,
    ) -> Result<LocalPreview> {
        let src_slot = local_profile_slot(source_slot);
        let dst_slot = local_profile_slot(target_slot);
        let src = self.require_local_profile(source)?;
        let dst = self.require_local_profile(target)?;
        if src.dir == dst.dir {
            return Err(Error::Refused("a browser cannot move into itself".into()));
        }
        // Never-launched first: touch nothing (no keys, no counts) until both
        // sides have been opened in their browser at least once.
        if paths::never_launched(&src.dir, src_slot) {
            return Err(Error::NeverLaunched {
                browser: src.display.clone(),
            });
        }
        if paths::never_launched(&dst.dir, dst_slot) {
            return Err(Error::NeverLaunched {
                browser: dst.display.clone(),
            });
        }
        // If either browser's own password cannot even be attempted, the move
        // can never start (reading needs the source's keys, writing needs the
        // target's), so refuse here with the same error instead of showing
        // counts that promise a move. The target's bar is the move's own:
        // its key must validate against its v11 rows when it has any,
        // and must never be the fallback.
        self.keys_for(&src.browser)?;
        self.keys_for_local_destination(&dst.browser, &dst.dir, dst_slot)?;
        let (counts, mut skipped) = self.count_stores(&src, src_slot);
        let locked_cookies = count_locked_cookies_in(&src.dir, src_slot);
        if locked_cookies > 0 {
            skipped.push(Skipped {
                browser: src.display.clone(),
                reason: skip_reason(&src.display, &Error::AppBound),
            });
        }
        Ok(LocalPreview {
            source: src.display,
            target: dst.display,
            logins: counts.logins,
            passwords: counts.passwords,
            cookies: counts.cookies,
            extensions: counts.extensions,
            bookmarks: counts.bookmarks,
            history: counts.history,
            locked_cookies,
            skipped,
        })
    }

    /// One same-device move: copy everything movable out of the source browser
    /// into the target browser, on this machine. No pairing, no shared place, no
    /// network: the payload travels in memory from one profile to the other, and
    /// the write into the target is journaled like any move, so it can be undone.
    /// The source is only read. Progress beats arrive in order; the last one is
    /// always the `done` step at 1.0.
    pub fn local_move(
        &mut self,
        source: &str,
        target: &str,
        source_slot: Option<&str>,
        target_slot: Option<&str>,
        profile_kinds: Option<&ProfileKinds>,
        on: &mut dyn FnMut(Progress),
    ) -> Result<LocalMoveReport> {
        if let Some(m) = profile_kinds {
            for list in m.values() {
                validate_kinds(Some(list.as_slice()))?;
            }
        }
        let src_slot = local_profile_slot(source_slot);
        let dst_slot = local_profile_slot(target_slot);
        let src = self.require_local_profile(source)?;
        let dst = self.require_local_profile(target)?;
        if src.dir == dst.dir {
            return Err(Error::Refused("a browser cannot move into itself".into()));
        }
        // Never-launched first: before the lock, keys, recover, or any plant.
        if paths::never_launched(&src.dir, src_slot) {
            return Err(Error::NeverLaunched {
                browser: src.display.clone(),
            });
        }
        if paths::never_launched(&dst.dir, dst_slot) {
            return Err(Error::NeverLaunched {
                browser: dst.display.clone(),
            });
        }
        let _move_lock = MoveLock::take(&self.state_dir)?;
        // The shell routes to the close-it screen through local_open_check; this is
        // the same check inside the move, so a browser opened in between is still
        // never written into.
        if profile_open(&src) || profile_open(&dst) {
            return Err(Error::BrowserOpen);
        }
        let src_keys = self.keys_for(&src.browser)?;
        // The destination key is obtained before anything is read or
        // recovered, under `keys_for_local_destination`'s rule (validated
        // against the destination's v11 rows when it has any, a discovered
        // non-fallback key when it has none): a destination whose key
        // cannot be obtained, or fails that rule, fails the move here,
        // before a single secret is written anywhere.
        let dst_keys = self.keys_for_local_destination(&dst.browser, &dst.dir, dst_slot)?;
        // A crashed earlier move is put back before a new one, on BOTH
        // browsers: the source may itself be the survivor of a crashed move
        // (as an earlier target), and reading it half-moved would carry the
        // damage on. After the key checks and the open check above, so a
        // move that can never start touches nothing.
        txn::recover(&src.dir)?;
        txn::recover(&dst.dir)?;

        on(Progress { frac: 0.1, step: "read".into(), line: format!("Reading {}", src.display) });
        let src_prof = engine::Profile {
            dir: &src.dir,
            slot: src_slot,
            keys: &src_keys,
            login_tag: HostTag::Without,
            browser: &src.browser,
            display: &src.display,
        };
        let pk = kinds_for_profile(profile_kinds, &local_kind_id(src_slot));
        let payload = engine::export(&src_prof, &self.device_name(), pk)?;

        on(Progress {
            frac: 0.55,
            step: "apply".into(),
            line: format!("Moving your things into {}", dst.display),
        });
        let dst_prof = engine::Profile {
            dir: &dst.dir,
            slot: dst_slot,
            keys: &dst_keys,
            login_tag: HostTag::Without,
            browser: &dst.browser,
            display: &dst.display,
        };
        // Written under the destination key obtained above with the
        // v11 label, never the store-vote label: the vote falls back
        // to the compiled-in fallback key on legacy or empty
        // destination stores.
        let applied = engine::import_with_write_prefix(&dst_prof, &payload, now_micros(), LinuxPrefix::V11)?;
        self.record_landings(&BTreeSet::from([dst.dir.clone()]), &self.load_landed())?;

        let history_visits_moved = applied
            .history
            .as_ref()
            .map(|h| (h.visits_inserted + h.visits_updated) as u64)
            .unwrap_or(0);
        let already_present_cookies = applied.cookies.kept_newer as u64;
        let already_present_logins = applied.logins.already_present as u64;
        let report = {
            let cookies = applied.cookies.imported as u64;
            let logins = (applied.logins.inserted + applied.logins.updated) as u64;
            let history_urls = applied
                .history
                .as_ref()
                .map(|h| (h.urls_inserted + h.urls_updated) as u64)
                .unwrap_or(0);
            let extensions = applied.extensions.ids.len() as u64;
            // What actually changed hands, for the summary: the moved
            // counts above, plus visits that landed on already-present
            // urls and a bookmarks file that was written, merged or kept
            // as a sibling (an identical bookmarks file is carried but
            // changes nothing, so it does not count as moved).
            let bookmarks_moved = matches!(
                applied.bookmarks.action,
                Some(
                    bookmarks::Action::Written
                        | bookmarks::Action::Merged
                        | bookmarks::Action::Conflict
                )
            );
            let moved = cookies
                + logins
                + history_urls
                + history_visits_moved
                + extensions
                + u64::from(bookmarks_moved);
            let summary = local_move_summary(
                &dst.display,
                moved,
                already_present_cookies + already_present_logins,
            );
            LocalMoveReport {
                source: src.display.clone(),
                target: dst.display.clone(),
                cookies,
                logins,
                history_urls,
                extensions,
                locked_cookies: count_locked_cookies_in(&src.dir, src_slot),
                preserved_cookies: applied.cookies.preserved_undecryptable as u64,
                extension_installs: applied.extension_installs.reports,
                already_present_cookies,
                already_present_logins,
                history_visits_moved,
                summary,
            }
        };
        on(Progress { frac: 1.0, step: "done".into(), line: report.summary.clone() });
        Ok(report)
    }

    /// Is either side of a same-device move open right now? Names the first one
    /// that is, so the shell can show the close-it-and-tap-again state for it.
    pub fn local_open_check(&self, source: &str, target: &str) -> Result<OpenCheck> {
        let src = self.require_local_profile(source)?;
        if profile_open(&src) {
            return Ok(OpenCheck::Blocked { browser: src.display });
        }
        let dst = self.require_local_profile(target)?;
        if profile_open(&dst) {
            return Ok(OpenCheck::Blocked { browser: dst.display });
        }
        Ok(OpenCheck::Clear)
    }

    /// Undo the last finished move into the target browser. The journal keeps
    /// one undo point per profile, so this undoes the newest finished move into
    /// that browser, whichever kind made it (a same-device move or a sync); a
    /// later move of either kind replaces the point. Without `force`, a profile
    /// that changed since the move is left alone and the outcome says so.
    pub fn local_undo(&self, target: &str, force: bool) -> Result<UndoOutcome> {
        let dst = self.require_local_profile(target)?;
        if profile_open(&dst) {
            return Err(Error::BrowserOpen);
        }
        Ok(match txn::undo_last(&dst.dir, force)? {
            txn::Undo::Done => UndoOutcome::Done,
            txn::Undo::Nothing => UndoOutcome::Nothing,
            txn::Undo::ChangedSince => UndoOutcome::Changed,
        })
    }
}

/// Is this profile's browser open right now? Two signals: the browser's own lock
/// marker with a live process behind it (the recorded pid, or the browser's host
/// processes when that pid is a sandbox pid), and the store lock canary (a write
/// lock on the cookie store that only a running browser's database can refuse).
fn profile_open(p: &DetectedProfile) -> bool {
    root_open(&p.dir)
}

fn root_open(root: &Path) -> bool {
    if singleton_live(root) {
        return true;
    }
    if profiles::list_slots(root).iter().any(|s| {
        store_locked(&paths::cookies_in(root, &s.name))
            || store_locked(&paths::login_data_in(root, &s.name))
            || store_locked(&paths::history_in(root, &s.name))
    }) {
        return true;
    }
    // A SingleProfile root's stores sit at the root itself.
    crate::browsers::has_single_profile_markers(root)
        && (store_locked(&paths::cookies_in(root, paths::SINGLE_SLOT))
            || store_locked(&paths::login_data_in(root, paths::SINGLE_SLOT))
            || store_locked(&paths::history_in(root, paths::SINGLE_SLOT)))
}

/// The browser leaves a `SingletonLock` marker naming its process while it runs.
/// The name is `hostname-pid`, but the pid only means something in the pid
/// namespace the browser runs in: a Flatpak browser records its sandbox pid
/// (the app is pid 2 there), which on the host is a kernel thread. A recorded
/// pid therefore proves the browser is open only when the host process behind
/// it is plausibly that browser. When it does not resolve, the browser's own
/// host processes are the next witness: a running Flatpak browser is alive on
/// the host even though its recorded pid is meaningless there, and only when
/// no host process speaks for it either is the browser really closed.
#[cfg(unix)]
fn singleton_live(dir: &Path) -> bool {
    let Ok(target) = std::fs::read_link(dir.join("SingletonLock")) else { return false };
    let s = target.to_string_lossy();
    let Some(pid) = s.rsplit('-').next().and_then(|t| t.parse::<i32>().ok()) else { return false };
    (process_live(pid) && pid_could_be_browser(pid, dir)) || host_browser_live(dir)
}

/// Identity screen for a live pid named by a SingletonLock. Kernel threads
/// and zombies are never a browser; they are the shapes with no command
/// line at all, told apart from a userspace process caught mid-exec (whose
/// command line also reads empty for a moment) by the process flags in
/// /proc/<pid>/stat. A process whose
/// command line names a browser binary, or this profile root (a browser
/// launched with --user-data-dir), is the browser. Anything we cannot
/// inspect (no /proc, no permission) and any larger pid we cannot rule out
/// stays "could be the browser": the guard keeps its bias toward protecting
/// a running browser's stores. Only the shapes that provably are not the
/// browser clear the check: no command line at all, or a boot-range pid
/// plainly running something else (init and its earliest children live
/// there; that is where sandbox-namespace pids land on the host).
#[cfg(unix)]
fn pid_could_be_browser(pid: i32, root: &Path) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return true;
    };
    if cmdline.is_empty() {
        return !is_kernel_thread_or_zombie(pid);
    }
    let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
    let argv0 = text.split(' ').next().unwrap_or_default();
    let base = argv0.rsplit('/').next().unwrap_or_default().to_lowercase();
    const BROWSER_TOKENS: [&str; 6] = ["brave", "chrome", "chromium", "msedge", "opera", "vivaldi"];
    if BROWSER_TOKENS.iter().any(|t| base.contains(t)) {
        return true;
    }
    if text.contains(&*root.to_string_lossy()) {
        return true;
    }
    pid >= 512
}

/// Kernel threads and zombies are never a browser, and both read as an
/// empty command line, but so does a userspace process in the middle of
/// exec. The stat flags tell them apart: PF_KTHREAD marks a kernel
/// thread, and a zombie's state is Z. Anything unprovable keeps the
/// benefit of the doubt (not proven kernel or zombie).
#[cfg(unix)]
fn is_kernel_thread_or_zombie(pid: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { return false };
        // comm is parenthesised and may itself contain spaces or parens;
        // the fields after the closing paren start at state (field 3),
        // so flags (field 9) is the seventh of them.
        let Some(rest) = stat.rsplit(')').next() else { return false };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.first() == Some(&"Z") {
            return true;
        }
        const PF_KTHREAD: i64 = 0x200000;
        fields
            .get(6)
            .and_then(|f| f.parse::<i64>().ok())
            .map(|flags| flags & PF_KTHREAD != 0)
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        false
    }
}

/// Host-side witnesses for a browser whose recorded singleton pid did not
/// resolve: a live process whose command line names this profile root or,
/// for a Flatpak install, its app (the sandbox launcher names the app id,
/// and the app's own processes name its app home), or a process holding
/// this root's SingletonSocket. Only Linux exposes the process table this
/// reads; elsewhere the recorded pid and the store lock canaries decide.
#[cfg(target_os = "linux")]
fn host_browser_live(root: &Path) -> bool {
    let app_id = crate::oscrypt::flatpak_app_id_from_install(root);
    let root_text = root.to_string_lossy().into_owned();
    let Ok(entries) = std::fs::read_dir("/proc") else { return false };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
        if pid == std::process::id() as i32 {
            continue;
        }
        let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else { continue };
        if !cmd.is_empty() && cmdline_names_this_browser(&cmd, &root_text, app_id) {
            return true;
        }
    }
    singleton_socket_held(root)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn host_browser_live(_root: &Path) -> bool {
    false
}

/// Does this process command line belong to the browser living at `root`?
/// A browser's processes name their user-data dir, and a Flatpak app's
/// processes name the app home or, for the sandbox launcher, the app id
/// itself. Anything else (another browser, another app, a plain sleeper)
/// does not match, so a stale singleton still clears.
#[cfg(target_os = "linux")]
fn cmdline_names_this_browser(cmdline: &[u8], root: &str, app_id: Option<&str>) -> bool {
    let text = String::from_utf8_lossy(cmdline).replace('\0', " ");
    if text.contains(root) {
        return true;
    }
    let Some(app) = app_id else { return false };
    if text.contains(&format!("/.var/app/{app}/")) {
        return true;
    }
    let argv0 = text.split(' ').next().unwrap_or_default();
    let base = argv0.rsplit('/').next().unwrap_or_default();
    (base == "bwrap" || base == "flatpak") && text.contains(app)
}

/// A process holding this root's SingletonSocket is the browser: that
/// socket is how a second launch hands off to the running instance.
#[cfg(target_os = "linux")]
fn singleton_socket_held(root: &Path) -> bool {
    let Ok(target) = std::fs::read_link(root.join("SingletonSocket")) else { return false };
    // The socket's kernel inode is not the inode of the file it leaves on
    // disk; /proc/net/unix maps the bound path to the inode the fd links
    // name.
    let Ok(table) = std::fs::read_to_string("/proc/net/unix") else { return false };
    let path = target.to_string_lossy();
    let mut needle = None;
    for line in table.lines() {
        let mut fields = line.split_whitespace();
        for _ in 0..6 {
            fields.next();
        }
        let (Some(ino), Some(p)) = (fields.next(), fields.next()) else { continue };
        if p == path {
            needle = Some(format!("socket:[{ino}]"));
            break;
        }
    }
    let Some(needle) = needle else { return false };
    let Ok(entries) = std::fs::read_dir("/proc") else { return false };
    for e in entries.flatten() {
        let name = e.file_name();
        if name.to_str().and_then(|s| s.parse::<i32>().ok()).is_none() {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(e.path().join("fd")) else { continue };
        for fd in fds.flatten() {
            if let Ok(t) = std::fs::read_link(fd.path()) {
                if t.to_string_lossy() == needle {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(unix)]
fn process_live(pid: i32) -> bool {
    if pid <= 0 { return false; }
    // EPERM also means the process exists, under another user.
    (unsafe { libc::kill(pid, 0) == 0 })
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn singleton_live(dir: &Path) -> bool {
    dir.join("SingletonLock").exists()
}

/// The lock canary: try to take the cookie store's write lock for a moment. A running
/// browser's database refuses; a closed one accepts and nothing changes.
fn store_locked(db: &Path) -> bool {
    if !db.exists() {
        return false;
    }
    let Ok(con) = rusqlite::Connection::open(db) else { return true };
    let _ = con.busy_timeout(std::time::Duration::ZERO);
    match con.execute_batch("BEGIN IMMEDIATE; ROLLBACK;") {
        Ok(()) => false,
        Err(rusqlite::Error::SqliteFailure(f, _)) => matches!(
            f.code,
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
        ),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_is_exactly_the_registry_ids() {
        // The comment on FAMILY claims a registry test pins the two lists
        // to each other; this is that test.
        let registry: Vec<&str> = crate::browsers::all().iter().map(|d| d.id).collect();
        assert_eq!(FAMILY.to_vec(), registry);
    }

    fn state() -> (tempfile::TempDir, App) {
        let t = tempfile::tempdir().unwrap();
        let app = App::open(t.path())
            .unwrap()
            .with_key_store(std::sync::Arc::new(crate::keychain::MemoryStore::default()));
        (t, app)
    }

    #[cfg(unix)]
    #[test]
    fn startup_does_not_recover_under_an_open_working_browser() {
        let (t, mut app) = state();
        let root = t.path().join("browser");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("store");
        std::fs::write(&file, b"before").unwrap();
        let tx = txn::Txn::begin(&root, &[("store", &file)]).unwrap();
        std::fs::write(&file, b"in progress").unwrap();
        std::os::unix::fs::symlink(format!("host-{}", std::process::id()), root.join("SingletonLock")).unwrap();
        app = app.with_profile("brave", &root);
        app.welcome_start().unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"in progress");
        drop(tx);
    }

    #[test]
    fn local_move_takes_the_same_lock_as_sync() {
        let (t, mut app) = state();
        let lock = MoveLock::take(t.path()).unwrap();
        assert!(matches!(
            app.local_move("brave", "chrome", None, None, None, &mut |_| {}),
            Err(Error::Refused(_))
        ));
        drop(lock);
    }

    #[test]
    fn partial_undo_records_each_completed_root_before_a_failure() {
        let (t, app) = state();
        let mut roots = Vec::new();
        for name in ["broken", "good"] {
            let root = t.path().join(name);
            std::fs::create_dir(&root).unwrap();
            let file = root.join("store");
            std::fs::write(&file, b"before").unwrap();
            let tx = txn::Txn::begin(&root, &[("store", &file)]).unwrap();
            let point = tx.dir().to_path_buf();
            std::fs::write(&file, b"after").unwrap();
            tx.commit().unwrap();
            if name == "broken" { std::fs::remove_file(point.join("s0")).unwrap(); }
            roots.push(LastMoveRoot { root: root.to_string_lossy().into_owned(), txn: current_undo_point(&root).unwrap() });
        }
        app.save_last_move(&LastMove { roots }).unwrap();
        assert!(app.undo_last(false).is_err());
        let remaining = app.load_last_move().unwrap().roots;
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].root.ends_with("broken"));
        assert_eq!(std::fs::read(t.path().join("good/store")).unwrap(), b"before");
    }

    #[test]
    fn legacy_key_migration_pins_the_account_before_renaming_or_reopening() {
        for name_key in [false, true] {
            let (t, mut app) = state();
            app.set_device_name("old name").unwrap();
            let key = SyncKey::generate().unwrap();
            if name_key {
                app.key_store.store("old name", &key).unwrap();
            } else {
                std::fs::write(t.path().join(LEGACY_KEY_FILE), key.to_key_file_text()).unwrap();
            }
            assert_eq!(app.load_key().unwrap().unwrap().to_key_file_text(), key.to_key_file_text());
            let id = app.device_id().unwrap();
            assert!(app.key_store.load(&id).unwrap().is_some());
            app.set_device_name("new name").unwrap();
            let mut reopened = App::open(t.path()).unwrap().with_key_store(app.key_store.clone());
            assert_eq!(reopened.load_key().unwrap().unwrap().to_key_file_text(), key.to_key_file_text());
            assert_eq!(reopened.device_id().unwrap(), id);
            assert!(!t.path().join(LEGACY_KEY_FILE).exists());
        }
    }

    #[test]
    fn root_open_checks_sibling_store_locks() {
        let t = tempfile::tempdir().unwrap();
        let slot = t.path().join("Profile 2");
        std::fs::create_dir(&slot).unwrap();
        let con = rusqlite::Connection::open(slot.join("Login Data")).unwrap();
        con.execute_batch("CREATE TABLE probe (n); BEGIN IMMEDIATE;").unwrap();
        assert!(root_open(t.path()));
        con.execute_batch("ROLLBACK").unwrap();
        assert!(!root_open(t.path()));
    }

    #[cfg(unix)]
    #[test]
    fn singleton_checks_live_process_without_proc() {
        let t = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(format!("host-{}", std::process::id()), t.path().join("SingletonLock")).unwrap();
        assert!(root_open(t.path()));
    }

    #[test]
    fn config_and_pipe_choice_persist() {
        let (t, mut app) = state();
        let chosen = t.path().join("shared");
        std::fs::create_dir(&chosen).unwrap();
        let info = app.use_pipe(&chosen).unwrap();
        assert_eq!(info.kind, "folder");
        assert!(info.place.ends_with("Move It"));
        app.set_device_name("kitchen laptop").unwrap();

        let again = App::open(t.path()).unwrap();
        assert_eq!(again.device_name(), "kitchen laptop");
        assert_eq!(again.config.pipe_kind.as_deref(), Some("folder"));
        assert!(again.place_path().unwrap().ends_with("Move It"));
    }

    #[test]
    fn use_pipe_refuses_a_missing_folder_and_accepts_a_git_clone() {
        let (t, mut app) = state();
        assert!(app.use_pipe(&t.path().join("nope")).is_err());

        let repo = t.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let ok = std::process::Command::new("git").arg("-C").arg(&repo).arg("init").arg("-q").status().unwrap();
        assert!(ok.success());
        let info = app.use_pipe(&repo).unwrap();
        assert_eq!(info.kind, "git");
    }

    #[test]
    fn welcome_start_reports_an_unpaired_device() {
        let (_t, app) = state();
        let prof = tempfile::tempdir().unwrap();
        let mut app = app.with_profile("brave", prof.path());
        let info = app.welcome_start().unwrap();
        assert!(!info.paired);
        assert!(!info.pipe_set);
        assert!(info.profile_found);
        assert_eq!(info.browser.as_deref(), Some("Brave"));
        assert_eq!(info.other_device, None);
    }

    #[test]
    fn browser_open_check_follows_the_store_lock() {
        let (_t, app) = state();
        let prof = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(prof.path().join("Default")).unwrap();
        let db = prof.path().join("Default").join("Cookies");
        {
            let con = rusqlite::Connection::open(&db).unwrap();
            con.execute_batch("CREATE TABLE cookies (host_key TEXT)").unwrap();
        }
        let app = app.with_profile("brave", prof.path());
        assert_eq!(app.browser_open_check(&[], &[]).unwrap(), OpenCheck::Clear);

        // A second connection holding the write lock is what a running browser looks like.
        let holder = rusqlite::Connection::open(&db).unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert_eq!(
            app.browser_open_check(&[], &[]).unwrap(),
            OpenCheck::Blocked { browser: "Brave".into() }
        );
        holder.execute_batch("ROLLBACK").unwrap();
        assert_eq!(app.browser_open_check(&[], &[]).unwrap(), OpenCheck::Clear);
    }

    #[cfg(unix)]
    fn singleton_root(target: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("browser");
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(target, root.join("SingletonLock")).unwrap();
        (t, root)
    }

    #[cfg(unix)]
    #[test]
    fn singleton_with_a_dead_pid_is_not_open() {
        let mut child = std::process::Command::new("/bin/sleep").arg("0.1").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        let (_t, root) = singleton_root(&format!("host-{pid}"));
        assert!(!singleton_live(&root));
    }

    #[cfg(unix)]
    #[test]
    fn singleton_with_a_live_browser_pid_is_open() {
        let t = tempfile::tempdir().unwrap();
        let fake = t.path().join("chrome");
        std::fs::copy("/bin/sleep", &fake).unwrap();
        let mut child = std::process::Command::new(&fake).arg("60").spawn().unwrap();
        let root = t.path().join("browser");
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(format!("host-{}", child.id()), root.join("SingletonLock")).unwrap();
        assert!(singleton_live(&root));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn flatpak_style_singleton_pid_is_not_the_host_browser() {
        // A Flatpak browser records its sandbox pid: "fedora-2". Host pid 2
        // is a kernel thread and pid 1 is init; neither is the browser, so
        // a stale Flatpak singleton must not block a move.
        let (_t, root) = singleton_root("fedora-2");
        assert!(!singleton_live(&root));
        let (_t2, root2) = singleton_root("fedora-1");
        assert!(!singleton_live(&root2));
    }

    /// A just-spawned process has no command line of its own until exec
    /// lands; wait for it so the scan below sees the real one.
    #[cfg(target_os = "linux")]
    fn wait_for_cmdline(pid: u32) {
        for _ in 0..200 {
            let ready = std::fs::read(format!("/proc/{pid}/cmdline"))
                .map(|c| !c.is_empty())
                .unwrap_or(false);
            if ready {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn flatpak_singleton_with_a_live_app_process_is_open() {
        // The singleton records the sandbox pid while the browser itself is
        // alive on the host: a process of the app (here one naming the app
        // home, as the browser's own processes name their user-data dir
        // under it) must still mark the root open.
        let t = tempfile::tempdir().unwrap();
        let app_home = t.path().join(".var/app/com.brave.Browser");
        let root = app_home.join("config/BraveSoftware/Brave-Browser");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("fedora-2", root.join("SingletonLock")).unwrap();
        let runner_dir = app_home.join("cache");
        std::fs::create_dir_all(&runner_dir).unwrap();
        let fake = runner_dir.join("runner");
        std::fs::copy("/bin/sleep", &fake).unwrap();
        let mut child = std::process::Command::new(&fake).arg("60").spawn().unwrap();
        wait_for_cmdline(child.id());
        assert!(singleton_live(&root));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn singleton_with_a_live_process_for_the_root_is_open() {
        // The recorded pid is dead, but a process naming this root (a
        // browser launched with --user-data-dir) is alive: open. Once it
        // exits and nothing speaks for the root, the singleton is stale.
        let mut dead = std::process::Command::new("/bin/sleep").arg("0.1").spawn().unwrap();
        let dead_pid = dead.id();
        dead.wait().unwrap();
        let (_t, root) = singleton_root(&format!("host-{dead_pid}"));
        let fake = root.join("browser-bin");
        std::fs::copy("/bin/sleep", &fake).unwrap();
        let mut child = std::process::Command::new(&fake).arg("60").spawn().unwrap();
        wait_for_cmdline(child.id());
        assert!(singleton_live(&root));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!singleton_live(&root));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn singleton_socket_holder_is_open() {
        // The recorded pid is dead and no process names the root, but a
        // process holds the root's SingletonSocket: the browser is open.
        let mut dead = std::process::Command::new("/bin/sleep").arg("0.1").spawn().unwrap();
        let dead_pid = dead.id();
        dead.wait().unwrap();
        let (t, root) = singleton_root(&format!("host-{dead_pid}"));
        let sock = t.path().join("singleton.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::os::unix::fs::symlink(&sock, root.join("SingletonSocket")).unwrap();
        assert!(singleton_live(&root));
        drop(listener);
        assert!(!singleton_live(&root));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cmdline_matching_names_only_this_browser() {
        let root = "/home/u/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser";
        let app = Some("com.brave.Browser");
        // A browser process naming its user-data dir.
        assert!(cmdline_names_this_browser(
            format!("/app/brave/brave\x00--type=renderer\x00--user-data-dir={root}\x00").as_bytes(),
            root,
            app,
        ));
        // The sandbox launcher naming the app id.
        assert!(cmdline_names_this_browser(
            b"/usr/bin/bwrap\x00--args\x00 76\x00--\x00com.brave.Browser\x00",
            root,
            app,
        ));
        // Another Flatpak app is not this browser.
        assert!(!cmdline_names_this_browser(
            b"/app/spotify\x00--user-data-dir=/home/u/.var/app/com.spotify.Client/cache\x00",
            root,
            app,
        ));
        // A plain process is not this browser, and the app shapes do not
        // count for a native root.
        assert!(!cmdline_names_this_browser(b"/bin/sleep\x00 60\x00", root, app));
        assert!(!cmdline_names_this_browser(
            b"/usr/bin/bwrap\x00--args\x00 76\x00--\x00com.brave.Browser\x00",
            "/home/u/.config/BraveSoftware/Brave-Browser",
            None,
        ));
    }

    #[test]
    fn pairing_wrong_codes_count_down_and_the_right_code_pairs() {
        let (t, a) = state();
        let a_prof = tempfile::tempdir().unwrap();
        let mut a = a.with_profile("brave", a_prof.path());
        let shared = t.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        a.use_pipe(&shared).unwrap();
        a.set_device_name("device-a").unwrap();
        let shown = a.pair_show_code().unwrap();
        assert_eq!(shown.this_device, "device-a");
        assert_eq!(shown.code.len(), 7, "six digits in two groups of three");

        let b_state = t.path().join("b-state");
        let mut b = App::open(&b_state).unwrap().with_key_store(std::sync::Arc::new(crate::keychain::MemoryStore::default())).with_profile("brave", t.path());
        b.use_pipe(&shared).unwrap();
        b.set_device_name("device-b").unwrap();

        // The offer names its cost; each wrong try is a full stretch, so count two.
        match b.pair_enter_code("000000").unwrap() {
            PairOutcome::Wrong { tries_left } => assert_eq!(tries_left, pairing::MAX_TRIES - 1),
            other => panic!("{other:?}"),
        }
        match b.pair_enter_code("111111").unwrap() {
            PairOutcome::Wrong { tries_left } => assert_eq!(tries_left, pairing::MAX_TRIES - 2),
            other => panic!("{other:?}"),
        }
        match b.pair_enter_code(&shown.code).unwrap() {
            PairOutcome::Success { other_device } => assert_eq!(other_device, "device-a"),
            other => panic!("{other:?}"),
        }
        // Device A learns who paired when it next starts.
        let info = a.welcome_start().unwrap();
        assert!(info.paired);
        assert_eq!(info.other_device.as_deref(), Some("device-b"));
    }

    #[test]
    fn bookmark_counter_counts_url_nodes_only() {
        let bm = br#"{"roots":{"bookmark_bar":{"type":"folder","children":[
            {"type":"url","url":"https://a.example"},
            {"type":"folder","children":[{"type":"url","url":"https://b.example"}]}
        ]},"other":{"type":"folder","children":[]}}}"#;
        assert_eq!(count_bookmark_urls(bm), 2);
        assert_eq!(count_bookmark_urls(b"not json"), 0);
    }

    fn src(browser: &str, slot: &str) -> SourceProfile {
        SourceProfile {
            id: profile_id(browser, slot),
            browser: browser.to_string(),
            root: PathBuf::from(format!("/nonexistent/{browser}")),
            slot: slot.to_string(),
            name: slot.to_string(),
        }
    }

    fn route(profile: &str, browser: &str) -> RouteChoice {
        RouteChoice { profile: profile.to_string(), browser: browser.to_string() }
    }

    #[test]
    fn profile_ids_slug_the_slot() {
        assert_eq!(profile_id("brave", "Default"), "brave:default");
        assert_eq!(profile_id("chrome", "Profile 1"), "chrome:profile-1");
        assert_eq!(profile_id("edge", "Profile 12"), "edge:profile-12");
    }

    #[test]
    fn routes_validate_and_normalize() {
        let sources = vec![src("brave", "Default"), src("brave", "Profile 1"), src("chrome", "Default")];
        // An empty route map is just the default move.
        assert!(validate_routes(&sources, &[], &[]).unwrap().is_empty());
        // Per-profile destinations, different browsers in one move.
        let m = validate_routes(
            &sources,
            &[],
            &[route("brave:default", "chrome"), route("brave:profile-1", "edge")],
        )
        .unwrap();
        assert_eq!(m.get("brave:default").map(String::as_str), Some("chrome"));
        assert_eq!(m.get("brave:profile-1").map(String::as_str), Some("edge"));
        // Routing onto itself is the default path: it drops out of the map.
        let m = validate_routes(&sources, &[], &[route("brave:default", "brave")]).unwrap();
        assert!(m.is_empty());
        // The whole family is allowed, Opera included (its key gap fails later,
        // per route, not here).
        assert!(validate_routes(&sources, &[], &[route("brave:default", "opera")]).is_ok());
        // Browser names match case-insensitively and normalize to lowercase.
        let m = validate_routes(&sources, &[], &[route("brave:default", "Chrome")]).unwrap();
        assert_eq!(m.get("brave:default").map(String::as_str), Some("chrome"));
        let m = validate_routes(&sources, &[], &[route("brave:default", "BRAVE")]).unwrap();
        assert!(m.is_empty(), "a case-only difference is still the own browser");
    }

    #[test]
    fn incoming_routes_drop_stale_ids() {
        let arriving = vec![ArrivingProfile {
            id: "brave:default".into(),
            name: "Work".into(),
            from_browser: "brave".into(),
            from_browser_display: "Brave".into(),
            from_device: "other".into(),
            destination: "brave".into(),
            routed: false,
            destination_note: None,
        }];
        let m = validate_incoming_routes(&arriving, &[route("brave:nope", "chrome")]).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn routes_refuse_the_malformed_shapes() {
        let sources = vec![src("brave", "Default"), src("chrome", "Default")];
        // Unknown profile id.
        assert!(validate_routes(&sources, &[], &[route("brave:work", "chrome")]).is_err());
        // A crafted id never resolves, however it is spelled.
        assert!(validate_routes(&sources, &[], &[route("brave:..", "chrome")]).is_err());
        // An exclusion id that names nothing excludes nothing and is not an
        // error: the set may be a remembered one with stale ids in it.
        assert!(validate_routes(&sources, &["brave:nope".into()], &[]).is_ok());
        // Duplicate route for one profile.
        assert!(validate_routes(
            &sources,
            &[],
            &[route("brave:default", "chrome"), route("brave:default", "edge")]
        )
        .is_err());
        // A route for a profile left out of the move.
        assert!(validate_routes(
            &sources,
            &["brave:default".into()],
            &[route("brave:default", "chrome")]
        )
        .is_err());
        // Non-family targets, named and unnamed.
        assert!(validate_routes(&sources, &[], &[route("brave:default", "firefox")]).is_err());
        assert!(validate_routes(&sources, &[], &[route("brave:default", "safari")]).is_err());
        assert!(validate_routes(&sources, &[], &[route("brave:default", "")]).is_err());
    }
}
