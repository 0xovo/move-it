//! The profile slots inside one browser's folder: listing them, naming them, choosing
//! a folder name for a new one, registering it in the browser's own `Local State`
//! the way the browser itself records profiles, and planting the empty stores a
//! brand-new profile starts with.
//!
//! A slot is a folder: `Default`, `Profile 1`, `Profile 2`, ... The browser keeps
//! its own registry in `Local State` under `profile.info_cache` (folder name ->
//! entry with a `name`), and `profile.profiles_order`. Registration here writes
//! exactly that, cloning a sibling entry's shape when one exists, so the browser
//! finds a profile that looks like one it made.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::paths::DEFAULT_SLOT;
use crate::oscrypt::Platform;
use crate::{Error, Result};

/// One profile inside a browser folder.
#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    /// The folder name: `Default`, `Profile 1`, ...
    pub name: String,
    /// What the person calls it.
    pub display: String,
    /// The folder itself.
    pub dir: PathBuf,
}

fn io(e: std::io::Error, what: &str, p: &Path) -> Error {
    Error::Io(format!("{what} {}: {e}", p.display()))
}

/// Folder names Chromium uses for real profiles: `Default`, or `Profile ` + a number.
/// (Guest and System profiles exist too; they are not a person's browser life and
/// never list, never receive.) This is also the write-side gate: a slot name from
/// anywhere else (a box manifest, a route) must pass it before it becomes a path.
pub fn is_slot_name(name: &str) -> bool {
    if name == DEFAULT_SLOT {
        return true;
    }
    name.strip_prefix("Profile ")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The browser's Local State as JSON, when it is there and parses.
pub fn read_local_state(root: &Path) -> Option<Value> {
    let bytes = std::fs::read(root.join("Local State")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn info_cache(ls: &Value) -> Option<&Map<String, Value>> {
    ls.get("profile")?.get("info_cache")?.as_object()
}

/// (slot, display) pairs from the browser's own registry, in the browser's own
/// order when `profiles_order` is there, registry order otherwise.
fn registered(ls: &Value) -> Vec<(String, String)> {
    let Some(cache) = info_cache(ls) else { return Vec::new() };
    let mut names: Vec<String> = cache.keys().cloned().collect();
    if let Some(order) = ls
        .get("profile")
        .and_then(|p| p.get("profiles_order"))
        .and_then(Value::as_array)
    {
        let order: Vec<&str> = order.iter().filter_map(Value::as_str).collect();
        names.sort_by_key(|n| order.iter().position(|o| *o == n).unwrap_or(usize::MAX));
    }
    names
        .into_iter()
        .filter(|n| is_slot_name(n))
        .map(|n| {
            let display = cache
                .get(&n)
                .and_then(|e| e.get("name"))
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string);
            (n, display.unwrap_or_default())
        })
        .collect()
}

/// The name a profile shows, from the registry, then its Preferences, then the
/// folder name itself.
fn display_for(root: &Path, slot: &str, registered_name: &str) -> String {
    if !registered_name.trim().is_empty() {
        return registered_name.to_string();
    }
    let prefs = root.join(slot).join("Preferences");
    if let Ok(bytes) = std::fs::read(&prefs) {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            if let Some(n) = v
                .get("profile")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                return n.to_string();
            }
        }
    }
    if slot == DEFAULT_SLOT {
        "Default".to_string()
    } else {
        slot.to_string()
    }
}

/// Every real profile slot in this browser folder: registered ones in the
/// browser's order first, then any slot folder the registry lost track of.
pub fn list_slots(root: &Path) -> Vec<Slot> {
    let mut out: Vec<Slot> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    if let Some(ls) = read_local_state(root) {
        for (name, reg_name) in registered(&ls) {
            let dir = root.join(&name);
            if dir.is_dir() {
                seen.push(name.clone());
                out.push(Slot { display: display_for(root, &name, &reg_name), name, dir });
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(root) {
        let mut found: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| is_slot_name(n) && !seen.contains(n))
            .collect();
        found.sort();
        for name in found {
            let dir = root.join(&name);
            out.push(Slot { display: display_for(root, &name, ""), name, dir });
        }
    }
    out
}

/// The folder name a brand-new profile should get: `Default` when the browser
/// folder has no profile at all yet, else the smallest free `Profile N`.
/// `also_taken` reserves names claimed earlier in the same move.
pub fn fresh_slot_name(root: &Path, also_taken: &[String]) -> String {
    let mut taken: Vec<String> = list_slots(root).into_iter().map(|s| s.name).collect();
    taken.extend(also_taken.iter().cloned());
    if !taken.iter().any(|n| n == DEFAULT_SLOT) && !root.join(DEFAULT_SLOT).exists() {
        return DEFAULT_SLOT.to_string();
    }
    let mut n = 1;
    loop {
        let cand = format!("Profile {n}");
        if !taken.contains(&cand) && !root.join(&cand).exists() {
            return cand;
        }
        n += 1;
    }
}

/// Local State JSON with `slot` registered under `display`. The new entry clones
/// a sibling entry's shape when the registry has one (the fields differ between
/// browser versions; a sibling is always the right shape for this install),
/// with the name replaced. `profiles_order` gains the slot when that list exists.
pub fn local_state_with_slot(ls: &Value, slot: &str, display: &str, now_secs: u64) -> Value {
    let mut out = if ls.is_object() { ls.clone() } else { json!({}) };
    let root_obj = out.as_object_mut().expect("object");
    // A registry key holding the wrong shape (another tool wrote it, an old
    // browser left it) is replaced with an empty object rather than crashing
    // the move: nothing meaningful can live in a non-object `profile`.
    if !root_obj.get("profile").is_some_and(Value::is_object) {
        root_obj.insert("profile".into(), json!({}));
    }
    let profile = root_obj
        .get_mut("profile")
        .and_then(Value::as_object_mut)
        .expect("profile object");
    if !profile.get("info_cache").is_some_and(Value::is_object) {
        profile.insert("info_cache".into(), json!({}));
    }
    let cache = profile.get_mut("info_cache").and_then(Value::as_object_mut).expect("cache object");
    if !cache.contains_key(slot) {
        let mut entry = cache
            .values()
            .find(|v| v.is_object())
            .cloned()
            .unwrap_or_else(|| {
                json!({
                    "avatar_icon": "chrome://theme/avatar_1",
                    "is_using_default_avatar": true,
                    "is_ephemeral": false,
                })
            });
        if let Some(e) = entry.as_object_mut() {
            e.insert("name".into(), json!(display));
            e.insert("is_using_default_name".into(), json!(false));
            e.insert("active_time".into(), json!(now_secs as f64));
        }
        cache.insert(slot.to_string(), entry);
    }
    if let Some(order) = profile.get_mut("profiles_order").and_then(Value::as_array_mut) {
        if !order.iter().any(|v| v.as_str() == Some(slot)) {
            order.push(json!(slot));
        }
    }
    out
}

/// Local State JSON with `slot` taken back out of the registry (used by tests and
/// by nothing in the move path: undo restores the snapshotted file instead).
pub fn local_state_without_slot(ls: &Value, slot: &str) -> Value {
    let mut out = ls.clone();
    if let Some(profile) = out.get_mut("profile").and_then(Value::as_object_mut) {
        if let Some(cache) = profile.get_mut("info_cache").and_then(Value::as_object_mut) {
            cache.remove(slot);
        }
        if let Some(order) = profile.get_mut("profiles_order").and_then(Value::as_array_mut) {
            order.retain(|v| v.as_str() != Some(slot));
        }
    }
    out
}

/// The Preferences file a new profile starts with: just its name. The browser
/// fills in everything else the first time the profile opens.
pub fn new_preferences(display: &str) -> Value {
    json!({ "profile": { "name": display } })
}

// ---- the empty stores a new profile starts with --------------------------------------
//
// No store import in this engine creates a missing database (by design: an existing
// profile with a missing store is a fact to report, not to paper over). A profile
// the engine itself just created is the one honest exception: it starts with the
// empty stores the browser would have made on first run, in the shapes current
// browsers write, so the normal imports have somewhere to land.

const COOKIES_SCHEMA: &str = "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
    INSERT INTO meta VALUES('version','24');
    CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL, value TEXT NOT NULL DEFAULT '', encrypted_value BLOB NOT NULL DEFAULT '',
    path TEXT NOT NULL, expires_utc INTEGER NOT NULL DEFAULT 0, is_secure INTEGER NOT NULL DEFAULT 0,
    is_httponly INTEGER NOT NULL DEFAULT 0, last_access_utc INTEGER NOT NULL DEFAULT 0,
    has_expires INTEGER NOT NULL DEFAULT 1, is_persistent INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 1, samesite INTEGER NOT NULL DEFAULT -1,
    source_scheme INTEGER NOT NULL DEFAULT 0, source_port INTEGER NOT NULL DEFAULT -1,
    last_update_utc INTEGER NOT NULL DEFAULT 0, source_type INTEGER NOT NULL DEFAULT 0,
    has_cross_site_ancestor INTEGER NOT NULL DEFAULT 1);
    CREATE UNIQUE INDEX cookies_unique_index ON cookies (host_key, top_frame_site_key, name, path);";

const LOGINS_SCHEMA: &str = "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
    INSERT INTO meta VALUES('version','35');
    CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR,
        username_value VARCHAR, password_element VARCHAR, password_value BLOB DEFAULT '',
        date_created INTEGER NOT NULL, date_last_used INTEGER NOT NULL, date_password_modified INTEGER NOT NULL,
        signon_realm VARCHAR NOT NULL, times_used INTEGER NOT NULL, form_data BLOB, date_received INTEGER,
        shared_preference INTEGER NOT NULL DEFAULT 0, submission_event INTEGER NOT NULL DEFAULT 0,
        sender_email VARCHAR, sender_name VARCHAR, date_sender_notice_sent INTEGER DEFAULT 0,
        keychain_identifier VARCHAR DEFAULT '', id INTEGER PRIMARY KEY AUTOINCREMENT, scheme INTEGER DEFAULT 0 NOT NULL,
        possible_username_pairs BLOB, moving_blocked_for BLOB, version INTEGER NOT NULL DEFAULT 0,
        encrypted_date_created BLOB DEFAULT '', encrypted_date_last_used BLOB DEFAULT '',
        encrypted_date_password_modified BLOB DEFAULT '', federation_url VARCHAR DEFAULT '', skip_zero_click INTEGER,
        generation_upload_status INTEGER DEFAULT 0, form_fetcher_path VARCHAR,
        date_received_is_readonly INTEGER NOT NULL DEFAULT 0, date_created_is_readonly INTEGER NOT NULL DEFAULT 0,
        possible_observer_handles BLOB, blacklisted_by_user INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX logins_signon ON logins (signon_realm);";

const HISTORY_SCHEMA: &str = "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
    INSERT INTO meta VALUES('version','22');
    CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
        visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
        last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
    CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
        from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER,
        visit_duration INTEGER DEFAULT 0 NOT NULL);";

fn make_db(path: &Path, schema: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io(e, "cannot create", parent))?;
    }
    let con = rusqlite::Connection::open(path).map_err(|e| Error::Io(format!("cannot create {}: {e}", path.display())))?;
    con.execute_batch(schema).map_err(|e| Error::Io(format!("cannot shape {}: {e}", path.display())))?;
    Ok(())
}

/// Plant the empty Cookies / Login Data / History stores in a profile folder the
/// engine just created, in their modern places. Existing files are never touched.
pub fn create_empty_stores(slot_dir: &Path) -> Result<()> {
    let cookies = slot_dir.join("Network").join("Cookies");
    if !cookies.exists() {
        make_db(&cookies, COOKIES_SCHEMA)?;
    }
    let logins = slot_dir.join("Login Data");
    if !logins.exists() {
        make_db(&logins, LOGINS_SCHEMA)?;
    }
    let history = slot_dir.join("History");
    if !history.exists() {
        make_db(&history, HISTORY_SCHEMA)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_with(prefs_name: Option<&str>) -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("browser");
        std::fs::create_dir_all(root.join("Default")).unwrap();
        if let Some(n) = prefs_name {
            std::fs::write(root.join("Default/Preferences"), json!({"profile": {"name": n}}).to_string()).unwrap();
        }
        (t, root)
    }

    #[test]
    fn slots_list_from_registry_then_folders() {
        let (_t, root) = root_with(None);
        std::fs::create_dir_all(root.join("Profile 2")).unwrap();
        std::fs::create_dir_all(root.join("Guest Profile")).unwrap();
        std::fs::write(
            root.join("Local State"),
            json!({"profile": {"info_cache": {
                "Default": {"name": "Main"},
                "Profile 1": {"name": "Work"}
            }, "profiles_order": ["Profile 1", "Default"]}}).to_string(),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("Profile 1")).unwrap();
        let slots = list_slots(&root);
        let names: Vec<&str> = slots.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["Profile 1", "Default", "Profile 2"], "registry order, then unregistered folders");
        assert_eq!(slots[0].display, "Work");
        assert_eq!(slots[1].display, "Main");
        assert_eq!(slots[2].display, "Profile 2", "folder-name fallback");
    }

    #[test]
    fn display_falls_back_to_preferences() {
        let (_t, root) = root_with(Some("From Prefs"));
        let slots = list_slots(&root);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].display, "From Prefs");
    }

    #[test]
    fn fresh_slot_names() {
        let (_t, root) = root_with(None);
        assert_eq!(fresh_slot_name(&root, &[]), "Profile 1");
        assert_eq!(fresh_slot_name(&root, &["Profile 1".into()]), "Profile 2");
        let empty = tempfile::tempdir().unwrap();
        let bare = empty.path().join("nothing");
        assert_eq!(fresh_slot_name(&bare, &[]), "Default", "a folder with no profile starts at Default");
    }

    #[test]
    fn registration_clones_the_sibling_shape() {
        let ls = json!({"profile": {"info_cache": {
            "Default": {"name": "Main", "avatar_icon": "chrome://theme/avatar_7", "custom_field": 3}
        }, "profiles_order": ["Default"]}, "other": {"keep": true}});
        let out = local_state_with_slot(&ls, "Profile 1", "Work", 42);
        let cache = out["profile"]["info_cache"].as_object().unwrap();
        assert_eq!(cache["Profile 1"]["name"], "Work");
        assert_eq!(cache["Profile 1"]["avatar_icon"], "chrome://theme/avatar_7", "sibling shape carried over");
        assert_eq!(cache["Profile 1"]["custom_field"], 3);
        assert_eq!(out["profile"]["profiles_order"], json!(["Default", "Profile 1"]));
        assert_eq!(out["other"]["keep"], true, "the rest of Local State is untouched");
        // Registering the same slot again changes nothing.
        let again = local_state_with_slot(&out, "Profile 1", "Other", 43);
        assert_eq!(again["profile"]["info_cache"]["Profile 1"]["name"], "Work");
        // And removal is the exact inverse.
        let back = local_state_without_slot(&out, "Profile 1");
        assert_eq!(back, ls);
    }

    #[test]
    fn registration_on_an_empty_local_state() {
        let out = local_state_with_slot(&json!({}), "Default", "Main", 1);
        assert_eq!(out["profile"]["info_cache"]["Default"]["name"], "Main");
    }

    #[test]
    fn registration_survives_a_misshapen_registry() {
        // Valid JSON, wrong shapes: the move must not panic on a registry
        // another tool left behind. The bad keys are replaced, the rest kept.
        let ls = json!({"profile": "leftover", "other": 1});
        let out = local_state_with_slot(&ls, "Profile 1", "Work", 10);
        assert_eq!(out["profile"]["info_cache"]["Profile 1"]["name"], "Work");
        assert_eq!(out["other"], 1);
        let ls = json!({"profile": {"info_cache": "nope"}});
        let out = local_state_with_slot(&ls, "Default", "Main", 10);
        assert_eq!(out["profile"]["info_cache"]["Default"]["name"], "Main");
    }
}

// ---- detection: which browsers are installed, and where ----

/// A browser profile found on this device: a user-data folder with a `Default` inside.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedProfile {
    /// Short name the engine knows: brave, chrome, chromium, edge.
    pub browser: String,
    /// The name a person calls it: Brave, Google Chrome, ...
    pub display: String,
    pub dir: PathBuf,
}

fn browser_display(name: &str) -> String {
    match name {
        "brave" => "Brave".to_string(),
        "chrome" => "Google Chrome".to_string(),
        "chromium" => "Chromium".to_string(),
        "edge" => "Microsoft Edge".to_string(),
        other => other.to_string(),
    }
}

/// (short name, folder under the config base) pairs, Linux.
fn linux_subs() -> [(&'static str, &'static str); 4] {
    [
        ("brave", "BraveSoftware/Brave-Browser"),
        ("chrome", "google-chrome"),
        ("chromium", "chromium"),
        ("edge", "microsoft-edge"),
    ]
}

/// (short name, folder under `~/Library/Application Support`) pairs, macOS.
fn mac_subs() -> [(&'static str, &'static str); 4] {
    [
        ("brave", "BraveSoftware/Brave-Browser"),
        ("chrome", "Google/Chrome"),
        ("chromium", "Chromium"),
        ("edge", "Microsoft Edge"),
    ]
}

/// Is this browser root the canonical macOS location for one of the known
/// browsers (`~/Library/Application Support/<browser folder>`)? A root
/// anywhere else is a non-default user data dir. That used to be taken as
/// proof the browser writes v11; live proof on Chrome 156 and Brave 1.98
/// showed both writing v10 there, so the location no longer decides the
/// write label (only the store's own rows do).
pub fn is_canonical_mac_root(root: &Path) -> bool {
    let comps: Vec<String> = root
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    for (_, sub) in mac_subs() {
        let tail: Vec<&str> = std::iter::once("Library")
            .chain(std::iter::once("Application Support"))
            .chain(sub.split('/'))
            .collect();
        if comps.len() >= tail.len()
            && comps[comps.len() - tail.len()..]
                .iter()
                .map(String::as_str)
                .eq(tail.into_iter())
        {
            return true;
        }
    }
    false
}

/// Every browser in `subs` whose folder under `base` holds a `Default`.
fn scan(base: &Path, subs: &[(&str, &str)]) -> Vec<DetectedProfile> {
    let mut out = Vec::new();
    for (name, sub) in subs {
        let dir = base.join(sub);
        if dir.join("Default").is_dir() {
            out.push(DetectedProfile {
                browser: name.to_string(),
                display: browser_display(name),
                dir,
            });
        }
    }
    out
}

/// Chromium profiles in their usual places on this machine. Windows: no
/// detection yet, so the caller names the profile folder itself.
pub fn detect_profiles() -> Vec<DetectedProfile> {
    match Platform::current() {
        Platform::Linux => {
            let base = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
            match base {
                Some(base) => scan(&base, &linux_subs()),
                None => Vec::new(),
            }
        }
        Platform::Mac => {
            match std::env::var_os("HOME") {
                Some(h) => scan(
                    &PathBuf::from(h).join("Library").join("Application Support"),
                    &mac_subs(),
                ),
                None => Vec::new(),
            }
        }
        Platform::Windows => Vec::new(),
    }
}

#[cfg(test)]
mod detection_tests {
    use super::*;

    fn plant(base: &Path, sub: &str, with_default: bool) {
        let d = base.join(sub);
        if with_default {
            std::fs::create_dir_all(d.join("Default")).unwrap();
        } else {
            std::fs::create_dir_all(&d).unwrap();
        }
    }

    #[test]
    fn mac_profile_table() {
        // The macOS folders are the contract with the live machine; pin them.
        assert_eq!(
            mac_subs(),
            [
                ("brave", "BraveSoftware/Brave-Browser"),
                ("chrome", "Google/Chrome"),
                ("chromium", "Chromium"),
                ("edge", "Microsoft Edge"),
            ]
        );
    }

    #[test]
    fn canonical_mac_roots_match_the_detection_table() {
        assert!(is_canonical_mac_root(Path::new(
            "/Users/x/Library/Application Support/Google/Chrome"
        )));
        assert!(is_canonical_mac_root(Path::new(
            "/Users/x/Library/Application Support/BraveSoftware/Brave-Browser"
        )));
        assert!(is_canonical_mac_root(Path::new(
            "/Users/x/Library/Application Support/Chromium"
        )));
        assert!(!is_canonical_mac_root(Path::new("/tmp/staging/Google/Chrome")));
        assert!(!is_canonical_mac_root(Path::new(
            "/Users/x/Library/Application Support/Google/Chrome Beta"
        )));
        assert!(!is_canonical_mac_root(Path::new("/srv/x/.config/google-chrome")));
    }

    #[test]
    fn scan_finds_mac_profiles_with_a_default() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        plant(base, "BraveSoftware/Brave-Browser", true);
        plant(base, "Google/Chrome", true);
        plant(base, "Chromium", true);
        plant(base, "Microsoft Edge", false); // installed once, never run: no Default
        let found = scan(base, &mac_subs());
        let names: Vec<&str> = found.iter().map(|p| p.browser.as_str()).collect();
        assert_eq!(names, ["brave", "chrome", "chromium"]);
        assert_eq!(found[0].display, "Brave");
        assert_eq!(found[1].display, "Google Chrome");
        assert_eq!(
            found[0].dir,
            base.join("BraveSoftware/Brave-Browser")
        );
        assert_eq!(found[2].dir, base.join("Chromium"));
    }

    #[test]
    fn scan_finds_linux_profiles_and_skips_absent_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        plant(base, "BraveSoftware/Brave-Browser", true);
        plant(base, "microsoft-edge", true);
        let found = scan(base, &linux_subs());
        let names: Vec<&str> = found.iter().map(|p| p.browser.as_str()).collect();
        assert_eq!(names, ["brave", "edge"]);
        assert_eq!(found[1].display, "Microsoft Edge");
    }

    #[test]
    fn scan_of_an_empty_base_finds_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(scan(tmp.path(), &mac_subs()).is_empty());
        assert!(scan(tmp.path(), &linux_subs()).is_empty());
    }
}
