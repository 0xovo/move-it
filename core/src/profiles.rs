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

use crate::paths::{DEFAULT_SLOT, SINGLE_SLOT};
use crate::oscrypt::{Platform, LINUX_PASSWORD_ENV};
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
    if name == DEFAULT_SLOT || name == SINGLE_SLOT {
        return true;
    }
    name.strip_prefix("Profile ")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// [`is_slot_name`], scoped to one browser's layout: the single-profile
/// slot name is a real slot ONLY for a SingleProfile browser. Everywhere
/// else it names no folder (a Standard root's slot folders are `Default`
/// and `Profile N`), so accepting it there would aim writes at the
/// browser root itself. Listing keeps using the unscoped predicate (a
/// folder scan does not know which browser it belongs to yet); the
/// validation seams (a box's named slot, an engine landing) use this.
pub fn is_slot_name_for(name: &str, layout: crate::browsers::LayoutKind) -> bool {
    if name == SINGLE_SLOT {
        return layout == crate::browsers::LayoutKind::SingleProfile;
    }
    is_slot_name(name)
}

/// [`is_slot_name_for`], with the layout taken from the registry row for
/// `browser` (Standard for a name the registry does not know).
pub fn is_slot_name_for_browser(name: &str, browser: &str) -> bool {
    let layout = crate::browsers::by_id(browser)
        .map(|d| d.layout)
        .unwrap_or(crate::browsers::LayoutKind::Standard);
    is_slot_name_for(name, layout)
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

/// Every profile slot in this browser folder, under its layout. A
/// SingleProfile root has exactly one slot, [`SINGLE_SLOT`], whose folder
/// is the root itself, and only when the root actually holds a profile.
pub fn list_slots_for(root: &Path, layout: crate::browsers::LayoutKind) -> Vec<Slot> {
    match layout {
        crate::browsers::LayoutKind::Standard => list_slots(root),
        crate::browsers::LayoutKind::SingleProfile => list_slots_single(root),
    }
}

/// [`list_slots_for`], with the layout taken from the registry row for
/// `browser` (Standard for a name the registry does not know).
pub fn list_slots_for_browser(root: &Path, browser: &str) -> Vec<Slot> {
    let layout = crate::browsers::by_id(browser)
        .map(|d| d.layout)
        .unwrap_or(crate::browsers::LayoutKind::Standard);
    list_slots_for(root, layout)
}

fn list_slots_single(root: &Path) -> Vec<Slot> {
    if !crate::browsers::has_single_profile_markers(root) {
        return Vec::new();
    }
    let mut display = "Default".to_string();
    if let Ok(bytes) = std::fs::read(root.join("Preferences")) {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            if let Some(n) = v
                .get("profile")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                display = n.to_string();
            }
        }
    }
    vec![Slot { name: SINGLE_SLOT.to_string(), display, dir: root.to_path_buf() }]
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
    fn single_slot_is_only_a_slot_for_single_profile_browsers() {
        use crate::browsers::LayoutKind;
        assert!(is_slot_name_for("Single", LayoutKind::SingleProfile));
        assert!(!is_slot_name_for("Single", LayoutKind::Standard));
        assert!(is_slot_name_for_browser("Single", "opera"));
        assert!(is_slot_name_for_browser("Single", "opera-gx"));
        assert!(!is_slot_name_for_browser("Single", "chrome"));
        assert!(!is_slot_name_for_browser("Single", "brave"));
        // Ordinary slots are accepted under either layout check.
        assert!(is_slot_name_for_browser("Default", "chrome"));
        assert!(is_slot_name_for_browser("Profile 2", "chrome"));
        assert!(!is_slot_name_for_browser("Profile X", "chrome"));
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

/// A browser install found on this device: a user-data folder that
/// holds profile data (a `Default` inside for a Standard browser, the
/// profile itself for a SingleProfile one).
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedProfile {
    /// Short name the engine knows: brave, chrome, chromium, edge, ...
    pub browser: String,
    /// The name a person calls it: Brave, Google Chrome, ...
    pub display: String,
    pub dir: PathBuf,
    /// How this browser lays its profiles out (from the registry).
    pub layout: crate::browsers::LayoutKind,
}

fn browser_display(name: &str) -> String {
    crate::browsers::display_for(name)
        .map(str::to_string)
        .unwrap_or_else(|| name.to_string())
}

/// Where a Chromium browser keeps its user-data on this machine.
#[derive(Debug, Clone, PartialEq)]
pub struct ChromiumInstallRoot {
    pub browser: String,
    pub display: String,
    pub dir: PathBuf,
    /// How this browser lays its profiles out (from the registry).
    pub layout: crate::browsers::LayoutKind,
}

fn xdg_config_under(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
}

/// Every Chromium install root under `home` / `xdg_config`: native XDG first,
/// then Flatpak fills browsers that are still missing. The same browser never
/// appears twice; native wins over Flatpak. The browser set, the folders,
/// the listing order and the per-browser presence test all come from the
/// registry (`crate::browsers`): a Standard browser is present when its
/// folder holds a `Default`, a SingleProfile browser when the folder
/// itself holds a profile.
pub fn linux_chromium_install_roots_at(home: &Path, xdg_config: &Path) -> Vec<ChromiumInstallRoot> {
    let mut by_name: std::collections::BTreeMap<String, ChromiumInstallRoot> =
        std::collections::BTreeMap::new();
    for def in crate::browsers::all() {
        let Some(sub) = def.linux_dir else { continue };
        let dir = xdg_config.join(sub);
        if def.present_at(&dir) {
            by_name.insert(
                def.id.to_string(),
                ChromiumInstallRoot {
                    browser: def.id.to_string(),
                    display: def.display.to_string(),
                    dir,
                    layout: def.layout,
                },
            );
        }
    }
    let flatpak = std::env::var(LINUX_PASSWORD_ENV)
        .ok()
        .is_none_or(|p| p.is_empty());
    if flatpak {
        for def in crate::browsers::all() {
            let Some((app_ids, sub)) = def.flatpak else { continue };
            if by_name.contains_key(def.id) {
                continue;
            }
            for app_id in app_ids {
                let dir = home.join(".var/app").join(app_id).join("config").join(sub);
                if def.present_at(&dir) {
                    by_name.insert(
                        def.id.to_string(),
                        ChromiumInstallRoot {
                            browser: def.id.to_string(),
                            display: format!("{} (Flatpak)", def.display),
                            dir,
                            layout: def.layout,
                        },
                    );
                    break;
                }
            }
        }
    }
    let mut out = Vec::new();
    for def in crate::browsers::all() {
        if let Some(r) = by_name.remove(def.id) {
            out.push(r);
        }
    }
    out
}

/// Chromium install roots on this Linux host. `native_base` overrides the XDG
/// config folder (harness fixtures); Flatpak is still read from `$HOME`.
pub fn linux_chromium_install_roots(native_base: Option<&Path>) -> Vec<ChromiumInstallRoot> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let xdg = native_base
        .map(Path::to_path_buf)
        .unwrap_or_else(|| xdg_config_under(&home));
    linux_chromium_install_roots_at(&home, &xdg)
}

/// Directories that hold Firefox `profiles.ini` (any known Linux layout).
pub fn linux_firefox_profile_homes_at(home: &Path, xdg_config: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [
        xdg_config.join("mozilla/firefox"),
        home.join(".mozilla/firefox"),
        home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
        home.join(".var/app/org.mozilla.firefox/config/mozilla/firefox"),
    ] {
        if !dir.join("profiles.ini").is_file() {
            continue;
        }
        let key = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        if !out.iter().any(|p: &PathBuf| {
            std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()) == key
        }) {
            out.push(dir);
        }
    }
    out
}

pub fn linux_firefox_profile_homes(native_base: Option<&Path>) -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let xdg = native_base
        .map(Path::to_path_buf)
        .unwrap_or_else(|| xdg_config_under(&home));
    linux_firefox_profile_homes_at(&home, &xdg)
}

/// (short name, folder under `~/Library/Application Support`) pairs,
/// macOS, from the registry, in listing order.
fn mac_subs() -> Vec<(&'static str, &'static str)> {
    crate::browsers::all()
        .iter()
        .filter_map(|d| d.mac_dir.map(|sub| (d.id, sub)))
        .collect()
}

/// (short name, folder under the config base) pairs, Linux, from the
/// registry, in listing order.
fn linux_subs() -> Vec<(&'static str, &'static str)> {
    crate::browsers::all()
        .iter()
        .filter_map(|d| d.linux_dir.map(|sub| (d.id, sub)))
        .collect()
}

/// Is this browser root the canonical macOS location for one of the known
/// stable browsers (`~/Library/Application Support/<browser folder>`)? A root
/// anywhere else is a non-default user data dir. That used to be taken as
/// proof the browser writes v11; live proof on Chrome 156 and Brave 1.98
/// showed both writing v10 there, so the location no longer decides the
/// write label (only the store's own rows do). Channel builds and
/// SingleProfile browsers are not canonical roots for this check: the
/// stable Standard browsers are the set it has always covered.
pub fn is_canonical_mac_root(root: &Path) -> bool {
    let comps: Vec<String> = root
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    for def in crate::browsers::all() {
        if def.channel_of.is_some() || def.layout != crate::browsers::LayoutKind::Standard {
            continue;
        }
        let Some(sub) = def.mac_dir else { continue };
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

/// Every browser in `defs` whose folder under `base` holds profile data,
/// with `dir_of` picking the per-OS folder out of each registry row.
fn scan(
    base: &Path,
    defs: &[&'static crate::browsers::BrowserDef],
    dir_of: fn(&crate::browsers::BrowserDef) -> Option<&'static str>,
) -> Vec<DetectedProfile> {
    let mut out = Vec::new();
    for def in defs {
        let Some(sub) = dir_of(def) else { continue };
        let dir = base.join(sub);
        if def.present_at(&dir) {
            out.push(DetectedProfile {
                browser: def.id.to_string(),
                display: def.display.to_string(),
                dir,
                layout: def.layout,
            });
        }
    }
    out
}

/// Chromium profiles in their usual places on this machine. Windows: no
/// detection yet, so the caller names the profile folder itself.
pub fn detect_profiles() -> Vec<DetectedProfile> {
    match Platform::current() {
        Platform::Linux => linux_chromium_install_roots(None)
            .into_iter()
            .map(|r| DetectedProfile {
                browser: r.browser,
                display: r.display,
                dir: r.dir,
                layout: r.layout,
            })
            .collect(),
        Platform::Mac => {
            match std::env::var_os("HOME") {
                Some(h) => scan(
                    &PathBuf::from(h).join("Library").join("Application Support"),
                    &crate::browsers::defs_for_platform(Platform::Mac),
                    |d| d.mac_dir,
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
                ("opera", "com.operasoftware.Opera"),
                ("vivaldi", "Vivaldi"),
                ("chrome-beta", "Google/Chrome Beta"),
                ("chrome-dev", "Google/Chrome Dev"),
                ("chrome-canary", "Google/Chrome Canary"),
                ("edge-beta", "Microsoft Edge Beta"),
                ("edge-dev", "Microsoft Edge Dev"),
                ("brave-beta", "BraveSoftware/Brave-Browser-Beta"),
                ("brave-nightly", "BraveSoftware/Brave-Browser-Nightly"),
                ("opera-gx", "com.operasoftware.OperaGX"),
            ]
        );
        assert_eq!(
            linux_subs(),
            [
                ("brave", "BraveSoftware/Brave-Browser"),
                ("chrome", "google-chrome"),
                ("chromium", "chromium"),
                ("edge", "microsoft-edge"),
                ("opera", "opera"),
                ("vivaldi", "vivaldi"),
                ("chrome-beta", "google-chrome-beta"),
                ("chrome-dev", "google-chrome-unstable"),
                ("chrome-canary", "google-chrome-canary"),
                ("edge-beta", "microsoft-edge-beta"),
                ("edge-dev", "microsoft-edge-dev"),
                ("brave-beta", "BraveSoftware/Brave-Browser-Beta"),
                ("brave-nightly", "BraveSoftware/Brave-Browser-Nightly"),
                ("opera-gx", "opera-gx"),
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
        let found = scan(base, &crate::browsers::defs_for_platform(Platform::Mac), |d| d.mac_dir);
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
        let found = scan(base, &crate::browsers::defs_for_platform(Platform::Linux), |d| d.linux_dir);
        let names: Vec<&str> = found.iter().map(|p| p.browser.as_str()).collect();
        assert_eq!(names, ["brave", "edge"]);
        assert_eq!(found[1].display, "Microsoft Edge");
    }

    #[test]
    fn scan_of_an_empty_base_finds_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(scan(tmp.path(), &crate::browsers::defs_for_platform(Platform::Mac), |d| d.mac_dir).is_empty());
        assert!(scan(tmp.path(), &crate::browsers::defs_for_platform(Platform::Linux), |d| d.linux_dir).is_empty());
    }

    #[test]
    fn linux_flatpak_brave_without_native_xdg() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let xdg = home.join(".config");
        std::fs::create_dir_all(
            home.join(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/Default"),
        )
        .unwrap();
        let found = linux_chromium_install_roots_at(home, &xdg);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].browser, "brave");
        assert_eq!(found[0].display, "Brave (Flatpak)");
    }

    #[test]
    fn linux_native_brave_wins_over_flatpak() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let xdg = home.join(".config");
        plant(&xdg, "BraveSoftware/Brave-Browser", true);
        std::fs::create_dir_all(
            home.join(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/Default"),
        )
        .unwrap();
        let found = linux_chromium_install_roots_at(home, &xdg);
        assert_eq!(found.iter().filter(|r| r.browser == "brave").count(), 1);
        assert_eq!(found[0].display, "Brave");
        assert_eq!(found[0].dir, xdg.join("BraveSoftware/Brave-Browser"));
    }

    #[test]
    fn linux_ungoogled_chromium_flatpak() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let xdg = home.join(".config");
        std::fs::create_dir_all(
            home.join(".var/app/io.github.ungoogled_software.ungoogled_chromium/config/chromium/Default"),
        )
        .unwrap();
        let found = linux_chromium_install_roots_at(home, &xdg);
        assert!(found.iter().any(|r| r.browser == "chromium" && r.display.contains("Flatpak")));
    }

    #[test]
    fn linux_firefox_profile_ini_locations() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let xdg = home.join(".config");
        let ff = xdg.join("mozilla/firefox");
        std::fs::create_dir_all(&ff).unwrap();
        std::fs::write(ff.join("profiles.ini"), "[General]\nStartWithLastProfile=1\n").unwrap();
        let legacy = home.join(".mozilla/firefox");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("profiles.ini"), "[General]\n").unwrap();
        let found = linux_firefox_profile_homes_at(home, &xdg);
        assert_eq!(found.len(), 2);
        assert!(found.contains(&ff));
        assert!(found.contains(&legacy));
    }

    #[test]
    fn linux_firefox_flatpak_profile_ini() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let xdg = home.join(".config");
        let ff = home.join(".var/app/org.mozilla.firefox/config/mozilla/firefox");
        std::fs::create_dir_all(&ff).unwrap();
        std::fs::write(ff.join("profiles.ini"), "[General]\n").unwrap();
        let found = linux_firefox_profile_homes_at(home, &xdg);
        assert_eq!(found, vec![ff]);
    }

    #[test]
    fn linux_firefox_profiles_ini_relative_paths_are_under_the_ini_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let xdg = home.join(".config");
        let ini_dir = xdg.join("mozilla/firefox");
        std::fs::create_dir_all(ini_dir.join("abc.default")).unwrap();
        std::fs::write(
            ini_dir.join("profiles.ini"),
            "[Profile0]\nName=default\nIsRelative=1\nPath=abc.default\n",
        )
        .unwrap();
        assert!(ini_dir.join("abc.default").is_dir());
        assert!(linux_firefox_profile_homes_at(home, &xdg).contains(&ini_dir));
    }

    #[test]
    fn linux_discovers_vivaldi_and_channel_builds() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let xdg = home.join(".config");
        plant(&xdg, "vivaldi", true);
        plant(&xdg, "google-chrome-beta", true);
        plant(&xdg, "BraveSoftware/Brave-Browser-Nightly", true);
        plant(&xdg, "microsoft-edge-dev", true);
        let found = linux_chromium_install_roots_at(home, &xdg);
        let names: Vec<&str> = found.iter().map(|r| r.browser.as_str()).collect();
        assert_eq!(names, ["vivaldi", "chrome-beta", "edge-dev", "brave-nightly"]);
        assert_eq!(found[0].display, "Vivaldi");
        assert_eq!(found[0].layout, crate::browsers::LayoutKind::Standard);
    }

    #[test]
    fn linux_discovers_opera_as_a_single_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let xdg = home.join(".config");
        // Opera's folder IS the profile: stores at its root, no Default inside.
        let opera = xdg.join("opera");
        std::fs::create_dir_all(&opera).unwrap();
        std::fs::write(opera.join("Preferences"), b"{}").unwrap();
        std::fs::write(opera.join("History"), b"x").unwrap();
        // An Opera GX folder with no profile markers is not a profile.
        std::fs::create_dir_all(xdg.join("opera-gx")).unwrap();
        let found = linux_chromium_install_roots_at(home, &xdg);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].browser, "opera");
        assert_eq!(found[0].layout, crate::browsers::LayoutKind::SingleProfile);
        let slots = list_slots_for(&found[0].dir, found[0].layout);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].name, SINGLE_SLOT);
        assert_eq!(slots[0].dir, found[0].dir);
    }
}
