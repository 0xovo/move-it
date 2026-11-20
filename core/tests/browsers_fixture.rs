//! Fixture-level tests for the browsers the registry added (Vivaldi, the
//! channel builds, Opera and Opera GX): synthetic profiles built in temp
//! dirs, in the same style as `engine_roundtrip.rs`. Per browser the
//! fixture is discovered, its rows are counted (the census), and where the
//! format allows a seal/open round trip must carry the rows whole.
//! No real profiles, no real browser launches.

use std::path::{Path, PathBuf};

use moveit_core::browsers::{self, LayoutKind};
use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::engine::{self, Profile};
use moveit_core::history;
use moveit_core::logins::{self, Login};
use moveit_core::oscrypt::{HostTag, LinuxPrefix, Lock};
use moveit_core::paths;
use moveit_core::profiles;
use moveit_core::sealed::SyncKey;

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

fn make_db(path: &Path, schema: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch(schema).unwrap();
}

fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
}

fn cookie(host: &str, name: &str, value: &str, cre: i64) -> Cookie {
    Cookie {
        host: host.into(), name: name.into(), path: "/".into(), value: value.into(),
        expires_utc: 0, creation_utc: cre, last_access_utc: cre, is_secure: 1,
        is_httponly: 0, samesite: -1, last_update_utc: Some(cre), top_frame_site_key: String::new(),
    }
}

fn login(user: &str, pw: &str, created: i64) -> Login {
    Login {
        origin_url: "https://mail.example.com/login".into(),
        action_url: "https://mail.example.com/auth".into(),
        username_value: user.into(),
        password_value: pw.into(),
        date_created: created,
        date_last_used: created + 500,
        times_used: 3,
        signon_realm: "https://mail.example.com".into(),
        date_password_modified: created,
    }
}

/// Plant the three empty stores inside one profile folder (a slot folder
/// for a Standard browser, the root itself for a SingleProfile one).
fn plant_stores(profile_dir: &Path) {
    make_db(&profile_dir.join("Network").join("Cookies"), COOKIES_SCHEMA);
    make_db(&profile_dir.join("Login Data"), LOGINS_SCHEMA);
    make_db(&profile_dir.join("History"), HISTORY_SCHEMA);
    std::fs::write(profile_dir.join("Preferences"), b"{\"profile\":{\"name\":\"Fixture\"}}").unwrap();
}

/// Plant a full fixture for one browser under an XDG config base: the
/// user-data root at its registry Linux folder, a `Local State`, empty
/// stores, then `n_cookies` cookies, one login and one history row sealed
/// with the shared test key. Returns the user-data root.
fn plant_fixture(xdg: &Path, id: &str, n_cookies: usize) -> PathBuf {
    let def = browsers::by_id(id).unwrap();
    let root = xdg.join(def.linux_dir.unwrap());
    let profile_dir = match def.layout {
        LayoutKind::Standard => root.join("Default"),
        LayoutKind::SingleProfile => root.clone(),
    };
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("Local State"), b"{}").unwrap();
    plant_stores(&profile_dir);
    let k = keys();
    let cs: Vec<Cookie> = (0..n_cookies)
        .map(|i| cookie(&format!(".host{i}.test"), "sid", &format!("value-{i}"), 100 + i as i64))
        .collect();
    if !cs.is_empty() {
        cookies::import(&profile_dir.join("Network").join("Cookies"), &cs, &k).unwrap();
    }
    logins::import(&profile_dir.join("Login Data"), &[login("fixture-user", "fixture-pw", 1000)], &k, HostTag::Without).unwrap();
    let con = rusqlite::Connection::open(profile_dir.join("History")).unwrap();
    con.execute(
        "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES ('https://example.com/', 'Example', 1, 13350000000000000)",
        [],
    )
    .unwrap();
    root
}

/// (cookies, logins, history urls) counted in one profile.
fn census(root: &Path, slot: &str) -> (usize, usize, usize) {
    let k = keys();
    let c = cookies::export_detailed(&paths::cookies_in(root, slot), &k).unwrap();
    let l = logins::export_detailed(&paths::login_data_in(root, slot), &k).unwrap();
    let h = history::export(&paths::history_in(root, slot)).unwrap();
    (c.total, l.logins.len(), h.urls.len())
}

fn profile<'a>(dir: &'a Path, slot: &'a str, keys: &'a Keys, browser: &'a str, display: &'a str) -> Profile<'a> {
    Profile { dir, slot, keys, login_tag: HostTag::Without, browser, display }
}

/// Seal `src` and land the box in `dst`, both named by registry id + slot.
fn round_trip(src: &Path, src_slot: &str, src_id: &str, dst: &Path, dst_slot: &str, dst_id: &str) {
    let k = keys();
    let key = SyncKey::from_bytes([7u8; 32]);
    let src_def = browsers::by_id(src_id).unwrap();
    let dst_def = browsers::by_id(dst_id).unwrap();
    let sealed = engine::seal_box(
        &profile(src, src_slot, &k, src_id, src_def.display),
        "fixture:src",
        &key,
    )
    .unwrap();
    let payload = engine::open_box(&sealed, &key).unwrap();
    engine::import(
        &profile(dst, dst_slot, &k, dst_id, dst_def.display),
        &payload,
        17_000_000_000_000i64,
    )
    .unwrap();
}

/// Every added browser: discovery finds its fixture profile and the
/// census counts its rows.
#[test]
fn every_added_browser_is_discovered_and_counted() {
    let added = [
        "vivaldi",
        "chrome-beta",
        "chrome-dev",
        "chrome-canary",
        "edge-beta",
        "edge-dev",
        "brave-beta",
        "brave-nightly",
        "opera",
        "opera-gx",
    ];
    for id in added {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let xdg = t.path().join("config");
        std::fs::create_dir_all(&home).unwrap();
        let root = plant_fixture(&xdg, id, 2);
        let found = profiles::linux_chromium_install_roots_at(&home, &xdg);
        let install = found
            .iter()
            .find(|r| r.browser == id)
            .unwrap_or_else(|| panic!("{id} not discovered: {found:?}"));
        assert_eq!(install.dir, root, "{id} root");
        let def = browsers::by_id(id).unwrap();
        assert_eq!(install.layout, def.layout, "{id} layout");
        let slots = profiles::list_slots_for(&install.dir, install.layout);
        assert_eq!(slots.len(), 1, "{id} slots");
        let (c, l, h) = census(&install.dir, &slots[0].name);
        assert_eq!((c, l, h), (2, 1, 1), "{id} census");
    }
}

#[test]
fn vivaldi_round_trips_with_chrome_both_ways() {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().join("home");
    let xdg = t.path().join("config");
    std::fs::create_dir_all(&home).unwrap();
    let vivaldi = plant_fixture(&xdg, "vivaldi", 2);
    let chrome = plant_fixture(&xdg, "chrome", 0);
    // Vivaldi -> Chrome.
    round_trip(&vivaldi, "Default", "vivaldi", &chrome, "Default", "chrome");
    assert_eq!(census(&chrome, "Default"), (2, 1, 1));
    let k = keys();
    let got = cookies::export(&paths::cookies_in(&chrome, "Default"), &k).unwrap();
    assert!(got.iter().any(|c| c.host == ".host0.test" && c.value == "value-0"));
    // Chrome -> Vivaldi (the chrome fixture now carries the rows).
    let vivaldi2 = plant_fixture(&t.path().join("config2"), "vivaldi", 0);
    round_trip(&chrome, "Default", "chrome", &vivaldi2, "Default", "vivaldi");
    assert_eq!(census(&vivaldi2, "Default"), (2, 1, 1));
}

#[test]
fn chrome_beta_fixture_round_trips_to_chrome() {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().join("home");
    let xdg = t.path().join("config");
    std::fs::create_dir_all(&home).unwrap();
    let beta = plant_fixture(&xdg, "chrome-beta", 2);
    let chrome = plant_fixture(&xdg, "chrome", 0);
    let found = profiles::linux_chromium_install_roots_at(&home, &xdg);
    assert!(found.iter().any(|r| r.browser == "chrome-beta"), "beta discovered");
    round_trip(&beta, "Default", "chrome-beta", &chrome, "Default", "chrome");
    assert_eq!(census(&chrome, "Default"), (2, 1, 1));
}

#[test]
fn opera_round_trips_to_opera_in_the_single_profile_layout() {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().join("home");
    let xdg = t.path().join("config");
    std::fs::create_dir_all(&home).unwrap();
    let src = plant_fixture(&xdg, "opera", 2);
    let dst = plant_fixture(&t.path().join("config2"), "opera", 0);
    // The single slot is the root itself, and Local State sits beside the stores.
    assert!(src.join("Local State").is_file());
    assert_eq!(paths::slot_dir(&src, paths::SINGLE_SLOT), src);
    round_trip(&src, paths::SINGLE_SLOT, "opera", &dst, paths::SINGLE_SLOT, "opera");
    assert_eq!(census(&dst, paths::SINGLE_SLOT), (2, 1, 1));
    let k = keys();
    let got = cookies::export(&paths::cookies_in(&dst, paths::SINGLE_SLOT), &k).unwrap();
    assert!(got.iter().any(|c| c.host == ".host1.test" && c.value == "value-1"));
}

#[test]
fn opera_gx_fixture_uses_the_single_profile_layout_too() {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().join("home");
    let xdg = t.path().join("config");
    std::fs::create_dir_all(&home).unwrap();
    let gx = plant_fixture(&xdg, "opera-gx", 1);
    let dst = plant_fixture(&t.path().join("config2"), "opera-gx", 0);
    round_trip(&gx, paths::SINGLE_SLOT, "opera-gx", &dst, paths::SINGLE_SLOT, "opera-gx");
    assert_eq!(census(&dst, paths::SINGLE_SLOT), (1, 1, 1));
}
