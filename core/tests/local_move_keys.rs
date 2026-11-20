//! The same-device move's destination-key contract: moved cookies and
//! logins are sealed under the destination browser's keyring key with
//! the v11 label, a destination whose key is only the compiled-in
//! fallback is refused before anything is written, and a moved
//! extension that the source browser had registered (but whose files
//! live outside the profile, the unpacked shape) is registered in the
//! target profile too.
//!
//! The browser password is pinned through the same env override the
//! other surface tests use; here the pinned word stands in for the
//! destination's keyring key, and pinning the fallback word itself
//! stands in for a machine where no keyring key exists. The tests in
//! this file pin different words, so they serialise on a lock instead
//! of racing over the process-wide override.

use std::path::Path;
use std::sync::Mutex;

use moveit_core::api::{App, UndoOutcome};
use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::logins::{self, Login};
use moveit_core::oscrypt::{login_prefix_host, HostTag, LinuxPrefix, Lock};

const COOKIES_SCHEMA: &str = "CREATE TABLE cookies (
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

const HISTORY_SCHEMA: &str = "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
    INSERT INTO meta VALUES('version','22');
    CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
        visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
        last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
    CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
        from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER,
        visit_duration INTEGER DEFAULT 0 NOT NULL);";

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
        possible_observer_handles BLOB);
    CREATE INDEX logins_signon ON logins (signon_realm);";

/// The destination keyring key both fixture browsers hold in these tests.
const KEYRING_SECRET: &str = "destination-keyring-secret";
/// An extension with a binary tree in the source profile.
const EXT_INSTALLED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// An unpacked extension: state in the profile, registration in the
/// source's Preferences, files outside the profile (the rig shape).
const EXT_UNPACKED: &str = "cccccccccccccccccccccccccccccccc";

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn pin(secret: &str) -> std::sync::MutexGuard<'static, ()> {
    let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("MOVEIT_LINUX_PASSWORD", secret);
    guard
}

fn make_db(path: &Path, schema: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch(schema).unwrap();
}

fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux(KEYRING_SECRET, LinuxPrefix::V10), from_libsecret_v2: false }
}

fn fresh_profile(dir: &Path) {
    make_db(&dir.join("Default/Cookies"), COOKIES_SCHEMA);
    make_db(&dir.join("Default/History"), HISTORY_SCHEMA);
    make_db(&dir.join("Default/Login Data"), LOGINS_SCHEMA);
}

fn login(user: &str, pw: &str, created: i64) -> Login {
    Login {
        origin_url: "https://example.com/".into(),
        action_url: "https://example.com/login".into(),
        username_value: user.into(),
        password_value: pw.into(),
        date_created: created,
        date_last_used: created,
        times_used: 1,
        signon_realm: "https://example.com".into(),
        date_password_modified: created,
    }
}

fn cookie(host: &str, name: &str, value: &str, cre: i64) -> Cookie {
    Cookie {
        host: host.into(),
        name: name.into(),
        path: "/".into(),
        value: value.into(),
        expires_utc: 0,
        creation_utc: cre,
        last_access_utc: cre,
        is_secure: 1,
        is_httponly: 0,
        samesite: -1,
        last_update_utc: Some(cre),
        top_frame_site_key: String::new(),
    }
}

fn plant_source(dir: &Path) {
    fresh_profile(dir);
    logins::import(
        &dir.join("Default/Login Data"),
        &[login("alice", "pw-a", 100)],
        &keys(),
        HostTag::Without,
    )
    .unwrap();
    cookies::import(
        &dir.join("Default/Cookies"),
        &[cookie(".example.com", "sess", "v1", 100)],
        &keys(),
    )
    .unwrap();
    // An installed extension (binary tree plus state).
    let ver_dir = dir.join(format!("Default/Extensions/{EXT_INSTALLED}/1.0_0"));
    std::fs::create_dir_all(&ver_dir).unwrap();
    std::fs::write(
        ver_dir.join("manifest.json"),
        br#"{"version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}"#,
    )
    .unwrap();
    // The unpacked extension: state in the profile, a registration in
    // Preferences, and no folder under Extensions at all.
    let state = dir.join(format!("Default/Local Extension Settings/{EXT_UNPACKED}"));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("state.txt"), b"unpacked-state").unwrap();
    let prefs = serde_json::json!({
        "extensions": { "settings": { EXT_UNPACKED: {
            "state": 1,
            "from_webstore": false,
            "location": 8,
            "path": "/fixture/unpacked-ext",
            "manifest": { "version": "1.0" },
        } } },
    });
    std::fs::write(dir.join("Default/Preferences"), serde_json::to_vec(&prefs).unwrap()).unwrap();
}

/// The Chrome target: one login and one cookie of its own, planted the
/// legacy way (v10 rows), like a destination whose existing stores
/// predate its keyring use.
fn plant_target(dir: &Path) {
    fresh_profile(dir);
    logins::import(&dir.join("Default/Login Data"), &[login("carol", "pw-c", 50)], &keys(), HostTag::Without)
        .unwrap();
    cookies::import(&dir.join("Default/Cookies"), &[cookie(".own.example", "mine", "keep", 10)], &keys())
        .unwrap();
}

fn app(state: &Path, src: &Path, dst: &Path) -> App {
    App::open(state)
        .unwrap()
        .with_key_store(std::sync::Arc::new(moveit_core::keychain::MemoryStore::default()))
        .with_local_profile("brave", src)
        .with_local_profile("chrome", dst)
}

fn raw_cookie_blob(dir: &Path, name: &str) -> Vec<u8> {
    let con = rusqlite::Connection::open(dir.join("Default/Cookies")).unwrap();
    con.query_row("SELECT encrypted_value FROM cookies WHERE name=?1", [name], |r| r.get(0)).unwrap()
}

fn raw_login_blob(dir: &Path, user: &str) -> Vec<u8> {
    let con = rusqlite::Connection::open(dir.join("Default/Login Data")).unwrap();
    con.query_row("SELECT password_value FROM logins WHERE username_value=?1", [user], |r| r.get(0))
        .unwrap()
}

#[test]
fn local_move_writes_v11_under_the_destination_keyring_key() {
    let _pin = pin(KEYRING_SECRET);
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let mut a = app(&t.path().join("state"), &src, &dst);

    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.cookies, 1);
    assert_eq!(report.logins, 1);

    // The moved cookie carries the v11 label and opens under the
    // destination's keyring key, and under no fallback-derived key.
    let blob = raw_cookie_blob(&dst, "sess");
    assert_eq!(&blob[..3], b"v11", "moved cookie must carry the v11 label");
    assert_eq!(
        Lock::linux(KEYRING_SECRET, LinuxPrefix::V11).decrypt(".example.com", &blob).unwrap(),
        "v1"
    );
    assert!(
        Lock::linux("peanuts", LinuxPrefix::V11).decrypt(".example.com", &blob).is_err(),
        "moved cookie must not open under the fallback key"
    );

    // Same for the moved login.
    let blob = raw_login_blob(&dst, "alice");
    assert_eq!(&blob[..3], b"v11", "moved login must carry the v11 label");
    let host = login_prefix_host("https://example.com/", "https://example.com");
    assert_eq!(
        Lock::linux(KEYRING_SECRET, LinuxPrefix::V11).decrypt(&host, &blob).unwrap(),
        "pw-a"
    );
    assert!(Lock::linux("peanuts", LinuxPrefix::V11).decrypt(&host, &blob).is_err());

    // And the whole target store reads back under the destination keys.
    assert_eq!(cookies::export(&dst.join("Default/Cookies"), &keys()).unwrap().len(), 2);
    assert_eq!(logins::export(&dst.join("Default/Login Data"), &keys()).unwrap().len(), 2);
}

#[test]
fn local_move_refuses_a_fallback_destination_key_and_writes_nothing() {
    // Pinning the fallback word is what discovery returns when no
    // keyring item exists for the destination browser at all.
    let _pin = pin("peanuts");
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let before_cookies = std::fs::read(dst.join("Default/Cookies")).unwrap();
    let before_logins = std::fs::read(dst.join("Default/Login Data")).unwrap();
    let mut a = app(&t.path().join("state"), &src, &dst);

    let err = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap_err();
    assert!(
        format!("{err}").contains("fallback key"),
        "the refusal must name the fallback problem: {err}"
    );
    assert!(a.local_preview("brave", "chrome", None, None).is_err(), "the preview refuses too");

    // Nothing was written: the target stores are byte-identical and
    // hold only the target's own rows, none of them fallback-sealed
    // copies of the source's secrets.
    assert_eq!(std::fs::read(dst.join("Default/Cookies")).unwrap(), before_cookies);
    assert_eq!(std::fs::read(dst.join("Default/Login Data")).unwrap(), before_logins);
    assert_eq!(cookies::export(&dst.join("Default/Cookies"), &keys()).unwrap().len(), 1);
    assert_eq!(logins::export(&dst.join("Default/Login Data"), &keys()).unwrap().len(), 1);
}

#[test]
fn local_move_registers_an_unpacked_extension_in_the_target_preferences() {
    let _pin = pin(KEYRING_SECRET);
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let mut a = app(&t.path().join("state"), &src, &dst);

    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();

    // The state travelled, as before.
    assert_eq!(
        std::fs::read(dst.join(format!("Default/Local Extension Settings/{EXT_UNPACKED}/state.txt"))).unwrap(),
        b"unpacked-state"
    );
    // And the extension is now registered in the target: its id sits in
    // extensions.settings of both Preferences and Secure Preferences,
    // which is what makes the target browser run it.
    for name in ["Preferences", "Secure Preferences"] {
        let prefs: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dst.join("Default").join(name)).unwrap()).unwrap();
        let settings = &prefs["extensions"]["settings"];
        assert!(
            settings.get(EXT_UNPACKED).is_some(),
            "{name} must register the unpacked extension: {prefs}"
        );
        assert_eq!(settings[EXT_UNPACKED]["location"], 8, "the source entry is carried, not invented");
    }
    assert!(
        report
            .extension_installs
            .iter()
            .any(|r| r.id == EXT_UNPACKED && r.status == "installed"),
        "the move reports the registration as installed: {:?}",
        report.extension_installs
    );

    // Undo takes the registration back out with everything else.
    assert_eq!(a.local_undo("chrome", false).unwrap(), UndoOutcome::Done);
    let prefs_path = dst.join("Default/Preferences");
    if prefs_path.exists() {
        let prefs: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&prefs_path).unwrap()).unwrap();
        assert!(prefs["extensions"]["settings"].get(EXT_UNPACKED).is_none());
    }
}
