//! One profile's worth of data, sealed and carried into a second profile, checked whole.
//! This is the glue (engine.rs) exercised against real SQLite stores on disk.

use std::path::Path;

use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::engine::{self, Profile};
use moveit_core::oscrypt::{HostTag, LinuxPrefix, Lock};
use moveit_core::sealed::SyncKey;

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

fn make_db(path: &Path, schema: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch(schema).unwrap();
}

fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
}

/// A profile with empty stores the engine can read and write.
fn fresh_profile(dir: &Path) {
    make_db(&dir.join("Default/Cookies"), COOKIES_SCHEMA);
    make_db(&dir.join("Default/History"), HISTORY_SCHEMA);
    make_db(&dir.join("Default/Login Data"), LOGINS_SCHEMA);
}

fn cookie(host: &str, name: &str, value: &str, cre: i64) -> Cookie {
    Cookie {
        host: host.into(), name: name.into(), path: "/".into(), value: value.into(),
        expires_utc: 0, creation_utc: cre, last_access_utc: cre, is_secure: 1,
        is_httponly: 0, samesite: -1, last_update_utc: Some(cre), top_frame_site_key: String::new(),
    }
}

fn plant_cookies(dir: &Path, cs: &[Cookie]) {
    cookies::import(&dir.join("Default/Cookies"), cs, &keys()).unwrap();
}

fn profile<'a>(dir: &'a Path, k: &'a Keys) -> Profile<'a> {
    Profile {
        dir,
        slot: "Default",
        keys: k,
        login_tag: HostTag::Without,
        browser: "chrome",
        display: "Google Chrome",
    }
}

#[test]
fn a_full_round_trip_carries_cookies_history_and_bookmarks() {
    let t = tempfile::tempdir().unwrap();
    let (a, b) = (t.path().join("A"), t.path().join("B"));
    fresh_profile(&a);
    fresh_profile(&b);
    plant_cookies(&a, &[cookie(".acme.test", "sid", "SECRET-SESSION", 100), cookie(".news.test", "pref", "dark", 90)]);
    std::fs::write(a.join("Default/Bookmarks"), br#"{"roots":{"bookmark_bar":{"children":[]}}}"#).unwrap();

    let k = keys();
    let key = SyncKey::from_bytes([3u8; 32]);
    let sealed = engine::seal_box(&profile(&a, &k), "fedora:A", &key).unwrap();
    // The box must not contain the cookie value in the clear.
    assert!(!sealed.windows(14).any(|w| w == b"SECRET-SESSION"), "value leaked into the sealed box");

    let payload = engine::open_box(&sealed, &key).unwrap();
    engine::import(&profile(&b, &k), &payload, 17_000_000_000_000i64).unwrap();

    let got = cookies::export(&b.join("Default/Cookies"), &k).unwrap();
    assert_eq!(got.len(), 2);
    assert!(got.iter().any(|c| c.host == ".acme.test" && c.value == "SECRET-SESSION"));
    assert!(b.join("Default/Bookmarks").exists());
}

#[test]
fn trading_boxes_both_ways_converges() {
    // A and B each have one unique cookie and a shared one with a different value; after each
    // imports the other's box, both must agree.
    let t = tempfile::tempdir().unwrap();
    let (a, b) = (t.path().join("A"), t.path().join("B"));
    fresh_profile(&a);
    fresh_profile(&b);
    plant_cookies(&a, &[cookie(".a.test", "x", "a-only", 10), cookie(".shared.test", "s", "alpha", 50)]);
    plant_cookies(&b, &[cookie(".b.test", "y", "b-only", 20), cookie(".shared.test", "s", "bravo", 50)]);

    let k = keys();
    let key = SyncKey::from_bytes([9u8; 32]);
    let box_a = engine::seal_box(&profile(&a, &k), "A", &key).unwrap();
    let box_b = engine::seal_box(&profile(&b, &k), "B", &key).unwrap();
    engine::import(&profile(&a, &k), &engine::open_box(&box_b, &key).unwrap(), 1).unwrap();
    engine::import(&profile(&b, &k), &engine::open_box(&box_a, &key).unwrap(), 1).unwrap();

    let mut ca = cookies::export(&a.join("Default/Cookies"), &k).unwrap();
    let mut cb = cookies::export(&b.join("Default/Cookies"), &k).unwrap();
    ca.sort_by(|x, y| (x.host.clone(), x.name.clone()).cmp(&(y.host.clone(), y.name.clone())));
    cb.sort_by(|x, y| (x.host.clone(), x.name.clone()).cmp(&(y.host.clone(), y.name.clone())));
    assert_eq!(ca, cb, "the two profiles must hold the same cookies after trading boxes");
    assert_eq!(ca.len(), 3);
}

#[test]
fn a_locked_cookie_db_rolls_the_whole_import_back() {
    let t = tempfile::tempdir().unwrap();
    let (a, b) = (t.path().join("A"), t.path().join("B"));
    fresh_profile(&a);
    fresh_profile(&b);
    plant_cookies(&a, &[cookie(".a.test", "x", "val", 10)]);
    std::fs::write(b.join("Default/Bookmarks"), b"OLD BOOKMARKS").unwrap();

    let k = keys();
    let key = SyncKey::from_bytes([1u8; 32]);
    let payload = engine::open_box(&engine::seal_box(&profile(&a, &k), "A", &key).unwrap(), &key).unwrap();

    // Hold the cookie DB open with an exclusive lock: the import must change nothing in B.
    let hold = rusqlite::Connection::open(b.join("Default/Cookies")).unwrap();
    hold.busy_timeout(std::time::Duration::from_millis(100)).unwrap();
    hold.execute_batch("BEGIN EXCLUSIVE").unwrap();

    let err = engine::import(&profile(&b, &k), &payload, 1);
    assert!(err.is_err(), "a locked store must fail the move");
    assert_eq!(std::fs::read(b.join("Default/Bookmarks")).unwrap(), b"OLD BOOKMARKS", "bookmarks rolled back");
}
