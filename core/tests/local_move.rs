//! The same-device move (api.rs) exercised the way the shell will use it: two
//! fixture browsers on one machine, no pairing, no shared place, a preview, a
//! move, and an undo. The source must come through untouched, byte for byte.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use moveit_core::api::{App, OpenCheck, Progress, UndoOutcome};
use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::history;
use moveit_core::logins::{self, Login};
use moveit_core::oscrypt::{HostTag, LinuxPrefix, Lock};

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

/// The keyring secret the fixtures share. The surface discovers the browser
/// password itself; the env override pins it to this word so fixtures open.
/// It is deliberately NOT the compiled-in fallback ("peanuts"): a
/// same-device move writes under the destination's validated keyring key
/// (v11) and refuses a fallback destination key, so the fixtures' shared
/// secret stands in for the keyring key both browsers hold here.
const KEYRING_SECRET: &str = "moveit-test-keyring-secret";

fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux(KEYRING_SECRET, LinuxPrefix::V10), from_libsecret_v2: false }
}

fn pin_browser_password() {
    std::env::set_var("MOVEIT_LINUX_PASSWORD", KEYRING_SECRET);
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

fn plant_history(dir: &Path, n: usize) {
    let mut section = history::Section::default();
    for i in 0..n {
        section.urls.push(history::HistoryUrl {
            url: format!("https://site{i}.example/"),
            title: String::new(),
            typed_count: 0,
            last_visit_time: 1_000 + i as i64,
            hidden: 0,
        });
    }
    history::import(&dir.join("Default/History"), &section).unwrap();
}

fn plant_bookmarks(dir: &Path) {
    std::fs::write(
        dir.join("Default/Bookmarks"),
        br#"{"roots":{"bookmark_bar":{"type":"folder","children":[
            {"type":"url","url":"https://a.example"},
            {"type":"url","url":"https://b.example"}]}}}"#,
    )
    .unwrap();
}

/// The Brave source: two logins, two cookies, three history urls, two bookmarks,
/// two extensions with state on disk.
fn plant_source(dir: &Path) {
    fresh_profile(dir);
    logins::import(
        &dir.join("Default/Login Data"),
        &[login("alice", "pw-a", 100), login("bob", "pw-b", 200)],
        &keys(),
        HostTag::Without,
    )
    .unwrap();
    cookies::import(
        &dir.join("Default/Cookies"),
        &[cookie(".example.com", "sess", "v1", 100), cookie(".news.example", "pref", "dark", 90)],
        &keys(),
    )
    .unwrap();
    plant_history(dir, 3);
    plant_bookmarks(dir);
    const EXT_ONE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EXT_TWO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    for (id, ver) in [(EXT_ONE, "1.0_0"), (EXT_TWO, "1.0_0")] {
        let ver_dir = dir.join(format!("Default/Extensions/{id}/{ver}"));
        std::fs::create_dir_all(&ver_dir).unwrap();
        std::fs::write(
            ver_dir.join("manifest.json"),
            br#"{"version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}"#,
        )
        .unwrap();
    }
    let state = dir.join(format!("Default/Local Extension Settings/{EXT_ONE}"));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("state.txt"), b"extone-state").unwrap();
}

/// The Chrome target: one login and one cookie of its own, nothing else.
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

/// The bytes of the stores a move must never change on the source side.
fn store_bytes(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut m = BTreeMap::new();
    for rel in ["Default/Cookies", "Default/History", "Default/Login Data", "Default/Bookmarks"] {
        let p = dir.join(rel);
        if p.exists() {
            m.insert(p.clone(), std::fs::read(&p).unwrap());
        }
    }
    m
}

#[test]
fn local_move_round_trip_and_undo() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    // No pipe, no pairing, no sync key: the app state is a bare folder.
    let mut a = app(&t.path().join("state"), &src, &dst);

    // The pick screen's list carries both browsers.
    let browsers = a.local_browsers();
    assert!(browsers.iter().any(|b| b.browser == "brave" && b.display == "Brave"));
    assert!(browsers.iter().any(|b| b.browser == "chrome" && b.display == "Google Chrome"));

    // The preview counts the source, names the target, skips nothing.
    let preview = a.local_preview("brave", "chrome", None, None).unwrap();
    assert_eq!(preview.source, "Brave");
    assert_eq!(preview.target, "Google Chrome");
    assert_eq!(preview.logins, 2);
    assert_eq!(preview.passwords, 2);
    assert_eq!(preview.history, 3);
    assert_eq!(preview.bookmarks, 2);
    assert_eq!(preview.extensions, 2);
    assert_eq!(preview.locked_cookies, 0);
    assert!(preview.skipped.is_empty(), "nothing should be skipped: {:?}", preview.skipped);

    let before = store_bytes(&src);
    let mut events: Vec<Progress> = Vec::new();
    let report = a.local_move("brave", "chrome", None, None, None, &mut |p| events.push(p)).unwrap();
    assert_eq!(report.source, "Brave");
    assert_eq!(report.target, "Google Chrome");
    assert_eq!(report.cookies, 2);
    assert_eq!(report.logins, 2);
    assert_eq!(report.history_urls, 3);
    assert_eq!(report.extensions, 1, "only ext one has saved state to carry");
    assert!(!events.is_empty());
    assert_eq!(events.first().unwrap().step, "read");
    let last = events.last().unwrap();
    assert_eq!(last.step, "done");
    assert_eq!(last.frac, 1.0);
    for w in events.windows(2) {
        assert!(w[1].frac >= w[0].frac, "progress must not run backwards: {events:?}");
    }

    // The source is byte-identical afterwards.
    assert_eq!(store_bytes(&src), before, "a local move only reads its source");

    // Chrome now holds its own things plus Brave's, readable with Chrome's keys.
    let found = logins::export(&dst.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(found.len(), 3);
    for (u, pw) in [("carol", "pw-c"), ("alice", "pw-a"), ("bob", "pw-b")] {
        assert!(
            found.iter().any(|l| l.username_value == u && l.password_value == pw),
            "login {u} must be in Chrome now: {found:?}"
        );
    }
    let got = cookies::export(&dst.join("Default/Cookies"), &keys()).unwrap();
    assert_eq!(got.len(), 3);
    assert!(got.iter().any(|c| c.host == ".example.com" && c.value == "v1"));
    assert!(got.iter().any(|c| c.host == ".own.example" && c.value == "keep"));
    // What landed is encrypted at rest, not plaintext with a new label.
    let wrong = Keys::Gcm { lock: Lock::windows([7; 32]) };
    assert_eq!(
        cookies::export(&dst.join("Default/Cookies"), &wrong)
            .unwrap()
            .len(),
        0,
        "wrong keys yield nothing readable"
    );
    let hist = history::export(&dst.join("Default/History")).unwrap();
    assert_eq!(hist.urls.len(), 3);
    let bm = std::fs::read(dst.join("Default/Bookmarks")).unwrap();
    assert!(bm.windows(17).any(|w| w == b"https://a.example"), "bookmarks carried into Chrome");
    let ext_state = dst.join("Default/Local Extension Settings/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/state.txt");
    assert_eq!(std::fs::read(&ext_state).unwrap(), b"extone-state", "extension state carried");

    // Undo puts Chrome back to exactly what it was.
    assert_eq!(a.local_undo("chrome", false).unwrap(), UndoOutcome::Done);
    let after = logins::export(&dst.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].username_value, "carol");
    let got = cookies::export(&dst.join("Default/Cookies"), &keys()).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].host, ".own.example");
    assert!(!dst.join("Default/Bookmarks").exists(), "undo removes the carried bookmarks file");
    assert_eq!(a.local_undo("chrome", false).unwrap(), UndoOutcome::Nothing);
}

#[test]
fn local_move_applies_profile_kinds() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let kinds = BTreeMap::from([(
        "local:default".to_string(),
        vec!["bookmarks".to_string()],
    )]);
    let report = a.local_move("brave", "chrome", None, None, Some(&kinds), &mut |_| {}).unwrap();
    assert_eq!(report.logins, 0);
    assert_eq!(report.cookies, 0);
    assert_eq!(report.history_urls, 0);
    let bm = std::fs::read(dst.join("Default/Bookmarks")).unwrap();
    assert!(bm.windows(17).any(|w| w == b"https://a.example"), "bookmarks must land");
    let found = logins::export(&dst.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(found.len(), 1, "other kinds must not move");
}

#[test]
fn local_move_legacy_kinds_apply_to_the_source() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let kinds = BTreeMap::from([("*".to_string(), vec!["bookmarks".to_string()])]);
    let report = a.local_move("brave", "chrome", None, None, Some(&kinds), &mut |_| {}).unwrap();
    assert_eq!(report.logins, 0);
    assert_eq!(report.cookies, 0);
    let bm = std::fs::read(dst.join("Default/Bookmarks")).unwrap();
    assert!(bm.windows(17).any(|w| w == b"https://a.example"));
}

#[test]
fn local_move_refuses_itself_and_unknown_browsers() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    plant_source(&src);
    let mut a = app(&t.path().join("state"), &src, &src);
    assert!(a.local_preview("brave", "brave", None, None).is_err(), "a browser cannot move into itself");
    assert!(a.local_move("brave", "brave", None, None, None, &mut |_| {}).is_err());
    assert!(a.local_preview("brave", "opera", None, None).is_err(), "an unknown target is refused plainly");
    assert!(a.local_move("opera", "brave", None, None, None, &mut |_| {}).is_err(), "an unknown source is refused plainly");
}

#[test]
fn local_move_reports_locked_cookies_and_moves_the_rest() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    // One App-Bound cookie in the source, planted raw the way a locked-down
    // browser writes it.
    {
        let con = rusqlite::Connection::open(src.join("Default/Cookies")).unwrap();
        let mut blob = b"v20".to_vec();
        blob.extend_from_slice(&[7u8; 40]);
        con.execute(
            "INSERT INTO cookies (creation_utc, host_key, name, path, encrypted_value) VALUES (1, '.locked.example', 'sess', '/', ?1)",
            rusqlite::params![blob],
        )
        .unwrap();
    }
    let mut a = app(&t.path().join("state"), &src, &dst);

    let preview = a.local_preview("brave", "chrome", None, None).unwrap();
    assert_eq!(preview.locked_cookies, 1);
    if cfg!(target_os = "windows") {
        assert!(
            preview.skipped.iter().any(|s| s.browser == "Brave" && s.reason.contains("App-Bound")),
            "the locked cookies must be named as skipped: {:?}",
            preview.skipped
        );
    } else {
        assert!(
            preview.skipped.iter().any(|s| {
                s.browser == "Brave" && s.reason.contains("sealed by the browser on Windows")
            }),
            "v20 cookies must be counted on Linux: {:?}",
            preview.skipped
        );
    }

    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.locked_cookies, 1);
    assert_eq!(report.cookies, 2, "the movable cookies still move");
    let got = cookies::export(&dst.join("Default/Cookies"), &keys()).unwrap();
    assert_eq!(got.len(), 3);
    assert!(!got.iter().any(|c| c.host == ".locked.example"), "the locked cookie stays behind");
}

#[test]
fn local_open_check_names_the_open_browser_and_the_move_refuses() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let mut a = app(&t.path().join("state"), &src, &dst);

    assert_eq!(a.local_open_check("brave", "chrome").unwrap(), OpenCheck::Clear);
    // A second connection holding the write lock is what a running Chrome looks like.
    let holder = rusqlite::Connection::open(dst.join("Default/Cookies")).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        a.local_open_check("brave", "chrome").unwrap(),
        OpenCheck::Blocked { browser: "Google Chrome".into() }
    );
    assert!(a.local_move("brave", "chrome", None, None, None, &mut |_| {}).is_err(), "never write into an open browser");
    holder.execute_batch("ROLLBACK").unwrap();
    assert_eq!(a.local_open_check("brave", "chrome").unwrap(), OpenCheck::Clear);
}


#[test]
fn a_second_registration_for_a_name_replaces_the_first() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let first = t.path().join("first");
    let second = t.path().join("second");
    let dst = t.path().join("chrome-prof");
    plant_source(&first); // 3 history urls
    fresh_profile(&second);
    plant_history(&second, 1); // distinguishable: exactly 1 history url
    plant_target(&dst);
    let a = App::open(&t.path().join("state"))
        .unwrap()
        .with_local_profile("brave", &first)
        .with_local_profile("brave", &second)
        .with_local_profile("chrome", &dst);
    let preview = a.local_preview("brave", "chrome", None, None).unwrap();
    assert_eq!(preview.history, 1, "the second registration is the one that counts");
    assert_eq!(a.local_browsers().iter().filter(|b| b.browser == "brave").count(), 1);
}

#[test]
fn an_unreadable_browser_is_refused_at_preview_not_after_it() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let firefox = t.path().join("firefox-prof");
    let dst = t.path().join("chrome-prof");
    plant_target(&firefox);
    plant_target(&dst);
    let mut a = App::open(&t.path().join("state"))
        .unwrap()
        .with_local_profile("firefox", &firefox)
        .with_local_profile("chrome", &dst);
    // This surface cannot attempt a Firefox password at all (no adapter
    // for it yet), so the preview refuses with the same error the move
    // would give, instead of counts that promise a move.
    assert!(a.local_preview("firefox", "chrome", None, None).is_err());
    assert!(a.local_move("firefox", "chrome", None, None, None, &mut |_| {}).is_err());
    // The target's keys gate the preview too: a move into a browser whose
    // password cannot be attempted can never write, so it refuses up front.
    assert!(a.local_preview("chrome", "firefox", None, None).is_err());
    assert!(a.local_move("chrome", "firefox", None, None, None, &mut |_| {}).is_err());
}

#[test]
fn local_undo_refuses_while_the_target_browser_is_open() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let mut a = App::open(&t.path().join("state"))
        .unwrap()
        .with_local_profile("brave", &src)
        .with_local_profile("chrome", &dst);
    a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();

    let holder = rusqlite::Connection::open(dst.join("Default/Cookies")).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(a.local_undo("chrome", false).is_err(), "undo must not swap stores under a running browser");
    holder.execute_batch("ROLLBACK").unwrap();
    drop(holder);
    assert_eq!(a.local_undo("chrome", false).unwrap(), UndoOutcome::Done);
}

#[test]
fn local_undo_undoes_the_newest_move_into_that_browser() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let other = t.path().join("chromium-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    fresh_profile(&other);
    logins::import(&other.join("Default/Login Data"), &[login("dave", "dave-pw", 3_000)], &keys(), HostTag::Without).unwrap();
    let mut a = App::open(&t.path().join("state"))
        .unwrap()
        .with_local_profile("brave", &src)
        .with_local_profile("chromium", &other)
        .with_local_profile("chrome", &dst);
    a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    a.local_move("chromium", "chrome", None, None, None, &mut |_| {}).unwrap();

    // The journal keeps one undo point per profile: the second move replaced
    // the first move's point, so undo reverses the newest move only.
    assert_eq!(a.local_undo("chrome", false).unwrap(), UndoOutcome::Done);
    let names: Vec<String> = logins::export(&dst.join("Default/Login Data"), &keys())
        .unwrap()
        .iter()
        .map(|l| l.username_value.clone())
        .collect();
    assert!(names.contains(&"carol".to_string()) && names.contains(&"alice".to_string()));
    assert!(!names.contains(&"dave".to_string()), "the newest move was the one undone");
    assert_eq!(a.local_undo("chrome", false).unwrap(), UndoOutcome::Nothing);
}

#[test]
fn welcome_start_recovers_an_unfinished_move_into_any_browser() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    // Keep detection away from the real machine's browsers.
    let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
    std::env::set_var("XDG_CONFIG_HOME", t.path().join("xdg"));
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let cookies_path = dst.join("Default/Cookies");
    let original = std::fs::read(&cookies_path).unwrap();
    // A second copy of this test binary plays a move that is killed midway:
    // a real process death, so the folder lock dies with it exactly as it
    // would for the app.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_mid_move_helper", "--test-threads=1"])
        .env("MOVEIT_CRASH_DIR", t.path())
        .status()
        .unwrap();
    assert!(!status.success(), "the helper must die mid-move");
    assert_eq!(std::fs::read(&cookies_path).unwrap(), b"half-moved");

    let mut a = App::open(&t.path().join("state"))
        .unwrap()
        .with_key_store(std::sync::Arc::new(moveit_core::keychain::MemoryStore::default()))
        .with_profile("brave", &src)
        .with_local_profile("chrome", &dst);
    a.welcome_start().unwrap();
    match old_xdg {
        Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }
    assert_eq!(
        std::fs::read(&cookies_path).unwrap(),
        original,
        "the unfinished move into a non-working browser is put back"
    );
}

/// The killed process in the welcome_start recovery test above.
/// Without MOVEIT_CRASH_DIR (a normal suite run) it does nothing.
#[test]
fn crash_mid_move_helper() {
    let Ok(dir) = std::env::var("MOVEIT_CRASH_DIR") else { return };
    let dst = Path::new(&dir).join("chrome-prof");
    let cookies_path = dst.join("Default/Cookies");
    let tx = moveit_core::txn::Txn::begin(&dst, &[("cookies", &cookies_path)]).unwrap();
    std::fs::write(&cookies_path, b"half-moved").unwrap();
    std::mem::forget(tx);
    std::process::abort();
}


#[cfg(unix)]
#[test]
fn welcome_start_leaves_an_open_browsers_unfinished_move_alone() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
    std::env::set_var("XDG_CONFIG_HOME", t.path().join("xdg"));
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let cookies_path = dst.join("Default/Cookies");
    let original = std::fs::read(&cookies_path).unwrap();
    // The same killed-process crash as the recovery test: a real journal, a
    // half-written store.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_mid_move_helper", "--test-threads=1"])
        .env("MOVEIT_CRASH_DIR", t.path())
        .status()
        .unwrap();
    assert!(!status.success());
    assert_eq!(std::fs::read(&cookies_path).unwrap(), b"half-moved");
    // Chrome is open now: its singleton names this very (living) process.
    let lock_target = format!("this-machine-{}", std::process::id());
    std::os::unix::fs::symlink(&lock_target, dst.join("SingletonLock")).unwrap();
    let mut a = App::open(&t.path().join("state"))
        .unwrap()
        .with_key_store(std::sync::Arc::new(moveit_core::keychain::MemoryStore::default()))
        .with_profile("brave", &src)
        .with_local_profile("chrome", &dst);
    a.welcome_start().unwrap();
    assert_eq!(
        std::fs::read(&cookies_path).unwrap(),
        b"half-moved",
        "an open browser's stores are not swapped under it"
    );
    // Closed again: the next start puts the half-move back.
    std::fs::remove_file(dst.join("SingletonLock")).unwrap();
    a.welcome_start().unwrap();
    match old_xdg {
        Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }
    assert_eq!(std::fs::read(&cookies_path).unwrap(), original);
}


/// The killed process in the source-recovery test below: it begins a
/// move into the source profile, scribbles its cookie store, and dies
/// holding the journal (a leaked in-process journal would keep the
/// folder lock, which a real crash does not).
/// Without MOVEIT_CRASH_SRC_DIR (a normal suite run) it does nothing.
#[test]
fn crash_mid_source_helper() {
    let Ok(dir) = std::env::var("MOVEIT_CRASH_SRC_DIR") else { return };
    let src = Path::new(&dir).join("brave-prof");
    let cookies_path = src.join("Default/Cookies");
    let tx = moveit_core::txn::Txn::begin(&src, &[("cookies", &cookies_path)]).unwrap();
    std::fs::write(&cookies_path, b"half-moved").unwrap();
    std::mem::forget(tx);
    std::process::abort();
}

#[test]
fn a_crashed_move_in_the_source_is_put_back_before_the_read() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    // An earlier move INTO the source died half-way: a live journal and a
    // scribbled cookie store. The next move out of it must read the
    // restored store, not the wreck.
    let cookies_path = src.join("Default/Cookies");
    let original = std::fs::read(&cookies_path).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_mid_source_helper", "--test-threads=1"])
        .env("MOVEIT_CRASH_SRC_DIR", t.path())
        .status()
        .unwrap();
    assert!(!status.success());
    assert_eq!(std::fs::read(&cookies_path).unwrap(), b"half-moved");
    assert!(moveit_core::txn::has_unfinished(&src));

    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert!(!moveit_core::txn::has_unfinished(&src), "the journal was recovered");
    assert_eq!(std::fs::read(&cookies_path).unwrap(), original, "source restored before the read");
    assert!(report.cookies > 0, "the restored cookies are what moved");
}

#[cfg(unix)]
#[test]
fn recovery_waits_while_the_source_browser_is_open() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    plant_target(&dst);
    let cookies_path = src.join("Default/Cookies");
    let tx = moveit_core::txn::Txn::begin(&src, &[("cookies", &cookies_path)]).unwrap();
    std::fs::write(&cookies_path, b"half-moved").unwrap();
    std::mem::forget(tx);
    // The source browser is open: its singleton names this living process.
    let lock_target = format!("this-machine-{}", std::process::id());
    std::os::unix::fs::symlink(&lock_target, src.join("SingletonLock")).unwrap();

    let mut a = app(&t.path().join("state"), &src, &dst);
    let err = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap_err();
    assert!(matches!(err, moveit_core::Error::BrowserOpen), "{err:?}");
    assert_eq!(std::fs::read(&cookies_path).unwrap(), b"half-moved", "nothing was swapped under the open browser");
    assert!(moveit_core::txn::has_unfinished(&src), "the journal waits for a closed browser");
}


#[test]
fn never_launched_profiles_refuse_preview_and_move_without_planting() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    // Installed but never opened: Default exists, no Cookies / Login Data.
    std::fs::create_dir_all(src.join("Default")).unwrap();
    std::fs::create_dir_all(dst.join("Default")).unwrap();
    make_db(&dst.join("Default/History"), HISTORY_SCHEMA);

    let mut a = app(&t.path().join("state"), &src, &dst);
    let preview_err = a.local_preview("brave", "chrome", None, None).unwrap_err();
    assert!(
        matches!(
            &preview_err,
            moveit_core::Error::NeverLaunched { browser } if browser == "Brave"
        ),
        "{preview_err:?}"
    );
    let move_err = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap_err();
    assert!(
        matches!(
            &move_err,
            moveit_core::Error::NeverLaunched { browser } if browser == "Brave"
        ),
        "{move_err:?}"
    );
    assert!(!src.join("Default/Cookies").exists());
    assert!(!src.join("Default/Network/Cookies").exists());
    assert!(!src.join("Default/Login Data").exists());
    assert!(!dst.join("Default/Cookies").exists());
    assert!(!dst.join("Default/Network/Cookies").exists());
    assert!(!dst.join("Default/Login Data").exists());
}

#[test]
fn never_launched_target_refuses_even_when_source_is_ready() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source(&src);
    std::fs::create_dir_all(dst.join("Default")).unwrap();
    let mut a = app(&t.path().join("state"), &src, &dst);
    let err = a.local_preview("brave", "chrome", None, None).unwrap_err();
    assert!(
        matches!(
            &err,
            moveit_core::Error::NeverLaunched { browser } if browser == "Google Chrome"
        ),
        "{err:?}"
    );
    let move_err = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap_err();
    assert!(
        matches!(
            &move_err,
            moveit_core::Error::NeverLaunched { browser } if browser == "Google Chrome"
        ),
        "{move_err:?}"
    );
    assert!(!dst.join("Default/Cookies").exists());
    assert!(!dst.join("Default/Network/Cookies").exists());
    assert!(!dst.join("Default/Login Data").exists());
}

#[test]
fn any_one_store_lets_the_never_launched_guard_pass() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    // Three shapes Chromium uses across Linux/macOS/Windows: modern Cookies,
    // legacy Cookies, and Login Data alone. Each alone is enough to proceed.
    for (label, plant) in [
        ("modern", "Default/Network/Cookies"),
        ("legacy", "Default/Cookies"),
        ("logins", "Default/Login Data"),
    ] {
        let src = t.path().join(format!("src-{label}"));
        let dst = t.path().join(format!("dst-{label}"));
        plant_source(&src);
        std::fs::create_dir_all(dst.join("Default")).unwrap();
        if plant.ends_with("Login Data") {
            make_db(&dst.join(plant), LOGINS_SCHEMA);
        } else {
            make_db(&dst.join(plant), COOKIES_SCHEMA);
        }
        let a = app(&t.path().join(format!("state-{label}")), &src, &dst);
        // Guard passed: failure past this point is keys/open, not NeverLaunched.
        let err = a.local_preview("brave", "chrome", None, None);
        assert!(
            !matches!(err, Err(moveit_core::Error::NeverLaunched { .. })),
            "{label}: {err:?}"
        );
    }
}

fn plant_source_profile1(dir: &Path) {
    let slot = dir.join("Profile 1");
    std::fs::create_dir_all(&slot).unwrap();
    std::fs::create_dir_all(dir.join("Default")).unwrap();
    make_db(&slot.join("Cookies"), COOKIES_SCHEMA);
    make_db(&slot.join("History"), HISTORY_SCHEMA);
    make_db(&slot.join("Login Data"), LOGINS_SCHEMA);
    logins::import(
        &slot.join("Login Data"),
        &[login("p1", "secret", 100)],
        &keys(),
        HostTag::Without,
    )
    .unwrap();
    cookies::import(
        &slot.join("Cookies"),
        &[cookie(".profile1.example", "sid", "1", 100)],
        &keys(),
    )
    .unwrap();
    let mut section = history::Section::default();
    for i in 0..2 {
        section.urls.push(history::HistoryUrl {
            url: format!("https://p1-{i}.example/"),
            title: String::new(),
            typed_count: 0,
            last_visit_time: 1_000 + i as i64,
            hidden: 0,
        });
    }
    history::import(&slot.join("History"), &section).unwrap();
    const EXT: &str = "cccccccccccccccccccccccccccccccc";
    let ver_dir = slot.join(format!("Extensions/{EXT}/1.0_0"));
    std::fs::create_dir_all(&ver_dir).unwrap();
    std::fs::write(
        ver_dir.join("manifest.json"),
        br#"{"version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}"#,
    )
    .unwrap();
    let state = slot.join(format!("Local Extension Settings/{EXT}"));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("state.txt"), b"p1-ext").unwrap();
}

#[test]
fn local_move_profile1_source_slot_round_trip_and_undo() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_source_profile1(&src);
    plant_target(&dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let preview = a.local_preview("brave", "chrome", Some("Profile 1"), None).unwrap();
    assert_eq!(preview.logins, 1);
    assert_eq!(preview.cookies, 1);
    assert_eq!(preview.history, 2);
    assert_eq!(preview.extensions, 1);
    let before = store_bytes(&src);
    let report = a
        .local_move("brave", "chrome", Some("Profile 1"), None, None, &mut |_| {})
        .unwrap();
    assert_eq!(report.logins, preview.logins);
    assert_eq!(report.cookies, preview.cookies);
    assert_eq!(report.history_urls, preview.history);
    assert_eq!(report.extensions, preview.extensions);
    assert_eq!(store_bytes(&src), before, "source Profile 1 is read-only");
    assert_eq!(a.undo_last(false).unwrap(), UndoOutcome::Done);
}

#[test]
fn local_move_updates_the_home_undo_record() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("target");
    plant_source(&src);
    plant_target(&dst);
    let before = store_bytes(&dst);
    let empty_base = tempfile::tempdir().unwrap();
    let mut a = app(&t.path().join("state"), &src, &dst)
        .with_browser_base(empty_base.path())
        .with_profile("chrome", &dst);
    a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    let home = a.home_state().unwrap();
    assert!(home.can_undo);
    assert!(home.last_sync.is_some());
    assert_eq!(a.undo_last(false).unwrap(), UndoOutcome::Done);
    assert_eq!(store_bytes(&dst), before);
    assert!(!a.home_state().unwrap().can_undo);
}

// ---- Already-present reporting (notes/localmove-noop-investigation.md) ----
//
// Two synthetic profiles planted with the same identities; only the
// timestamps differ, which is what decides the merge. No extensions and
// no bookmarks, so the report counts are purely cookies/logins/history.

fn plant_dedupe_profile(
    dir: &Path,
    stamp: i64,
    cookie_names: &[&str],
    login_users: &[&str],
    history: &[(&str, i64, Vec<i64>)],
) {
    fresh_profile(dir);
    if !cookie_names.is_empty() {
        let rows: Vec<Cookie> = cookie_names
            .iter()
            .map(|n| cookie(".example.com", n, &format!("v-{n}"), stamp))
            .collect();
        cookies::import(&dir.join("Default/Cookies"), &rows, &keys()).unwrap();
    }
    if !login_users.is_empty() {
        let rows: Vec<Login> = login_users
            .iter()
            .map(|u| login(u, &format!("pw-{u}"), stamp))
            .collect();
        logins::import(&dir.join("Default/Login Data"), &rows, &keys(), HostTag::Without).unwrap();
    }
    if !history.is_empty() {
        let mut section = history::Section::default();
        for (url, last, visits) in history {
            section.urls.push(history::HistoryUrl {
                url: (*url).to_string(),
                title: String::new(),
                typed_count: 0,
                last_visit_time: *last,
                hidden: 0,
            });
            for t in visits {
                section.visits.push(history::Visit {
                    url: (*url).to_string(),
                    visit_time: *t,
                    from_visit_time: None,
                    transition: 0,
                    visit_duration: 0,
                });
            }
        }
        history::import(&dir.join("Default/History"), &section).unwrap();
    }
}

#[test]
fn local_move_destination_newer_reports_already_present() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    let hist_src: &[(&str, i64, Vec<i64>)] = &[("https://site0.example/", 1000, vec![1000])];
    let hist_dst: &[(&str, i64, Vec<i64>)] = &[("https://site0.example/", 2000, vec![1000])];
    plant_dedupe_profile(&src, 100, &["sess", "pref"], &["alice"], hist_src);
    plant_dedupe_profile(&dst, 200, &["sess", "pref"], &["alice"], hist_dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let preview = a.local_preview("brave", "chrome", None, None).unwrap();
    assert_eq!((preview.cookies, preview.logins, preview.history), (2, 1, 1));
    let cookies_before = std::fs::read(dst.join("Default/Cookies")).unwrap();
    let logins_before = std::fs::read(dst.join("Default/Login Data")).unwrap();
    let mut events: Vec<Progress> = Vec::new();
    let report = a
        .local_move("brave", "chrome", None, None, None, &mut |p| events.push(p))
        .unwrap();
    assert_eq!((report.cookies, report.logins, report.history_urls), (0, 0, 0));
    assert_eq!(report.history_visits_moved, 0);
    assert_eq!(report.already_present_cookies, 2, "the whole cookie preview was already there");
    assert_eq!(report.already_present_logins, 1, "the whole login preview was already there");
    assert_eq!(report.summary, "Nothing new to move: Google Chrome already has all of this");
    assert_ne!(report.summary, "Everything moved");
    let last = events.last().unwrap();
    assert_eq!(last.step, "done");
    assert_eq!(last.line, report.summary, "the progress done line is the report summary");
    assert_eq!(
        std::fs::read(dst.join("Default/Cookies")).unwrap(),
        cookies_before,
        "kept cookies leave the target store byte-identical"
    );
    assert_eq!(
        std::fs::read(dst.join("Default/Login Data")).unwrap(),
        logins_before,
        "kept logins leave the target store byte-identical"
    );
}

#[test]
fn local_move_source_newer_lands_everything_and_reports_no_already_present() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    let hist_src: &[(&str, i64, Vec<i64>)] = &[("https://site0.example/", 2000, vec![1000])];
    let hist_dst: &[(&str, i64, Vec<i64>)] = &[("https://site0.example/", 1000, vec![1000])];
    plant_dedupe_profile(&src, 200, &["sess", "pref"], &["alice"], hist_src);
    plant_dedupe_profile(&dst, 100, &["sess", "pref"], &["alice"], hist_dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.cookies, 2, "newer source cookies replace the target copies");
    assert_eq!(report.logins, 1, "the newer source login updates the target copy");
    assert_eq!(report.history_urls, 1, "the newer last visit updates the url");
    assert_eq!(report.already_present_cookies, 0);
    assert_eq!(report.already_present_logins, 0);
    assert_eq!(report.summary, "Everything moved");
}

#[test]
fn local_move_exact_tie_reports_already_present_not_imported() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    let hist: &[(&str, i64, Vec<i64>)] = &[("https://site0.example/", 1500, vec![1500])];
    plant_dedupe_profile(&src, 150, &["sess", "pref"], &["alice"], hist);
    plant_dedupe_profile(&dst, 150, &["sess", "pref"], &["alice"], hist);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!((report.cookies, report.logins, report.history_urls), (0, 0, 0));
    assert_eq!(report.history_visits_moved, 0);
    assert_eq!(report.already_present_cookies, 2, "a tie keeps the destination row");
    assert_eq!(report.already_present_logins, 1, "a tie keeps the destination row");
    assert_eq!(report.summary, "Nothing new to move: Google Chrome already has all of this");
}

#[test]
fn local_move_partial_overlap_reports_moved_and_already_had() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    let hist_src: &[(&str, i64, Vec<i64>)] = &[("https://site0.example/", 1000, vec![1000])];
    let hist_dst: &[(&str, i64, Vec<i64>)] = &[("https://site0.example/", 2000, vec![1000])];
    plant_dedupe_profile(&src, 100, &["sess", "pref", "extra"], &["alice", "bob"], hist_src);
    plant_dedupe_profile(&dst, 200, &["sess", "pref"], &["alice"], hist_dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.cookies, 1, "only the missing cookie lands");
    assert_eq!(report.already_present_cookies, 2, "the shared cookies were already there, newer");
    assert_eq!(report.logins, 1, "only the missing login lands");
    assert_eq!(report.already_present_logins, 1, "the shared login was already there, newer");
    assert_eq!(report.summary, "Moved 2, already had 3");
    let got = cookies::export(&dst.join("Default/Cookies"), &keys()).unwrap();
    assert_eq!(got.len(), 3);
    let found = logins::export(&dst.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(found.len(), 2);
}

#[test]
fn local_move_visit_only_history_change_is_reported() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    let hist_src: &[(&str, i64, Vec<i64>)] = &[
        ("https://site0.example/", 1000, vec![3000, 4000]),
        ("https://site1.example/", 1000, vec![3000]),
    ];
    let hist_dst: &[(&str, i64, Vec<i64>)] = &[
        ("https://site0.example/", 5000, vec![1000]),
        ("https://site1.example/", 5000, vec![1000]),
    ];
    plant_dedupe_profile(&src, 100, &[], &[], hist_src);
    plant_dedupe_profile(&dst, 200, &[], &[], hist_dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.history_urls, 0, "no url is inserted or updated");
    assert_eq!(report.history_visits_moved, 3, "the new visits landed and are reported");
    assert_eq!(report.summary, "Everything moved");
    let hist = history::export(&dst.join("Default/History")).unwrap();
    assert_eq!(hist.urls.len(), 2);
    assert_eq!(hist.visits.len(), 5, "the target gained the three source visits");
}

#[test]
fn local_move_repeat_move_reports_already_present_never_bare_zero() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    let hist_src: &[(&str, i64, Vec<i64>)] = &[
        ("https://site0.example/", 1000, vec![1000]),
        ("https://site1.example/", 1000, vec![1000]),
    ];
    plant_dedupe_profile(&src, 100, &["sess", "pref"], &["alice", "bob"], hist_src);
    plant_dedupe_profile(&dst, 50, &["own"], &["carol"], &[]);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let first = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!((first.cookies, first.logins, first.history_urls), (2, 2, 2));
    assert_eq!((first.already_present_cookies, first.already_present_logins), (0, 0));
    assert_eq!(first.summary, "Everything moved");
    let mut events: Vec<Progress> = Vec::new();
    let second = a
        .local_move("brave", "chrome", None, None, None, &mut |p| events.push(p))
        .unwrap();
    assert_eq!((second.cookies, second.logins, second.history_urls), (0, 0, 0));
    assert_eq!(second.history_visits_moved, 0);
    assert_eq!(second.already_present_cookies, 2, "the repeat move finds its cookies already there");
    assert_eq!(second.already_present_logins, 2, "the repeat move finds its logins already there");
    assert_eq!(second.summary, "Nothing new to move: Google Chrome already has all of this");
    assert_eq!(events.last().unwrap().line, second.summary);
}

/// Plant a raw cookie row with an explicit encrypted_value blob: the rows
/// no import would ever write (v20, dead-key) are planted byte for byte.
fn plant_raw_cookie(dir: &Path, name: &str, blob: Vec<u8>, created: i64) {
    let con = rusqlite::Connection::open(dir.join("Default/Cookies")).unwrap();
    con.execute(
        "INSERT INTO cookies (creation_utc, host_key, name, path, encrypted_value) VALUES (?1, '.example.com', ?2, '/', ?3)",
        rusqlite::params![created, name, blob],
    )
    .unwrap();
}

#[test]
fn local_move_v20_target_cookie_counts_unreadable_not_already_present() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_dedupe_profile(&src, 300, &["sess"], &[], &[]);
    plant_dedupe_profile(&dst, 200, &["own"], &[], &[]);
    // The target also holds the source cookie's identity as a v20 row:
    // locked to the target browser itself, unreadable from outside, so
    // the incoming (newer) cookie is dropped without any comparison.
    let mut blob = b"v20".to_vec();
    blob.extend_from_slice(&[7u8; 40]);
    plant_raw_cookie(&dst, "sess", blob.clone(), 100);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.cookies, 0, "the incoming cookie is dropped");
    assert_eq!(report.already_present_cookies, 0, "an unreadable row is never already present");
    assert_eq!(report.kept_unreadable_cookies, 1, "the v20 drop is counted as kept unreadable");
    assert!(
        !report.summary.contains("already has all of this"),
        "the summary must not claim the target has all of this: {}",
        report.summary
    );
    assert!(
        report.summary.contains("could not be read"),
        "the summary names the unreadable kept row in plain words: {}",
        report.summary
    );
    let now: Vec<u8> = rusqlite::Connection::open(dst.join("Default/Cookies"))
        .unwrap()
        .query_row("SELECT encrypted_value FROM cookies WHERE name='sess'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(now, blob, "the v20 row is byte-identical afterwards");
}

#[test]
fn local_move_dead_key_target_cookie_counts_unreadable_not_already_present() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_dedupe_profile(&src, 300, &["sess"], &[], &[]);
    plant_dedupe_profile(&dst, 200, &["own"], &[], &[]);
    // One readable v11 cookie in the target, so the destination key gate
    // (at least one v11 row must open when v11 rows exist) stays green
    // while the dead row below stays unreadable. Planted raw: an import
    // would re-seal it under the store's voted prefix (v10 here).
    let own2_blob = Lock::linux(KEYRING_SECRET, LinuxPrefix::V11)
        .encrypt(".example.com", "v-own2", HostTag::With)
        .unwrap();
    plant_raw_cookie(&dst, "own2", own2_blob, 200);
    // The target's copy of the source cookie was written under a key that
    // rotated away: it lands in the scan's dead set and cannot be read.
    // The blob is v11 (authenticated), so the wrong key fails for sure;
    // a v10 blob is unauthenticated CBC and a wrong key can "decrypt" it
    // into garbage, which is why the store's own dead-row test uses v11.
    let rotated = Lock::linux("rotated-away", LinuxPrefix::V11);
    let blob = rotated.encrypt(".example.com", "old-value", HostTag::With).unwrap();
    plant_raw_cookie(&dst, "sess", blob, 100);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.cookies, 0, "the incoming cookie is dropped");
    assert_eq!(report.already_present_cookies, 0, "a dead-key row is never already present");
    assert_eq!(report.kept_unreadable_cookies, 1, "the dead-key drop is counted as kept unreadable");
    assert_eq!(report.preserved_cookies, 1, "the dead row itself is counted preserved");
    assert!(!report.summary.contains("already has all of this"), "summary: {}", report.summary);
    assert!(report.summary.contains("could not be read"), "summary: {}", report.summary);
}

#[test]
fn local_move_newer_login_against_protected_target_counts_unreadable() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    plant_dedupe_profile(&src, 900, &[], &["alice"], &[]);
    plant_dedupe_profile(&dst, 100, &[], &["carol"], &[]);
    // The target also holds alice, as a v20 row no outside key can read,
    // stamped far older than the incoming login: the incoming login is
    // strictly newer on every visible field and is still dropped.
    let mut blob = b"v20".to_vec();
    blob.extend_from_slice(&[9u8; 40]);
    let con = rusqlite::Connection::open(dst.join("Default/Login Data")).unwrap();
    con.execute(
        "INSERT INTO logins (origin_url, username_value, password_value, date_created, date_last_used, date_password_modified, signon_realm, times_used) VALUES ('https://example.com/', 'alice', ?1, 1, 1, 1, 'https://example.com', 0)",
        rusqlite::params![blob],
    )
    .unwrap();
    drop(con);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.logins, 0, "the incoming login is dropped");
    assert_eq!(report.already_present_logins, 0, "a protected row is never already present");
    assert_eq!(
        report.kept_unreadable_logins, 1,
        "a strictly newer login dropped against a protected row is kept unreadable"
    );
    assert!(!report.summary.contains("already has all of this"), "summary: {}", report.summary);
    assert!(report.summary.contains("could not be read"), "summary: {}", report.summary);
}

/// The incoming bob whose realm rewrite must collide: newer than both
/// target rows on every visible field, with the second row's realm.
fn colliding_bob() -> Login {
    Login {
        origin_url: "https://example.com/".into(),
        action_url: "https://example.com/login".into(),
        username_value: "bob".into(),
        password_value: "pw-bob".into(),
        date_created: 900,
        date_last_used: 900,
        times_used: 1,
        signon_realm: "https://b.example".into(),
        date_password_modified: 900,
    }
}

/// Plant the target side of a realm collision: two rows for bob at the
/// same origin, differing only by realm, under Chromium's UNIQUE index,
/// so a winning incoming bob whose realm would be rewritten onto the
/// other row is refused by the constraint. The password blobs are empty:
/// the merge never has to read them, because the incoming login wins on
/// the visible fields alone.
fn plant_realm_collision_target(dir: &Path) {
    let con = rusqlite::Connection::open(dir.join("Default/Login Data")).unwrap();
    for (realm, created) in [("https://a.example", 5i64), ("https://b.example", 4)] {
        con.execute(
            "INSERT INTO logins (origin_url, username_element, username_value, password_element, password_value, date_created, date_last_used, date_password_modified, signon_realm, times_used) VALUES ('https://example.com/', '', 'bob', '', x'', ?1, ?1, ?1, ?2, 1)",
            rusqlite::params![created, realm],
        )
        .unwrap();
    }
    con.execute(
        "CREATE UNIQUE INDEX logins_realm_collision ON logins (origin_url, username_element, username_value, password_element, signon_realm)",
        [],
    )
    .unwrap();
}

#[test]
fn local_move_constraint_skipped_login_blocks_all_of_this_summary() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    // Source: one cookie the target already holds newer, plus bob.
    fresh_profile(&src);
    cookies::import(&src.join("Default/Cookies"), &[cookie(".example.com", "sess", "v-sess", 100)], &keys()).unwrap();
    logins::import(&src.join("Default/Login Data"), &[colliding_bob()], &keys(), HostTag::Without).unwrap();
    // Target: the same cookie newer, and the realm collision for bob.
    fresh_profile(&dst);
    cookies::import(&dst.join("Default/Cookies"), &[cookie(".example.com", "sess", "v-sess", 200)], &keys()).unwrap();
    plant_realm_collision_target(&dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!((report.cookies, report.logins), (0, 0), "nothing lands");
    assert_eq!(report.already_present_cookies, 1, "the cookie was already there, newer");
    assert_eq!(report.already_present_logins, 0, "the refused login was not already there");
    assert_eq!(report.constraint_skipped_logins, 1, "the refusal is carried in the report");
    assert!(
        !report.summary.contains("already has all of this"),
        "a refused login is not in the target, so the summary must not claim it is: {}",
        report.summary
    );
    assert!(report.summary.contains("refused"), "the summary mentions the refusal: {}", report.summary);
    assert_eq!(
        report.summary,
        "Nothing new to move; 1 saved password was refused in Google Chrome and did not land"
    );
}

#[test]
fn local_move_constraint_skipped_login_blocks_everything_moved_summary() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    // Source: alice, who lands, plus bob, who collides.
    fresh_profile(&src);
    logins::import(
        &src.join("Default/Login Data"),
        &[login("alice", "pw-a", 900), colliding_bob()],
        &keys(),
        HostTag::Without,
    )
    .unwrap();
    fresh_profile(&dst);
    plant_realm_collision_target(&dst);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.logins, 1, "alice lands");
    assert_eq!(report.constraint_skipped_logins, 1, "bob is refused and carried in the report");
    assert_ne!(report.summary, "Everything moved", "one login neither landed nor was already there");
    assert!(report.summary.contains("refused"), "the summary mentions the refusal: {}", report.summary);
    assert_eq!(
        report.summary,
        "Moved 1; 1 saved password was refused in Google Chrome and did not land"
    );
}

#[test]
fn local_move_history_url_and_visit_count_once_in_summary() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    let hist_src: &[(&str, i64, Vec<i64>)] = &[("https://site0.example/", 1000, vec![1000])];
    plant_dedupe_profile(&src, 100, &["sess"], &[], hist_src);
    plant_dedupe_profile(&dst, 200, &["sess"], &[], &[]);
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.history_urls, 1, "the new url lands");
    assert_eq!(report.history_visits_moved, 1, "its visit lands and keeps its own figure");
    assert_eq!(report.already_present_cookies, 1);
    assert_eq!(
        report.summary, "Moved 1, already had 1",
        "the url and its visit are one thing landed, not two"
    );
}

#[test]
fn local_move_bookmarks_conflict_is_not_counted_as_moved() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    let dst = t.path().join("chrome-prof");
    fresh_profile(&src);
    fresh_profile(&dst);
    // The source bookmarks file is not a bookmark tree at all: it cannot
    // be merged into the target file and is parked beside it instead.
    std::fs::write(src.join("Default/Bookmarks"), b"this is not a bookmark tree").unwrap();
    plant_bookmarks(&dst);
    let dst_bookmarks_before = std::fs::read(dst.join("Default/Bookmarks")).unwrap();
    let mut a = app(&t.path().join("state"), &src, &dst);
    let report = a.local_move("brave", "chrome", None, None, None, &mut |_| {}).unwrap();
    assert_eq!(report.bookmarks_conflict, 1, "the conflict is acknowledged as its own count");
    assert_ne!(report.summary, "Everything moved", "nothing landed in the target bookmarks");
    assert_eq!(
        report.summary,
        "Nothing moved; the bookmarks file could not be merged into Google Chrome and was kept beside it"
    );
    assert_eq!(
        std::fs::read(dst.join("Default/Bookmarks")).unwrap(),
        dst_bookmarks_before,
        "the target bookmarks file is untouched"
    );
    let parked = std::fs::read_dir(dst.join("Default"))
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with("Bookmarks.moveit-incoming-"));
    assert!(parked, "the incoming file is parked beside the target bookmarks");
}
