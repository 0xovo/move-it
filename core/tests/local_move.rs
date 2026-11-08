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

/// The keys the fixtures are planted with. The surface discovers the browser
/// password itself; the env override pins it to the same word so fixtures open.
fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
}

fn pin_browser_password() {
    std::env::set_var("MOVEIT_LINUX_PASSWORD", "peanuts");
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
    for id in ["extone", "exttwo"] {
        std::fs::create_dir_all(dir.join("Default/Extensions").join(id)).unwrap();
    }
    let state = dir.join("Default/Local Extension Settings/extone");
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
    let preview = a.local_preview("brave", "chrome").unwrap();
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
    let report = a.local_move("brave", "chrome", &mut |p| events.push(p)).unwrap();
    assert_eq!(report.source, "Brave");
    assert_eq!(report.target, "Google Chrome");
    assert_eq!(report.cookies, 2);
    assert_eq!(report.logins, 2);
    assert_eq!(report.history_urls, 3);
    assert_eq!(report.extensions, 1, "only extone has saved state to carry");
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
    assert!(cookies::export(&dst.join("Default/Cookies"), &wrong).is_err());
    let hist = history::export(&dst.join("Default/History")).unwrap();
    assert_eq!(hist.urls.len(), 3);
    let bm = std::fs::read(dst.join("Default/Bookmarks")).unwrap();
    assert!(bm.windows(17).any(|w| w == b"https://a.example"), "bookmarks carried into Chrome");
    let ext_state = dst.join("Default/Local Extension Settings/extone/state.txt");
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
fn local_move_refuses_itself_and_unknown_browsers() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("brave-prof");
    plant_source(&src);
    let mut a = app(&t.path().join("state"), &src, &src);
    assert!(a.local_preview("brave", "brave").is_err(), "a browser cannot move into itself");
    assert!(a.local_move("brave", "brave", &mut |_| {}).is_err());
    assert!(a.local_preview("brave", "opera").is_err(), "an unknown target is refused plainly");
    assert!(a.local_move("opera", "brave", &mut |_| {}).is_err(), "an unknown source is refused plainly");
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

    let preview = a.local_preview("brave", "chrome").unwrap();
    assert_eq!(preview.locked_cookies, 1);
    assert!(
        preview.skipped.iter().any(|s| s.browser == "Brave" && s.reason.contains("App-Bound")),
        "the locked cookies must be named as skipped: {:?}",
        preview.skipped
    );

    let report = a.local_move("brave", "chrome", &mut |_| {}).unwrap();
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
    assert!(a.local_move("brave", "chrome", &mut |_| {}).is_err(), "never write into an open browser");
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
    let preview = a.local_preview("brave", "chrome").unwrap();
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
    assert!(a.local_preview("firefox", "chrome").is_err());
    assert!(a.local_move("firefox", "chrome", &mut |_| {}).is_err());
    // The target's keys gate the preview too: a move into a browser whose
    // password cannot be attempted can never write, so it refuses up front.
    assert!(a.local_preview("chrome", "firefox").is_err());
    assert!(a.local_move("chrome", "firefox", &mut |_| {}).is_err());
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
    a.local_move("brave", "chrome", &mut |_| {}).unwrap();

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
    a.local_move("brave", "chrome", &mut |_| {}).unwrap();
    a.local_move("chromium", "chrome", &mut |_| {}).unwrap();

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
    let report = a.local_move("brave", "chrome", &mut |_| {}).unwrap();
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
    let err = a.local_move("brave", "chrome", &mut |_| {}).unwrap_err();
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
    let preview_err = a.local_preview("brave", "chrome").unwrap_err();
    assert!(
        matches!(
            &preview_err,
            moveit_core::Error::NeverLaunched { browser } if browser == "Brave"
        ),
        "{preview_err:?}"
    );
    let move_err = a.local_move("brave", "chrome", &mut |_| {}).unwrap_err();
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
    let err = a.local_preview("brave", "chrome").unwrap_err();
    assert!(
        matches!(
            &err,
            moveit_core::Error::NeverLaunched { browser } if browser == "Google Chrome"
        ),
        "{err:?}"
    );
    let move_err = a.local_move("brave", "chrome", &mut |_| {}).unwrap_err();
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
        let err = a.local_preview("brave", "chrome");
        assert!(
            !matches!(err, Err(moveit_core::Error::NeverLaunched { .. })),
            "{label}: {err:?}"
        );
    }
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
    let mut a = app(&t.path().join("state"), &src, &dst);
    a.local_move("brave", "chrome", &mut |_| {}).unwrap();
    let home = a.home_state().unwrap();
    assert!(home.can_undo);
    assert!(home.last_sync.is_some());
    assert_eq!(a.undo_last(false).unwrap(), UndoOutcome::Done);
    assert_eq!(store_bytes(&dst), before);
    assert!(!a.home_state().unwrap().can_undo);
}
