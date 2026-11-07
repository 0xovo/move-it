//! Routing roundtrips: two app states ("devices") over one folder pipe, each with
//! its own browser tree under its own XDG base. Profiles routed to another browser
//! must land as that browser's own fresh profiles, values intact, with no other
//! profile on either device changed, and one undo must take the whole move back
//! out across every browser it touched.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use moveit_core::api::{App, PairOutcome, RouteChoice, UndoOutcome};
use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::history;
use moveit_core::logins::{self, Login};
use moveit_core::oscrypt::{HostTag, LinuxPrefix, Lock};
use moveit_core::keychain::KeyStore;
use moveit_core::{paths, txn};

/// The tests steer the process environment (each device's XDG base), so they run
/// one at a time.
static ENV_LOCK: Mutex<()> = Mutex::new(());

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

const EXT_ID: &str = "aaaabbbbccccddddaaaabbbbccccdddd";

fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
}

fn make_db(path: &Path, schema: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch(schema).unwrap();
}

fn cookie(marker: &str) -> Cookie {
    Cookie {
        host: format!(".{marker}.example"),
        name: "sess".into(),
        path: "/".into(),
        value: format!("v-{marker}"),
        expires_utc: 0,
        creation_utc: 100,
        last_access_utc: 100,
        is_secure: 1,
        is_httponly: 0,
        samesite: -1,
        last_update_utc: Some(100),
        top_frame_site_key: String::new(),
    }
}

fn login(marker: &str) -> Login {
    Login {
        origin_url: format!("https://{marker}.example/"),
        action_url: format!("https://{marker}.example/login"),
        username_value: format!("user-{marker}"),
        password_value: format!("pw-{marker}"),
        date_created: 100,
        date_last_used: 100,
        times_used: 1,
        signon_realm: format!("https://{marker}.example"),
        date_password_modified: 100,
    }
}

/// Plant one profile with a full set of markers in a browser root.
fn plant(root: &Path, slot: &str, display: &str, marker: &str) {
    let dir = root.join(slot);
    make_db(&dir.join("Cookies"), COOKIES_SCHEMA);
    make_db(&dir.join("History"), HISTORY_SCHEMA);
    make_db(&dir.join("Login Data"), LOGINS_SCHEMA);
    cookies::import(&dir.join("Cookies"), &[cookie(marker)], &keys()).unwrap();
    logins::import(&dir.join("Login Data"), &[login(marker)], &keys(), HostTag::Without).unwrap();
    let mut section = history::Section::default();
    section.urls.push(history::HistoryUrl {
        url: format!("https://{marker}.example/"),
        title: String::new(),
        typed_count: 0,
        last_visit_time: 1_000,
        hidden: 0,
    });
    history::import(&dir.join("History"), &section).unwrap();
    std::fs::write(
        dir.join("Bookmarks"),
        format!(
            r#"{{"roots":{{"bookmark_bar":{{"type":"folder","children":[{{"type":"url","url":"https://{marker}.example"}}]}}}}}}"#
        ),
    )
    .unwrap();
    let ext_dir = dir.join("Local Extension Settings").join(EXT_ID);
    std::fs::create_dir_all(&ext_dir).unwrap();
    std::fs::write(ext_dir.join("000003.log"), format!("ext-state-{marker}")).unwrap();
    std::fs::write(
        dir.join("Preferences"),
        format!(r#"{{"profile":{{"name":"{display}"}}}}"#),
    )
    .unwrap();
}

/// Register slots in a root's Local State the way the browser itself records them.
fn write_local_state(root: &Path, slots: &[(&str, &str)]) {
    std::fs::create_dir_all(root).unwrap();
    let cache: Vec<String> = slots
        .iter()
        .map(|(s, n)| {
            format!(
                r#""{s}":{{"name":"{n}","is_using_default_name":false,"active_time":1700000000.0,"avatar_icon":"x"}}"#
            )
        })
        .collect();
    let order: Vec<String> = slots.iter().map(|(s, _)| format!(r#""{s}""#)).collect();
    std::fs::write(
        root.join("Local State"),
        format!(
            r#"{{"profile":{{"info_cache":{{{}}},"profiles_order":[{}]}}}}"#,
            cache.join(","),
            order.join(",")
        ),
    )
    .unwrap();
}

fn local_state(root: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root.join("Local State")).unwrap()).unwrap()
}

/// One device: an App with its own state folder and its own browser tree (under
/// `{prefix}-xdg`, where the test planted it), pinned to its main browser the way
/// the shell pins the working profile.
fn device(
    t: &Path,
    prefix: &str,
    name: &str,
    pipe_dir: &Path,
    browser: &str,
    root: &Path,
) -> (App, PathBuf) {
    let base = t.join(format!("{prefix}-xdg"));
    std::env::set_var("XDG_CONFIG_HOME", &base);
    let state = t.join(format!("{prefix}-state"));
    let mut app = App::open(&state).unwrap().with_key_store(store_for(&state));
    app.use_pipe(pipe_dir).unwrap();
    app.set_device_name(name).unwrap();
    (app.with_profile(browser, root), base)
}


/// One in-memory keychain per state folder, shared by every App opened on
/// it: reopening an app on the same state sees the same keychain, and no
/// test ever touches the real OS keychain.
fn store_for(
    state: &Path,
) -> std::sync::Arc<moveit_core::keychain::MemoryStore> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static STORES: OnceLock<
        Mutex<HashMap<PathBuf, Arc<moveit_core::keychain::MemoryStore>>>,
    > = OnceLock::new();
    let map = STORES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().unwrap();
    map.entry(state.to_path_buf())
        .or_insert_with(|| Arc::new(moveit_core::keychain::MemoryStore::default()))
        .clone()
}

fn pair(a: &mut App, b: &mut App) {
    let shown = a.pair_show_code().unwrap();
    match b.pair_enter_code(&shown.code).unwrap() {
        PairOutcome::Success { .. } => {}
        other => panic!("pairing failed: {other:?}"),
    }
}

fn route(profile: &str, browser: &str) -> RouteChoice {
    RouteChoice { profile: profile.to_string(), browser: browser.to_string() }
}

fn store_digests(root: &Path, slot: &str) -> Vec<String> {
    let dir = root.join(slot);
    ["Cookies", "Login Data", "History"]
        .iter()
        .map(|f| txn::digest(&dir.join(f)).map(|(_, h)| h).unwrap_or_default())
        .chain([std::fs::read(dir.join("Bookmarks")).map(|b| format!("{b:?}")).unwrap_or_default()])
        .collect()
}

fn read_markers(root: &Path, slot: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let dir = root.join(slot);
    let cks = cookies::export(&paths::cookies_in(root, slot), &keys())
        .unwrap_or_default()
        .into_iter()
        .map(|c| c.value)
        .collect();
    let lgs = logins::export(&paths::login_data_in(root, slot), &keys())
        .unwrap_or_default()
        .into_iter()
        .map(|l| l.username_value)
        .collect();
    let urls = history::export(&paths::history_in(root, slot))
        .map(|s| s.urls.into_iter().map(|u| u.url).collect())
        .unwrap_or_default();
    (cks, lgs, urls)
}

fn setup() {
    std::env::set_var("MOVEIT_LINUX_PASSWORD", "peanuts");
}

#[test]
fn brave_profile_routed_to_chrome_lands_as_a_fresh_chrome_profile() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    // Device A: Brave with one profile, "Work".
    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    // Device B: Chrome with its own profile, "Personal".
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "Personal", "personal");
    write_local_state(&chrome_b, &[("Default", "Personal")]);

    let (mut a, _base_a) = device(t.path(), "a", "device-a", &pipe_dir, "brave", &brave_a);
    let (mut b, _base_b) = device(t.path(), "b", "device-b", &pipe_dir, "chrome", &chrome_b);
    pair(&mut a, &mut b);

    let brave_before = store_digests(&brave_a, "Default");
    let chrome_before = store_digests(&chrome_b, "Default");

    // A sends its Brave profile to Chrome.
    let report_a = a
        .move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {})
        .unwrap();
    assert!(report_a.wrote_box);
    assert_eq!(store_digests(&brave_a, "Default"), brave_before, "sealing never writes the source");

    // B moves: the routed profile lands as a new Chrome profile.
    let report_b = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    assert_eq!(report_b.routes.len(), 1, "one incoming profile: {report_b:?}");
    let line = &report_b.routes[0];
    assert_eq!(line.profile, "brave:default");
    assert_eq!(line.from_browser, "brave");
    assert_eq!(line.to_browser, "chrome");
    assert_eq!(line.status, "moved");
    assert_eq!(line.into_profile.as_deref(), Some("Profile 1"));
    assert!(line.created);

    // The new profile holds Brave's browser life, decrypted with Chrome's keys.
    let (cks, lgs, urls) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"]);
    assert_eq!(lgs, ["user-work"]);
    assert_eq!(urls, ["https://work.example/"]);
    let bm = std::fs::read_to_string(chrome_b.join("Profile 1/Bookmarks")).unwrap();
    assert!(bm.contains("https://work.example"), "bookmarks landed: {bm}");
    let ext = std::fs::read_to_string(
        chrome_b.join("Profile 1/Local Extension Settings").join(EXT_ID).join("000003.log"),
    )
    .unwrap();
    assert_eq!(ext, "ext-state-work");

    // It is registered the way Chrome registers profiles, under its own name.
    let ls = local_state(&chrome_b);
    assert_eq!(ls["profile"]["info_cache"]["Profile 1"]["name"], "Work");
    assert!(
        ls["profile"]["profiles_order"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "Profile 1")
    );

    // Nothing else moved: B's own Chrome profile and A's Brave profile are intact.
    assert_eq!(store_digests(&chrome_b, "Default"), chrome_before);
    let (cks, lgs, _) = read_markers(&chrome_b, "Default");
    assert_eq!(cks, ["v-personal"]);
    assert_eq!(lgs, ["user-personal"]);

    // One undo takes the routed profile back out, registration included.
    assert!(b.home_state().unwrap().can_undo);
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Done);
    assert!(!chrome_b.join("Profile 1").exists(), "undo removes the created profile whole");
    let ls = local_state(&chrome_b);
    assert!(ls["profile"]["info_cache"].get("Profile 1").is_none());
    assert_eq!(store_digests(&chrome_b, "Default"), chrome_before);
    assert!(!b.home_state().unwrap().can_undo);

    // The sync dance keeps the boxes flowing: A moves again and re-seals its
    // Brave profile (choosing the route again: routes belong to one move);
    // B moves again and the routed profile lands fresh once more, because
    // undo took its first home away.
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();
    let report_b2 = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    assert_eq!(report_b2.routes.len(), 1);
    assert_eq!(report_b2.routes[0].into_profile.as_deref(), Some("Profile 1"));
    assert!(report_b2.routes[0].created);
    // One more cycle: now the same box merges into the landed home instead of
    // stacking up a new profile on every move.
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();
    let report_b3 = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    let line = report_b3
        .routes
        .iter()
        .find(|l| l.profile == "brave:default")
        .expect("the brave profile arrives again");
    assert_eq!(line.into_profile.as_deref(), Some("Profile 1"));
    assert!(!line.created, "the same box merges into its landed home");
    assert!(!chrome_b.join("Profile 2").exists(), "no duplicate profile piles up");
    let (cks, _, _) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"]);
}

#[test]
fn one_move_many_destinations_and_duplicate_targets() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    // Device A: two Brave profiles and one Chrome profile.
    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    plant(&brave_a, "Profile 1", "Play", "play");
    write_local_state(&brave_a, &[("Default", "Work"), ("Profile 1", "Play")]);
    let chrome_a = t.path().join("a-xdg/google-chrome");
    plant(&chrome_a, "Default", "AChrome", "achrome");
    write_local_state(&chrome_a, &[("Default", "AChrome")]);
    // Device B: one Brave and one Chrome profile of its own.
    let brave_b = t.path().join("b-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_b, "Default", "BBrave", "bbrave");
    write_local_state(&brave_b, &[("Default", "BBrave")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "BChrome", "bchrome");
    write_local_state(&chrome_b, &[("Default", "BChrome")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &pipe_dir, "brave", &brave_a);
    let (mut b, _bb) = device(t.path(), "b", "device-b", &pipe_dir, "chrome", &chrome_b);
    pair(&mut a, &mut b);

    let brave_b_before = store_digests(&brave_b, "Default");
    let chrome_b_before = store_digests(&chrome_b, "Default");

    // Work and Play both go to Chrome (two fresh profiles there), AChrome goes to Brave.
    a.move_start(
        Some(&[]),
        &[
            route("brave:default", "chrome"),
            route("brave:profile-1", "chrome"),
            route("chrome:default", "brave"),
        ],
        &mut |_| {},
    )
    .unwrap();
    let report_b = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    assert_eq!(report_b.routes.len(), 3, "three landings: {report_b:?}");
    assert!(report_b.routes.iter().all(|l| l.status == "moved"), "{report_b:?}");

    // Each routed profile is its own fresh profile, with only its own markers.
    let (cks, _, _) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"], "first Chrome landing is Work alone");
    let (cks, _, _) = read_markers(&chrome_b, "Profile 2");
    assert_eq!(cks, ["v-play"], "second Chrome landing is Play alone");
    let (cks, lgs, _) = read_markers(&brave_b, "Profile 1");
    assert_eq!(cks, ["v-achrome"]);
    assert_eq!(lgs, ["user-achrome"]);

    // B's own profiles are untouched.
    assert_eq!(store_digests(&brave_b, "Default"), brave_b_before);
    assert_eq!(store_digests(&chrome_b, "Default"), chrome_b_before);

    // One undo covers every destination of the move.
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Done);
    assert!(!chrome_b.join("Profile 1").exists());
    assert!(!chrome_b.join("Profile 2").exists());
    assert!(!brave_b.join("Profile 1").exists());
    assert_eq!(store_digests(&brave_b, "Default"), brave_b_before);
    assert_eq!(store_digests(&chrome_b, "Default"), chrome_b_before);
    let ls = local_state(&chrome_b);
    assert!(ls["profile"]["info_cache"].get("Profile 1").is_none());
    let ls = local_state(&brave_b);
    assert!(ls["profile"]["info_cache"].get("Profile 1").is_none());
}

#[test]
fn a_failing_destination_does_not_stop_the_others_and_undo_still_works() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    let chrome_a = t.path().join("a-xdg/google-chrome");
    plant(&chrome_a, "Default", "AChrome", "achrome");
    write_local_state(&chrome_a, &[("Default", "AChrome")]);

    let brave_b = t.path().join("b-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_b, "Default", "BBrave", "bbrave");
    write_local_state(&brave_b, &[("Default", "BBrave")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "BChrome", "bchrome");
    write_local_state(&chrome_b, &[("Default", "BChrome")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &pipe_dir, "brave", &brave_a);
    let (mut b, _bb) = device(t.path(), "b", "device-b", &pipe_dir, "chrome", &chrome_b);
    pair(&mut a, &mut b);

    let brave_b_before = store_digests(&brave_b, "Default");

    a.move_start(
        Some(&[]),
        &[route("brave:default", "chrome"), route("chrome:default", "brave")],
        &mut |_| {},
    )
    .unwrap();

    // B's Brave folder cannot be written (its transaction cannot even start),
    // while Chrome is fine.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&brave_b, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    let report_b = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&brave_b, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let moved: Vec<_> = report_b.routes.iter().filter(|l| l.status == "moved").collect();
    let failed: Vec<_> = report_b.routes.iter().filter(|l| l.status == "failed").collect();
    assert_eq!(moved.len(), 1, "the Chrome route lands: {report_b:?}");
    assert_eq!(moved[0].to_browser, "chrome");
    assert_eq!(failed.len(), 1, "the Brave route fails on its own line: {report_b:?}");
    assert_eq!(failed[0].to_browser, "brave");
    assert!(failed[0].reason.is_some());

    // The landed profile is real, the failed destination is exactly as it was.
    let (cks, _, _) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"]);
    assert_eq!(store_digests(&brave_b, "Default"), brave_b_before);
    assert!(!brave_b.join("Profile 1").exists());

    // Undo covers what landed; the failed side has nothing to undo.
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Done);
    assert!(!chrome_b.join("Profile 1").exists());
    assert_eq!(store_digests(&brave_b, "Default"), brave_b_before);
}

#[test]
fn a_poisoned_ledger_cannot_redirect_a_merge() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "Personal", "personal");
    write_local_state(&chrome_b, &[("Default", "Personal")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &pipe_dir, "brave", &brave_a);
    let (mut b, _bb) = device(t.path(), "b", "device-b", &pipe_dir, "chrome", &chrome_b);
    pair(&mut a, &mut b);

    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();
    b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    // The landing carries its marker inside the created profile.
    assert!(chrome_b.join("Profile 1/.moveit-landing").exists());

    // Poison the ledger: pretend Work's home is Chrome's own Default profile.
    let landed_path = t.path().join("b-state/landed.json");
    let mut book: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&landed_path).unwrap()).unwrap();
    book["entries"][0]["landed_slot"] = serde_json::json!("Default");
    std::fs::write(&landed_path, serde_json::to_vec(&book).unwrap()).unwrap();

    // The next delivery must NOT merge into Default: the marker there is
    // missing, so the profile lands fresh again, in a new slot of its own.
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();
    let report_b = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    let line = report_b
        .routes
        .iter()
        .find(|l| l.profile == "brave:default")
        .expect("the brave profile arrives again");
    assert_eq!(line.status, "moved");
    assert!(line.created, "a poisoned home is no home: the landing is fresh");
    assert_eq!(line.into_profile.as_deref(), Some("Profile 2"));
    let (cks, lgs, _) = read_markers(&chrome_b, "Default");
    assert_eq!(cks, ["v-personal"], "the existing profile was never merged into");
    assert_eq!(lgs, ["user-personal"]);
    let (cks, _, _) = read_markers(&chrome_b, "Profile 2");
    assert_eq!(cks, ["v-work"]);
    let (cks, _, _) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"], "the original landing is untouched too");
}

#[test]
fn a_move_that_lands_nothing_ends_undo_for_the_older_move() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "Personal", "personal");
    write_local_state(&chrome_b, &[("Default", "Personal")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &pipe_dir, "brave", &brave_a);
    let (mut b, _bb) = device(t.path(), "b", "device-b", &pipe_dir, "chrome", &chrome_b);
    pair(&mut a, &mut b);

    // A first, successful landing: undo points at it.
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();
    b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    assert!(b.home_state().unwrap().can_undo);

    // A second move whose only landing fails (Edge cannot be read here).
    a.move_start(Some(&[]), &[route("brave:default", "edge")], &mut |_| {}).unwrap();
    let report_b = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    assert_eq!(report_b.routes.len(), 1);
    assert_eq!(report_b.routes[0].status, "failed");

    // Undo now belongs to the last move, which landed nothing: it must not
    // reach back and remove the first move's profile.
    assert!(!b.home_state().unwrap().can_undo);
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Nothing);
    assert!(chrome_b.join("Profile 1").exists(), "the older landing survives");
    let (cks, _, _) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"]);
    // And the answer stays stable on a second ask.
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Nothing);
    assert!(chrome_b.join("Profile 1").exists());
}

#[test]
fn preview_counts_exclusions_and_routes_together() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    plant(&brave_a, "Profile 1", "Play", "play");
    write_local_state(&brave_a, &[("Default", "Work"), ("Profile 1", "Play")]);
    let (a, _ba) = device(t.path(), "a", "device-a", &pipe_dir, "brave", &brave_a);

    // Unticking Play takes it out of the totals but keeps it listed, flagged.
    let preview = a.preview_counts(&["brave:profile-1".to_string()], &[]).unwrap();
    let brave = &preview.browsers[0];
    assert_eq!(brave.logins, 1, "only Work counts toward the move");
    assert_eq!(brave.profiles.len(), 2);
    let play = brave.profiles.iter().find(|p| p.id == "brave:profile-1").unwrap();
    assert!(play.excluded);
    assert_eq!(play.logins, 1, "its own row still shows its counts");

    // A route shows in the same preview the move would use.
    let preview = a.preview_counts(&[], &[route("brave:profile-1", "chrome")]).unwrap();
    let play = preview.browsers[0]
        .profiles
        .iter()
        .find(|p| p.id == "brave:profile-1")
        .unwrap();
    assert_eq!(play.destination, "chrome");
    assert!(play.routed);

    // The combination move_start refuses, preview refuses too.
    assert!(a
        .preview_counts(&["brave:profile-1".to_string()], &[route("brave:profile-1", "chrome")])
        .is_err());
}

#[test]
fn a_box_with_mixed_case_browser_names_still_routes() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "Personal", "personal");
    write_local_state(&chrome_b, &[("Default", "Personal")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &pipe_dir, "brave", &brave_a);
    let (mut b, _bb) = device(t.path(), "b", "device-b", &pipe_dir, "chrome", &chrome_b);
    pair(&mut a, &mut b);
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();

    // Rewrite the sealed box the way a differently-cased peer might: browser
    // names in the manifest are matched case-insensitively on read.
    // The sync key lives in the keychain now, under the device's stable
    // id; the state folder no longer carries a key file.
    let a_state = t.path().join("a-state");
    let account = a.device_id().unwrap();
    let key = store_for(&a_state)
        .load(&account)
        .unwrap()
        .expect("the paired key is in the keychain");
    let box_path = pipe_dir.join("Move It/moveit-box.json");
    let bytes = std::fs::read(&box_path).unwrap();
    let mut payload = moveit_core::engine::open_box(&bytes, &key).unwrap();
    payload.manifest.insert("profile_browser".into(), serde_json::json!("BRAVE"));
    payload.manifest.insert("route_browser".into(), serde_json::json!("Chrome"));
    let env = moveit_core::sealed::seal(&payload, &key).unwrap();
    std::fs::write(&box_path, serde_json::to_vec(&env).unwrap()).unwrap();

    let report_b = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    assert_eq!(report_b.routes.len(), 1);
    assert_eq!(report_b.routes[0].status, "moved", "{report_b:?}");
    assert_eq!(report_b.routes[0].into_profile.as_deref(), Some("Profile 1"));
    let (cks, _, _) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"]);
}

fn git(dir: &Path, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(ok.status.success(), "git {args:?} in {}: {}", dir.display(), String::from_utf8_lossy(&ok.stderr));
}

#[test]
fn landings_are_recorded_even_when_the_send_fails() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();

    // A git pipe over a local bare remote, one clone per device.
    let origin = t.path().join("origin.git");
    std::fs::create_dir(&origin).unwrap();
    git(&origin, &["init", "-q", "--bare", "-b", "main"]);
    let clone_a = t.path().join("clone-a");
    let clone_b = t.path().join("clone-b");
    for (clone, name) in [(&clone_a, "a"), (&clone_b, "b")] {
        git(t.path(), &["clone", "-q", origin.to_str().unwrap(), clone.to_str().unwrap()]);
        git(clone, &["config", "user.name", "t"]);
        git(clone, &["config", "user.email", "t@t"]);
        git(clone, &["checkout", "-q", "-b", "main"]);
        let _ = name;
    }

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "Personal", "personal");
    write_local_state(&chrome_b, &[("Default", "Personal")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &clone_a, "brave", &brave_a);
    let (mut b, _bb) = device(t.path(), "b", "device-b", &clone_b, "chrome", &chrome_b);
    pair(&mut a, &mut b);
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();

    // The remote now refuses every push (fetch still works): B's move lands
    // the profile, then cannot finish sending.
    let hook = origin.join("hooks/pre-receive");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let failed = b.move_start(Some(&[]), &[], &mut |_| {});
    assert!(failed.is_err(), "the send failure must surface: {failed:?}");

    // But the landing is real, and the records describe it truthfully.
    let (cks, _, _) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"]);
    assert!(b.home_state().unwrap().can_undo, "the committed landing is undoable");

    // With the remote healed, the next delivery merges into the landed home:
    // the ledger was written even though the earlier move reported an error.
    std::fs::remove_file(&hook).unwrap();
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();
    let report_b = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    let line = report_b
        .routes
        .iter()
        .find(|l| l.profile == "brave:default")
        .expect("the brave profile arrives again");
    assert_eq!(line.into_profile.as_deref(), Some("Profile 1"));
    assert!(!line.created, "the home survived the failed send");
    assert!(!chrome_b.join("Profile 2").exists());

    // Undo belongs to the second move: it restores the state after the first
    // (failed-send) move, in which the landed profile already existed.
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Done);
    assert!(chrome_b.join("Profile 1").exists());
    let (cks, _, _) = read_markers(&chrome_b, "Profile 1");
    assert_eq!(cks, ["v-work"]);
}

#[test]
fn routing_to_an_unreadable_browser_fails_the_route_only() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "Personal", "personal");
    write_local_state(&chrome_b, &[("Default", "Personal")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &pipe_dir, "brave", &brave_a);
    let (mut b, base_b) = device(t.path(), "b", "device-b", &pipe_dir, "chrome", &chrome_b);
    pair(&mut a, &mut b);

    // Edge is in the family, but this build cannot read Edge's password yet, and
    // B has no Edge folder at all: the route fails plainly, nothing is created.
    a.move_start(Some(&[]), &[route("brave:default", "edge")], &mut |_| {}).unwrap();
    let report_b = b.move_start(Some(&[]), &[], &mut |_| {}).unwrap();
    assert_eq!(report_b.routes.len(), 1);
    let line = &report_b.routes[0];
    assert_eq!(line.status, "failed");
    assert_eq!(line.to_browser, "edge");
    assert!(
        line.reason.as_deref().is_some_and(|r| r.contains("Microsoft Edge")),
        "the reason names Edge plainly: {line:?}"
    );
    assert!(!base_b.join("microsoft-edge").exists(), "no folder appears for a failed route");
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Nothing);
}

#[test]
fn busy_retry_undo_restores_the_state_before_both_rounds() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();

    // A git pipe over a local bare remote, one clone per device.
    let origin = t.path().join("origin.git");
    std::fs::create_dir(&origin).unwrap();
    git(&origin, &["init", "-q", "--bare", "-b", "main"]);
    let clone_a = t.path().join("clone-a");
    let clone_b = t.path().join("clone-b");
    for (clone, name) in [(&clone_a, "a"), (&clone_b, "b")] {
        git(t.path(), &["clone", "-q", origin.to_str().unwrap(), clone.to_str().unwrap()]);
        git(clone, &["config", "user.name", "t"]);
        git(clone, &["config", "user.email", "t@t"]);
        git(clone, &["checkout", "-q", "-b", "main"]);
        let _ = name;
    }

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "Personal", "personal");
    write_local_state(&chrome_b, &[("Default", "Personal")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &clone_a, "brave", &brave_a);
    let (mut b, _bb) = device(t.path(), "b", "device-b", &clone_b, "chrome", &chrome_b);
    pair(&mut a, &mut b);
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();

    let before = std::fs::read(chrome_b.join("Local State")).unwrap();
    let mut raced = false;
    b.move_start(Some(&[]), &[], &mut |p| {
        if p.step == "send" && !raced {
            raced = true;
            std::fs::write(clone_a.join("moveit-race"), "remote advanced").unwrap();
            git(&clone_a, &["add", "moveit-race"]);
            git(&clone_a, &["commit", "-qm", "race"]);
            git(&clone_a, &["push", "-q", "origin", "HEAD:main"]);
        }
    }).unwrap();
    assert!(raced);
    assert!(chrome_b.join("Profile 1").exists());
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Done);
    assert!(!chrome_b.join("Profile 1").exists());
    assert_eq!(std::fs::read(chrome_b.join("Local State")).unwrap(), before);
}


#[test]
fn landings_are_recorded_before_a_box_write_failure() {
    let _guard = ENV_LOCK.lock().unwrap();
    setup();
    let t = tempfile::tempdir().unwrap();

    // A git pipe over a local bare remote, one clone per device.
    let origin = t.path().join("origin.git");
    std::fs::create_dir(&origin).unwrap();
    git(&origin, &["init", "-q", "--bare", "-b", "main"]);
    let clone_a = t.path().join("clone-a");
    let clone_b = t.path().join("clone-b");
    for (clone, name) in [(&clone_a, "a"), (&clone_b, "b")] {
        git(t.path(), &["clone", "-q", origin.to_str().unwrap(), clone.to_str().unwrap()]);
        git(clone, &["config", "user.name", "t"]);
        git(clone, &["config", "user.email", "t@t"]);
        git(clone, &["checkout", "-q", "-b", "main"]);
        let _ = name;
    }

    let brave_a = t.path().join("a-xdg/BraveSoftware/Brave-Browser");
    plant(&brave_a, "Default", "Work", "work");
    write_local_state(&brave_a, &[("Default", "Work")]);
    let chrome_b = t.path().join("b-xdg/google-chrome");
    plant(&chrome_b, "Default", "Personal", "personal");
    write_local_state(&chrome_b, &[("Default", "Personal")]);

    let (mut a, _ba) = device(t.path(), "a", "device-a", &clone_a, "brave", &brave_a);
    let (mut b, _bb) = device(t.path(), "b", "device-b", &clone_b, "chrome", &chrome_b);
    pair(&mut a, &mut b);
    a.move_start(Some(&[]), &[route("brave:default", "chrome")], &mut |_| {}).unwrap();

    let failed = b.move_start(Some(&[]), &[], &mut |p| {
        if p.step == "seal" {
            std::fs::create_dir(clone_b.join("moveit-box.json.tmp-moveit")).unwrap();
        }
    });
    assert!(failed.is_err(), "the box write must fail");
    assert!(chrome_b.join("Profile 1").exists());
    let home = b.home_state().unwrap();
    assert!(home.can_undo);
    assert!(home.last_sync.is_some());
    let state = t.path().join("b-state");
    assert!(state.join("landed.json").exists());
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Done);
    assert!(!chrome_b.join("Profile 1").exists());
}
