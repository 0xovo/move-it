//! The app surface (api.rs) exercised the way the shell will use it: fixture profiles on
//! disk, two app states sharing one folder pipe, real pairing, a real move, an undo.

use std::path::{Path, PathBuf};

use moveit_core::api::{App, OpenCheck, PairOutcome, Progress, UndoOutcome};
use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::history;
use moveit_core::logins::{self, Login};
use moveit_core::oscrypt::{HostTag, LinuxPrefix, Lock};
use moveit_core::pipe;
use moveit_core::sealed::{Payload, SyncKey};

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

/// The keys the fixtures are planted with. The surface discovers the browser password
/// itself; the env override pins it to the same word so the fixtures open.
fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
}

fn pin_browser_password() {
    std::env::set_var("MOVEIT_LINUX_PASSWORD", "peanuts");
    // Keep profile enumeration hermetic: no real browser folders leak into the
    // fixture world, so the pinned working profile is the only source.
    std::env::set_var("XDG_CONFIG_HOME", "/tmp/moveit-test-empty-xdg");
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

fn app(state: &Path, profile: &Path, device: &str, pipe_dir: &Path) -> App {
    let mut a = App::open(state).unwrap().with_key_store(store_for(state)).with_profile("brave", profile);
    a.use_pipe(pipe_dir).unwrap();
    a.set_device_name(device).unwrap();
    a
}

#[test]
fn preview_counts_what_would_move_and_names_what_would_not() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let prof = t.path().join("prof");
    fresh_profile(&prof);

    // Two logins, three history urls, two bookmarks, two extensions.
    logins::import(
        &prof.join("Default/Login Data"),
        &[login("alice", "pw-a", 100), login("bob", "pw-b", 200)],
        &keys(),
        HostTag::Without,
    )
    .unwrap();
    let mut section = history::Section::default();
    for i in 0..3 {
        section.urls.push(history::HistoryUrl {
            url: format!("https://site{i}.example/"),
            title: String::new(),
            typed_count: 0,
            last_visit_time: 1_000 + i,
            hidden: 0,
        });
    }
    history::import(&prof.join("Default/History"), &section).unwrap();
    std::fs::write(
        prof.join("Default/Bookmarks"),
        br#"{"roots":{"bookmark_bar":{"type":"folder","children":[
            {"type":"url","url":"https://a.example"},
            {"type":"url","url":"https://b.example"}]}}}"#,
    )
    .unwrap();
    for id in ["extone", "exttwo"] {
        std::fs::create_dir_all(prof.join("Default/Extensions").join(id)).unwrap();
    }
    // One App-Bound cookie, planted raw the way a locked-down browser writes it.
    {
        let con = rusqlite::Connection::open(prof.join("Default/Cookies")).unwrap();
        let mut blob = b"v20".to_vec();
        blob.extend_from_slice(&[7u8; 40]);
        con.execute(
            "INSERT INTO cookies (creation_utc, host_key, name, path, encrypted_value) VALUES (1, '.locked.example', 'sess', '/', ?1)",
            rusqlite::params![blob],
        )
        .unwrap();
    }

    let state = t.path().join("state");
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let mut a = app(&state, &prof, "device-a", &pipe_dir);

    let preview = a.preview_counts(&[], &[]).unwrap();
    let brave = preview
        .browsers
        .iter()
        .find(|b| b.name == "brave")
        .expect("the brave profile is in the preview");
    assert_eq!(brave.logins, 2);
    assert_eq!(brave.passwords, 2);
    assert_eq!(brave.history, 3);
    assert_eq!(brave.bookmarks, 2);
    assert_eq!(brave.extensions, 2);
    assert_eq!(brave.profiles.len(), 1);
    assert_eq!(brave.profiles[0].id, "brave:default");
    assert_eq!(brave.profiles[0].destination, "brave");
    assert!(!brave.profiles[0].routed);
    if cfg!(target_os = "windows") {
        assert!(
            brave.skipped.iter().any(|s| s.browser == "Brave" && s.reason.contains("App-Bound")),
            "the App-Bound cookie must be named as skipped: {:?}",
            brave.skipped
        );
    } else {
        assert!(
            brave.skipped.iter().any(|s| {
                s.browser == "Brave" && s.reason.contains("sealed by the browser on Windows")
            }),
            "v20 cookies must be counted and named on Linux: {:?}",
            brave.skipped
        );
    }
}

#[test]
fn pair_move_home_and_undo_across_two_devices() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    let prof_a = t.path().join("prof-a");
    let prof_b = t.path().join("prof-b");
    fresh_profile(&prof_a);
    fresh_profile(&prof_b);
    logins::import(
        &prof_a.join("Default/Login Data"),
        &[login("alice", "pw-a", 100), login("bob", "pw-b", 200)],
        &keys(),
        HostTag::Without,
    )
    .unwrap();
    let ck = Cookie {
        host: ".example.com".into(),
        name: "sess".into(),
        path: "/".into(),
        value: "v1".into(),
        expires_utc: 0,
        creation_utc: 100,
        last_access_utc: 100,
        is_secure: 1,
        is_httponly: 0,
        samesite: -1,
        last_update_utc: Some(100),
        top_frame_site_key: String::new(),
    };
    cookies::import(&prof_a.join("Default/Cookies"), &[ck], &keys()).unwrap();

    let mut a = app(&t.path().join("state-a"), &prof_a, "device-a", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "device-b", &pipe_dir);

    // Pair: A shows, B types. One wrong try first, and it must count down.
    let shown = a.pair_show_code().unwrap();
    match b.pair_enter_code("000000").unwrap() {
        PairOutcome::Wrong { tries_left } => assert_eq!(tries_left, 9),
        other => panic!("{other:?}"),
    }
    match b.pair_enter_code(&shown.code).unwrap() {
        PairOutcome::Success { other_device } => assert_eq!(other_device, "device-a"),
        other => panic!("{other:?}"),
    }

    // A moves: its box lands in the shared folder, and the move itself is where A
    // learns who paired (the paired note is read exactly once, by the move).
    let mut events_a: Vec<Progress> = Vec::new();
    let report_a = a.move_start(None, &[], None, &mut |p| events_a.push(p)).unwrap();
    assert!(report_a.wrote_box);
    assert_ordered(&events_a);
    assert_eq!(a.welcome_start().unwrap().other_device.as_deref(), Some("device-b"));

    // B moves: A's logins and cookie arrive.
    let mut events_b: Vec<Progress> = Vec::new();
    let report_b = b.move_start(None, &[], None, &mut |p| events_b.push(p)).unwrap();
    assert_ordered(&events_b);
    assert!(events_b.iter().any(|p| p.step == "apply"), "B must apply A's box: {events_b:?}");
    assert_eq!(report_b.logins, 2);
    let found = logins::export(&prof_b.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.iter().any(|l| l.username_value == "alice" && l.password_value == "pw-a"));

    // Home on B: a sync just happened and it can be undone.
    let home = b.home_state().unwrap();
    assert!(home.last_sync.is_some());
    assert!(home.can_undo);

    // Undo on B puts its (empty) profile back.
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Done);
    let after = logins::export(&prof_b.join("Default/Login Data"), &keys()).unwrap();
    assert!(after.is_empty(), "undo must restore the empty profile");
    assert!(!b.home_state().unwrap().can_undo);
    assert_eq!(b.undo_last(false).unwrap(), UndoOutcome::Nothing);
}

#[test]
fn browser_open_check_blocks_while_a_writer_holds_the_store() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let prof = t.path().join("prof");
    fresh_profile(&prof);
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let a = app(&t.path().join("state"), &prof, "device-a", &pipe_dir);

    assert_eq!(a.browser_open_check(&[], &[]).unwrap(), OpenCheck::Clear);
    let holder = rusqlite::Connection::open(prof.join("Default/Cookies")).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        a.browser_open_check(&[], &[]).unwrap(),
        OpenCheck::Blocked { browser: "Brave".into() }
    );
    holder.execute_batch("ROLLBACK").unwrap();
    assert_eq!(a.browser_open_check(&[], &[]).unwrap(), OpenCheck::Clear);
}

fn assert_ordered(events: &[Progress]) {
    assert!(!events.is_empty());
    assert_eq!(events.first().unwrap().step, "refresh");
    let last = events.last().unwrap();
    assert_eq!(last.step, "done");
    assert_eq!(last.frac, 1.0);
    for w in events.windows(2) {
        assert!(w[1].frac >= w[0].frac, "progress must not run backwards: {events:?}");
    }
    let steps: Vec<&str> = events.iter().map(|p| p.step.as_str()).collect();
    let pos = |s: &str| steps.iter().position(|x| *x == s);
    if let (Some(seal), Some(apply)) = (pos("seal"), pos("apply")) {
        assert!(apply < seal, "apply comes before seal: {steps:?}");
    }
    assert!(pos("seal").is_some() && pos("done").is_some());
}

// ---- per-profile unticking ----------------------------------------------------

fn fresh_profile_sub(dir: &Path, sub: &str) {
    make_db(&dir.join(sub).join("Cookies"), COOKIES_SCHEMA);
    make_db(&dir.join(sub).join("History"), HISTORY_SCHEMA);
    make_db(&dir.join(sub).join("Login Data"), LOGINS_SCHEMA);
}

/// A Brave root with Default (named "Profile 1") and Profile 1 (named "Work").
fn two_profile_root(dir: &Path) {
    fresh_profile_sub(dir, "Default");
    fresh_profile_sub(dir, "Profile 1");
    std::fs::write(
        dir.join("Local State"),
        br#"{"profile":{"info_cache":{
            "Default":{"name":"Profile 1"},
            "Profile 1":{"name":"Work"}}}}"#,
    )
    .unwrap();
}

fn tagged_login(tag: &str, created: i64) -> Login {
    Login {
        origin_url: format!("https://{tag}.example/"),
        action_url: format!("https://{tag}.example/login"),
        username_value: format!("user-{tag}"),
        password_value: format!("pw-{tag}"),
        date_created: created,
        date_last_used: created,
        times_used: 1,
        signon_realm: format!("https://{tag}.example"),
        date_password_modified: created,
    }
}

/// Plant one of everything, all carrying `tag`, into one profile folder.
fn plant_markers(dir: &Path, sub: &str, tag: &str) {
    logins::import(&dir.join(sub).join("Login Data"), &[tagged_login(tag, 100)], &keys(), HostTag::Without).unwrap();
    let ck = Cookie {
        host: format!(".{tag}.example"),
        name: "sess".into(),
        path: "/".into(),
        value: format!("cookie-{tag}"),
        expires_utc: 0,
        creation_utc: 100,
        last_access_utc: 100,
        is_secure: 1,
        is_httponly: 0,
        samesite: -1,
        last_update_utc: Some(100),
        top_frame_site_key: String::new(),
    };
    cookies::import(&dir.join(sub).join("Cookies"), &[ck], &keys()).unwrap();
    let mut section = history::Section::default();
    section.urls.push(history::HistoryUrl {
        url: format!("https://{tag}.example/"),
        title: String::new(),
        typed_count: 0,
        last_visit_time: 1_000,
        hidden: 0,
    });
    history::import(&dir.join(sub).join("History"), &section).unwrap();
    std::fs::write(
        dir.join(sub).join("Bookmarks"),
        format!(r#"{{"roots":{{"bookmark_bar":{{"type":"folder","children":[{{"type":"url","url":"https://{tag}.example"}}]}}}}}}"#),
    )
    .unwrap();
    std::fs::create_dir_all(dir.join(sub).join("Extensions").join("extmark")).unwrap();
    let state = dir.join(sub).join("Local Extension Settings").join("extmark");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("state.txt"), format!("ext-marker-{tag}")).unwrap();
}

/// Give an app a key without a peer: showing a code is enough.
fn paired_alone(state: &Path, profile: &Path, device: &str, pipe_dir: &Path) -> App {
    let mut a = app(state, profile, device, pipe_dir);
    a.pair_show_code().unwrap();
    a
}

fn app_key(state: &Path) -> SyncKey {
    use moveit_core::keychain::KeyStore;
    let store = store_for(state);
    if let Ok(bytes) = std::fs::read(state.join("config.json")) {
        if let Ok(cfg) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(account) = cfg["device_id"].as_str() {
                if let Ok(Some(k)) = store.load(account) {
                    return k;
                }
            }
        }
    }
    // The config is damaged or deleted (the fail-closed test does both):
    // the key still sits in the store under the device's account.
    let entries = store.entries();
    assert_eq!(entries.len(), 1, "one key in the store: {entries:?}");
    SyncKey::from_key_file_text(&entries[0].1).unwrap()
}

/// Every box in the pipe place, opened: (file name, payload).
fn open_place_boxes(pipe_dir: &Path, key: &SyncKey) -> Vec<(String, Payload)> {
    let place = pipe_dir.join("Move It");
    pipe::boxes_in(&place)
        .unwrap()
        .iter()
        .map(|p| {
            let bytes = std::fs::read(p).unwrap();
            let payload = moveit_core::engine::open_box(&bytes, key).unwrap();
            (p.file_name().unwrap().to_string_lossy().into_owned(), payload)
        })
        .collect()
}

/// All the text a box carries, manifest and files together, for marker searches.
fn payload_text(p: &Payload) -> String {
    let mut s = serde_json::to_string(&p.manifest).unwrap();
    if let Some(b) = &p.bookmarks {
        s.push_str(&String::from_utf8_lossy(b));
    }
    for (k, v) in &p.ext_files {
        s.push_str(k);
        s.push_str(&String::from_utf8_lossy(v));
    }
    s
}

fn no_progress() -> impl FnMut(Progress) {
    |_| {}
}

#[test]
fn preview_lists_profiles_with_new_flags_and_remembered_ticks() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let prof = t.path().join("prof");
    two_profile_root(&prof);
    plant_markers(&prof, "Default", "home");
    plant_markers(&prof, "Profile 1", "work");
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let mut a = paired_alone(&t.path().join("state"), &prof, "device-a", &pipe_dir);

    let preview = a.preview_counts(&[], &[]).unwrap();
    assert_eq!(preview.browsers.len(), 1);
    let b = &preview.browsers[0];
    assert_eq!(b.name, "brave");
    let ids: Vec<&str> = b.profiles.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["brave:default", "brave:profile-1"]);
    assert_eq!(b.profiles[0].name, "Profile 1");
    assert_eq!(b.profiles[1].name, "Work");
    assert!(b.profiles.iter().all(|p| p.is_new), "first sight: everything is new");
    assert!(b.profiles.iter().all(|p| p.ticked));
    assert_eq!(b.profiles[1].logins, 1);
    assert_eq!(b.logins, 2, "totals run over both profiles");

    // A move absorbs what it saw: nothing is new afterwards.
    a.move_start(None, &[], None, &mut no_progress()).unwrap();
    let preview = a.preview_counts(&[], &[]).unwrap();
    assert!(preview.browsers[0].profiles.iter().all(|p| !p.is_new), "after a move, seen profiles are known");

    // A profile that appears later is new, flagged, and ticked.
    fresh_profile_sub(&prof, "Profile 2");
    plant_markers(&prof, "Profile 2", "late");
    let preview = a.preview_counts(&[], &[]).unwrap();
    let b = &preview.browsers[0];
    assert_eq!(b.profiles.len(), 3);
    assert!(b.profiles[2].is_new && b.profiles[2].ticked);
    assert!(!b.profiles[0].is_new && !b.profiles[1].is_new);

    // Untick Work in a move; a fresh App on the same state opens with it unticked
    // and its counts out of the totals.
    a.move_start(Some(&["brave:profile-1".to_string()]), &[], None, &mut no_progress()).unwrap();
    let mut a2 = app(&t.path().join("state"), &prof, "device-a", &pipe_dir);
    let preview = a2.preview_counts(&[], &[]).unwrap();
    let b = &preview.browsers[0];
    assert!(!b.profiles[1].ticked, "the untick is remembered across app instances");
    assert!(b.profiles[0].ticked && b.profiles[2].ticked);
    assert_eq!(b.logins, 2, "only the ticked profiles count: home + late");
}

#[test]
fn excluded_profile_never_enters_the_box_or_the_other_device() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();

    let prof_a = t.path().join("prof-a");
    two_profile_root(&prof_a);
    plant_markers(&prof_a, "Default", "home");
    plant_markers(&prof_a, "Profile 1", "work");
    let prof_b = t.path().join("prof-b");
    two_profile_root(&prof_b);

    let state_a = t.path().join("state-a");
    let mut a = app(&state_a, &prof_a, "device-a", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "device-b", &pipe_dir);
    let shown = a.pair_show_code().unwrap();
    match b.pair_enter_code(&shown.code).unwrap() {
        PairOutcome::Success { .. } => {}
        other => panic!("{other:?}"),
    }

    a.move_start(Some(&["brave:profile-1".to_string()]), &[], None, &mut no_progress()).unwrap();

    // Judge from the sealed boxes themselves, not from API answers: the ticked
    // profile's markers are all there, the unticked profile's are nowhere.
    let boxes = open_place_boxes(&pipe_dir, &app_key(&state_a));
    assert_eq!(boxes.len(), 1, "one ticked profile, one box: {boxes:?}");
    assert_eq!(boxes[0].0, pipe::BOX_FILE);
    let text = payload_text(&boxes[0].1);
    for marker in ["user-home", "pw-home", ".home.example", "cookie-home", "ext-marker-home", "https://home.example"] {
        assert!(text.contains(marker), "ticked profile marker {marker} must be in the box");
    }
    for marker in ["user-work", "pw-work", ".work.example", "cookie-work", "ext-marker-work", "https://work.example"] {
        assert!(!text.contains(marker), "unticked profile marker {marker} must not be in any box");
    }
    assert!(!pipe_dir.join("Move It").join("moveit-box-brave-profile-1.json").exists());

    // The other device imports what exists: Default fills, Work stays empty.
    let report_b = b.move_start(None, &[], None, &mut no_progress()).unwrap();
    assert_eq!(report_b.boxes_read, 1);
    let home = logins::export(&prof_b.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(home.len(), 1);
    assert_eq!(home[0].username_value, "user-home");
    let work = logins::export(&prof_b.join("Profile 1/Login Data"), &keys()).unwrap();
    assert!(work.is_empty(), "the unticked profile must not arrive by any route");
    let work_hist = history::export(&prof_b.join("Profile 1/History")).unwrap();
    assert!(work_hist.urls.is_empty());
}

#[test]
fn lookalike_and_stale_ids_exclude_nothing() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof = t.path().join("prof");
    two_profile_root(&prof);
    plant_markers(&prof, "Default", "home");
    plant_markers(&prof, "Profile 1", "work");
    let state = t.path().join("state");
    let mut a = paired_alone(&state, &prof, "device-a", &pipe_dir);

    // A prefix of a real id, a real id with a tail, an id for a profile that does
    // not exist, and the same folder name under another browser: none may bite.
    let report = a
        .move_start(
            Some(&[
                "brave:profile".to_string(),
                "brave:profile-1x".to_string(),
                "brave:profile-9".to_string(),
                "chrome:profile-1".to_string(),
            ]),
            &[],
            None,
            &mut no_progress(),
        )
        .unwrap();
    assert!(report.wrote_box);
    let boxes = open_place_boxes(&pipe_dir, &app_key(&state));
    let all: String = boxes.iter().map(|(_, p)| payload_text(p)).collect();
    assert!(all.contains("user-work"), "profile-1 must still move: {all}");
    assert!(pipe_dir.join("Move It").join("moveit-box-brave-profile-1.json").exists());
}

#[test]
fn all_profiles_unticked_moves_nothing_and_is_not_an_error() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof = t.path().join("prof");
    two_profile_root(&prof);
    plant_markers(&prof, "Default", "home");
    plant_markers(&prof, "Profile 1", "work");
    let state = t.path().join("state");
    let mut a = paired_alone(&state, &prof, "device-a", &pipe_dir);

    let report = a
        .move_start(Some(&["brave:default".to_string(), "brave:profile-1".to_string()]), &[], None, &mut no_progress())
        .unwrap();
    assert!(!report.wrote_box);
    assert!(open_place_boxes(&pipe_dir, &app_key(&state)).is_empty(), "an all-unticked browser contributes nothing");
}

#[test]
fn unticking_default_leaves_the_other_profile_to_move_alone() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof_a = t.path().join("prof-a");
    two_profile_root(&prof_a);
    plant_markers(&prof_a, "Default", "home");
    plant_markers(&prof_a, "Profile 1", "work");
    let prof_b = t.path().join("prof-b");
    two_profile_root(&prof_b);
    let state_a = t.path().join("state-a");
    let mut a = app(&state_a, &prof_a, "device-a", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "device-b", &pipe_dir);
    let shown = a.pair_show_code().unwrap();
    assert!(matches!(b.pair_enter_code(&shown.code).unwrap(), PairOutcome::Success { .. }));

    a.move_start(Some(&["brave:default".to_string()]), &[], None, &mut no_progress()).unwrap();
    let place = pipe_dir.join("Move It");
    assert!(!place.join(pipe::BOX_FILE).exists(), "the unticked Default leaves no main box");
    assert!(place.join("moveit-box-brave-profile-1.json").exists());

    b.move_start(None, &[], None, &mut no_progress()).unwrap();
    let work = logins::export(&prof_b.join("Profile 1/Login Data"), &keys()).unwrap();
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].username_value, "user-work");
    assert!(logins::export(&prof_b.join("Default/Login Data"), &keys()).unwrap().is_empty());
}

#[test]
fn renaming_a_profile_keeps_its_id_and_its_untick() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof = t.path().join("prof");
    two_profile_root(&prof);
    plant_markers(&prof, "Default", "home");
    plant_markers(&prof, "Profile 1", "work");
    let state = t.path().join("state");
    let mut a = paired_alone(&state, &prof, "device-a", &pipe_dir);
    a.move_start(Some(&["brave:profile-1".to_string()]), &[], None, &mut no_progress()).unwrap();

    // The person renames Work to Job in the browser: folder (and id) unchanged.
    std::fs::write(
        prof.join("Local State"),
        br#"{"profile":{"info_cache":{
            "Default":{"name":"Profile 1"},
            "Profile 1":{"name":"Job"}}}}"#,
    )
    .unwrap();
    let mut a2 = app(&state, &prof, "device-a", &pipe_dir);
    let preview = a2.preview_counts(&[], &[]).unwrap();
    let work = &preview.browsers[0].profiles[1];
    assert_eq!(work.id, "brave:profile-1");
    assert_eq!(work.name, "Job");
    assert!(!work.ticked, "a rename must not resurrect an unticked profile");
}

#[test]
fn corrupt_or_deleted_config_fails_closed() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof_a = t.path().join("prof-a");
    two_profile_root(&prof_a);
    let prof_b = t.path().join("prof-b");
    two_profile_root(&prof_b);
    let state_a = t.path().join("state-a");
    let mut a = app(&state_a, &prof_a, "device-a", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "device-b", &pipe_dir);
    let shown = a.pair_show_code().unwrap();
    assert!(matches!(b.pair_enter_code(&shown.code).unwrap(), PairOutcome::Success { .. }));
    assert!(a.preview_counts(&[], &[]).is_ok());

    // Corrupted between preview and move: the app refuses to open at all, and
    // nothing reaches the shared place.
    std::fs::write(state_a.join("config.json"), b"{not json").unwrap();
    assert!(App::open(&state_a).is_err(), "a damaged config is a refusal, not a reset");
    assert!(open_place_boxes(&pipe_dir, &app_key(&state_a)).is_empty());

    // Deleted: the app opens fresh, but with no pipe chosen a move is refused
    // before anything is sealed or sent.
    std::fs::remove_file(state_a.join("config.json")).unwrap();
    let mut fresh = App::open(&state_a).unwrap().with_key_store(store_for(&state_a)).with_profile("brave", &prof_a);
    assert!(fresh.move_start(None, &[], None, &mut no_progress()).is_err());
    assert!(open_place_boxes(&pipe_dir, &app_key(&state_a)).is_empty());
}

// Enumerates Brave and Chrome under $XDG_CONFIG_HOME; profile scanning is Linux-only today.
#[cfg(target_os = "linux")]
#[test]
fn browsers_move_side_by_side_and_colliding_names_do_not_collide() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let xdg = t.path().join("xdg");
    let brave_root = xdg.join("BraveSoftware/Brave-Browser");
    let chrome_root = xdg.join("google-chrome");
    two_profile_root(&brave_root);
    two_profile_root(&chrome_root); // both browsers have a profile named "Work"
    plant_markers(&brave_root, "Default", "bravedef");
    plant_markers(&brave_root, "Profile 1", "bravework");
    plant_markers(&chrome_root, "Default", "chromedef");
    plant_markers(&chrome_root, "Profile 1", "chromework");
    std::env::set_var("XDG_CONFIG_HOME", &xdg);

    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let state_a = t.path().join("state-a");
    // The env is process-wide and the other tests in this binary reset it
    // (pin_browser_password): re-assert this test's config home right before
    // each open, since an app captures its base when it opens.
    std::env::set_var("XDG_CONFIG_HOME", &xdg);
    let mut a = App::open(&state_a).unwrap().with_key_store(store_for(&state_a));
    a.use_pipe(&pipe_dir).unwrap();
    a.set_device_name("device-a").unwrap();
    let shown = a.pair_show_code().unwrap();

    // A Chrome-only receiver pairs up front, while the offer is fresh.
    let recv_root = t.path().join("recv-chrome");
    two_profile_root(&recv_root);
    // The env is process-wide and the other tests in this binary reset it
    // (pin_browser_password): re-assert this test's config home right before
    // each open, since an app captures its base when it opens.
    std::env::set_var("XDG_CONFIG_HOME", &xdg);
    let mut recv = App::open(&t.path().join("state-recv")).unwrap().with_key_store(store_for(&t.path().join("state-recv"))).with_profile("chrome", &recv_root);
    recv.use_pipe(&pipe_dir).unwrap();
    recv.set_device_name("device-b").unwrap();
    assert!(matches!(recv.pair_enter_code(&shown.code).unwrap(), PairOutcome::Success { .. }));

    let preview = a.preview_counts(&[], &[]).unwrap();
    let names: Vec<&str> = preview.browsers.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, ["brave", "chrome"]);
    let chrome = &preview.browsers[1];
    let cids: Vec<&str> = chrome.profiles.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(cids, ["chrome:default", "chrome:profile-1"]);
    assert_eq!(chrome.profiles[1].name, "Work", "the same display name as Brave's, a different id");

    // Untick Brave's Work only: Chrome's Work still moves.
    a.move_start(Some(&["brave:profile-1".to_string()]), &[], None, &mut no_progress()).unwrap();
    let place = pipe_dir.join("Move It");
    assert!(place.join(pipe::BOX_FILE).exists(), "Brave Default");
    assert!(!place.join("moveit-box-brave-profile-1.json").exists(), "Brave Work stays home");
    assert!(place.join("moveit-box-chrome-default.json").exists());
    assert!(place.join("moveit-box-chrome-profile-1.json").exists(), "Chrome Work is not Brave Work");

    // The receiver applies Chrome boxes into Chrome; the Brave box merges into
    // Brave on this shared config home, not into Chrome.
    let report = recv.move_start(None, &[], None, &mut no_progress()).unwrap();
    assert_eq!(report.boxes_read, 3, "Brave Default plus the two Chrome boxes");
    let def = logins::export(&recv_root.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(def.len(), 1);
    assert_eq!(def[0].username_value, "user-chromedef");
    let work = logins::export(&recv_root.join("Profile 1/Login Data"), &keys()).unwrap();
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].username_value, "user-chromework");

    // A browser Move It cannot read yet (Edge) appears later in the same home:
    // it previews as new, and a move that cannot read it must not absorb it —
    // its profiles stay new until a move really takes them in.
    let edge_root = xdg.join("microsoft-edge");
    two_profile_root(&edge_root);
    // Its stores will not open: a browser Move It cannot read yet.
    for sub in ["Default", "Profile 1"] {
        std::fs::write(edge_root.join(sub).join("Login Data"), b"not a database").unwrap();
        std::fs::write(edge_root.join(sub).join("Cookies"), b"not a database").unwrap();
    }
    // The env is process-wide and the other tests in this binary reset it
    // (pin_browser_password): re-assert this test's config home right before
    // each open, since an app captures its base when it opens.
    std::env::set_var("XDG_CONFIG_HOME", &xdg);
    let mut a2 = App::open(&state_a).unwrap().with_key_store(store_for(&state_a));
    let preview = a2.preview_counts(&[], &[]).unwrap();
    let edge = preview.browsers.iter().find(|b| b.name == "edge").expect("edge is detected");
    assert!(edge.profiles.iter().all(|p| p.is_new), "first sight of Edge: new");
    assert!(
        a2.move_start(None, &[], None, &mut no_progress()).is_err(),
        "a move that cannot read a browser says so, and still absorbs nothing of it"
    );
    let preview = a2.preview_counts(&[], &[]).unwrap();
    let edge = preview.browsers.iter().find(|b| b.name == "edge").unwrap();
    assert!(edge.profiles.iter().all(|p| p.is_new), "an unreadable browser is never absorbed as known");
    let brave = preview.browsers.iter().find(|b| b.name == "brave").unwrap();
    assert!(brave.profiles.iter().all(|p| !p.is_new), "the browsers that moved are known");

    // An untick remembered for the unreadable browser survives a later move
    // that passes a fresh set: the set is only replaced for browsers that
    // actually took part in the move.
    let cfg_path = state_a.join("config.json");
    let mut cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg["excluded_profiles"] = serde_json::json!(["edge:profile-1"]);
    std::fs::write(&cfg_path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    // The env is process-wide and the other tests in this binary reset it
    // (pin_browser_password): re-assert this test's config home right before
    // each open, since an app captures its base when it opens.
    std::env::set_var("XDG_CONFIG_HOME", &xdg);
    let mut a3 = App::open(&state_a).unwrap().with_key_store(store_for(&state_a));
    assert!(a3.move_start(Some(&["brave:profile-1".to_string()]), &[], None, &mut no_progress()).is_err());
    let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    let unticked: Vec<&str> = cfg["excluded_profiles"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
    assert!(unticked.contains(&"edge:profile-1"), "Edge never moved, so its untick is not wiped: {unticked:?}");
    assert!(unticked.contains(&"brave:profile-1"), "the fresh answer for Brave is remembered: {unticked:?}");
}

/// Seal a box by hand with a manifest tag of our choosing: the raw material
/// for tag forgery probes.
fn forge_box(src_root: &Path, src_sub: &str, key: &SyncKey, browser: &str, slot: &str, name: &str) -> Vec<u8> {
    let prof = moveit_core::engine::Profile {
        dir: src_root,
        slot: src_sub,
        keys: &keys(),
        login_tag: HostTag::Without,
        browser: "brave",
        display: "Brave",
    };
    let mut payload = moveit_core::engine::export(&prof, "device-x", None).unwrap();
    payload.manifest.insert("profile_browser".into(), browser.into());
    payload.manifest.insert("profile_slot".into(), slot.into());
    payload.manifest.insert("profile_name".into(), name.into());
    let env = moveit_core::sealed::seal(&payload, key).unwrap();
    serde_json::to_vec(&env).unwrap()
}

#[test]
fn a_forged_tag_cannot_reroute_data_or_dodge_an_untick() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof_a = t.path().join("prof-a");
    two_profile_root(&prof_a);
    plant_markers(&prof_a, "Default", "home");
    plant_markers(&prof_a, "Profile 1", "work");
    let prof_b = t.path().join("prof-b");
    two_profile_root(&prof_b);
    let state_a = t.path().join("state-a");
    let mut a = app(&state_a, &prof_a, "device-a", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "device-b", &pipe_dir);
    let shown = a.pair_show_code().unwrap();
    assert!(matches!(b.pair_enter_code(&shown.code).unwrap(), PairOutcome::Success { .. }));
    let key = app_key(&state_a);
    let place = pipe_dir.join("Move It");

    // Forgery 1 (the exclusion dodge): Work's data wearing Default's id.
    let f1 = forge_box(&prof_a, "Profile 1", &key, "brave", "Profile 1", "Work");
    std::fs::write(place.join(pipe::BOX_FILE), &f1).unwrap();
    // Forgery 2 (the reroute): Default's data wearing Work's id, aimed at Default.
    let f2 = forge_box(&prof_a, "Default", &key, "brave", "Default", "Profile 1");
    std::fs::write(place.join("moveit-box-brave-profile-1.json"), &f2).unwrap();

    let report = b.move_start(Some(&["brave:profile-1".to_string()]), &[], None, &mut no_progress()).unwrap();
    assert!(report.boxes_skipped >= 2, "both forgeries refused: {report:?}");
    assert_eq!(report.boxes_read, 0);
    assert!(logins::export(&prof_b.join("Default/Login Data"), &keys()).unwrap().is_empty(), "nothing rerouted into Default");
    assert!(logins::export(&prof_b.join("Profile 1/Login Data"), &keys()).unwrap().is_empty(), "nothing dodged the untick into Work");

    // Control: an honest tag for Default still applies.
    let honest = forge_box(&prof_a, "Default", &key, "brave", "Default", "Profile 1");
    std::fs::write(place.join(pipe::BOX_FILE), &honest).unwrap();
    let report = b.move_start(None, &[], None, &mut no_progress()).unwrap();
    assert_eq!(report.boxes_read, 1);
    let def = logins::export(&prof_b.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(def.len(), 1);
    assert_eq!(def[0].username_value, "user-home");
}

#[test]
fn a_box_for_a_colliding_folder_lands_nowhere() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof_a = t.path().join("prof-a");
    two_profile_root(&prof_a);
    plant_markers(&prof_a, "Profile 1", "work");
    // The receiver has both slug twins: "Profile 1" (which enumeration keeps)
    // and "Profile-1" (which it drops). Neither may receive the other's boxes.
    let prof_b = t.path().join("prof-b");
    for sub in ["Default", "Profile 1", "Profile-1"] {
        fresh_profile_sub(&prof_b, sub);
    }
    std::fs::write(
        prof_b.join("Local State"),
        br#"{"profile":{"info_cache":{
            "Default":{"name":"Profile 1"},
            "Profile 1":{"name":"Work"},
            "Profile-1":{"name":"Odd"}}}}"#,
    )
    .unwrap();
    let state_a = t.path().join("state-a");
    let mut a = app(&state_a, &prof_a, "device-a", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "device-b", &pipe_dir);
    let shown = a.pair_show_code().unwrap();
    assert!(matches!(b.pair_enter_code(&shown.code).unwrap(), PairOutcome::Success { .. }));
    let key = app_key(&state_a);
    let place = pipe_dir.join("Move It");

    // A self-consistent tag for the dropped twin: id matches its folder, but
    // the folder takes no part here, so the box is skipped whole.
    let collide = forge_box(&prof_a, "Profile 1", &key, "brave", "Profile-1", "Odd");
    std::fs::write(place.join("moveit-box-brave-profile-1.json"), &collide).unwrap();
    let report = b.move_start(None, &[], None, &mut no_progress()).unwrap();
    assert_eq!(report.boxes_read, 0);
    assert!(
        report.boxes_skipped >= 1
            || report.routes.iter().any(|r| r.status == "failed"),
        "{report:?}"
    );
    assert!(logins::export(&prof_b.join("Profile 1/Login Data"), &keys()).unwrap().is_empty());
    assert!(logins::export(&prof_b.join("Profile-1/Login Data"), &keys()).unwrap().is_empty(), "the dropped folder receives nothing");

    // Control: the same payload tagged for the folder that does take part lands.
    let honest = forge_box(&prof_a, "Profile 1", &key, "brave", "Profile 1", "Work");
    std::fs::write(place.join("moveit-box-brave-profile-1.json"), &honest).unwrap();
    let report = b.move_start(None, &[], None, &mut no_progress()).unwrap();
    assert_eq!(report.boxes_read, 1);
    let work = logins::export(&prof_b.join("Profile 1/Login Data"), &keys()).unwrap();
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].username_value, "user-work");
    assert!(logins::export(&prof_b.join("Profile-1/Login Data"), &keys()).unwrap().is_empty());
}

#[test]
fn a_corrupt_box_is_skipped_and_the_move_goes_through() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof_a = t.path().join("prof-a");
    two_profile_root(&prof_a);
    plant_markers(&prof_a, "Default", "home");
    plant_markers(&prof_a, "Profile 1", "work");
    let prof_b = t.path().join("prof-b");
    two_profile_root(&prof_b);
    let state_a = t.path().join("state-a");
    let mut a = app(&state_a, &prof_a, "device-a", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "device-b", &pipe_dir);
    let shown = a.pair_show_code().unwrap();
    assert!(matches!(b.pair_enter_code(&shown.code).unwrap(), PairOutcome::Success { .. }));
    a.move_start(None, &[], None, &mut no_progress()).unwrap();

    // A truncated second box lands in the place (a sync conflict copy that lost
    // a fight, a half-written file). It must not wedge every future move.
    std::fs::write(pipe_dir.join("Move It").join("moveit-box-brave-profile-1.json"), b"{bad").unwrap();
    let report = b.move_start(None, &[], None, &mut no_progress()).unwrap();
    assert!(report.boxes_skipped >= 1, "the bad box is counted, not fatal: {report:?}");
    let def = logins::export(&prof_b.join("Default/Login Data"), &keys()).unwrap();
    assert_eq!(def.len(), 1, "the good box still applied");
    assert_eq!(def[0].username_value, "user-home");
}

#[test]
fn one_unreadable_profile_does_not_stop_its_siblings_sealing() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof = t.path().join("prof");
    two_profile_root(&prof);
    plant_markers(&prof, "Default", "home");
    plant_markers(&prof, "Profile 1", "work");
    // Work's cookie store is wrecked: its export fails on its own.
    std::fs::write(prof.join("Profile 1").join("Cookies"), b"this is not a database").unwrap();
    let state = t.path().join("state");
    let mut a = paired_alone(&state, &prof, "device-a", &pipe_dir);

    let result = a.move_start(None, &[], None, &mut no_progress());
    assert!(result.is_err(), "the failure is reported, not hidden");
    let boxes = open_place_boxes(&pipe_dir, &app_key(&state));
    assert_eq!(boxes.len(), 1, "Default still sealed on its own: {}", boxes.len());
    assert!(payload_text(&boxes[0].1).contains("user-home"));
}

#[test]
fn same_named_devices_still_sync_by_id() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof_a = t.path().join("prof-a");
    two_profile_root(&prof_a);
    plant_markers(&prof_a, "Default", "home");
    let prof_b = t.path().join("prof-b");
    two_profile_root(&prof_b);
    plant_markers(&prof_b, "Default", "away");
    // Both devices carry the same name: names collide, ids must not.
    let mut a = app(&t.path().join("state-a"), &prof_a, "same-name", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "same-name", &pipe_dir);
    let shown = a.pair_show_code().unwrap();
    assert!(matches!(b.pair_enter_code(&shown.code).unwrap(), PairOutcome::Success { .. }));

    a.move_start(None, &[], None, &mut no_progress()).unwrap();
    let report = b.move_start(None, &[], None, &mut no_progress()).unwrap();
    assert!(report.boxes_read >= 1, "the same-named peer's box is not mistaken for its own: {report:?}");
    let found = logins::export(&prof_b.join("Default/Login Data"), &keys()).unwrap();
    assert!(found.iter().any(|l| l.username_value == "user-home"), "A's login landed on B");

    let report = a.move_start(None, &[], None, &mut no_progress()).unwrap();
    assert!(report.boxes_read >= 1, "and the other way around: {report:?}");
    let found = logins::export(&prof_a.join("Default/Login Data"), &keys()).unwrap();
    assert!(found.iter().any(|l| l.username_value == "user-away"), "B's login landed on A");
}


#[cfg(unix)]
#[test]
fn move_start_refuses_while_a_browser_is_open_and_touches_nothing() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof_a = t.path().join("prof-a");
    let prof_b = t.path().join("prof-b");
    fresh_profile(&prof_a);
    fresh_profile(&prof_b);
    logins::import(
        &prof_a.join("Default/Login Data"),
        &[login("alice", "pw-a", 100)],
        &keys(),
        HostTag::Without,
    )
    .unwrap();
    let mut a = app(&t.path().join("state-a"), &prof_a, "device-a", &pipe_dir);
    let mut b = app(&t.path().join("state-b"), &prof_b, "device-b", &pipe_dir);
    let shown = a.pair_show_code().unwrap();
    assert!(matches!(b.pair_enter_code(&shown.code).unwrap(), PairOutcome::Success { .. }));
    a.move_start(None, &[], None, &mut |_| {}).unwrap();

    // B's browser is open now: its singleton names this living process.
    let lock_target = format!("this-machine-{}", std::process::id());
    std::os::unix::fs::symlink(&lock_target, prof_b.join("SingletonLock")).unwrap();

    fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if e.file_name() != "SingletonLock" {
                    out.insert(
                        p.strip_prefix(dir).unwrap().to_string_lossy().into_owned(),
                        std::fs::read(&p).unwrap(),
                    );
                }
            }
        }
        out
    }
    let pipe_before = snapshot(&pipe_dir);
    let prof_before = snapshot(&prof_b);
    let config_before = std::fs::read(t.path().join("state-b/config.json")).unwrap();

    let err = b.move_start(None, &[], None, &mut |_| {}).unwrap_err();
    assert!(matches!(err, moveit_core::Error::BrowserOpen), "{err:?}");
    assert_eq!(snapshot(&pipe_dir), pipe_before, "no box written, none withdrawn");
    assert_eq!(snapshot(&prof_b), prof_before, "the profile is byte-identical");
    assert_eq!(
        std::fs::read(t.path().join("state-b/config.json")).unwrap(),
        config_before,
        "no state was saved"
    );
    assert!(
        !std::fs::read_dir(&prof_b)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".moveit-txn")),
        "no journal was started"
    );

    // Closed again, the very same move lands.
    std::fs::remove_file(prof_b.join("SingletonLock")).unwrap();
    let report = b.move_start(None, &[], None, &mut |_| {}).unwrap();
    assert_eq!(report.logins, 1);
}

#[test]
fn move_start_refuses_a_never_launched_source_without_planting() {
    pin_browser_password();
    let t = tempfile::tempdir().unwrap();
    let pipe_dir = t.path().join("shared");
    std::fs::create_dir(&pipe_dir).unwrap();
    let prof = t.path().join("brave");
    // Installed once, never opened: Default folder, no cookie/login stores.
    std::fs::create_dir_all(prof.join("Default")).unwrap();
    let mut a = paired_alone(&t.path().join("state"), &prof, "device-a", &pipe_dir);
    let err = a.move_start(None, &[], None, &mut |_| {}).unwrap_err();
    assert!(
        matches!(
            &err,
            moveit_core::Error::NeverLaunched { browser } if browser == "Brave"
        ),
        "{err:?}"
    );
    assert!(!prof.join("Default/Cookies").exists());
    assert!(!prof.join("Default/Network/Cookies").exists());
    assert!(!prof.join("Default/Login Data").exists());
}
