//! Cache folders (GPU/shader/code caches) never travel: a synthetic
//! profile with junk files inside them seals and opens with the cache
//! dirs absent from the result and every other file byte-identical.
//! The caches are machine-built (GPU/driver) and rebuild on their own;
//! a moved profile carrying them died in the target's graphics stack.

use std::path::{Path, PathBuf};

use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::engine::{self, Profile};
use moveit_core::extstate;
use moveit_core::oscrypt::{HostTag, LinuxPrefix, Lock};
use moveit_core::paths;
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

const EXT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn make_db(path: &Path, schema: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch(schema).unwrap();
}

fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
}

fn fresh_profile(dir: &Path) {
    make_db(&dir.join("Default/Network/Cookies"), COOKIES_SCHEMA);
    make_db(&dir.join("Default/History"), HISTORY_SCHEMA);
    make_db(&dir.join("Default/Login Data"), LOGINS_SCHEMA);
    write(&dir.join("Default/Preferences"), b"{}");
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Every directory name anywhere under `root`.
fn dir_names_under(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                out.push(e.file_name().to_string_lossy().into_owned());
                stack.push(e.path());
            }
        }
    }
    out
}

fn profile<'a>(dir: &'a Path, k: &'a Keys) -> Profile<'a> {
    Profile { dir, slot: "Default", keys: k, login_tag: HostTag::Without, browser: "chrome", display: "Google Chrome" }
}

#[test]
fn caches_are_excluded_from_a_seal_open_round_trip() {
    let t = tempfile::tempdir().unwrap();
    let (a, b) = (t.path().join("A"), t.path().join("B"));
    fresh_profile(&a);
    fresh_profile(&b);
    let k = keys();
    cookies::import(
        &a.join("Default/Network/Cookies"),
        &[Cookie {
            host: ".acme.test".into(), name: "sid".into(), path: "/".into(), value: "SECRET".into(),
            expires_utc: 0, creation_utc: 100, last_access_utc: 100, is_secure: 1,
            is_httponly: 0, samesite: -1, last_update_utc: Some(100), top_frame_site_key: String::new(),
        }],
        &k,
    )
    .unwrap();

    // Real carried files: extension state and the extension binary tree.
    write(&a.join(format!("Default/Local Extension Settings/{EXT_ID}/data.txt")), b"state-bytes");
    write(&a.join(format!("Default/Extensions/{EXT_ID}/1.0_0/code.js")), b"code-bytes");
    // Junk inside cache dirs at every level the class names:
    // profile-root level, per-profile level, and nested inside carried trees.
    write(&a.join("ShaderCache/junk.bin"), b"root-shader-junk");
    write(&a.join("GrShaderCache/junk.bin"), b"root-grshader-junk");
    for name in paths::PROFILE_CACHE_DIRS {
        write(&a.join("Default").join(name).join("junk.bin"), b"profile-cache-junk");
    }
    write(&a.join(format!("Default/Local Extension Settings/{EXT_ID}/GPUCache/junk.bin")), b"nested-junk");
    write(&a.join(format!("Default/Extensions/{EXT_ID}/1.0_0/Code Cache/junk.bin")), b"nested-junk");

    let key = SyncKey::from_bytes([5u8; 32]);
    let sealed = engine::seal_box(&profile(&a, &k), "fixture:A", &key).unwrap();
    let payload = engine::open_box(&sealed, &key).unwrap();
    // The box itself carries no cache path.
    for logical in payload.ext_files.keys().chain(payload.ext_bins.keys()) {
        assert!(!paths::logical_path_has_cache_dir(logical), "box carries {logical}");
    }

    engine::import(&profile(&b, &k), &payload, 17_000_000_000_000i64).unwrap();

    // No cache dir anywhere in the result.
    for name in dir_names_under(&b) {
        assert!(!paths::is_cache_dir_name(&name), "cache dir {name} landed in the target");
    }
    // Every other file byte-identical.
    assert_eq!(
        std::fs::read(b.join(format!("Default/Local Extension Settings/{EXT_ID}/data.txt"))).unwrap(),
        b"state-bytes"
    );
    assert_eq!(
        std::fs::read(b.join(format!("Default/Extensions/{EXT_ID}/1.0_0/code.js"))).unwrap(),
        b"code-bytes"
    );
    let got = cookies::export(&b.join("Default/Network/Cookies"), &k).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].value, "SECRET");
}

#[test]
fn a_box_naming_cache_files_does_not_write_them() {
    // Open direction alone: a payload built by hand (as a box from
    // anywhere else could) naming cache entries beside real ones.
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("B");
    let slot = root.join("Default");
    std::fs::create_dir_all(&slot).unwrap();
    let good = format!("Local Extension Settings/{EXT_ID}/data.txt");
    let bad = format!("Local Extension Settings/{EXT_ID}/GPUCache/junk.bin");
    let mut files = std::collections::BTreeMap::new();
    files.insert(good.clone(), b"state-bytes".to_vec());
    files.insert(bad.clone(), b"nested-junk".to_vec());
    let manifest = serde_json::json!({
        "installed_ids": [EXT_ID],
        "folders": ["Local Extension Settings"],
        "files": [
            {"path": good, "size": 11, "sha256": "x"},
            {"path": bad, "size": 11, "sha256": "x"},
        ],
        "total_bytes": 22,
    });
    let stats = extstate::import_in(&root, "Default", &manifest, &files).unwrap();
    assert_eq!(stats.files, 1, "only the real file is written");
    assert_eq!(std::fs::read(slot.join(format!("Local Extension Settings/{EXT_ID}/data.txt"))).unwrap(), b"state-bytes");
    assert!(!slot.join(format!("Local Extension Settings/{EXT_ID}/GPUCache")).exists());
}

#[test]
fn the_cache_name_sets_match_the_two_levels() {
    assert_eq!(paths::ROOT_CACHE_DIRS, ["ShaderCache", "GrShaderCache"]);
    for name in ["GPUCache", "ShaderCache", "GrShaderCache", "DawnWebGPUCache", "DawnGraphiteCache", "Code Cache"] {
        assert!(paths::PROFILE_CACHE_DIRS.contains(&name), "{name}");
        assert!(paths::is_cache_dir_name(name), "{name}");
    }
    assert!(!paths::is_cache_dir_name("Extensions"));
    assert!(!paths::is_cache_dir_name("Network"));
    assert!(paths::logical_path_has_cache_dir("Extensions/x/1.0_0/Code Cache/junk"));
    assert!(!paths::logical_path_has_cache_dir("Extensions/x/1.0_0/code.js"));
    // Matching is case-insensitive, in the predicate and through a path.
    assert!(paths::is_cache_dir_name("gpucache"));
    assert!(paths::is_cache_dir_name("GpuCache"));
    assert!(paths::is_cache_dir_name("code cache"));
    assert!(paths::logical_path_has_cache_dir("Extensions/x/1.0_0/gpucache/junk.bin"));
    // The final component of a payload path is a FILE: a file named like
    // a cache folder is data, so a path ending in one has no cache dir.
    assert!(!paths::logical_path_has_cache_dir("Local Extension Settings/x/GPUCache"));
    assert!(!paths::logical_path_has_cache_dir("GPUCache"));
}

#[test]
fn lowercase_cache_dirs_are_pruned_and_a_cache_named_file_survives() {
    let t = tempfile::tempdir().unwrap();
    let (a, b) = (t.path().join("A"), t.path().join("B"));
    fresh_profile(&a);
    fresh_profile(&b);
    let k = keys();

    // A lowercase cache DIRECTORY inside carried trees: pruned on seal.
    write(&a.join(format!("Default/Local Extension Settings/{EXT_ID}/gpucache/junk.bin")), b"nested-junk");
    write(&a.join(format!("Default/Extensions/{EXT_ID}/1.0_0/gpucache/junk.bin")), b"nested-junk");
    // A cache-named FILE (final component) in the same trees: data, carried.
    // It sits one folder down, not beside the cache directory above: a
    // `GPUCache` file and a `gpucache` directory cannot be siblings on a
    // case-insensitive filesystem (NTFS, APFS), so planting them side by
    // side made the fixture itself impossible there. The assertions are
    // unchanged: the lowercase cache dirs are still pruned from both
    // trees, and a file whose name is a cache name still travels whole.
    write(&a.join(format!("Default/Local Extension Settings/{EXT_ID}/keep/GPUCache")), b"state-file-bytes");
    write(&a.join(format!("Default/Extensions/{EXT_ID}/1.0_0/keep/GPUCache")), b"bin-file-bytes");

    let key = SyncKey::from_bytes([5u8; 32]);
    let sealed = engine::seal_box(&profile(&a, &k), "fixture:A", &key).unwrap();
    let payload = engine::open_box(&sealed, &key).unwrap();
    // The box carries the cache-named files and no cache directory path.
    assert!(payload
        .ext_files
        .keys()
        .any(|l| l == &format!("Local Extension Settings/{EXT_ID}/keep/GPUCache")));
    assert!(payload
        .ext_bins
        .keys()
        .any(|l| l.ends_with("/GPUCache")));
    for logical in payload.ext_files.keys().chain(payload.ext_bins.keys()) {
        assert!(!paths::logical_path_has_cache_dir(logical), "box carries {logical}");
    }

    engine::import(&profile(&b, &k), &payload, 17_000_000_000_000i64).unwrap();

    // No cache directory (any casing) landed, and the files survived whole.
    for name in dir_names_under(&b) {
        assert!(!paths::is_cache_dir_name(&name), "cache dir {name} landed in the target");
    }
    assert_eq!(
        std::fs::read(b.join(format!("Default/Local Extension Settings/{EXT_ID}/keep/GPUCache"))).unwrap(),
        b"state-file-bytes"
    );
    assert_eq!(
        std::fs::read(b.join(format!("Default/Extensions/{EXT_ID}/1.0_0/keep/GPUCache"))).unwrap(),
        b"bin-file-bytes"
    );
}
