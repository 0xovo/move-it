//! Move It overnight stress test.
//!
//! A *fleet* is one person's set of devices, all sharing one sync key and one browser password.
//! Each device starts with randomly planted browser data. Then, for several rounds, every device
//! seals a box and every other device opens it, exactly as real devices trading through a shared
//! folder would. The claim we are checking, thousands of times with random data and random order:
//!
//!   after enough rounds, every device in a fleet holds the IDENTICAL set of cookies, saved
//!   logins and history, no matter what order the boxes were traded in,
//!
//! plus: re-opening the same box a second time changes nothing (idempotent), and Undo puts a
//! device back byte-for-byte. Every fleet is driven by one seed, printed on any failure so it
//! can be replayed. Bookmarks are deliberately left out of the convergence check: they use a
//! keep-both rule and are not meant to converge.
//!
//! Usage: moveit-harness [--secs N] [--threads N] [--seed N]
//!        moveit-harness probe-logins <browser> <profile-dir>
//!        moveit-harness probe-cookies <browser> <profile-dir>
//!        moveit-harness pair-offer <data-dir> <shared-dir> <device>
//!        moveit-harness pair-accept <data-dir> <shared-dir> <device> <code>
//!        moveit-harness pair-status <device>
//!        moveit-harness pair-confirm <shared-dir> <device>
//!        moveit-harness detect-profiles
//!        moveit-harness seal <browser> <profile-dir> <out.box>
//!        moveit-harness open <browser> <profile-dir> <in.box>
//!
//! The probe form skips the stress test: it reads one real profile's saved logins with
//! browser-password discovery (logins::discover, scoped to that browser) and prints
//! what it found, one line per
//! login. That is the live check that the engine can read a profile a browser wrote.
//!
//! seal / open drive the real engine move: discover the browser password the same
//! way the probes do, seal a profile into a box (writing a sidecar `<out.box>.key`)
//! or open a box into a fresh profile. Each prints one JSON stats line on stdout.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::engine::{self, Applied, Profile};
use moveit_core::history;
use moveit_core::keychain;
use moveit_core::pairing::{self, Accept};
use moveit_core::localstorage;
use moveit_core::logins::{self, Login};
use moveit_core::oscrypt::{HostTag, LinuxBrowser, LinuxPrefix, Lock, MacBrowser};
use moveit_core::paths;
use moveit_core::sealed::{Payload, SyncKey};
use moveit_core::txn;
use moveit_core::Error;

// -------- a tiny deterministic PRNG (splitmix64), so a seed replays exactly --------
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

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
    rusqlite::Connection::open(path).unwrap().execute_batch(schema).unwrap();
}

fn keys() -> Keys {
    Keys::Cbc { lock: Lock::linux("peanuts", LinuxPrefix::V10), from_libsecret_v2: false }
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

// A small universe of hosts/names so devices genuinely collide on identity.
const HOSTS: [&str; 6] = [".acme.test", ".news.test", ".shop.test", ".mail.test", ".bank.test", ".社.test"];
const NAMES: [&str; 4] = ["sid", "pref", "tok", "csrf"];
const TIMES: [i64; 4] = [100, 200, 200, 300]; // the doubled 200 forces equal-timestamp ties

fn plant(dir: &Path, rng: &mut Rng, k: &Keys) {
    let n = 3 + rng.below(6) as usize;
    let mut cs = Vec::new();
    for _ in 0..n {
        let cre = *rng.pick(&TIMES);
        let part = if rng.below(4) == 0 { "https://top.test".into() } else { String::new() };
        // One time in four, pin the value to a constant so two devices can collide on
        // (changed, creation, last_access, value) and differ only in expiry or the flags. That
        // forces the tie to be broken by the rest of the total order, which is exactly the fix
        // we want stressed: both sides must still pick the same winner.
        let value = if rng.below(4) == 0 { "SAME".to_string() } else { format!("v{}", rng.next() % 100000) };
        cs.push(Cookie {
            host: rng.pick(&HOSTS).to_string(),
            name: rng.pick(&NAMES).to_string(),
            path: "/".into(),
            value,
            expires_utc: *rng.pick(&[0i64, 200, 999]),
            creation_utc: cre,
            last_access_utc: cre,
            is_secure: rng.below(2) as i64,
            is_httponly: rng.below(2) as i64,
            samesite: (rng.below(3) as i64) - 1,
            last_update_utc: Some(cre),
            top_frame_site_key: part,
        });
    }
    cookies::import(&dir.join("Default/Cookies"), &cs, k).unwrap();

    let mut ls = Vec::new();
    for _ in 0..(1 + rng.below(4)) {
        let host = rng.pick(&HOSTS).trim_start_matches('.').to_string();
        let cre = *rng.pick(&TIMES);
        ls.push(Login {
            origin_url: format!("https://{host}/"),
            action_url: format!("https://{host}/login"),
            username_value: format!("user{}", rng.below(3)),
            password_value: format!("pw{}", rng.next() % 100000),
            date_created: cre,
            date_last_used: cre,
            times_used: rng.below(5) as i64,
            signon_realm: format!("https://{host}/"),
            date_password_modified: cre,
        });
    }
    logins::import(&dir.join("Default/Login Data"), &ls, k, HostTag::Without).unwrap();

    let sec = history::Section {
        urls: (0..(1 + rng.below(4)))
            .map(|_| history::HistoryUrl {
                url: format!("https://{}/p{}", rng.pick(&HOSTS).trim_start_matches('.'), rng.below(4)),
                title: format!("t{}", rng.below(9)),
                typed_count: rng.below(3) as i64,
                last_visit_time: *rng.pick(&TIMES),
                hidden: 0,
            })
            .collect(),
        visits: (0..(1 + rng.below(5)))
            .map(|_| history::Visit {
                url: format!("https://{}/p{}", rng.pick(&HOSTS).trim_start_matches('.'), rng.below(4)),
                visit_time: *rng.pick(&TIMES),
                from_visit_time: None,
                transition: rng.below(3) as i64,
                visit_duration: rng.below(9000) as i64,
            })
            .collect(),
    };
    history::import(&dir.join("Default/History"), &sec).unwrap();
}

/// A canonical fingerprint of the stores that must converge.
fn fingerprint(dir: &Path, k: &Keys) -> String {
    let mut cs = cookies::export(&dir.join("Default/Cookies"), k).unwrap();
    cs.sort_by(|a, b| {
        (&a.host, &a.top_frame_site_key, &a.name, &a.path, &a.value)
            .cmp(&(&b.host, &b.top_frame_site_key, &b.name, &b.path, &b.value))
    });
    let mut ls = logins::export(&dir.join("Default/Login Data"), k).unwrap();
    ls.sort_by(|a, b| {
        (&a.origin_url, &a.username_value, &a.password_value).cmp(&(&b.origin_url, &b.username_value, &b.password_value))
    });
    let mut h = history::export(&dir.join("Default/History")).unwrap();
    h.urls.sort_by(|a, b| a.url.cmp(&b.url));
    h.visits.sort_by(|a, b| (&a.url, a.visit_time).cmp(&(&b.url, b.visit_time)));
    // Values only; ids and recomputed counts are not part of the moved set.
    let shape = (
        cs.iter().map(|c| (&c.host, &c.top_frame_site_key, &c.name, &c.path, &c.value)).collect::<Vec<_>>(),
        ls.iter().map(|l| (&l.origin_url, &l.username_value, &l.password_value, l.times_used)).collect::<Vec<_>>(),
        h.urls.iter().map(|u| (&u.url, &u.title)).collect::<Vec<_>>(),
        h.visits.iter().map(|v| (&v.url, v.visit_time, v.visit_duration, v.transition)).collect::<Vec<_>>(),
    );
    serde_json::to_string(&shape).unwrap()
}

enum Outcome {
    Ok,
    Fail(String),
}

fn run_fleet(seed: u64) -> Outcome {
    let mut rng = Rng(seed);
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => return Outcome::Fail(format!("seed {seed}: no tempdir: {e}")),
    };
    let k = keys();
    let key = {
        let mut b = [0u8; 32];
        for x in b.iter_mut() {
            *x = rng.next() as u8;
        }
        SyncKey::from_bytes(b)
    };
    let devices = 2 + rng.below(3) as usize; // 2..4
    let dirs: Vec<_> = (0..devices).map(|i| tmp.path().join(format!("d{i}"))).collect();
    for d in &dirs {
        make_db(&d.join("Default/Cookies"), COOKIES_SCHEMA);
        make_db(&d.join("Default/History"), HISTORY_SCHEMA);
        make_db(&d.join("Default/Login Data"), LOGINS_SCHEMA);
        plant(d, &mut rng, &k);
    }

    let catch = |r: moveit_core::Result<()>, what: &str| -> std::result::Result<(), String> {
        r.map_err(|e| format!("seed {seed}: {what}: {e:?}"))
    };

    // Gossip rounds: each round, snapshot every device's box, then every device opens every peer's.
    let rounds = devices + 2;
    for _ in 0..rounds {
        let mut boxes = Vec::new();
        for (i, d) in dirs.iter().enumerate() {
            match engine::seal_box(&profile(d, &k), &format!("d{i}"), &key) {
                Ok(b) => boxes.push(b),
                Err(e) => return Outcome::Fail(format!("seed {seed}: seal d{i}: {e:?}")),
            }
        }
        for (i, d) in dirs.iter().enumerate() {
            for (j, b) in boxes.iter().enumerate() {
                if i == j {
                    continue;
                }
                let payload = match engine::open_box(b, &key) {
                    Ok(p) => p,
                    Err(e) => return Outcome::Fail(format!("seed {seed}: open d{j}: {e:?}")),
                };
                if let Err(e) = engine::import(&profile(d, &k), &payload, 17_000_000_000_000) {
                    return Outcome::Fail(format!("seed {seed}: import d{j}->d{i}: {e:?}"));
                }
            }
        }
    }

    // 1. Convergence: every device holds the identical set.
    let fps: Vec<String> = dirs.iter().map(|d| fingerprint(d, &k)).collect();
    if !fps.iter().all(|f| f == &fps[0]) {
        return Outcome::Fail(format!("seed {seed}: devices did not converge after {rounds} rounds"));
    }

    // 2. Idempotence: opening d1's box into d0 again must change nothing.
    let before = fps[0].clone();
    let again = engine::seal_box(&profile(&dirs[1], &k), "d1", &key).and_then(|b| engine::open_box(&b, &key));
    match again {
        Ok(p) => {
            if let Err(e) = catch(engine::import(&profile(&dirs[0], &k), &p, 17_000_000_000_000).map(|_| ()), "re-import") {
                return Outcome::Fail(e);
            }
        }
        Err(e) => return Outcome::Fail(format!("seed {seed}: reseal: {e:?}")),
    }
    if fingerprint(&dirs[0], &k) != before {
        return Outcome::Fail(format!("seed {seed}: re-importing the same box changed the profile"));
    }

    // 3. Undo: a fresh device, one move, then undo, must be byte-identical to before the move.
    let victim = tmp.path().join("victim");
    make_db(&victim.join("Default/Cookies"), COOKIES_SCHEMA);
    make_db(&victim.join("Default/History"), HISTORY_SCHEMA);
    make_db(&victim.join("Default/Login Data"), LOGINS_SCHEMA);
    plant(&victim, &mut rng, &k);
    if let Err(e) = catch(txn::recover(&victim).map(|_| ()), "recover") {
        return Outcome::Fail(e);
    }
    let pre = fingerprint(&victim, &k);
    let donor = engine::seal_box(&profile(&dirs[0], &k), "d0", &key).and_then(|b| engine::open_box(&b, &key)).unwrap();
    if let Err(e) = catch(engine::import(&profile(&victim, &k), &donor, 17_000_000_000_000).map(|_| ()), "victim import") {
        return Outcome::Fail(e);
    }
    match txn::undo_last(&victim, false) {
        Ok(txn::Undo::Done) => {}
        other => return Outcome::Fail(format!("seed {seed}: undo returned {other:?}")),
    }
    if fingerprint(&victim, &k) != pre {
        return Outcome::Fail(format!("seed {seed}: undo did not restore the profile"));
    }

    Outcome::Ok
}

fn arg(name: &str, default: u64) -> u64 {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// The macOS twin of a Linux browser identity: same caller spelling,
/// different key store. Opera has no macOS harness route and no twin.
#[cfg(target_os = "macos")]
fn mac_browser(browser: LinuxBrowser) -> Option<MacBrowser> {
    match browser {
        LinuxBrowser::Brave => Some(MacBrowser::Brave),
        LinuxBrowser::Chrome => Some(MacBrowser::Chrome),
        LinuxBrowser::Chromium => Some(MacBrowser::Chromium),
        LinuxBrowser::Edge => Some(MacBrowser::Edge),
        LinuxBrowser::Opera => None,
    }
}

fn probe_logins(browser: LinuxBrowser, dir: &str) -> ! {
    #[cfg(target_os = "macos")]
    let found = match mac_browser(browser) {
        Some(mb) => logins::discover_mac(Path::new(dir), mb),
        None => Err(Error::Refused(
            "no macOS Safe Storage discovery for this browser".into(),
        )),
    };
    #[cfg(not(target_os = "macos"))]
    let found = logins::discover(Path::new(dir), browser);
    match found {
        Ok(found) => {
            println!("probe-logins: profile={dir}");
            println!("probe-logins: {} login(s) discovered", found.len());
            for l in &found {
                println!(
                    "origin={} username={} password=<redacted>",
                    l.origin_url, l.username_value
                );
            }
            std::process::exit(0);
        }
        Err(e) => {
            println!("probe-logins: profile={dir}");
            println!("probe-logins: FAILED: {e:?}");
            std::process::exit(1);
        }
    }
}

fn probe_cookies(browser: LinuxBrowser, dir: &str) -> ! {
    let keys = match profile_keys(browser, Path::new(dir)) {
        Ok(k) => k,
        Err(e) => {
            println!("probe-cookies: profile={dir}");
            println!("probe-cookies: FAILED: {e:?}");
            std::process::exit(1);
        }
    };
    match cookies::export(&moveit_core::paths::cookies(Path::new(dir)), &keys) {
        Ok(found) => {
            println!("probe-cookies: profile={dir}");
            println!("probe-cookies: {} cookie(s) decrypted", found.len());
            for c in found.iter().take(10) {
                println!("host={} name={} value=<redacted>", c.host, c.name);
            }
            std::process::exit(0);
        }
        Err(e) => {
            println!("probe-cookies: profile={dir}");
            println!("probe-cookies: FAILED: {e:?}");
            std::process::exit(1);
        }
    }
}

// -------- pairing against the OS keychain (two instances, one shared folder) --------

fn pair_fail(what: &str, e: moveit_core::Error) -> ! {
    println!("{what}: FAILED: {e:?}");
    std::process::exit(1);
}

fn pair_offer(data: &str, shared: &str, device: &str) -> ! {
    let (data, shared) = (Path::new(data), Path::new(shared));
    for d in [data, shared] {
        if let Err(e) = std::fs::create_dir_all(d) {
            println!("pair-offer: FAILED: cannot create {}: {e}", d.display());
            std::process::exit(1);
        }
    }
    // First run on this device: the secret is generated straight into the keychain.
    let key = match keychain::ensure_key(&keychain::OsKeychain, device) {
        Ok(k) => k,
        Err(e) => pair_fail("pair-offer", e),
    };
    let code = match pairing::new_code(6) {
        Ok(c) => c,
        Err(e) => pair_fail("pair-offer", e),
    };
    if let Err(e) = pairing::offer(shared, &key, &code, device) {
        pair_fail("pair-offer", e);
    }
    println!("pair-offer: device={device}");
    println!("pair-offer: code: {}", pairing::display_code(&code));
    println!(
        "pair-offer: sync key is in the os keychain (service {}, account {device})",
        keychain::SERVICE
    );
    std::process::exit(0);
}

fn pair_accept(data: &str, shared: &str, device: &str, code: &str) -> ! {
    let (data, shared) = (Path::new(data), Path::new(shared));
    if let Err(e) = std::fs::create_dir_all(data) {
        println!("pair-accept: FAILED: cannot create {}: {e}", data.display());
        std::process::exit(1);
    }
    let tries = pairing::Tries { path: data.join("pairing-tries") };
    match pairing::accept_and_store(shared, code, device, &tries, &|key| keychain::store_key(device, key)) {
        Ok(Accept::Paired(key)) => {
            let _ = pairing::leave_paired_note(shared, &key, device);
            println!("pair-accept: paired: yes");
            println!(
                "pair-accept: sync key is in the os keychain (service {}, account {device})",
                keychain::SERVICE
            );
            std::process::exit(0);
        }
        Ok(Accept::WrongCode { tries_left }) => {
            println!("pair-accept: paired: no (wrong code, {tries_left} tries left)");
            std::process::exit(1);
        }
        Ok(Accept::NeedNewCode) => {
            println!("pair-accept: paired: no (too many wrong codes, or the offer expired)");
            std::process::exit(1);
        }
        Ok(Accept::Nothing) => {
            println!("pair-accept: paired: no (no offer in the shared place)");
            std::process::exit(1);
        }
        Err(e) => pair_fail("pair-accept", e),
    }
}

fn pair_status(device: &str) -> ! {
    match keychain::load_key(device) {
        Ok(Some(_)) => {
            println!("pair-status: paired: yes");
            std::process::exit(0);
        }
        Ok(None) => {
            println!("pair-status: paired: no");
            std::process::exit(0);
        }
        Err(e) => pair_fail("pair-status", e),
    }
}

fn pair_confirm(shared: &str, device: &str) -> ! {
    let key = match keychain::load_key(device) {
        Ok(Some(k)) => k,
        Ok(None) => {
            println!("pair-confirm: not paired (no key in the keychain)");
            std::process::exit(1);
        }
        Err(e) => pair_fail("pair-confirm", e),
    };
    match pairing::check_paired(Path::new(shared), &key) {
        Ok(Some(name)) => {
            println!("pair-confirm: {name} paired with this device");
            std::process::exit(0);
        }
        Ok(None) => {
            println!("pair-confirm: nobody has paired yet");
            std::process::exit(1);
        }
        Err(e) => pair_fail("pair-confirm", e),
    }
}

fn parse_browser(name: &str) -> LinuxBrowser {
    match LinuxBrowser::from_name(name) {
        Some(b) => b,
        None => {
            eprintln!(
                "unknown browser {name} (brave, chrome, chromium, edge, opera)"
            );
            std::process::exit(2);
        }
    }
}

fn fail_engine(e: Error) -> ! {
    // App-Bound must be distinguishable: the proof-matrix driver maps it to a
    // structured skip, never FAIL. Keep the tag stable for that match.
    match e {
        Error::AppBound => eprintln!("error: AppBound: {e}"),
        other => eprintln!("error: {other:?}: {other}"),
    }
    std::process::exit(1);
}

/// Browser-password discovery shared by probe-* / seal / open.
/// Linux reads the secret service and never fails (the compiled-in
/// fallback applies, like Chromium itself). macOS reads that browser's
/// Safe Storage item in the login Keychain, which can refuse (locked
/// keychain, missing item), so this is fallible on every platform.
fn profile_keys(browser: LinuxBrowser, dir: &Path) -> Result<Keys, Error> {
    #[cfg(target_os = "windows")]
    {
        let _ = browser;
        return windows_master_key(dir)
            .map(|master| Keys::Gcm { lock: Lock::windows(master) });
    }
    #[cfg(target_os = "macos")]
    {
        let mb = match mac_browser(browser) {
            Some(mb) => mb,
            None => {
                return Err(Error::Refused(
                    "no macOS Safe Storage discovery for this browser".into(),
                ))
            }
        };
        let (password, from_keychain) = moveit_core::oscrypt::mac_browser_password_for(mb)?;
        return Ok(Keys::Cbc {
            lock: Lock::mac(&password),
            // An empty store follows the scheme this user data folder's own
            // browser already seals with, read from the browser's own pref hashes.
            from_libsecret_v2: mb.empty_store_v11_from_trusted_item(from_keychain)
                || (from_keychain && moveit_core::oscrypt::mac_data_dir_speaks_v11(dir)),
        });
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = dir;
        let (password, from_trusted) =
            moveit_core::oscrypt::linux_browser_password_for_at(browser, Some(dir))?;
        Ok(Keys::Cbc {
            lock: Lock::linux(&password, LinuxPrefix::V10),
            from_libsecret_v2: browser.empty_store_v11_from_trusted_item(from_trusted),
        })
    }
}

fn parse_wrapped_master_key(local_state_json: &[u8]) -> Result<Vec<u8>, Error> {
    use base64::Engine;
    let doc: serde_json::Value = serde_json::from_slice(local_state_json)
        .map_err(|e| Error::Corrupt(format!("Local State is not valid JSON: {e}")))?;
    let encoded = doc
        .get("os_crypt")
        .and_then(|o| o.get("encrypted_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Corrupt("Local State has no os_crypt.encrypted_key".into()))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| Error::Corrupt(format!("os_crypt.encrypted_key is not base64: {e}")))?;
    let wrapped = raw
        .strip_prefix(b"DPAPI" as &[u8])
        .ok_or_else(|| Error::Corrupt("os_crypt.encrypted_key lacks the DPAPI prefix".into()))?;
    if wrapped.is_empty() {
        return Err(Error::Corrupt("os_crypt.encrypted_key wraps an empty key".into()));
    }
    Ok(wrapped.to_vec())
}

/// Read this profile's Local State and DPAPI-unwrap its master key.
#[cfg(target_os = "windows")]
fn windows_master_key(dir: &Path) -> Result<[u8; 32], Error> {
    let state_path = moveit_core::paths::local_state(dir);
    let bytes = std::fs::read(&state_path)
        .map_err(|e| Error::Io(format!("cannot read {}: {e}", state_path.display())))?;
    let wrapped = parse_wrapped_master_key(&bytes)?;
    let plain = dpapi_unprotect(&wrapped)?;
    plain.as_slice().try_into().map_err(|_| {
        Error::Corrupt(format!(
            "DPAPI-unwrapped master key is {} bytes, expected 32",
            plain.len()
        ))
    })
}

/// One DPAPI unwrap (CryptUnprotectData) in the current user's session.
/// UI_FORBIDDEN: a proof harness must never pop a consent dialog; a
/// locked store is an honest error, not a prompt.
#[cfg(target_os = "windows")]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, Error> {
    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *const u8,
    }
    #[repr(C)]
    struct DataBlobMut {
        cb_data: u32,
        pb_data: *mut u8,
    }
    #[link(name = "crypt32")]
    extern "system" {
        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *const std::ffi::c_void,
            p_prompt_struct: *const std::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlobMut,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    let input = DataBlob { cb_data: data.len() as u32, pb_data: data.as_ptr() };
    let mut output = DataBlobMut { cb_data: 0, pb_data: std::ptr::null_mut() };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pb_data.is_null() {
        return Err(Error::Io(
            "DPAPI could not unwrap the browser master key (locked Windows session?)".into(),
        ));
    }
    let plain =
        unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
    unsafe { LocalFree(output.pb_data as *mut std::ffi::c_void) };
    Ok(plain)
}

fn key_sidecar(box_path: &Path) -> std::path::PathBuf {
    let mut p = box_path.as_os_str().to_owned();
    p.push(".key");
    std::path::PathBuf::from(p)
}

/// Per-store counts the proof-matrix driver classifies rows from.
fn stats_from_payload(payload: &Payload) -> serde_json::Value {
    let m = &payload.manifest;
    let n = |key: &str| m.get(key).and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
    let history = m
        .get("history")
        .map(|h| {
            let urls = h.get("urls").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
            let visits = h.get("visits").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
            urls + visits
        })
        .unwrap_or(0);
    let bookmarks = match m.get("bookmarks") {
        Some(b) if b.get("present").and_then(|v| v.as_bool()) == Some(true) => 1,
        _ => 0,
    };
    let extensions = m
        .get("extensions")
        .and_then(|e| e.get("files"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    serde_json::json!({
        "cookies": n("cookies"),
        "logins": n("passwords"),
        "history": history,
        "bookmarks": bookmarks,
        "extensions": extensions,
        "localstorage": n("ext_localstorage"),
    })
}

fn stats_from_applied(a: &Applied) -> serde_json::Value {
    let history = a
        .history
        .as_ref()
        .map(|h| h.urls_inserted + h.urls_updated + h.visits_inserted + h.visits_updated)
        .unwrap_or(0);
    let bookmarks = if a.bookmarks.carried { 1 } else { 0 };
    serde_json::json!({
        "cookies": a.cookies.imported,
        "logins": a.logins.inserted + a.logins.updated,
        "history": history,
        "bookmarks": bookmarks,
        "extensions": a.extensions.files + a.extensions.folders,
        "localstorage": a.localstorage.inserted + a.localstorage.updated,
    })
}

fn cmd_seal(browser: LinuxBrowser, dir: &str, out_box: &str) -> ! {
    let keys = match profile_keys(browser, Path::new(dir)) {
        Ok(k) => k,
        Err(e) => fail_engine(e),
    };
    let profile = Profile {
        dir: Path::new(dir),
        slot: "Default",
        keys: &keys,
        login_tag: HostTag::Without,
        browser: "chrome",
        display: "Google Chrome",
    };
    let key = match SyncKey::generate() {
        Ok(k) => k,
        Err(e) => fail_engine(e),
    };
    let key_path = key_sidecar(Path::new(out_box));
    if let Err(e) = key.write_new_key_file(&key_path) {
        fail_engine(e);
    }
    let sealed = match engine::seal_box(&profile, "moveit-harness", &key) {
        Ok(b) => b,
        Err(e) => fail_engine(e),
    };
    if let Err(e) = std::fs::write(out_box, &sealed) {
        eprintln!("error: cannot write box {out_box}: {e}");
        std::process::exit(1);
    }
    // Counts from the sealed box itself (open is local, no second profile read).
    let payload = match engine::open_box(&sealed, &key) {
        Ok(p) => p,
        Err(e) => fail_engine(e),
    };
    println!("{}", stats_from_payload(&payload));
    std::process::exit(0);
}

/// Harness writes stay in explicit temporary fixture folders, including through links.
/// A target outside the temp folder is accepted only when the invocation
/// deliberately passes --allow-real-dir; the default still refuses.
fn require_scratch_dir(dir: &Path, allow_real_dir: bool) -> Result<(), Error> {
    let canonical = std::fs::canonicalize(dir)
        .map_err(|_| Error::Refused("the harness needs an existing scratch profile directory".into()))?;
    if !canonical.is_dir() {
        return Err(Error::Refused("the harness only writes profiles inside a scratch directory under the system temp folder".into()));
    }
    if allow_real_dir {
        return Ok(());
    }
    let temp = std::fs::canonicalize(std::env::temp_dir()).map_err(|e| Error::Io(e.to_string()))?;
    if canonical == temp || !canonical.starts_with(&temp) {
        return Err(Error::Refused("the harness only writes profiles inside a scratch directory under the system temp folder".into()));
    }
    Ok(())
}

fn require_api_profiles(args: &[String]) -> Result<(), Error> {
    let allow_real_dir = args.iter().any(|a| a == "--allow-real-dir");
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let opt = |name: &str| args.iter().position(|a| a == name)
        .and_then(|i| args.get(i + 1)).filter(|v| !v.starts_with("--"));
    let needed: &[&str] = match cmd {
        "move_start" | "welcome_start" | "undo_last" => &["--profile"],
        "local_move" => &["--from", "--to"],
        "local_undo" => &["--to"],
        _ => &[],
    };
    for flag in needed {
        if opt(flag).is_none() {
            return Err(Error::Refused(format!("{cmd} requires an explicit {flag} scratch profile")));
        }
    }
    for flag in ["--profile", "--from", "--to", "--browser-base"] {
        if let Some(dir) = opt(flag) { require_scratch_dir(Path::new(dir), allow_real_dir)?; }
    }
    Ok(())
}

fn harness_browser_display(browser: LinuxBrowser) -> String {
    match browser {
        LinuxBrowser::Brave => "Brave".into(),
        LinuxBrowser::Chrome => "Google Chrome".into(),
        LinuxBrowser::Chromium => "Chromium".into(),
        LinuxBrowser::Edge => "Microsoft Edge".into(),
        LinuxBrowser::Opera => "Opera".into(),
    }
}

fn cmd_open(browser: LinuxBrowser, dir: &str, in_box: &str, allow_real_dir: bool) -> ! {
    if let Err(e) = require_scratch_dir(Path::new(dir), allow_real_dir) { fail_engine(e); }
    if paths::never_launched(Path::new(dir), "Default") {
        fail_engine(Error::NeverLaunched {
            browser: harness_browser_display(browser),
        });
    }
    let keys = match profile_keys(browser, Path::new(dir)) {
        Ok(k) => k,
        Err(e) => fail_engine(e),
    };
    let profile = Profile {
        dir: Path::new(dir),
        slot: "Default",
        keys: &keys,
        login_tag: HostTag::Without,
        browser: "chrome",
        display: "Google Chrome",
    };
    let key_path = key_sidecar(Path::new(in_box));
    let key = match SyncKey::read_key_file(&key_path) {
        Ok(k) => k,
        Err(e) => fail_engine(e),
    };
    let bytes = match std::fs::read(in_box) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read box {in_box}: {e}");
            std::process::exit(1);
        }
    };
    let payload = match engine::open_box(&bytes, &key) {
        Ok(p) => p,
        Err(e) => fail_engine(e),
    };
    let applied = match engine::import(&profile, &payload, localstorage::chrome_now_us()) {
        Ok(a) => a,
        Err(e) => fail_engine(e),
    };
    println!("{}", stats_from_applied(&applied));
    std::process::exit(0);
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("pair-offer") {
        match (argv.get(2), argv.get(3), argv.get(4)) {
            (Some(data), Some(shared), Some(device)) => pair_offer(data, shared, device),
            _ => {
                eprintln!("usage: moveit-harness pair-offer <data-dir> <shared-dir> <device>");
                std::process::exit(2);
            }
        }
    }
    if argv.get(1).map(String::as_str) == Some("pair-accept") {
        match (argv.get(2), argv.get(3), argv.get(4)) {
            (Some(data), Some(shared), Some(device)) if argv.len() > 5 => {
                pair_accept(data, shared, device, &argv[5..].join(""))
            }
            _ => {
                eprintln!("usage: moveit-harness pair-accept <data-dir> <shared-dir> <device> <code>");
                std::process::exit(2);
            }
        }
    }
    if argv.get(1).map(String::as_str) == Some("pair-status") {
        match argv.get(2) {
            Some(device) => pair_status(device),
            _ => {
                eprintln!("usage: moveit-harness pair-status <device>");
                std::process::exit(2);
            }
        }
    }
    if argv.get(1).map(String::as_str) == Some("pair-confirm") {
        match (argv.get(2), argv.get(3)) {
            (Some(shared), Some(device)) => pair_confirm(shared, device),
            _ => {
                eprintln!("usage: moveit-harness pair-confirm <shared-dir> <device>");
                std::process::exit(2);
            }
        }
    }
    if argv.get(1).map(String::as_str) == Some("api") {
        api_main(&argv[1..]);
    }
    if argv.get(1).map(String::as_str) == Some("detect-profiles") {
        for p in moveit_core::profiles::detect_profiles() {
            println!("{} {} {}", p.browser, p.display, p.dir.display());
        }
        std::process::exit(0);
    }
    if argv.get(1).map(String::as_str) == Some("probe-cookies") {
        match (argv.get(2), argv.get(3)) {
            (Some(browser), Some(dir)) => probe_cookies(parse_browser(browser), dir),
            _ => {
                eprintln!("usage: moveit-harness probe-cookies <browser> <profile-dir>");
                std::process::exit(2);
            }
        }
    }
    if argv.get(1).map(String::as_str) == Some("probe-logins") {
        match (argv.get(2), argv.get(3)) {
            (Some(browser), Some(dir)) => probe_logins(parse_browser(browser), dir),
            _ => {
                eprintln!("usage: moveit-harness probe-logins <browser> <profile-dir>");
                std::process::exit(2);
            }
        }
    }
    if argv.get(1).map(String::as_str) == Some("seal") {
        match (argv.get(2), argv.get(3), argv.get(4)) {
            (Some(browser), Some(dir), Some(out)) => cmd_seal(parse_browser(browser), dir, out),
            _ => {
                eprintln!("usage: moveit-harness seal <browser> <profile-dir> <out.box>");
                std::process::exit(2);
            }
        }
    }
    if argv.get(1).map(String::as_str) == Some("open") {
        match (argv.get(2), argv.get(3), argv.get(4)) {
            (Some(browser), Some(dir), Some(inbox)) => cmd_open(parse_browser(browser), dir, inbox, argv.iter().any(|a| a == "--allow-real-dir")),
            _ => {
                eprintln!("usage: moveit-harness open <browser> <profile-dir> <in.box> [--allow-real-dir]");
                std::process::exit(2);
            }
        }
    }
    if argv.get(1).map(String::as_str) != Some("stress") {
        eprintln!("usage: moveit-harness <verb> [args] — verbs: stress, probe-logins, probe-cookies, seal, open, pair-offer, pair-accept, pair-status, pair-confirm, detect-profiles, api");
        std::process::exit(2);
    }
    let secs = arg("--secs", 3600);
    let threads = arg("--threads", 14).max(1);
    let base_seed = arg("--seed", 0x5EED_u64.wrapping_mul(0x9E3779B97F4A7C15));
    let deadline = Instant::now() + Duration::from_secs(secs);

    let fleets = Arc::new(AtomicU64::new(0));
    let fails = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    println!("moveit-harness: {threads} threads, {secs}s, base seed {base_seed:#x}");

    let mut handles = Vec::new();
    for t in 0..threads {
        let (fleets, fails, stop) = (fleets.clone(), fails.clone(), stop.clone());
        handles.push(std::thread::spawn(move || {
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                let seed = base_seed ^ (t as u64).wrapping_shl(40) ^ i.wrapping_mul(0x100000001B3);
                if let Outcome::Fail(why) = run_fleet(seed) {
                    fails.fetch_add(1, Ordering::Relaxed);
                    eprintln!("FAIL {why}");
                }
                fleets.fetch_add(1, Ordering::Relaxed);
                i += 1;
            }
        }));
    }

    // Progress line every 30s.
    let (pf, pl, ps) = (fleets.clone(), fails.clone(), stop.clone());
    let reporter = std::thread::spawn(move || {
        while !ps.load(Ordering::Relaxed) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_secs(30));
            println!(
                "[{:>5}s left] fleets={} fails={}",
                deadline.saturating_duration_since(Instant::now()).as_secs(),
                pf.load(Ordering::Relaxed),
                pl.load(Ordering::Relaxed)
            );
        }
    });

    for h in handles {
        let _ = h.join();
    }
    stop.store(true, Ordering::Relaxed);
    let _ = reporter.join();

    let (total, failed) = (fleets.load(Ordering::Relaxed), fails.load(Ordering::Relaxed));
    println!("\nDONE: {total} fleets run, {failed} failed.");
    println!("{}", serde_json::json!({"fleets": total, "fails": failed, "base_seed": base_seed, "secs": secs}));
    std::process::exit(if failed == 0 { 0 } else { 1 });
}

// -------- the app surface, one subcommand per shell command --------
// Usage: moveit-harness api <command> [--state DIR] [--device NAME]
//        [--browser NAME] [--profile DIR] [--browser-base DIR] [--force] [arg]
// Writes require explicit profiles under the system temp folder. Discovery is isolated
// to --browser-base (also scratch), or the state folder's browser-fixtures child.
// Results print as one JSON value; a move also prints each progress beat as it happens.

/// The move's profile choices from the command line: `--exclude id,id` and
/// repeatable `--route id=browser`.
fn move_args() -> (Vec<String>, Vec<moveit_core::api::RouteChoice>) {
    let args: Vec<String> = std::env::args().collect();
    let mut excluded: Vec<String> = Vec::new();
    let mut routes: Vec<moveit_core::api::RouteChoice> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--exclude" => {
                if let Some(v) = args.get(i + 1) {
                    excluded.extend(
                        v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()),
                    );
                    i += 1;
                }
            }
            "--route" => {
                if let Some(v) = args.get(i + 1) {
                    if let Some((id, b)) = v.split_once('=') {
                        routes.push(moveit_core::api::RouteChoice {
                            profile: id.to_string(),
                            browser: b.to_string(),
                        });
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    (excluded, routes)
}

fn api_fail(e: &moveit_core::Error) -> ! {
    println!("{}", serde_json::json!({ "error": format!("{e}") }));
    std::process::exit(1);
}

fn api_main(args: &[String]) -> ! {
    use moveit_core::api::App;
    if let Err(e) = require_api_profiles(args) { api_fail(&e); }
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let opt = |name: &str| {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };
    let positional = |idx: usize| {
        // The first non-flag argument after the command word.
        let mut n = 0;
        let mut i = 2;
        while i < args.len() {
            if args[i] == "--force" {
                // A switch, not a setting: it has no value to step over.
                i += 1;
            } else if args[i].starts_with("--") {
                i += 2;
            } else {
                if n == idx {
                    return Some(args[i].clone());
                }
                n += 1;
                i += 1;
            }
        }
        None
    };
    let state = opt("--state").unwrap_or_else(|| "moveit-state".to_string());
    let browser_base = opt("--browser-base").map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(&state).join("browser-fixtures"));
    let mut app = match App::open(Path::new(&state)) {
        Ok(a) => a.with_browser_base(&browser_base),
        Err(e) => api_fail(&e),
    };
    if let Some(name) = opt("--device") {
        if let Err(e) = app.set_device_name(&name) {
            api_fail(&e);
        }
    }
    // The working-profile pin belongs to the sync commands. Same-device
    // commands resolve their two browsers by name (detection, or --from/--to
    // below); a --profile pin would shadow the target's registration and move
    // the wrong folder, so it is not applied to them.
    if !cmd.starts_with("local_") {
        if let Some(dir) = opt("--profile") {
            let browser = opt("--browser").unwrap_or_else(|| "brave".to_string());
            app = app.with_profile(&browser, Path::new(&dir));
        }
    }
    // Same-device commands pin their two profiles by name: --from for the
    // source, --to for the target. local_undo takes only --to: a --from there
    // would register first for the same name and win the lookup.
    if cmd != "local_undo" {
        if let Some(from) = opt("--from") {
            if let Some(name) = positional(0) {
                app = app.with_local_profile(&name, Path::new(&from));
            }
        }
    }
    if let Some(to) = opt("--to") {
        let name = if cmd == "local_undo" { positional(0) } else { positional(1) };
        if let Some(name) = name {
            app = app.with_local_profile(&name, Path::new(&to));
        }
    }
    let need_pair = || -> (String, String) {
        match (positional(0), positional(1)) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                eprintln!("usage: api <local_preview|local_move|local_open_check> <source> <target>");
                std::process::exit(2);
            }
        }
    };
    let print = |v: serde_json::Value| -> ! {
        println!("{}", serde_json::to_string(&v).unwrap());
        std::process::exit(0);
    };
    macro_rules! run {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(e) => api_fail(&e),
            }
        };
    }
    match cmd {
        "welcome_start" => print(serde_json::to_value(run!(app.welcome_start())).unwrap()),
        "pair_show_code" => print(serde_json::to_value(run!(app.pair_show_code())).unwrap()),
        "pair_enter_code" => {
            let code = positional(0).unwrap_or_else(|| {
                eprintln!("usage: api pair_enter_code <code>");
                std::process::exit(2);
            });
            print(serde_json::to_value(run!(app.pair_enter_code(&code))).unwrap())
        }
        "use_pipe" => {
            let path = positional(0).unwrap_or_else(|| {
                eprintln!("usage: api use_pipe <path>");
                std::process::exit(2);
            });
            print(serde_json::to_value(run!(app.use_pipe(Path::new(&path)))).unwrap())
        }
        "preview_counts" => {
            let (excluded, routes) = move_args();
            print(serde_json::to_value(run!(app.preview_counts(&excluded, &routes))).unwrap())
        }
        "move_start" => {
            let mut beats: Vec<serde_json::Value> = Vec::new();
            let (excluded, routes) = move_args();
            let report = run!(app.move_start(Some(&excluded), &routes, None, &mut |p| {
                let v = serde_json::to_value(&p).unwrap();
                println!("{}", serde_json::json!({ "event": "progress", "progress": v }));
                beats.push(v);
            }));
            print(serde_json::json!({ "report": serde_json::to_value(report).unwrap() }))
        }
        "home_state" => print(serde_json::to_value(run!(app.home_state())).unwrap()),
        "undo_last" => {
            let force = args.iter().any(|a| a == "--force");
            print(serde_json::to_value(run!(app.undo_last(force))).unwrap())
        }
        "browser_open_check" => {
            print(serde_json::to_value(run!(app.browser_open_check(&[], &[]))).unwrap())
        }
        "local_browsers" => print(serde_json::to_value(app.local_browsers()).unwrap()),
        "local_preview" => {
            let (src, dst) = need_pair();
            let src_slot = opt("--source-slot");
            let dst_slot = opt("--target-slot");
            print(serde_json::to_value(run!(app.local_preview(
                &src,
                &dst,
                src_slot.as_deref(),
                dst_slot.as_deref(),
            )))
            .unwrap())
        }
        "local_move" => {
            let (src, dst) = need_pair();
            let src_slot = opt("--source-slot");
            let dst_slot = opt("--target-slot");
            let report = run!(app.local_move(
                &src,
                &dst,
                src_slot.as_deref(),
                dst_slot.as_deref(),
                None,
                &mut |p| {
                println!(
                    "{}",
                    serde_json::json!({ "event": "progress", "progress": serde_json::to_value(&p).unwrap() })
                );
            }));
            print(serde_json::json!({ "report": serde_json::to_value(report).unwrap() }))
        }
        "local_open_check" => {
            let (src, dst) = need_pair();
            print(serde_json::to_value(run!(app.local_open_check(&src, &dst))).unwrap())
        }
        "local_undo" => {
            let name = positional(0).unwrap_or_else(|| {
                eprintln!("usage: api local_undo <target> [--to DIR] [--force]");
                std::process::exit(2);
            });
            let force = args.iter().any(|a| a == "--force");
            print(serde_json::to_value(run!(app.local_undo(&name, force))).unwrap())
        }
        _ => {
            eprintln!(
                "usage: moveit-harness api <welcome_start|pair_show_code|pair_enter_code|use_pipe|preview_counts|move_start|home_state|undo_last|browser_open_check|local_browsers|local_preview|local_move|local_open_check|local_undo> [--state DIR] [--device NAME] [--browser NAME] [--profile DIR] [--from DIR] [--to DIR] [--force] [arg]"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applied_stats_count_only_cookies_that_moved() {
        let mut applied = Applied::default();
        applied.cookies.imported = 2;
        applied.cookies.kept_newer = 7;
        assert_eq!(stats_from_applied(&applied)["cookies"], 2);
    }

    #[test]
    fn mutations_require_explicit_scratch_profiles() {
        for args in [
            vec!["api", "move_start"],
            vec!["api", "local_move", "brave", "chrome"],
            vec!["api", "local_move", "brave", "chrome", "--from", "/"],
        ] {
            let args: Vec<String> = args.into_iter().map(String::from).collect();
            assert!(matches!(require_api_profiles(&args), Err(Error::Refused(_))));
        }
        let t = tempfile::tempdir().unwrap();
        let args = ["api", "local_move", "brave", "chrome", "--from", t.path().to_str().unwrap(), "--to", t.path().to_str().unwrap()];
        assert!(require_api_profiles(&args.map(String::from)).is_ok());
        assert!(require_scratch_dir(&std::env::temp_dir(), false).is_err());
        #[cfg(unix)]
        {
            let link = t.path().join("escape");
            std::os::unix::fs::symlink("/", &link).unwrap();
            assert!(require_scratch_dir(&link, false).is_err());
        }
    }

    #[test]
    fn real_dir_targets_need_the_opt_in_flag() {
        // The crate dir is a real directory outside the system temp folder.
        let here = std::env::current_dir().unwrap();
        assert!(require_scratch_dir(&here, false).is_err());
        assert!(require_scratch_dir(&here, true).is_ok());
        // Missing and non-directory paths refuse even with the flag.
        assert!(require_scratch_dir(&here.join("no-such-dir"), true).is_err());
        assert!(require_scratch_dir(&here.join("Cargo.toml"), true).is_err());
        let args: Vec<String> = ["api", "local_move", "brave", "chrome", "--from", here.to_str().unwrap(), "--to", here.to_str().unwrap()]
            .into_iter().map(String::from).collect();
        assert!(matches!(require_api_profiles(&args), Err(Error::Refused(_))));
        let mut args = args;
        args.push("--allow-real-dir".into());
        assert!(require_api_profiles(&args).is_ok());
    }
}
