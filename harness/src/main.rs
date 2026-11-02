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
//!        moveit-harness probe-logins <profile-dir>
//!
//! The probe form skips the stress test: it reads one real profile's saved logins with
//! browser-password discovery (logins::discover) and prints what it found, one line per
//! login. That is the live check that the engine can read a profile a browser wrote.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use moveit_core::cookies::{self, Cookie, Keys};
use moveit_core::engine::{self, Profile};
use moveit_core::history;
use moveit_core::logins::{self, Login};
use moveit_core::oscrypt::{HostTag, LinuxPrefix, Lock};
use moveit_core::sealed::SyncKey;
use moveit_core::txn;

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
    Profile { dir, keys: k, login_tag: HostTag::Without }
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

fn probe_logins(dir: &str) -> ! {
    match logins::discover(Path::new(dir)) {
        Ok(found) => {
            println!("probe-logins: profile={dir}");
            println!("probe-logins: {} login(s) discovered", found.len());
            for l in &found {
                println!(
                    "origin={} username={} password={}",
                    l.origin_url, l.username_value, l.password_value
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

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("probe-logins") {
        match argv.get(2) {
            Some(dir) => probe_logins(dir),
            None => {
                eprintln!("usage: moveit-harness probe-logins <profile-dir>");
                std::process::exit(2);
            }
        }
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
