//! The pipe: the one place both devices reach, where the sealed box (and, once, the pairing
//! note) lives. Two kinds, as the spec says:
//!
//! - **Folder** (the default for most people): any folder a sync app already keeps in step,
//!   such as Google Drive, Dropbox, iCloud, OneDrive, or a drive both systems of a dual boot
//!   can reach. Files go in a `Move It` subfolder.
//! - **Git** (advanced): a private repo cloned by the person's own git
//!   setup; Move It adds no credential handling, just fetch, fast-forward, commit, push.
//!
//! Sync apps make "conflicted copy" files when two devices write while offline. Every merge in
//! the engine gives the same result in either order, so conflicted boxes are simply read and
//! merged too, then cleared on the next push. The person never sees a conflict.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{Error, Result};

pub const BOX_FILE: &str = "moveit-box.json";
pub const FOLDER_NAME: &str = "Move It";
/// Bound every git helper call so a hung fetch/push cannot hang the app.
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const README: &str = "This folder holds Move It's sealed box: your browsers, sealed so only your own paired \
devices can open it. On its own it is useless to anyone else. Do not edit it by hand.\n";

/// Drop the userinfo from any `scheme://userinfo@host` fragment: a
/// `user:pass@` pair and a bare token (`https://TOKEN@host`) alike.
fn redact_git_full(raw: &str) -> String {
    let mut s = raw.to_string();
    let mut i = 0;
    while let Some(rel) = s[i..].find("://") {
        let start = i + rel + 3;
        let rest = &s[start..];
        let Some(at_rel) = rest.find('@') else { break };
        let slash = rest.find('/').unwrap_or(usize::MAX);
        if at_rel < slash && at_rel > 0 {
            s.replace_range(start..start + at_rel, "***");
            i = start + 3;
            continue;
        }
        i = start;
    }
    s
}

/// Cap a message for display: a git error never shows a huge dump on a
/// user-facing screen. Classification (lost race vs real refusal) always
/// reads the uncapped text first; only the reported copy is cut.
fn cap_git_msg(s: &str) -> String {
    const MAX: usize = 400;
    let count = s.chars().count();
    if count > MAX {
        format!("{}…", s.chars().take(MAX).collect::<String>())
    } else {
        s.to_string()
    }
}

fn redact_git_msg(raw: &str) -> String {
    cap_git_msg(&redact_git_full(raw))
}

/// Run a command with piped stdio, kill it if it exceeds `timeout`, and return its output.
/// Kill the child and, on unix, its whole process group: the child was
/// spawned in its own group, so a helper it started cannot outlive it.
fn kill_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pgid = child.id() as libc::pid_t;
        // SAFETY: killpg on the child's own group id; the group was made
        // for this child at spawn and holds only its helpers.
        unsafe {
            libc::killpg(pgid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

fn output_with_timeout(mut cmd: Command, timeout: Duration, label: &str) -> Result<std::process::Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::Io(format!("{label} is not available: {e}")))?;
    let mut stdout_pipe = child.stdout.take().ok_or_else(|| Error::Io(format!("{label} produced no stdout pipe")))?;
    let mut stderr_pipe = child.stderr.take().ok_or_else(|| Error::Io(format!("{label} produced no stderr pipe")))?;
    let (tx_out, rx_out) = std::sync::mpsc::channel();
    let (tx_err, rx_err) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        let _ = tx_out.send(buf);
    });
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        let _ = tx_err.send(buf);
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                kill_tree(&mut child);
                let _ = child.wait();
                return Err(Error::Io(format!("{label} timed out")));
            }
            Err(e) => return Err(Error::Io(format!("{label} failed: {e}"))),
        }
    };
    // The child has exited, but a grandchild can hold a pipe open past it:
    // the drain gets whatever time is left, never less than a short grace,
    // and then the run returns with what arrived.
    let grace = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_secs(2));
    let stdout = rx_out.recv_timeout(grace).unwrap_or_default();
    let stderr = rx_err.recv_timeout(grace).unwrap_or_default();
    Ok(std::process::Output { status, stdout, stderr })
}

pub trait Pipe {
    /// Where the box and the pairing note live, after [`Pipe::refresh`].
    fn place(&self) -> &Path;
    /// Bring the place up to date with the other device (git: fetch and fast-forward).
    fn refresh(&self) -> Result<()>;
    /// Every box to read: the main one first, then any conflicted copies.
    fn boxes(&self) -> Result<Vec<PathBuf>> {
        boxes_in(self.place())
    }
    /// Send what is in the place to the other device (git: commit and push). `note` names the device.
    fn publish(&self, note: &str) -> Result<()>;
}

/// The main box plus conflicted copies like "moveit-box (1).json" or
/// "moveit-box (conflicted copy 2026-11-02).json".
pub fn boxes_in(place: &Path) -> Result<Vec<PathBuf>> {
    let mut main = Vec::new();
    let mut extra = Vec::new();
    let rd = match std::fs::read_dir(place) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(main),
        Err(e) => return Err(Error::Io(format!("cannot read {}: {e}", place.display()))),
    };
    for e in rd {
        let e = e.map_err(|e| Error::Io(e.to_string()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name == BOX_FILE {
            main.push(e.path());
        } else if name.starts_with("moveit-box") && name.ends_with(".json") && !name.contains("tmp-moveit") {
            extra.push(e.path());
        }
    }
    extra.sort();
    main.extend(extra);
    Ok(main)
}

/// True for the names sync apps give a conflicted copy of the main box
/// ("moveit-box (1).json", "moveit-box (conflicted copy 2026-11-02).json").
/// Named per-profile boxes ("moveit-box-brave-default.json") are NOT conflicts:
/// they are live boxes other profiles still travel in.
fn is_conflict_copy(name: &str) -> bool {
    name.starts_with("moveit-box (") || name.contains("conflicted copy")
}

/// After a successful push of a merged box, clear the conflicted copies it absorbed.
/// Only the sync apps' conflict names go; per-profile boxes are left alone.
pub fn clear_conflicts(place: &Path) -> Result<usize> {
    let mut n = 0;
    for p in boxes_in(place)? {
        let is_conflict = p
            .file_name()
            .is_some_and(|f| f != BOX_FILE && is_conflict_copy(&f.to_string_lossy()));
        if is_conflict && std::fs::remove_file(&p).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

/// Write the box: temp file then rename, so the sync app never uploads half a box.
pub fn write_box_bytes(place: &Path, bytes: &[u8]) -> Result<()> {
    write_named_box(place, BOX_FILE, bytes).map(|_| ())
}

/// Write one named box file (a per-profile box next to the main one), same
/// temp-then-rename discipline. Returns true when the bytes on disk changed.
fn validate_box_file_name(name: &str) -> Result<()> {
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(Error::Refused("box file name is not allowed".into()));
    }
    if name == BOX_FILE || is_conflict_copy(name) || is_profile_box(name) {
        return Ok(());
    }
    Err(Error::Refused("box file name is not allowed".into()))
}

pub fn write_named_box(place: &Path, name: &str, bytes: &[u8]) -> Result<bool> {
    validate_box_file_name(name)?;
    std::fs::create_dir_all(place).map_err(|e| Error::Io(e.to_string()))?;
    let target = place.join(name);
    if std::fs::read(&target).is_ok_and(|old| old == bytes) {
        return Ok(false);
    }
    let tmp = place.join(format!("{name}.tmp-moveit"));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| Error::Io(e.to_string()))?;
        f.write_all(bytes).map_err(|e| Error::Io(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    }
    std::fs::rename(&tmp, &target).map_err(|e| Error::Io(e.to_string()))?;
    #[cfg(unix)]
    if let Ok(f) = std::fs::File::open(place) {
        let _ = f.sync_all();
    }
    let readme = place.join("README.txt");
    if !readme.exists() {
        let _ = std::fs::write(readme, README);
    }
    Ok(true)
}

/// The box file name one source profile travels in (the main box is the working
/// profile's; every other profile gets its own named file).
pub fn profile_box_name(browser: &str, slot_slug: &str) -> String {
    format!("moveit-box-{browser}-{slot_slug}.json")
}

/// True for a per-profile box file name (as opposed to the main box or a
/// sync app's conflicted copy of it).
pub fn is_profile_box(name: &str) -> bool {
    name.starts_with("moveit-box-") && name.ends_with(".json") && !name.contains("tmp-moveit")
}

pub struct FolderPipe {
    place: PathBuf,
}

impl FolderPipe {
    /// `chosen` is the folder the person picked; Move It works in its own subfolder.
    pub fn new(chosen: &Path) -> Result<FolderPipe> {
        if !chosen.is_dir() {
            return Err(Error::Refused(format!("{} is not a folder this device can reach", chosen.display())));
        }
        let place = chosen.join(FOLDER_NAME);
        std::fs::create_dir_all(&place).map_err(|e| Error::Io(e.to_string()))?;
        Ok(FolderPipe { place })
    }
}

impl Pipe for FolderPipe {
    fn place(&self) -> &Path {
        &self.place
    }
    fn refresh(&self) -> Result<()> {
        Ok(())
    }
    fn publish(&self, _note: &str) -> Result<()> {
        Ok(())
    }
}

pub struct GitPipe {
    repo: PathBuf,
}

impl GitPipe {
    pub fn new(repo: &Path) -> Result<GitPipe> {
        if !repo.join(".git").exists() {
            return Err(Error::Refused(format!(
                "{} is not a git clone; clone your private repo there first",
                repo.display()
            )));
        }
        Ok(GitPipe { repo: repo.to_path_buf() })
    }

    fn git(&self, args: &[&str]) -> Result<String> {
        self.git_classified(args)
            .map_err(|e| match e {
                Error::Io(m) => Error::Io(cap_git_msg(&m)),
                other => other,
            })
    }

    /// Like [`Pipe::git`], but the error keeps the full (redacted) stderr:
    /// a caller classifying the failure reads all of it, not a cut copy.
    fn git_classified(&self, args: &[&str]) -> Result<String> {
        let label = format!("git {}", args.first().copied().unwrap_or("command"));
        let mut cmd = Command::new("git");
        cmd.arg("-C")
            .arg(&self.repo)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C")
            .stdin(Stdio::null());
        let out = output_with_timeout(cmd, GIT_TIMEOUT, &label)?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
            return Err(Error::Io(format!("{label} failed: {}", redact_git_full(msg.trim()))));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn branch(&self) -> Result<String> {
        self.git(&["symbolic-ref", "--short", "HEAD"])
    }

    fn has_remote_branch(&self, b: &str) -> bool {
        self.git(&["rev-parse", "--verify", "--quiet", &format!("refs/remotes/origin/{b}")]).is_ok()
    }
}

impl Pipe for GitPipe {
    fn place(&self) -> &Path {
        &self.repo
    }

    /// Fetch and take the other device's state. The box is rebuilt from the browsers after this,
    /// so discarding our local box is fine; but a pairing note (from `pairing::offer`/`accept`)
    /// may be committed and not yet pushed, and resetting would drop it. So we carry the pairing
    /// files across the reset by hand. This avoids a rebase conflict on the box across retries.
    fn refresh(&self) -> Result<()> {
        self.git(&["fetch", "origin"])?;
        let b = self.branch()?;
        if !self.has_remote_branch(&b) {
            return Ok(());
        }
        let saved: Vec<(&str, Vec<u8>)> = [crate::pairing::OFFER_FILE, crate::pairing::PAIRED_FILE]
            .iter()
            .filter_map(|f| std::fs::read(self.repo.join(f)).ok().map(|d| (*f, d)))
            .collect();
        self.git(&["reset", "--hard", &format!("origin/{b}")])?;
        for (f, d) in saved {
            std::fs::write(self.repo.join(f), d).map_err(|e| Error::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// Commit the Move It files and push. A push that loses a race returns Error::Busy so the
    /// caller runs one more round (refresh, merge, publish).
    fn publish(&self, note: &str) -> Result<()> {
        // Stage exactly the Move It files that exist (the box, pairing notes, README), never the
        // half-written tmp file and nothing else in the repo. An explicit pathspec that matches
        // nothing makes `git add` error, so only name files that are actually present.
        let mut staged = false;
        for entry in std::fs::read_dir(&self.repo).map_err(|e| Error::Io(e.to_string()))?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let ours = name == "README.txt" || (name.starts_with("moveit-") && !name.ends_with(".tmp-moveit"));
            if ours {
                self.git(&["add", "--", &name])?;
                staged = true;
            }
        }
        // Also stage deletions of tracked Move It files that are now gone (cleared conflicts,
        // including sync-app copies like "moveit-box (1).json"). A bare name only caught the box.
        self.git(&["add", "-A", "--", "moveit-*"]).ok();
        if !staged || self.git(&["diff", "--cached", "--quiet"]).is_ok() {
            return Ok(());
        }
        self.git(&["commit", "-q", "-m", &format!("Move It: sync from {note}")])?;
        let b = self.branch()?;
        match self.git_classified(&["push", "origin", &format!("HEAD:{b}")]) {
            Ok(_) => Ok(()),
            // A LOST RACE (someone pushed first) is the only case we retry as Busy. A push the
            // remote actively refuses (protected branch, hook, push protection) is a real error
            // and must surface, not loop: those say "[remote rejected]" / "declined", while a
            // race says non-fast-forward / fetch first.
            Err(Error::Io(m))
                if (m.contains("non-fast-forward") || m.contains("fetch first"))
                    && !m.contains("[remote rejected]")
                    && !m.contains("declined") =>
            {
                Err(Error::Busy)
            }
            Err(Error::Io(m)) => Err(Error::Io(cap_git_msg(&m))),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_errors_hide_credentials_and_stay_short() {
        let raw = "fatal: could not read from remote repository.\nhttps://alice:s3cret@github.com/o/r.git non-fast-forward";
        let clean = redact_git_msg(raw);
        assert!(!clean.contains("s3cret"), "password must not appear");
        assert!(!clean.contains("alice:"), "user:pass form must not appear");
        assert!(clean.contains("***@github.com"), "host kept so the error is still useful");
        assert!(clean.contains("non-fast-forward"), "busy detection phrases must survive");
        let long = "x".repeat(1000);
        assert!(redact_git_msg(&long).chars().count() <= 401);
    }

    #[cfg(unix)]
    #[test]
    fn hung_helper_is_killed_and_returns_a_clean_error() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let err = output_with_timeout(cmd, Duration::from_millis(200), "sleep").unwrap_err();
        assert!(matches!(err, Error::Io(ref m) if m.contains("timed out")), "{err:?}");
    }

    #[test]
    fn conflicted_copies_are_found_and_cleared() {
        let t = tempfile::tempdir().unwrap();
        let p = FolderPipe::new(t.path()).unwrap();
        write_box_bytes(p.place(), b"main").unwrap();
        std::fs::write(p.place().join("moveit-box (1).json"), b"a").unwrap();
        std::fs::write(p.place().join("moveit-box (conflicted copy).json"), b"b").unwrap();
        std::fs::write(p.place().join("unrelated.json"), b"c").unwrap();
        let found = p.boxes().unwrap();
        assert_eq!(found.len(), 3);
        assert!(found[0].ends_with(BOX_FILE), "main box first");
        assert_eq!(clear_conflicts(p.place()).unwrap(), 2);
        assert_eq!(p.boxes().unwrap().len(), 1);
        assert!(p.place().join("unrelated.json").exists());
        assert!(p.place().join("README.txt").exists());
    }

    #[test]
    fn folder_must_exist() {
        assert!(FolderPipe::new(Path::new("/nonexistent/moveit-test")).is_err());
    }

    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    #[test]
    fn git_pipe_round_trip_and_lost_race() {
        let t = tempfile::tempdir().unwrap();
        let origin = t.path().join("origin.git");
        std::fs::create_dir(&origin).unwrap();
        git(&origin, &["init", "-q", "--bare", "-b", "main"]);
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        for d in [&a, &b] {
            git(t.path(), &["clone", "-q", origin.to_str().unwrap(), d.to_str().unwrap()]);
            git(d, &["config", "user.name", "t"]);
            git(d, &["config", "user.email", "t@t"]);
            git(d, &["checkout", "-q", "-b", "main"]);
        }
        let pa = GitPipe::new(&a).unwrap();
        let pb = GitPipe::new(&b).unwrap();
        pa.refresh().unwrap();
        write_box_bytes(pa.place(), b"from a").unwrap();
        pa.publish("a").unwrap();
        // b has not refreshed: its push loses the race and says Busy.
        write_box_bytes(pb.place(), b"from b").unwrap();
        assert_eq!(pb.publish("b").unwrap_err(), Error::Busy);
        // Next round: refresh takes a's box, b merges, writes, publishes.
        pb.refresh().unwrap();
        assert_eq!(std::fs::read(pb.place().join(BOX_FILE)).unwrap(), b"from a");
        write_box_bytes(pb.place(), b"merged").unwrap();
        pb.publish("b").unwrap();
        pa.refresh().unwrap();
        assert_eq!(std::fs::read(pa.place().join(BOX_FILE)).unwrap(), b"merged");
    }

    #[test]
    fn refresh_keeps_an_unpushed_pairing_note() {
        let t = tempfile::tempdir().unwrap();
        let origin = t.path().join("origin.git");
        std::fs::create_dir(&origin).unwrap();
        git(&origin, &["init", "-q", "--bare", "-b", "main"]);
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        for d in [&a, &b] {
            git(t.path(), &["clone", "-q", origin.to_str().unwrap(), d.to_str().unwrap()]);
            git(d, &["config", "user.name", "t"]);
            git(d, &["config", "user.email", "t@t"]);
            git(d, &["checkout", "-q", "-b", "main"]);
        }
        let (pa, pb) = (GitPipe::new(&a).unwrap(), GitPipe::new(&b).unwrap());
        // A publishes a box first.
        write_box_bytes(pa.place(), b"box from a").unwrap();
        pa.publish("a").unwrap();
        // B writes a pairing note and publishes; it loses the race.
        std::fs::write(b.join("moveit-paired.json"), b"B has paired").unwrap();
        assert_eq!(pb.publish("b").unwrap_err(), Error::Busy);
        // The old behaviour (reset --hard) would delete the note here. It must survive.
        pb.refresh().unwrap();
        assert_eq!(std::fs::read(b.join("moveit-paired.json")).unwrap(), b"B has paired", "pairing note kept");
        assert_eq!(std::fs::read(b.join(BOX_FILE)).unwrap(), b"box from a", "and A's box arrived");
        pb.publish("b").unwrap();
        pa.refresh().unwrap();
        assert!(a.join("moveit-paired.json").exists(), "A now sees the pairing note");
    }
}
