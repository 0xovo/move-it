//! Where each store lives inside a Chromium profile folder.
//!
//! A browser folder (the root) holds one folder per profile: `Default`, `Profile 1`,
//! and so on. Those folder names are the slots. The plain functions are the `Default`
//! slot, the shape this engine started with; the `_in` functions name the slot.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

pub const DEFAULT_SLOT: &str = "Default";

/// The slot name of a SingleProfile browser's one profile (see
/// `crate::browsers::LayoutKind`): the browser folder itself is the
/// profile, so this slot's folder is the root, not a folder inside it.
/// No real Chromium profile folder is ever named this.
pub const SINGLE_SLOT: &str = "Single";

/// The folder one profile lives in, inside its browser's folder.
/// For [`SINGLE_SLOT`] the root itself is the profile folder.
pub fn slot_dir(root: &Path, slot: &str) -> PathBuf {
    if slot == SINGLE_SLOT {
        return root.to_path_buf();
    }
    root.join(slot)
}

/// The folder one profile lives in, under a layout: for a Standard root
/// the named slot folder, for a SingleProfile root the root itself.
pub fn profile_dir(root: &Path, slot: &str, layout: crate::browsers::LayoutKind) -> PathBuf {
    match layout {
        crate::browsers::LayoutKind::SingleProfile => root.to_path_buf(),
        crate::browsers::LayoutKind::Standard => slot_dir(root, slot),
    }
}

/// Refuse when writing to `dest` would land outside `root`.
///
/// Every component strictly between `root` and `dest` is inspected as it is,
/// never through a link: if any of them is a symbolic link, the write lands
/// wherever the link points, in a profile (or a whole browser folder) that
/// was never picked, never checked for a running browser and never
/// snapshotted. Components that do not exist yet cannot be links, and the
/// deepest one that does exist is compared resolved against the resolved
/// root, so a `..` folded into `dest` cannot climb out either. `root`
/// itself is the boundary and is not inspected: a browser folder reached
/// through a link of the user's own choosing is still theirs to move.
pub fn check_contained(root: &Path, dest: &Path) -> Result<()> {
    let outside = || {
        Error::Refused(format!(
            "{} is outside the profile folder {}; Move It will not write there",
            dest.display(),
            root.display()
        ))
    };
    if !dest.starts_with(root) {
        return Err(outside());
    }
    let mut deepest: Option<PathBuf> = None;
    let mut cur = dest.to_path_buf();
    while cur != root {
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(Error::Refused(format!(
                    "{} is a symbolic link; Move It never follows links",
                    cur.display()
                )));
            }
            Ok(_) => {
                if deepest.is_none() {
                    deepest = Some(cur.clone());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(format!("cannot inspect {}: {e}", cur.display()))),
        }
        cur = match cur.parent() {
            Some(p) => p.to_path_buf(),
            None => return Err(outside()),
        };
    }
    // The walk sees each component as it is, but a `..` only shows its hand
    // once resolved: compare the deepest existing part against the root,
    // both resolved, as the last word.
    if let Some(deepest) = deepest {
        let root_real = match std::fs::canonicalize(root) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::Io(format!("cannot inspect {}: {e}", root.display()))),
        };
        let dest_real = std::fs::canonicalize(&deepest)
            .map_err(|e| Error::Io(format!("cannot inspect {}: {e}", deepest.display())))?;
        if !dest_real.starts_with(&root_real) {
            return Err(Error::Refused(format!(
                "{} resolves outside the profile folder {}; Move It will not write there",
                dest.display(),
                root.display()
            )));
        }
    }
    Ok(())
}

/// Cookies moved to a slot's `Network/Cookies` in newer builds; older keep `Cookies`
/// directly in the slot. Returns the one that exists, else the modern location
/// (for a profile not yet created).
pub fn cookies(profile: &Path) -> PathBuf {
    cookies_in(profile, DEFAULT_SLOT)
}

pub fn cookies_in(root: &Path, slot: &str) -> PathBuf {
    let dir = slot_dir(root, slot);
    let modern = dir.join("Network").join("Cookies");
    let legacy = dir.join("Cookies");
    // Both can exist: a profile copied from another machine (or an old browser
    // version) leaves a dead store behind next to the live one. The browser
    // writes the live one, so the newer file wins.
    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(&modern), mtime(&legacy)) {
        (Some(m), Some(l)) if l > m => legacy,
        (Some(_), _) => modern,
        (None, Some(_)) => legacy,
        (None, None) => modern,
    }
}

/// True when this profile slot has never been launched: neither a cookie store
/// (modern `Network/Cookies` or legacy `Cookies`) nor `Login Data` exists.
/// Does not create or prefer a path the way [`cookies_in`] does — existence
/// only. Same relative layout on Linux, macOS, and Windows.
pub fn never_launched(root: &Path, slot: &str) -> bool {
    let dir = slot_dir(root, slot);
    !dir.join("Network").join("Cookies").exists()
        && !dir.join("Cookies").exists()
        && !dir.join("Login Data").exists()
}

pub fn history(profile: &Path) -> PathBuf {
    history_in(profile, DEFAULT_SLOT)
}

pub fn history_in(root: &Path, slot: &str) -> PathBuf {
    slot_dir(root, slot).join("History")
}

pub fn login_data(profile: &Path) -> PathBuf {
    login_data_in(profile, DEFAULT_SLOT)
}

pub fn login_data_in(root: &Path, slot: &str) -> PathBuf {
    slot_dir(root, slot).join("Login Data")
}

pub fn bookmarks(profile: &Path) -> PathBuf {
    bookmarks_in(profile, DEFAULT_SLOT)
}

pub fn bookmarks_in(root: &Path, slot: &str) -> PathBuf {
    slot_dir(root, slot).join("Bookmarks")
}

pub fn local_state(profile: &Path) -> PathBuf {
    profile.join("Local State")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chromium keeps the same relative store names under a profile dir on
    /// Linux, macOS, and Windows. Windows is exercised here via an explicit
    /// profile dir fixture (no live Windows path discovery required).
    #[test]
    fn never_launched_path_shapes_across_oses() {
        let t = tempfile::tempdir().unwrap();
        for os_root in ["linux-config", "mac-app-support", "windows-local-appdata"] {
            let root = t.path().join(os_root).join("Browser");
            let slot = "Default";
            std::fs::create_dir_all(slot_dir(&root, slot)).unwrap();
            assert!(never_launched(&root, slot), "{os_root}: empty Default");

            std::fs::write(slot_dir(&root, slot).join("Preferences"), b"{}").unwrap();
            assert!(never_launched(&root, slot), "{os_root}: prefs alone");

            let modern = slot_dir(&root, slot).join("Network").join("Cookies");
            std::fs::create_dir_all(modern.parent().unwrap()).unwrap();
            std::fs::write(&modern, b"x").unwrap();
            assert!(!never_launched(&root, slot), "{os_root}: modern Cookies");
            std::fs::remove_file(&modern).unwrap();

            let legacy = slot_dir(&root, slot).join("Cookies");
            std::fs::write(&legacy, b"x").unwrap();
            assert!(!never_launched(&root, slot), "{os_root}: legacy Cookies");
            std::fs::remove_file(&legacy).unwrap();

            let logins = slot_dir(&root, slot).join("Login Data");
            std::fs::write(&logins, b"x").unwrap();
            assert!(!never_launched(&root, slot), "{os_root}: Login Data");
        }
    }

    #[test]
    fn contained_paths_pass_and_outside_paths_refuse() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("browser");
        std::fs::create_dir_all(root.join("Default/Network")).unwrap();
        check_contained(&root, &root.join("Default/Network/Cookies")).unwrap();
        check_contained(&root, &root.join("Default/Not Yet Created/deep/file")).unwrap();
        check_contained(&root, &root).unwrap();
        assert!(matches!(check_contained(&root, &t.path().join("elsewhere")), Err(Error::Refused(_))));
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_ancestor_is_refused() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("browser");
        let other = t.path().join("other-profile");
        std::fs::create_dir_all(other.join("Extensions")).unwrap();
        std::fs::create_dir_all(root.join("Default")).unwrap();
        symlink(other.join("Extensions"), root.join("Default/Extensions")).unwrap();
        let dest = root.join("Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0_0/manifest.json");
        assert!(matches!(check_contained(&root, &dest), Err(Error::Refused(_))), "linked ancestor");
        assert!(matches!(check_contained(&root, &root.join("Default/Extensions")), Err(Error::Refused(_))), "the link itself");
        // A linked slot folder redirects the whole profile the same way.
        let root2 = t.path().join("browser2");
        std::fs::create_dir_all(&root2).unwrap();
        symlink(&other, root2.join("Default")).unwrap();
        assert!(matches!(check_contained(&root2, &root2.join("Default/Cookies")), Err(Error::Refused(_))), "linked slot");
    }

    #[cfg(unix)]
    #[test]
    fn a_root_reached_through_a_link_still_passes() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real-browser");
        std::fs::create_dir_all(real.join("Default")).unwrap();
        let alias = t.path().join("alias-browser");
        symlink(&real, &alias).unwrap();
        check_contained(&alias, &alias.join("Default/Cookies")).unwrap();
    }

    #[test]
    fn a_folded_dotdot_escape_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("browser");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir_all(t.path().join("outside")).unwrap();
        let dest = root.join("a/../../outside/file");
        assert!(matches!(check_contained(&root, &dest), Err(Error::Refused(_))));
    }

    #[test]
    fn newer_cookie_store_wins_when_both_exist() {
        let t = tempfile::tempdir().unwrap();
        let slot = t.path().join(DEFAULT_SLOT);
        std::fs::create_dir_all(slot.join("Network")).unwrap();
        let modern = slot.join("Network").join("Cookies");
        let legacy = slot.join("Cookies");
        std::fs::write(&modern, b"old").unwrap();
        std::fs::write(&legacy, b"live").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400 * 100);
        std::fs::File::options().write(true).open(&modern).unwrap().set_modified(old).unwrap();
        assert_eq!(cookies_in(t.path(), DEFAULT_SLOT), legacy);
        std::fs::File::options().write(true).open(&legacy).unwrap().set_modified(old - std::time::Duration::from_secs(60)).unwrap();
        assert_eq!(cookies_in(t.path(), DEFAULT_SLOT), modern);
    }
}
