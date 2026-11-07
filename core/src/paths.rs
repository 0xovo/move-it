//! Where each store lives inside a Chromium profile folder.
//!
//! A browser folder (the root) holds one folder per profile: `Default`, `Profile 1`,
//! and so on. Those folder names are the slots. The plain functions are the `Default`
//! slot, the shape this engine started with; the `_in` functions name the slot.

use std::path::{Path, PathBuf};

pub const DEFAULT_SLOT: &str = "Default";

/// The folder one profile lives in, inside its browser's folder.
pub fn slot_dir(root: &Path, slot: &str) -> PathBuf {
    root.join(slot)
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
    if modern.exists() {
        modern
    } else if legacy.exists() {
        legacy
    } else {
        modern
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
}
