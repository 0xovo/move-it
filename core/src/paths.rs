//! Where each store lives inside a Chromium profile folder.

use std::path::{Path, PathBuf};

fn default(profile: &Path) -> PathBuf {
    profile.join("Default")
}

/// Cookies moved to `Default/Network/Cookies` in newer builds; older keep `Default/Cookies`.
/// Returns the one that exists, else the modern location (for a profile not yet created).
pub fn cookies(profile: &Path) -> PathBuf {
    let modern = default(profile).join("Network").join("Cookies");
    let legacy = default(profile).join("Cookies");
    if modern.exists() {
        modern
    } else if legacy.exists() {
        legacy
    } else {
        modern
    }
}

pub fn history(profile: &Path) -> PathBuf {
    default(profile).join("History")
}

pub fn login_data(profile: &Path) -> PathBuf {
    default(profile).join("Login Data")
}

pub fn bookmarks(profile: &Path) -> PathBuf {
    default(profile).join("Bookmarks")
}

pub fn local_state(profile: &Path) -> PathBuf {
    profile.join("Local State")
}
