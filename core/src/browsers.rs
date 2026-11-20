//! The one table of Chromium-family browsers Move It knows.
//!
//! Before this module, browser knowledge was scattered: `oscrypt` carried a
//! `LinuxBrowser` and a `MacBrowser` enum with the keyring / Keychain names,
//! `profiles` carried the per-OS folder tables and the listing order, and
//! `api` carried its own display-name and folder maps. Every fact about one
//! browser now lives in exactly one [`BrowserDef`] row here: discovery
//! (`profiles`), secret lookup (`oscrypt`) and the app surface (`api`) all
//! read from this table, so adding a browser is adding a row.
//!
//! Channel builds (Chrome Beta, Brave Nightly, ...) are rows built by the
//! [`channel`] constructor from their stable browser's row: they copy the
//! stable browser's secret names and App-Bound flag and differ only in id,
//! display name and folder names. There are no hand-written per-channel
//! copies of the secret logic anywhere.

use crate::oscrypt::Platform;

/// How a browser lays its profiles out on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    /// The user-data folder is a root holding one folder per profile
    /// (`Default`, `Profile 1`, ...) plus a `Local State` file at the root.
    Standard,
    /// The user-data folder *is* the profile: stores and `Local State` sit
    /// directly inside it and there is exactly one profile. The one slot
    /// such a root has is [`crate::paths::SINGLE_SLOT`].
    SingleProfile,
}

/// Everything Move It knows about one browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserDef {
    /// Short name the engine knows: `brave`, `chrome-beta`, `opera-gx`, ...
    pub id: &'static str,
    /// The name a person calls it: `Brave`, `Google Chrome Beta`, ...
    pub display: &'static str,
    /// Folder under the Linux config base (`$XDG_CONFIG_HOME` or `~/.config`).
    pub linux_dir: Option<&'static str>,
    /// Folder under `~/Library/Application Support` on macOS.
    pub mac_dir: Option<&'static str>,
    /// Folder under `%LOCALAPPDATA%` on Windows (the user-data root for a
    /// Standard browser; unused for SingleProfile, which is roaming).
    pub win_local_dir: Option<&'static str>,
    /// Folder under `%APPDATA%` (roaming) on Windows. Only the Opera family
    /// lives here, and for it this folder is the profile itself.
    pub win_roaming_dir: Option<&'static str>,
    pub layout: LayoutKind,
    /// macOS Keychain service names for the Safe Storage item, in probe
    /// order. Almost every browser has exactly one; Opera GX has two
    /// because the sources conflict (see its row).
    pub mac_services: &'static [&'static str],
    /// macOS Keychain account of the Safe Storage item.
    pub mac_account: &'static str,
    /// Linux Secret Service labels of the Safe Storage item, in probe
    /// order. Almost every browser has exactly one; Opera (and GX) carry
    /// two because Opera's own historical label and the Chromium label it
    /// aliases on Linux are both live candidates (see the Opera row).
    pub linux_labels: &'static [&'static str],
    /// Linux Secret Service `application` attribute values, in probe order.
    /// The first is the browser's own; later entries are the aliased stable
    /// browser's, tried when the browser kept the stable browser's item.
    pub linux_apps: &'static [&'static str],
    /// The stable browser this channel build aliases for secrets, when this
    /// row is a channel build. The secret fields above are copies of that
    /// browser's, made by [`channel`]; this field records the alias itself.
    pub secret_of: Option<&'static str>,
    /// The stable browser this row is a channel build of, if any.
    pub channel_of: Option<&'static str>,
    /// Whether this browser seals new Windows values with App-Bound
    /// Encryption (`v20`), which Move It refuses by design.
    pub app_bound: bool,
    /// Flatpak app ids that install this browser, and the folder under the
    /// app's `config/` each uses. Chromium carries two ids: its own and
    /// Ungoogled Chromium's, which is indistinguishable on disk.
    pub flatpak: Option<(&'static [&'static str], &'static str)>,
}

impl BrowserDef {
    /// The row whose secrets this browser uses: itself, or the stable
    /// browser for a channel build.
    pub fn secret_def(&self) -> &'static BrowserDef {
        // Resolved through the table (not by returning `self`) so the
        // result is the 'static row even when `self` is a borrowed copy.
        by_id(self.secret_of.unwrap_or(self.id)).expect("every def is a registry row")
    }

    /// Whether a folder at the user-data location actually holds this
    /// browser's profile data. Standard: a `Default` profile folder.
    /// SingleProfile: the folder itself carries profile markers.
    pub fn present_at(&self, dir: &std::path::Path) -> bool {
        match self.layout {
            LayoutKind::Standard => dir.join("Default").is_dir(),
            LayoutKind::SingleProfile => has_single_profile_markers(dir),
        }
    }
}

/// Profile markers for a SingleProfile folder: the files a launched profile
/// keeps at its own root. Any one of them says the folder is a profile.
pub fn has_single_profile_markers(dir: &std::path::Path) -> bool {
    dir.join("Preferences").is_file()
        || dir.join("History").is_file()
        || dir.join("Login Data").is_file()
        || dir.join("Cookies").is_file()
        || dir.join("Network").join("Cookies").is_file()
}

/// Build a channel build's row from its stable browser's row: same secret
/// names, same App-Bound flag, new id / display / folders.
const fn channel(
    base: &BrowserDef,
    id: &'static str,
    display: &'static str,
    linux_dir: &'static str,
    mac_dir: &'static str,
    win_local_dir: &'static str,
) -> BrowserDef {
    BrowserDef {
        id,
        display,
        linux_dir: Some(linux_dir),
        mac_dir: Some(mac_dir),
        win_local_dir: Some(win_local_dir),
        win_roaming_dir: None,
        layout: LayoutKind::Standard,
        mac_services: base.mac_services,
        mac_account: base.mac_account,
        linux_labels: base.linux_labels,
        linux_apps: base.linux_apps,
        secret_of: Some(base.id),
        channel_of: Some(base.id),
        app_bound: base.app_bound,
        flatpak: None,
    }
}

pub const BRAVE: BrowserDef = BrowserDef {
    id: "brave",
    display: "Brave",
    linux_dir: Some("BraveSoftware/Brave-Browser"),
    mac_dir: Some("BraveSoftware/Brave-Browser"),
    win_local_dir: Some("BraveSoftware/Brave-Browser/User Data"),
    win_roaming_dir: None,
    layout: LayoutKind::Standard,
    mac_services: &["Brave Safe Storage"],
    mac_account: "Brave",
    linux_labels: &["Brave Safe Storage"],
    linux_apps: &["brave"],
    secret_of: None,
    channel_of: None,
    app_bound: true,
    flatpak: Some((&["com.brave.Browser"], "BraveSoftware/Brave-Browser")),
};

pub const CHROME: BrowserDef = BrowserDef {
    id: "chrome",
    display: "Google Chrome",
    linux_dir: Some("google-chrome"),
    mac_dir: Some("Google/Chrome"),
    win_local_dir: Some("Google/Chrome/User Data"),
    win_roaming_dir: None,
    layout: LayoutKind::Standard,
    mac_services: &["Chrome Safe Storage"],
    mac_account: "Chrome",
    linux_labels: &["Chrome Safe Storage"],
    linux_apps: &["chrome"],
    secret_of: None,
    channel_of: None,
    app_bound: true,
    flatpak: Some((&["com.google.Chrome"], "google-chrome")),
};

pub const CHROMIUM: BrowserDef = BrowserDef {
    id: "chromium",
    display: "Chromium",
    linux_dir: Some("chromium"),
    mac_dir: Some("Chromium"),
    win_local_dir: Some("Chromium/User Data"),
    win_roaming_dir: None,
    layout: LayoutKind::Standard,
    mac_services: &["Chromium Safe Storage"],
    mac_account: "Chromium",
    linux_labels: &["Chromium Safe Storage"],
    linux_apps: &["chromium"],
    secret_of: None,
    channel_of: None,
    app_bound: false,
    flatpak: Some((
        &["org.chromium.Chromium", "io.github.ungoogled_software.ungoogled_chromium"],
        "chromium",
    )),
};

pub const EDGE: BrowserDef = BrowserDef {
    id: "edge",
    display: "Microsoft Edge",
    linux_dir: Some("microsoft-edge"),
    mac_dir: Some("Microsoft Edge"),
    win_local_dir: Some("Microsoft/Edge/User Data"),
    win_roaming_dir: None,
    layout: LayoutKind::Standard,
    mac_services: &["Microsoft Edge Safe Storage"],
    mac_account: "Microsoft Edge",
    linux_labels: &["Microsoft Edge Safe Storage"],
    // Edge brands the libsecret item with the product name, not "edge".
    linux_apps: &["Microsoft Edge"],
    secret_of: None,
    channel_of: None,
    app_bound: true,
    flatpak: Some((&["com.microsoft.Edge"], "microsoft-edge")),
};

pub const OPERA: BrowserDef = BrowserDef {
    id: "opera",
    display: "Opera",
    linux_dir: Some("opera"),
    mac_dir: Some("com.operasoftware.Opera"),
    win_local_dir: None,
    // Roaming, not Local, and the folder is the profile itself.
    win_roaming_dir: Some("Opera Software/Opera Stable"),
    layout: LayoutKind::SingleProfile,
    mac_services: &["Opera Safe Storage"],
    mac_account: "Opera",
    // On Linux Opera's Safe Storage item has been seen under both its own
    // label (the pre-registry code's only label) and Chromium's, which the
    // census says real Opera aliases. Probe both, its own first; the
    // application attribute chain below works the same way.
    linux_labels: &["Opera Safe Storage", "Chromium Safe Storage"],
    linux_apps: &["Opera", "chromium"],
    secret_of: None,
    channel_of: None,
    app_bound: false,
    flatpak: Some((&["com.opera.Opera"], "opera")),
};

pub const VIVALDI: BrowserDef = BrowserDef {
    id: "vivaldi",
    display: "Vivaldi",
    linux_dir: Some("vivaldi"),
    mac_dir: Some("Vivaldi"),
    win_local_dir: Some("Vivaldi/User Data"),
    win_roaming_dir: None,
    layout: LayoutKind::Standard,
    mac_services: &["Vivaldi Safe Storage"],
    mac_account: "Vivaldi",
    // On Linux Vivaldi aliases Chrome's keyring item: Chrome's label, and
    // the application attribute is probed vivaldi first, then chrome (the
    // aliased browser's), because the exact attribute Vivaldi stamps is
    // not firmly sourced.
    linux_labels: &["Chrome Safe Storage"],
    linux_apps: &["vivaldi", "chrome"],
    secret_of: None,
    channel_of: None,
    app_bound: false,
    flatpak: Some((&["com.vivaldi.Vivaldi"], "vivaldi")),
};

pub const OPERA_GX: BrowserDef = BrowserDef {
    id: "opera-gx",
    display: "Opera GX",
    linux_dir: Some("opera-gx"),
    mac_dir: Some("com.operasoftware.OperaGX"),
    win_local_dir: None,
    win_roaming_dir: Some("Opera Software/Opera GX Stable"),
    layout: LayoutKind::SingleProfile,
    // UNRESOLVED: sources conflict on GX's Safe Storage service. A macOS
    // analysis lists a distinct "Opera Safe Storage 2023"; HackBrowserData
    // aliases GX to Opera's item. Probe in this order and use the first
    // that answers; do not treat either name as settled.
    mac_services: &["Opera Safe Storage 2023", "Opera Safe Storage"],
    mac_account: "Opera",
    // Linux: aliased to Chromium like Opera, on the same evidence, so it
    // carries Opera's two candidate labels too; GX's own application
    // attribute is unverified, so its guessed name is probed first and
    // Opera's aliasing chain follows.
    linux_labels: &["Opera Safe Storage", "Chromium Safe Storage"],
    linux_apps: &["Opera GX", "Opera", "chromium"],
    secret_of: None,
    channel_of: None,
    app_bound: false,
    flatpak: None,
};

pub const CHROME_BETA: BrowserDef = channel(
    &CHROME,
    "chrome-beta",
    "Google Chrome Beta",
    "google-chrome-beta",
    "Google/Chrome Beta",
    "Google/Chrome Beta/User Data",
);

pub const CHROME_DEV: BrowserDef = channel(
    &CHROME,
    "chrome-dev",
    "Google Chrome Dev",
    "google-chrome-unstable",
    "Google/Chrome Dev",
    "Google/Chrome Dev/User Data",
);

pub const CHROME_CANARY: BrowserDef = channel(
    &CHROME,
    "chrome-canary",
    "Google Chrome Canary",
    // Rarely shipped on Linux; the path is listed so discovery fires if a
    // Canary install ever appears there.
    "google-chrome-canary",
    "Google/Chrome Canary",
    "Google/Chrome SxS/User Data",
);

pub const EDGE_BETA: BrowserDef = channel(
    &EDGE,
    "edge-beta",
    "Microsoft Edge Beta",
    "microsoft-edge-beta",
    "Microsoft Edge Beta",
    "Microsoft/Edge Beta/User Data",
);

pub const EDGE_DEV: BrowserDef = channel(
    &EDGE,
    "edge-dev",
    "Microsoft Edge Dev",
    "microsoft-edge-dev",
    "Microsoft Edge Dev",
    "Microsoft/Edge Dev/User Data",
);

pub const BRAVE_BETA: BrowserDef = channel(
    &BRAVE,
    "brave-beta",
    "Brave Beta",
    "BraveSoftware/Brave-Browser-Beta",
    "BraveSoftware/Brave-Browser-Beta",
    "BraveSoftware/Brave-Browser-Beta/User Data",
);

pub const BRAVE_NIGHTLY: BrowserDef = channel(
    &BRAVE,
    "brave-nightly",
    "Brave Nightly",
    "BraveSoftware/Brave-Browser-Nightly",
    "BraveSoftware/Brave-Browser-Nightly",
    "BraveSoftware/Brave-Browser-Nightly/User Data",
);

/// Every browser in the table, in listing order: the stable browsers in
/// the order discovery has always listed them, then the new stable
/// browsers, then the channel builds and Opera GX.
pub const BROWSERS: &[&BrowserDef] = &[
    &BRAVE,
    &CHROME,
    &CHROMIUM,
    &EDGE,
    &OPERA,
    &VIVALDI,
    &CHROME_BETA,
    &CHROME_DEV,
    &CHROME_CANARY,
    &EDGE_BETA,
    &EDGE_DEV,
    &BRAVE_BETA,
    &BRAVE_NIGHTLY,
    &OPERA_GX,
];

/// The row for one browser id, when Move It knows it.
pub fn by_id(id: &str) -> Option<&'static BrowserDef> {
    BROWSERS.iter().copied().find(|d| d.id == id)
}

/// Every known browser row, in listing order.
pub fn all() -> &'static [&'static BrowserDef] {
    BROWSERS
}

/// The display name for a browser id, when known.
pub fn display_for(id: &str) -> Option<&'static str> {
    by_id(id).map(|d| d.display)
}

/// The browsers with a user-data folder on `platform`, in listing order.
/// Windows yields (def, folder, is_roaming) triples from whichever of the
/// local / roaming fields the row carries; the other platforms yield the
/// defs and read their own folder field.
pub fn defs_for_platform(platform: Platform) -> Vec<&'static BrowserDef> {
    all()
        .iter()
        .copied()
        .filter(|d| match platform {
            Platform::Linux => d.linux_dir.is_some(),
            Platform::Mac => d.mac_dir.is_some(),
            Platform::Windows => d.win_local_dir.is_some() || d.win_roaming_dir.is_some(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_is_complete() {
        for d in all() {
            assert!(!d.id.is_empty(), "id");
            assert!(!d.display.is_empty(), "{} display", d.id);
            assert!(d.linux_dir.is_some(), "{} linux path", d.id);
            assert!(d.mac_dir.is_some(), "{} mac path", d.id);
            assert!(
                d.win_local_dir.is_some() || d.win_roaming_dir.is_some(),
                "{} windows path",
                d.id
            );
            assert!(!d.mac_services.is_empty(), "{} mac service", d.id);
            assert!(!d.mac_account.is_empty(), "{} mac account", d.id);
            assert!(!d.linux_labels.is_empty(), "{} linux labels", d.id);
            assert!(d.linux_labels.iter().all(|l| !l.is_empty()), "{} linux label", d.id);
            assert!(!d.linux_apps.is_empty(), "{} linux apps", d.id);
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<&str> = all().iter().map(|d| d.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), all().len());
    }

    #[test]
    fn channels_alias_their_stable_secrets() {
        for (chan, stable) in [
            ("chrome-beta", "chrome"),
            ("chrome-dev", "chrome"),
            ("chrome-canary", "chrome"),
            ("edge-beta", "edge"),
            ("edge-dev", "edge"),
            ("brave-beta", "brave"),
            ("brave-nightly", "brave"),
        ] {
            let c = by_id(chan).unwrap();
            let s = by_id(stable).unwrap();
            assert_eq!(c.channel_of, Some(stable), "{chan}");
            assert_eq!(c.secret_def().id, stable, "{chan}");
            assert_eq!(c.mac_services, s.mac_services, "{chan} mac service");
            assert_eq!(c.mac_account, s.mac_account, "{chan} mac account");
            assert_eq!(c.linux_labels, s.linux_labels, "{chan} linux labels");
            assert_eq!(c.linux_apps, s.linux_apps, "{chan} linux apps");
            assert_eq!(c.app_bound, s.app_bound, "{chan} app-bound");
            assert_ne!(c.linux_dir, s.linux_dir, "{chan} has its own folder");
        }
        // No Edge Canary anywhere: it is out of scope by decision.
        assert!(by_id("edge-canary").is_none());
    }

    #[test]
    fn the_original_five_rows_match_the_pre_registry_facts() {
        // The refactor must not move any existing browser's facts. Every
        // field of the five pre-registry rows is pinned here against the
        // f646484 behaviour (oscrypt.rs / profiles.rs at that commit),
        // with ONE deliberate change: Opera's Linux label is now a
        // two-label probe set, its own historical "Opera Safe Storage"
        // (the f646484 label) plus the "Chromium Safe Storage" the
        // registry had switched to on census evidence.
        fn check(
            d: &BrowserDef,
            id: &str,
            display: &str,
            linux_dir: Option<&str>,
            mac_dir: Option<&str>,
            win_local: Option<&str>,
            win_roaming: Option<&str>,
            layout: LayoutKind,
            mac_services: &[&str],
            mac_account: &str,
            linux_labels: &[&str],
            linux_apps: &[&str],
            app_bound: bool,
            flatpak: Option<(&[&str], &str)>,
        ) {
            assert_eq!(d.id, id, "{id} id");
            assert_eq!(d.display, display, "{id} display");
            assert_eq!(d.linux_dir, linux_dir, "{id} linux_dir");
            assert_eq!(d.mac_dir, mac_dir, "{id} mac_dir");
            assert_eq!(d.win_local_dir, win_local, "{id} win_local_dir");
            assert_eq!(d.win_roaming_dir, win_roaming, "{id} win_roaming_dir");
            assert_eq!(d.layout, layout, "{id} layout");
            assert_eq!(d.mac_services, mac_services, "{id} mac_services");
            assert_eq!(d.mac_account, mac_account, "{id} mac_account");
            assert_eq!(d.linux_labels, linux_labels, "{id} linux_labels");
            assert_eq!(d.linux_apps, linux_apps, "{id} linux_apps");
            assert_eq!(d.secret_of, None, "{id} secret_of");
            assert_eq!(d.channel_of, None, "{id} channel_of");
            assert_eq!(d.app_bound, app_bound, "{id} app_bound");
            assert_eq!(d.flatpak, flatpak, "{id} flatpak");
        }
        check(
            &BRAVE, "brave", "Brave",
            Some("BraveSoftware/Brave-Browser"), Some("BraveSoftware/Brave-Browser"),
            Some("BraveSoftware/Brave-Browser/User Data"), None,
            LayoutKind::Standard,
            &["Brave Safe Storage"], "Brave",
            &["Brave Safe Storage"], &["brave"],
            true,
            Some((&["com.brave.Browser"] as &[&str], "BraveSoftware/Brave-Browser")),
        );
        check(
            &CHROME, "chrome", "Google Chrome",
            Some("google-chrome"), Some("Google/Chrome"),
            Some("Google/Chrome/User Data"), None,
            LayoutKind::Standard,
            &["Chrome Safe Storage"], "Chrome",
            &["Chrome Safe Storage"], &["chrome"],
            true,
            Some((&["com.google.Chrome"] as &[&str], "google-chrome")),
        );
        check(
            &CHROMIUM, "chromium", "Chromium",
            Some("chromium"), Some("Chromium"),
            Some("Chromium/User Data"), None,
            LayoutKind::Standard,
            &["Chromium Safe Storage"], "Chromium",
            &["Chromium Safe Storage"], &["chromium"],
            false,
            Some((&["org.chromium.Chromium", "io.github.ungoogled_software.ungoogled_chromium"] as &[&str], "chromium")),
        );
        check(
            &EDGE, "edge", "Microsoft Edge",
            Some("microsoft-edge"), Some("Microsoft Edge"),
            Some("Microsoft/Edge/User Data"), None,
            LayoutKind::Standard,
            &["Microsoft Edge Safe Storage"], "Microsoft Edge",
            &["Microsoft Edge Safe Storage"], &["Microsoft Edge"],
            true,
            Some((&["com.microsoft.Edge"] as &[&str], "microsoft-edge")),
        );
        check(
            &OPERA, "opera", "Opera",
            Some("opera"), Some("com.operasoftware.Opera"),
            None, Some("Opera Software/Opera Stable"),
            LayoutKind::SingleProfile,
            &["Opera Safe Storage"], "Opera",
            // Deliberate change from both ancestors: f646484 probed only
            // "Opera Safe Storage", the first registry version only
            // "Chromium Safe Storage"; the probe set is now both.
            &["Opera Safe Storage", "Chromium Safe Storage"], &["Opera", "chromium"],
            false,
            Some((&["com.opera.Opera"] as &[&str], "opera")),
        );
    }

    #[test]
    fn opera_family_is_single_profile_and_vivaldi_is_standard() {
        assert_eq!(OPERA.layout, LayoutKind::SingleProfile);
        assert_eq!(OPERA_GX.layout, LayoutKind::SingleProfile);
        assert_eq!(VIVALDI.layout, LayoutKind::Standard);
        assert_eq!(OPERA.win_roaming_dir, Some("Opera Software/Opera Stable"));
        assert_eq!(OPERA.win_local_dir, None);
    }

    #[test]
    fn opera_gx_probes_the_2023_service_first() {
        assert_eq!(
            OPERA_GX.mac_services,
            ["Opera Safe Storage 2023", "Opera Safe Storage"]
        );
    }

    #[test]
    fn vivaldi_linux_aliases_chrome_with_vivaldi_probed_first() {
        assert_eq!(VIVALDI.linux_labels, ["Chrome Safe Storage"]);
        assert_eq!(VIVALDI.linux_apps, ["vivaldi", "chrome"]);
        assert!(!VIVALDI.app_bound);
    }
}
