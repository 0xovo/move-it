//! Install extension *binaries* and registration in the target browser profile.
//! [`extstate`] carries settings and IndexedDB; this module makes extensions
//! actually appear under `chrome://extensions`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::oscrypt::Platform;
use crate::paths;
use crate::{Error, Result};

pub const EXT_BIN_PREFIX: &str = "Extensions";
pub const WEBSTORE_UPDATE_URL: &str = "https://clients2.google.com/service/update2/crx";

fn io(e: std::io::Error, what: &str, p: &Path) -> Error {
    Error::Io(format!("{what} {}: {e}", p.display()))
}

fn refuse_link(p: &Path) -> Error {
    Error::Refused(format!("{} is a symbolic link; Move It never follows links", p.display()))
}

fn meta(p: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(p) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(e, "cannot inspect", p)),
    }
}

fn real_dir(p: &Path) -> Result<bool> {
    match meta(p)? {
        None => Ok(false),
        Some(m) if m.file_type().is_symlink() => Err(refuse_link(p)),
        Some(m) => Ok(m.is_dir()),
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'a'..=b'p'))
}

/// Per-extension outcome for the move report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallReport {
    pub id: String,
    /// `installed` | `pending_open` | `failed`
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct InstallStats {
    pub reports: Vec<InstallReport>,
}

fn version_dirs(ext_root: &Path, id: &str) -> Result<Vec<String>> {
    let id_dir = ext_root.join(id);
    if !real_dir(&id_dir)? {
        return Ok(Vec::new());
    }
    let mut vers = Vec::new();
    for ent in fs::read_dir(&id_dir).map_err(|e| io(e, "cannot list", &id_dir))? {
        let ent = ent.map_err(|e| io(e, "cannot list", &id_dir))?;
        let ft = ent.file_type().map_err(|e| io(e, "cannot inspect", &ent.path()))?;
        if ft.is_symlink() {
            return Err(refuse_link(&ent.path()));
        }
        if ft.is_dir() {
            vers.push(ent.file_name().to_string_lossy().into_owned());
        }
    }
    vers.sort();
    Ok(vers)
}

fn version_key(name: &str) -> Vec<u32> {
    name.split('_')
        .flat_map(|part| part.split('.'))
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn pick_version(versions: &[String]) -> Option<&str> {
    versions
        .iter()
        .max_by(|a, b| version_key(a).cmp(&version_key(b)))
        .map(String::as_str)
}

/// Preferences files `merge_registrations` may rewrite or remove; snapshot both before import.
pub fn registration_store_paths(profile: &Path, slot: &str) -> [PathBuf; 2] {
    let slot_dir = paths::slot_dir(profile, slot);
    [slot_dir.join("Preferences"), slot_dir.join("Secure Preferences")]
}

fn read_manifest(ver_dir: &Path) -> Option<Value> {
    let p = ver_dir.join("manifest.json");
    let bytes = fs::read(&p).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn looks_webstore(manifest: &Value, id: &str) -> bool {
    if !valid_id(id) {
        return false;
    }
    if manifest
        .get("update_url")
        .and_then(Value::as_str)
        .is_some_and(|u| u.contains("google.com") && u.contains("service/update2/crx"))
    {
        return true;
    }
    if matches!(manifest.get("location").and_then(Value::as_u64), Some(4)) {
        return false;
    }
    if manifest.get("key").is_some() {
        return true;
    }
    manifest != &Value::Null
}

fn external_extensions_dir(browser_root: &Path) -> PathBuf {
    browser_root.join("External Extensions")
}

fn write_external_json(browser_root: &Path, id: &str) -> Result<PathBuf> {
    let dir = external_extensions_dir(browser_root);
    let path = dir.join(format!("{id}.json"));
    paths::check_contained(browser_root, &path)?;
    fs::create_dir_all(&dir).map_err(|e| io(e, "cannot create", &dir))?;
    let body = serde_json::to_vec_pretty(&json!({ "external_update_url": WEBSTORE_UPDATE_URL }))
        .map_err(|e| Error::Io(e.to_string()))?;
    fs::write(&path, body).map_err(|e| io(e, "cannot write", &path))?;
    Ok(path)
}

#[cfg(windows)]
fn write_windows_registry(id: &str, browser: &str) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hive = match browser {
        "edge" => r"Software\Microsoft\Edge\Extensions",
        "brave" => r"Software\BraveSoftware\Brave-Browser\Extensions",
        "chromium" => r"Software\Chromium\Extensions",
        _ => r"Software\Google\Chrome\Extensions",
    };
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(format!("{hive}\\{id}"))
        .map_err(|e| Error::Io(format!("cannot write registry for extension {id}: {e}")))?;
    key.set_value("update_url", &WEBSTORE_UPDATE_URL)
        .map_err(|e| Error::Io(format!("cannot write registry update_url for {id}: {e}")))?;
    Ok(())
}

#[cfg(not(windows))]
fn write_windows_registry(_id: &str, _browser: &str) -> Result<()> {
    Ok(())
}

fn register_store_extension(browser_root: &Path, browser: &str, id: &str) -> Result<()> {
    match Platform::current() {
        Platform::Linux | Platform::Mac => {
            write_external_json(browser_root, id)?;
        }
        Platform::Windows => {
            write_windows_registry(id, browser)?;
        }
    }
    Ok(())
}

fn store_report(id: &str, status: &str, detail: String) -> InstallReport {
    InstallReport {
        id: id.to_string(),
        status: status.to_string(),
        detail,
    }
}

fn read_prefs(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).map_err(|e| io(e, "cannot read", path))?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt("browser Preferences is not valid JSON".into()))
}

fn settings_from(prefs: &Value) -> Option<&Map<String, Value>> {
    prefs.get("extensions")?.get("settings")?.as_object()
}

/// Extension registration blobs from Preferences / Secure Preferences for export.
pub fn collect_registrations_in(profile: &Path, slot: &str, ids: &[String]) -> Result<Map<String, Value>> {
    let slot_dir = paths::slot_dir(profile, slot);
    let mut out = Map::new();
    let prefs = ["Preferences", "Secure Preferences"];
    for id in ids {
        if !valid_id(id) {
            continue;
        }
        for name in prefs {
            let path = slot_dir.join(name);
            if !path.is_file() {
                continue;
            }
            let Ok(v) = read_prefs(&path) else {
                continue;
            };
            if let Some(settings) = settings_from(&v) {
                if let Some(entry) = settings.get(id) {
                    out.insert(id.clone(), entry.clone());
                    break;
                }
            }
        }
    }
    Ok(out)
}

fn with_enabled_store_entry(mut entry: Value) -> Value {
    if let Some(obj) = entry.as_object_mut() {
        if obj.get("state").is_none() && obj.get("from_webstore").and_then(Value::as_bool) == Some(true) {
            obj.insert("state".into(), json!(1));
        }
    }
    entry
}

#[allow(dead_code)]
fn merge_into_prefs_file(path: &Path, regs: &Map<String, Value>) -> Result<usize> {
    let mut prefs = if path.is_file() {
        read_prefs(path)?
    } else {
        json!({})
    };
    let settings = prefs
        .as_object_mut()
        .and_then(|o| o.entry("extensions").or_insert_with(|| json!({})).as_object_mut())
        .and_then(|e| e.entry("settings").or_insert_with(|| json!({})).as_object_mut());
    let Some(settings) = settings else {
        return Err(Error::Corrupt(format!("cannot merge into {}", path.display())));
    };
    let mut n = 0;
    for (id, entry) in regs {
        settings.insert(id.clone(), with_enabled_store_entry(entry.clone()));
        n += 1;
    }
    let bytes = serde_json::to_vec(&prefs).map_err(|e| Error::Io(e.to_string()))?;
    fs::write(path, &bytes).map_err(|e| io(e, "cannot write", path))?;
    Ok(n)
}

fn merge_registrations(
    slot: &Path,
    browser: &str,
    regs: &Map<String, Value>,
    anchor_lock: Option<&crate::oscrypt::Lock>,
) -> Result<usize> {
    crate::prefhash::merge_registrations(slot, browser, regs, anchor_lock)
}

/// The macOS v11 gate for extension anchors, the same signal fix 2 uses
/// for v11 cookie and login writes: this platform is macOS and the target
/// user data folder's own browsers seal their pref hashes as v11
/// (`mac_data_dir_speaks_v11`, read here before the merge rewrites any
/// prefs file). Linux and Windows never pass the gate, so their merges
/// stay anchor-free exactly as before. When the gate passes, the target
/// lock must be a CBC lock that can seal the anchor; anything else fails
/// the import loudly instead of writing an unanchored registration.
fn extension_anchor_lock<'a>(
    browser_root: &Path,
    keys: &'a crate::cookies::Keys,
) -> Result<Option<&'a crate::oscrypt::Lock>> {
    if Platform::current() != Platform::Mac || !crate::oscrypt::mac_data_dir_speaks_v11(browser_root) {
        return Ok(None);
    }
    match keys {
        crate::cookies::Keys::Cbc { lock, .. } => Ok(Some(lock)),
        crate::cookies::Keys::Gcm { .. } => Err(Error::Refused(
            "cannot seal an extension registration anchor: the target browser key cannot write v11 values"
                .into(),
        )),
    }
}

/// Collect extension binaries from a live profile slot into logical paths `Extensions/<id>/<ver>/...`.
pub fn collect_bins_in(profile: &Path, slot: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    let ext_root = paths::slot_dir(profile, slot).join(EXT_BIN_PREFIX);
    if !real_dir(&ext_root)? {
        return Ok(out);
    }
    for id_ent in fs::read_dir(&ext_root).map_err(|e| io(e, "cannot list", &ext_root))? {
        let id_ent = id_ent.map_err(|e| io(e, "cannot list", &ext_root))?;
        let ft = id_ent.file_type().map_err(|e| io(e, "cannot inspect", &id_ent.path()))?;
        if ft.is_symlink() {
            return Err(refuse_link(&id_ent.path()));
        }
        if !ft.is_dir() {
            continue;
        }
        let id = id_ent.file_name().to_string_lossy().into_owned();
        if !valid_id(&id) {
            continue;
        }
        let vers = version_dirs(&ext_root, &id)?;
        let Some(ver) = pick_version(&vers) else {
            continue;
        };
        let ver_dir = ext_root.join(&id).join(ver);
        let prefix = format!("{EXT_BIN_PREFIX}/{id}/{ver}");
        walk_collect(&ver_dir, &prefix, &mut out)?;
    }
    Ok(out)
}

fn walk_collect(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    for ent in fs::read_dir(dir).map_err(|e| io(e, "cannot list", dir))? {
        let ent = ent.map_err(|e| io(e, "cannot list", dir))?;
        let ft = ent.file_type().map_err(|e| io(e, "cannot inspect", &ent.path()))?;
        if ft.is_symlink() {
            return Err(refuse_link(&ent.path()));
        }
        let name = ent.file_name().to_string_lossy().into_owned();
        if name == "_metadata" {
            continue;
        }
        let logical = format!("{prefix}/{name}");
        if ft.is_dir() {
            walk_collect(&ent.path(), &logical, out)?;
        } else if ft.is_file() {
            let data = fs::read(&ent.path()).map_err(|e| io(e, "cannot read", &ent.path()))?;
            out.insert(logical, data);
        }
    }
    Ok(())
}

fn write_bins_from_payload(slot: &Path, bins: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    // Every destination is validated before the first byte: this writer is
    // also called without a journal around it, so a refusal halfway through
    // must not leave a half-installed tree behind.
    let mut plan: Vec<(PathBuf, &Vec<u8>)> = Vec::with_capacity(bins.len());
    for (logical, data) in bins {
        let rest = logical
            .strip_prefix(&format!("{EXT_BIN_PREFIX}/"))
            .ok_or_else(|| Error::Corrupt(format!("extension binary path {logical:?} has wrong prefix")))?;
        let dest = slot.join(EXT_BIN_PREFIX).join(rest);
        paths::check_contained(slot, &dest)?;
        plan.push((dest, data));
    }
    for (dest, data) in plan {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| io(e, "cannot create", parent))?;
        }
        fs::write(&dest, data).map_err(|e| io(e, "cannot write", &dest))?;
    }
    Ok(())
}

/// Target dirs that install may replace (for txn snapshots).
pub fn target_paths(browser_root: &Path, slot: &str, ids: &[String], bins: &BTreeMap<String, Vec<u8>>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let slot_dir = paths::slot_dir(browser_root, slot);
    let ext_root = slot_dir.join(EXT_BIN_PREFIX);
    for id in ids {
        if !valid_id(id) {
            continue;
        }
        if let Some(ver) = bins
            .keys()
            .find_map(|k| k.strip_prefix(&format!("{EXT_BIN_PREFIX}/{id}/")).and_then(|r| r.split('/').next()))
            .map(str::to_string)
            .or_else(|| pick_version(&version_dirs(&ext_root, id).unwrap_or_default()).map(str::to_string))
        {
            out.push(ext_root.join(id).join(ver));
        }
    }
    let ext_dir = external_extensions_dir(browser_root);
    for id in ids {
        if valid_id(id) {
            out.push(ext_dir.join(format!("{id}.json")));
        }
    }
    out
}

/// Install extensions for `ids` on the target; `bins` may come from the sealed box.
pub fn install_in(
    browser_root: &Path,
    slot: &str,
    browser: &str,
    browser_display: &str,
    ids: &[String],
    bins: &BTreeMap<String, Vec<u8>>,
    registrations: &Map<String, Value>,
    keys: &crate::cookies::Keys,
) -> Result<InstallStats> {
    let slot_dir = paths::slot_dir(browser_root, slot);
    let ext_root = slot_dir.join(EXT_BIN_PREFIX);
    // The install writes under the slot and at the browser root. Refuse up
    // front when any of those destinations is reached through a link: a
    // linked Extensions folder would land the binaries in a profile that
    // was never picked, checked or snapshotted. (The one ancestor check
    // that existed before, in extstate, only ran for extensions carrying
    // settings files; this one is unconditional. The caller's journal
    // repeats the check over its snapshot set.)
    paths::check_contained(browser_root, &ext_root)?;
    for p in registration_store_paths(browser_root, slot) {
        paths::check_contained(browser_root, &p)?;
    }
    if !bins.is_empty() {
        write_bins_from_payload(&slot_dir, bins)?;
    }
    let anchor_lock = extension_anchor_lock(browser_root, keys)?;
    let _merged = merge_registrations(&slot_dir, browser, registrations, anchor_lock)?;
    let mut reports = Vec::new();
    for id in ids {
        if !valid_id(id) {
            reports.push(store_report(
                id,
                "failed",
                "could not install: extension id is not a Web Store shape".into(),
            ));
            continue;
        }
        let versions: Vec<String> = if let Some(v) = bins
            .keys()
            .find_map(|k| k.strip_prefix(&format!("{EXT_BIN_PREFIX}/{id}/")).and_then(|r| r.split('/').next()))
            .map(str::to_string)
        {
            vec![v]
        } else {
            version_dirs(&ext_root, id)?
        };
        let Some(ver) = pick_version(&versions) else {
            reports.push(store_report(id, "failed", "could not install: no extension files on disk".into()));
            continue;
        };
        let ver_dir = ext_root.join(id).join(ver);
        if !real_dir(&ver_dir)? {
            // Bins might list files without creating parent walk from payload write above.
            reports.push(store_report(id, "failed", "could not install: extension folder missing".into()));
            continue;
        }
        let manifest = read_manifest(&ver_dir).unwrap_or(Value::Null);
        let webstore = looks_webstore(&manifest, id);
        if registrations.contains_key(id) {
            let (status, detail) = if webstore {
                match register_store_extension(browser_root, browser, id) {
                    Ok(()) => (
                        "installed",
                        format!("installed in {browser_display} with registration copied from the source"),
                    ),
                    Err(e) => ("failed", format!("could not install: {e}")),
                }
            } else {
                (
                    "installed",
                    format!("installed in {browser_display} with registration copied from the source"),
                )
            };
            reports.push(store_report(id, status, detail));
        } else if webstore {
            match register_store_extension(browser_root, browser, id) {
                Ok(()) => reports.push(store_report(
                    id,
                    "pending_open",
                    format!("will install when {browser_display} opens"),
                )),
                Err(e) => reports.push(store_report(id, "failed", format!("could not install: {e}"))),
            }
        } else {
            reports.push(store_report(
                id,
                "installed",
                format!(
                    "installed (unpacked); open {browser_display} and enable the extension if it is not listed"
                ),
            ));
        }
    }
    Ok(InstallStats { reports })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "nkbihfbeogaeaoehlefnkodbefgpgknn";

    #[test]
    #[ignore = "live staging: Brave Profile 1 (0xovo) -> CfT, never MX Default"]
    fn staging_profile1_ext_install() {
        let brave = PathBuf::from(std::env::var("HOME").unwrap())
            .join("moveit/staging/ext-test/brave-src");
        let chrome = PathBuf::from(std::env::var("HOME").unwrap())
            .join("moveit/staging/ext-test/cft-target");
        if !brave.is_dir() || !chrome.is_dir() {
            eprintln!("skip: staging dirs missing");
            return;
        }
        use crate::engine::Profile;
        use crate::cookies::Keys;
        use crate::oscrypt::{linux_browser_password_for_at, HostTag, LinuxBrowser, LinuxPrefix, Lock};
        let (pw, trusted) =
            linux_browser_password_for_at(LinuxBrowser::Brave, Some(&brave)).expect("brave password");
        let keys = Keys::Cbc {
            lock: Lock::linux(&pw, LinuxPrefix::V10),
            from_libsecret_v2: LinuxBrowser::Brave.empty_store_v11_from_trusted_item(trusted),
        };
        let slot = "Profile 1";
        let src = Profile {
            dir: &brave,
            slot,
            keys: &keys,
            login_tag: HostTag::Without,
            browser: "brave",
            display: "Brave",
        };
        let payload =
            crate::engine::export(&src, "staging-proof", Some(&["extensions".to_string()])).unwrap();
        let ids = payload
            .manifest
            .get("extensions")
            .and_then(|v| v.get("installed_ids"))
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        assert!(ids > 0, "Profile 1 should list installed extension ids");
        let dst_keys = Keys::Cbc {
            lock: Lock::linux("peanuts", LinuxPrefix::V10),
            from_libsecret_v2: false,
        };
        let dst = Profile {
            dir: &chrome,
            slot: "Default",
            keys: &dst_keys,
            login_tag: HostTag::Without,
            browser: "chrome",
            display: "Google Chrome",
        };
        let applied = crate::engine::import(&dst, &payload, 1_700_000_000_000_000).unwrap();
        assert!(
            applied.extension_installs.reports.iter().any(|r| r.status == "installed"),
            "reports={:?}",
            applied.extension_installs.reports
        );
        let ext_root = chrome.join("Default/Extensions");
        assert!(ext_root.is_dir(), "Extensions dir must exist");
        assert!(
            std::fs::read_dir(&ext_root).unwrap().count() > 0,
            "at least one extension binary tree"
        );
    }

    #[test]
    fn registration_merge_undo_restores_preferences_files() {
        use crate::engine::{self, Profile};
        use crate::oscrypt::{HostTag, LinuxPrefix, Lock};
        use crate::txn;
        const REG_ID: &str = "nkbihfbeogaeaoehlefnkodbefgpgknn";
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let ver = "2.0_0";
        let ver_dir = src.path().join(format!("Default/Extensions/{REG_ID}/{ver}"));
        fs::create_dir_all(&ver_dir).unwrap();
        fs::write(
            ver_dir.join("manifest.json"),
            br#"{"version":"2.0","update_url":"https://clients2.google.com/service/update2/crx"}"#,
        )
        .unwrap();
        let prefs = src.path().join("Default/Preferences");
        fs::create_dir_all(prefs.parent().unwrap()).unwrap();
        fs::write(
            prefs,
            format!(
                r#"{{"extensions":{{"settings":{{"{REG_ID}":{{"manifest":{{"version":"2.0"}},"state":1,"from_webstore":true}}}}}}}}"#
            ),
        )
        .unwrap();
        let secure = src.path().join("Default/Secure Preferences");
        fs::write(&secure, br#"{"extensions":{"settings":{}}}"#).unwrap();
        let dst_prefs = dst.path().join("Default/Preferences");
        fs::create_dir_all(dst_prefs.parent().unwrap()).unwrap();
        fs::write(
            &dst_prefs,
            r#"{"extensions":{"settings":{"abcdefghijklmnopabcdefghijklmnop":{"state":1}}}}"#,
        )
        .unwrap();
        let dst_secure = dst.path().join("Default/Secure Preferences");
        fs::write(&dst_secure, br#"{"old":true,"extensions":{"settings":{}}}"#).unwrap();
        let before_prefs = fs::read(&dst_prefs).unwrap();
        let before_secure = fs::read(&dst_secure).unwrap();
        let keys = crate::cookies::Keys::Cbc {
            lock: Lock::linux("peanuts", LinuxPrefix::V10),
            from_libsecret_v2: false,
        };
        let src_prof = Profile {
            dir: src.path(),
            slot: "Default",
            keys: &keys,
            login_tag: HostTag::Without,
            browser: "chrome",
            display: "Google Chrome",
        };
        let payload = engine::export(&src_prof, "test", Some(&["extensions".to_string()])).unwrap();
        let dst_prof = Profile {
            dir: dst.path(),
            slot: "Default",
            keys: &keys,
            login_tag: HostTag::Without,
            browser: "chrome",
            display: "Google Chrome",
        };
        engine::import(&dst_prof, &payload, 1).unwrap();
        assert!(txn::undo_last(dst.path(), false).unwrap() == txn::Undo::Done);
        assert_eq!(fs::read(&dst_prefs).unwrap(), before_prefs);
        assert_eq!(fs::read(&dst_secure).unwrap(), before_secure);
    }

    #[test]
    fn pick_version_prefers_higher_numeric_release() {
        assert_eq!(pick_version(&["1.9_0".into(), "1.10_0".into()]).unwrap(), "1.10_0");
    }

    #[test]
    fn collect_and_install_store_extension() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let ver = "1.0_0";
        let ver_dir = src.path().join(format!("Default/Extensions/{ID}/{ver}"));
        fs::create_dir_all(&ver_dir).unwrap();
        fs::write(
            ver_dir.join("manifest.json"),
            br#"{"version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}"#,
        )
        .unwrap();
        fs::write(ver_dir.join("bg.js"), b"//").unwrap();
        let prefs = src.path().join("Default/Preferences");
        fs::create_dir_all(prefs.parent().unwrap()).unwrap();
        fs::write(
            prefs,
            format!(
                r#"{{"extensions":{{"settings":{{"{ID}":{{"manifest":{{"version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}},"state":1}}}}}}}}"#
            ),
        )
        .unwrap();
        let bins = collect_bins_in(src.path(), "Default").unwrap();
        assert_eq!(bins.len(), 2);
        let regs = collect_registrations_in(src.path(), "Default", &[ID.to_string()]).unwrap();
        let keys = crate::cookies::Keys::Cbc {
            lock: crate::oscrypt::Lock::linux("peanuts", crate::oscrypt::LinuxPrefix::V10),
            from_libsecret_v2: false,
        };
        let stats = install_in(
            dst.path(),
            "Default",
            "chrome",
            "Google Chrome",
            &[ID.to_string()],
            &bins,
            &regs,
            &keys,
        )
        .unwrap();
        assert_eq!(stats.reports.len(), 1);
        assert_eq!(stats.reports[0].status, "installed");
        assert!(dst.path().join("Default/Extensions").join(ID).join(ver).join("bg.js").is_file());
        // The external json is the Linux and Mac registration route. Windows
        // registration is registry-based, so no file is written there.
        #[cfg(not(windows))]
        assert!(dst.path().join("External Extensions").join(format!("{ID}.json")).is_file());
    }

    #[test]
    fn install_writes_no_anchor_off_the_macos_v11_gate() {
        // Regression guard for the fix A gate: off macOS, even a target
        // folder whose own pref hashes speak v11 and a Mac lock must
        // produce no settings_encrypted_hash anchor. The Linux leg is
        // proven green without engine-written anchors and stays that way.
        use base64::Engine;
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let ver = "1.0_0";
        let ver_dir = src.path().join(format!("Default/Extensions/{ID}/{ver}"));
        fs::create_dir_all(&ver_dir).unwrap();
        fs::write(
            ver_dir.join("manifest.json"),
            br#"{"version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}"#,
        )
        .unwrap();
        let prefs = src.path().join("Default/Preferences");
        fs::create_dir_all(prefs.parent().unwrap()).unwrap();
        fs::write(
            prefs,
            format!(
                r#"{{"extensions":{{"settings":{{"{ID}":{{"manifest":{{"version":"1.0"}},"state":1}}}}}}}}"#
            ),
        )
        .unwrap();
        // The target folder speaks v11 through its own sealed pref hash.
        let dst_slot = dst.path().join("Default");
        fs::create_dir_all(&dst_slot).unwrap();
        let seeded = json!({"protection": {
            "super_encrypted_hash":
                base64::engine::general_purpose::STANDARD.encode(b"v11-super"),
        }});
        fs::write(dst_slot.join("Secure Preferences"), serde_json::to_vec(&seeded).unwrap()).unwrap();
        assert!(crate::oscrypt::mac_data_dir_speaks_v11(dst.path()));
        let bins = collect_bins_in(src.path(), "Default").unwrap();
        let regs = collect_registrations_in(src.path(), "Default", &[ID.to_string()]).unwrap();
        let keys = crate::cookies::Keys::Cbc {
            lock: crate::oscrypt::Lock::mac("fixture-safe-storage-pw"),
            from_libsecret_v2: true,
        };
        let stats = install_in(
            dst.path(),
            "Default",
            "chrome",
            "Google Chrome",
            &[ID.to_string()],
            &bins,
            &regs,
            &keys,
        )
        .unwrap();
        assert_eq!(stats.reports[0].status, "installed");
        let secure: Value =
            serde_json::from_slice(&fs::read(dst_slot.join("Secure Preferences")).unwrap()).unwrap();
        assert!(secure["protection"]["macs"]["extensions"]["settings"][ID].is_string());
        if crate::oscrypt::Platform::current() != crate::oscrypt::Platform::Mac {
            assert!(
                secure["protection"]["macs"]["extensions"].get("settings_encrypted_hash").is_none(),
                "no anchor may be written off the macOS gate"
            );
        }
    }

    /// Another profile's extension folder, holding the manifest the repro protects.
    #[cfg(unix)]
    fn other_profile_with_manifest(root: &Path) {
        let ver_dir = root.join(format!("Default/Extensions/{ID}/1.0_0"));
        fs::create_dir_all(&ver_dir).unwrap();
        fs::write(ver_dir.join("manifest.json"), br#"{"name":"original"}"#).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn engine_import_refuses_a_linked_extensions_folder() {
        // The review repro, end to end: the target's Extensions folder is a
        // link into another profile, and the extension carries no settings
        // files, so nothing but the containment check stands in the way.
        // The import must refuse and the other profile's manifest must
        // stay byte-identical.
        use crate::engine::{self, Profile};
        use crate::oscrypt::{HostTag, LinuxPrefix, Lock};
        use std::os::unix::fs::symlink;
        let other = tempfile::tempdir().unwrap();
        other_profile_with_manifest(other.path());
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir_all(dst.path().join("Default")).unwrap();
        symlink(other.path().join("Default/Extensions"), dst.path().join("Default/Extensions")).unwrap();
        let src = tempfile::tempdir().unwrap();
        let ver_dir = src.path().join(format!("Default/Extensions/{ID}/1.0_0"));
        fs::create_dir_all(&ver_dir).unwrap();
        fs::write(ver_dir.join("manifest.json"), br#"{"name":"replaced"}"#).unwrap();
        let keys = crate::cookies::Keys::Cbc {
            lock: Lock::linux("peanuts", LinuxPrefix::V10),
            from_libsecret_v2: false,
        };
        let src_prof = Profile {
            dir: src.path(),
            slot: "Default",
            keys: &keys,
            login_tag: HostTag::Without,
            browser: "chrome",
            display: "Google Chrome",
        };
        let payload = engine::export(&src_prof, "test", Some(&["extensions".to_string()])).unwrap();
        let dst_prof = Profile {
            dir: dst.path(),
            slot: "Default",
            keys: &keys,
            login_tag: HostTag::Without,
            browser: "chrome",
            display: "Google Chrome",
        };
        let err = engine::import(&dst_prof, &payload, 1).unwrap_err();
        assert!(matches!(err, Error::Refused(_)), "{err:?}");
        assert_eq!(
            fs::read(other.path().join(format!("Default/Extensions/{ID}/1.0_0/manifest.json"))).unwrap(),
            br#"{"name":"original"}"#
        );
        let leftovers: Vec<_> = fs::read_dir(dst.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(crate::txn::TXN_PREFIX))
            .collect();
        assert!(leftovers.is_empty(), "no journal left behind: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn install_in_refuses_a_linked_extensions_folder() {
        // The same shape with no journal around the install: the writer
        // itself must refuse, not just the snapshot in front of it.
        use std::os::unix::fs::symlink;
        let other = tempfile::tempdir().unwrap();
        other_profile_with_manifest(other.path());
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir_all(dst.path().join("Default")).unwrap();
        symlink(other.path().join("Default/Extensions"), dst.path().join("Default/Extensions")).unwrap();
        let bins: BTreeMap<String, Vec<u8>> = [(
            format!("{EXT_BIN_PREFIX}/{ID}/1.0_0/manifest.json"),
            br#"{"name":"replaced"}"#.to_vec(),
        )]
        .into();
        let regs = Map::new();
        let keys = crate::cookies::Keys::Cbc {
            lock: crate::oscrypt::Lock::linux("peanuts", crate::oscrypt::LinuxPrefix::V10),
            from_libsecret_v2: false,
        };
        let err = install_in(
            dst.path(),
            "Default",
            "chrome",
            "Google Chrome",
            &[ID.to_string()],
            &bins,
            &regs,
            &keys,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Refused(_)), "{err:?}");
        assert_eq!(
            fs::read(other.path().join(format!("Default/Extensions/{ID}/1.0_0/manifest.json"))).unwrap(),
            br#"{"name":"original"}"#
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_external_extensions_folder_fails_that_install_only() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir_all(dst.path().join("Default")).unwrap();
        symlink(outside.path(), dst.path().join("External Extensions")).unwrap();
        let bins: BTreeMap<String, Vec<u8>> = [(
            format!("{EXT_BIN_PREFIX}/{ID}/1.0_0/manifest.json"),
            br#"{"version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}"#.to_vec(),
        )]
        .into();
        let regs: Map<String, Value> =
            serde_json::from_value(json!({ ID: { "state": 1, "from_webstore": true } })).unwrap();
        let keys = crate::cookies::Keys::Cbc {
            lock: crate::oscrypt::Lock::linux("peanuts", crate::oscrypt::LinuxPrefix::V10),
            from_libsecret_v2: false,
        };
        let stats = install_in(
            dst.path(),
            "Default",
            "chrome",
            "Google Chrome",
            &[ID.to_string()],
            &bins,
            &regs,
            &keys,
        )
        .unwrap();
        assert_eq!(stats.reports.len(), 1);
        assert_eq!(stats.reports[0].status, "failed", "{:?}", stats.reports);
        assert!(!outside.path().join(format!("{ID}.json")).exists());
        // The binaries themselves landed in the real profile.
        assert!(dst.path().join(format!("Default/Extensions/{ID}/1.0_0/manifest.json")).is_file());
    }
}
