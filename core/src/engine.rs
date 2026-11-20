//! The glue: one full read of a profile into a sealed box, and one full write of a box into a
//! profile. Every write is wrapped in the atomic journal (txn.rs), so a box is applied whole or
//! not at all, across all the stores at once.
//!
//! [`import_many`] is the multi-profile form: several boxes landing in one browser folder in a
//! single journal, including boxes routed here from another browser. A routed box lands in a
//! brand-new profile slot, created and registered in the browser's own `Local State` inside
//! the same journal, so undo takes the registration back out with everything else.
//!
//! Finding the browser's own password is deliberately NOT here: the caller passes [`cookies::Keys`]
//! and the Linux/Mac/Windows password discovery lives above this (and, for now, in the Python
//! reference). Everything else, the actual moving of a person's browser life, is here.

use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::cookies::{self, Cookie, Keys};
use crate::oscrypt::HostTag;
use crate::sealed::{Payload, BUNDLE_VERSION_2};
use crate::{bookmarks, extinstall, extstate, history, localstorage, logins, paths, profiles, txn};
use crate::{Error, Result};

/// A profile on this machine: a browser folder (`dir`) and the slot inside it.
pub struct Profile<'a> {
    pub dir: &'a std::path::Path,
    pub slot: &'a str,
    pub keys: &'a Keys,
    /// Logins: whether to write SHA256(host) in front (see oscrypt). Default: Without.
    pub login_tag: HostTag,
    /// Target browser short name (`chrome`, `brave`, …) for extension registration.
    pub browser: &'a str,
    /// Human label for progress and extension install messages.
    pub display: &'a str,
}

/// Valid `kinds` filter names for a partial move.
pub const MOVE_KINDS: &[&str] = &["passwords", "cookies", "bookmarks", "history", "extensions"];

fn wants_kind(kinds: Option<&[String]>, name: &str) -> bool {
    match kinds {
        None | Some([]) => true,
        Some(list) => list.iter().any(|k| k == name),
    }
}

/// A credential store that holds rows, exports none of them, and lost rows
/// to decryption failure must fail the seal: the key found on this device
/// does not belong to this profile, and sealing anyway would write a box
/// with no credentials in it and call that success (the Mac proof leg did
/// exactly this). A genuinely empty store (no rows at all) seals fine, and
/// a store whose rows are all App-Bound seals fine too: those rows are
/// refused by design, not lost to a wrong key. Partial loss keeps the old
/// behaviour: what decrypts moves, the rest is counted as skipped.
fn refuse_unreadable_store(store: &str, detail_total: usize, exported: usize, failed: usize) -> Result<()> {
    if detail_total > 0 && exported == 0 && failed > 0 {
        return Err(Error::Refused(format!(
            "this profile's {store} could not be read: {failed} of {detail_total} stored rows failed to decrypt with the browser key found on this device and not one stored row could be read, so sealing would silently drop them all"
        )));
    }
    Ok(())
}

/// Read everything movable out of a profile and build a v2 payload.
/// When `kinds` is set, only those sections are packed; importers skip missing keys.
pub fn export(p: &Profile, origin: &str, kinds: Option<&[String]>) -> Result<Payload> {
    let mut m = Map::new();
    m.insert("v".into(), BUNDLE_VERSION_2.into());
    m.insert("origin".into(), origin.into());
    let mut ext_files = std::collections::BTreeMap::new();
    let mut ext_bins = std::collections::BTreeMap::new();
    let mut bm_bytes = None;
    if wants_kind(kinds, "cookies") {
        let detail = cookies::export_detailed(&paths::cookies_in(p.dir, p.slot), p.keys)?;
        refuse_unreadable_store("cookies", detail.total, detail.cookies.len(), detail.failed)?;
        m.insert("cookies".into(), serde_json::to_value(&detail.cookies).map_err(ser)?);
        m.insert("skipped_cookies".into(), detail.app_bound.into());
    }
    if wants_kind(kinds, "passwords") {
        let detail = logins::export_detailed(&paths::login_data_in(p.dir, p.slot), p.keys)?;
        refuse_unreadable_store("saved logins", detail.total, detail.logins.len(), detail.failed)?;
        let skipped_logins = detail.app_bound + detail.failed;
        m.insert("passwords".into(), serde_json::to_value(&detail.logins).map_err(ser)?);
        m.insert("skipped_logins".into(), skipped_logins.into());
    }
    if wants_kind(kinds, "history") {
        let hist = history::export(&paths::history_in(p.dir, p.slot))?;
        m.insert("history".into(), serde_json::to_value(&hist).map_err(ser)?);
    }
    if wants_kind(kinds, "bookmarks") {
        let (bm_manifest, bytes) = bookmarks::export(&paths::bookmarks_in(p.dir, p.slot))?;
        m.insert("bookmarks".into(), serde_json::to_value(&bm_manifest).map_err(ser)?);
        bm_bytes = bytes;
    }
    if wants_kind(kinds, "extensions") {
        let ext = extstate::collect_in(p.dir, p.slot)?;
        let ls = localstorage::export_in(p.dir, p.slot)?;
        // Registrations are collected for every extension the profile
        // carries state for, not only the ones with a folder under
        // Extensions: an unpacked extension (loaded from a folder
        // outside the profile) has no binary tree in the profile, but
        // the browser did register it in Preferences, and that
        // registration is the only thing that makes the target browser
        // run it again. Its state folders are what mark it as carried.
        let ids = extstate::extension_id_candidates_in(p.dir, p.slot)?;
        let regs = extinstall::collect_registrations_in(p.dir, p.slot, &ids)?;
        m.insert("extensions".into(), Value::Object(ext.manifest));
        m.insert("ext_registrations".into(), Value::Object(regs));
        m.insert("ext_localstorage".into(), serde_json::to_value(&ls).map_err(ser)?);
        ext_files = ext.files;
        ext_bins = extinstall::collect_bins_in(p.dir, p.slot)?;
    }

    Ok(Payload {
        manifest: m,
        ext_files,
        ext_bins,
        bookmarks: bm_bytes,
    })
}

/// What a box write changed.
#[derive(Debug, Default)]
pub struct Applied {
    pub cookies: cookies::Stats,
    pub logins: logins::Stats,
    pub history: Option<history::Stats>,
    pub bookmarks: bookmarks::Report,
    pub extensions: extstate::Stats,
    pub extension_installs: extinstall::InstallStats,
    pub localstorage: localstorage::Report,
}

/// One payload's sections, decoded before anything on disk is touched.
struct Decoded<'a> {
    cookies: Vec<Cookie>,
    logins: Vec<logins::Login>,
    history: history::Section,
    localstorage: Vec<localstorage::Triple>,
    bm_manifest: bookmarks::Manifest,
    ext_manifest: Value,
    payload: &'a Payload,
}

fn decode(payload: &Payload) -> Result<Decoded<'_>> {
    let m = &payload.manifest;
    Ok(Decoded {
        cookies: from_section(m, "cookies")?,
        logins: from_section(m, "passwords")?,
        history: m.get("history").map(section).transpose()?.unwrap_or_default(),
        localstorage: match m.get("ext_localstorage") {
            Some(v) => localstorage::parse_section(v)?,
            None => Vec::new(),
        },
        bm_manifest: m.get("bookmarks").map(section).transpose()?.unwrap_or_default(),
        ext_manifest: m.get("extensions").cloned().unwrap_or_else(|| Value::Object(Map::new())),
        payload,
    })
}

/// Apply one decoded box to one slot whose stores are already snapshotted (and, for a
/// slot the caller just created, already planted empty).
fn installed_ids(ext_manifest: &Value) -> Vec<String> {
    ext_manifest
        .get("installed_ids")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// The extensions an import must install and register: the ones with a
/// binary tree in the profile (`installed_ids`) plus every id the box
/// carries a registration for. The second set is what an unpacked
/// extension arrives as (state and a Preferences entry, no binary tree);
/// installing only the first set left its state on disk with no
/// registration, so no target browser ever ran it.
fn install_ids(ext_manifest: &Value, regs: &Map<String, Value>) -> Vec<String> {
    let mut ids = installed_ids(ext_manifest);
    for id in regs.keys() {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    ids.sort();
    ids
}

fn registrations_of(payload: &Payload) -> Map<String, Value> {
    payload
        .manifest
        .get("ext_registrations")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn apply_one(
    root: &std::path::Path,
    slot: &str,
    d: &Decoded,
    keys: &Keys,
    login_tag: HostTag,
    now_us: i64,
    browser: &str,
    display: &str,
) -> Result<Applied> {
    let cookies_p = paths::cookies_in(root, slot);
    let history_p = paths::history_in(root, slot);
    let logins_p = paths::login_data_in(root, slot);
    let bookmarks_p = paths::bookmarks_in(root, slot);
    let mut a = Applied::default();
    // Missing cookie/login stores on a slot the engine just created are
    // planted by the caller. An existing never-launched profile must not
    // be planted into: refuse. A partial profile (one store already there)
    // still gets the other empty store so a section is not silently dropped.
    if (!cookies_p.exists() && !d.cookies.is_empty()) || (!logins_p.exists() && !d.logins.is_empty()) {
        if paths::never_launched(root, slot) {
            return Err(Error::NeverLaunched {
                browser: "the browser".into(),
            });
        }
        profiles::create_empty_stores(&paths::slot_dir(root, slot))?;
    }
    let m = &d.payload.manifest;
    if m.contains_key("cookies") && cookies_p.exists() {
        a.cookies = cookies::import(&cookies_p, &d.cookies, keys)?;
    }
    if m.contains_key("passwords") && logins_p.exists() {
        a.logins = logins::import(&logins_p, &d.logins, keys, login_tag)?;
    }
    if m.contains_key("history") {
        a.history = history::import(&history_p, &d.history)?;
    }
    if m.contains_key("bookmarks") {
        a.bookmarks = bookmarks::import(&bookmarks_p, &d.bm_manifest, d.payload.bookmarks.as_deref())?;
    }
    if m.contains_key("extensions") {
        a.extensions = extstate::import_in(root, slot, &d.ext_manifest, &d.payload.ext_files)?;
        a.localstorage = localstorage::import_in(root, slot, &d.localstorage, now_us)?;
        let regs = registrations_of(d.payload);
        let ids = install_ids(&d.ext_manifest, &regs);
        a.extension_installs =
            extinstall::install_in(root, slot, browser, display, &ids, &d.payload.ext_bins, &regs, keys)?;
    }
    Ok(a)
}

/// Write a box into a profile, all stores at once, all-or-nothing.
pub fn import(p: &Profile, box_payload: &Payload, now_us: i64) -> Result<Applied> {
    import_inner(p, box_payload, now_us, None)
}

/// Like [`import`], but cookies and logins are written under
/// `write_prefix` instead of the label the destination stores' existing
/// rows vote for. The same-device move uses this with the destination
/// browser's validated keyring key (a v11 key): the vote would seal
/// moved values under the compiled-in fallback key whenever the
/// destination's existing rows are legacy v10 or the store is empty.
pub fn import_with_write_prefix(
    p: &Profile,
    box_payload: &Payload,
    now_us: i64,
    write_prefix: crate::oscrypt::LinuxPrefix,
) -> Result<Applied> {
    import_inner(p, box_payload, now_us, Some(write_prefix))
}

fn import_inner(
    p: &Profile,
    box_payload: &Payload,
    now_us: i64,
    forced_prefix: Option<crate::oscrypt::LinuxPrefix>,
) -> Result<Applied> {
    let m = &box_payload.manifest;

    // Decode the sections up front, before touching disk, so a malformed box changes nothing.
    let cookies_in: Vec<Cookie> = from_section(m, "cookies")?;
    let logins_in: Vec<logins::Login> = from_section(m, "passwords")?;
    let hist_in: history::Section = m.get("history").map(section).transpose()?.unwrap_or_default();
    let ls_in = match m.get("ext_localstorage") {
        Some(v) => localstorage::parse_section(v)?,
        None => Vec::new(),
    };
    let bm_manifest: bookmarks::Manifest = m.get("bookmarks").map(section).transpose()?.unwrap_or_default();
    let empty = Value::Object(Map::new());
    let ext_manifest = m.get("extensions").unwrap_or(&empty);

  // Every store the box would touch, snapshotted together.
    let cookies_p = paths::cookies_in(p.dir, p.slot);
    let history_p = paths::history_in(p.dir, p.slot);
    let logins_p = paths::login_data_in(p.dir, p.slot);
    let bookmarks_p = paths::bookmarks_in(p.dir, p.slot);
    let ls_p = localstorage::store_path_in(p.dir, p.slot)?;
    let ext_dirs = if m.contains_key("extensions") {
        let mut dirs = extstate::target_dirs_in(p.dir, p.slot, ext_manifest, &box_payload.ext_files)?;
        dirs.extend(extinstall::target_paths(
            p.dir,
            p.slot,
            &install_ids(ext_manifest, &registrations_of(box_payload)),
            &box_payload.ext_bins,
        ));
        dirs
    } else {
        Vec::new()
    };

    let mut stores: Vec<(String, PathBuf)> = Vec::new();
    if m.contains_key("cookies") {
        stores.push(("cookies".into(), cookies_p.clone()));
    }
    if m.contains_key("history") {
        stores.push(("history".into(), history_p.clone()));
    }
    if m.contains_key("passwords") {
        stores.push(("logins".into(), logins_p.clone()));
    }
    if m.contains_key("bookmarks") {
        stores.push(("bookmarks".into(), bookmarks_p.clone()));
    }
    if m.contains_key("extensions") {
        if let Some(ref lp) = ls_p {
            stores.push(("localstorage".into(), lp.clone()));
        }
        for (name, path) in extinstall::registration_store_paths(p.dir, p.slot).into_iter().enumerate() {
            stores.push((if name == 0 { "extprefs".into() } else { "extsecureprefs".into() }, path));
        }
        for (i, d) in ext_dirs.iter().enumerate() {
            stores.push((format!("ext{i}"), d.clone()));
        }
    }
    let store_refs: Vec<(&str, &std::path::Path)> = stores.iter().map(|(n, p)| (n.as_str(), p.as_path())).collect();

    let tx = txn::Txn::begin(p.dir, &store_refs)?;
    // From here any `?` drops `tx`, which rolls every store back.
    let applied = (|| -> Result<Applied> {
        let mut a = Applied::default();
        // Missing cookie/login stores on a slot the engine just created are
        // planted by the caller. An existing never-launched profile must not
        // be planted into: refuse. A partial profile (one store already there)
        // still gets the other empty store so a section is not silently dropped.
        let need_cookies = m.contains_key("cookies");
        let need_logins = m.contains_key("passwords");
        if (need_cookies && !cookies_p.exists() && !cookies_in.is_empty())
            || (need_logins && !logins_p.exists() && !logins_in.is_empty())
        {
            if paths::never_launched(p.dir, p.slot) {
                return Err(Error::NeverLaunched {
                    browser: "the browser".into(),
                });
            }
            profiles::create_empty_stores(&paths::slot_dir(p.dir, p.slot))?;
        }
        if need_cookies && cookies_p.exists() {
            a.cookies = match forced_prefix {
                Some(prefix) => cookies::import_with_write_prefix(&cookies_p, &cookies_in, p.keys, prefix)?,
                None => cookies::import(&cookies_p, &cookies_in, p.keys)?,
            };
        }
        if need_logins && logins_p.exists() {
            a.logins = match forced_prefix {
                Some(prefix) => {
                    logins::import_with_write_prefix(&logins_p, &logins_in, p.keys, p.login_tag, prefix)?
                }
                None => logins::import(&logins_p, &logins_in, p.keys, p.login_tag)?,
            };
        }
        if m.contains_key("history") {
            a.history = history::import(&history_p, &hist_in)?;
        }
        if m.contains_key("bookmarks") {
            a.bookmarks = bookmarks::import(&bookmarks_p, &bm_manifest, box_payload.bookmarks.as_deref())?;
        }
        if m.contains_key("extensions") {
            a.extensions = extstate::import_in(p.dir, p.slot, ext_manifest, &box_payload.ext_files)?;
            a.localstorage = localstorage::import_in(p.dir, p.slot, &ls_in, now_us)?;
            let regs = registrations_of(box_payload);
            let ids = install_ids(ext_manifest, &regs);
            let display = if p.display.is_empty() { "the browser" } else { p.display };
            let browser = if p.browser.is_empty() { "chrome" } else { p.browser };
            a.extension_installs = extinstall::install_in(
                p.dir,
                p.slot,
                browser,
                display,
                &ids,
                &box_payload.ext_bins,
                &regs,
                p.keys,
            )?;
        }
        Ok(a)
    })();
    match applied {
        Ok(a) => {
            tx.commit()?;
            Ok(a)
        }
        Err(e) => {
            tx.rollback()?;
            Err(e)
        }
    }
}

/// Where one box should land inside one browser folder.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {    /// The profile with this folder name. Merged into when it is there; created and
    /// registered when it is not (the box's own profile, arriving on a device that
    /// does not have it yet).
    Slot(String),
    /// A brand-new profile, folder name chosen by the engine. This is where a box
    /// routed from another browser lands: always its own fresh profile, never over
    /// a profile the person already has.
    Fresh { display: String },
}

/// One box to land in [`import_many`].
#[derive(Clone)]
pub struct Job<'a> {
    pub target: Target,
    pub payload: &'a Payload,
}

/// What [`import_many`] did for one job.
#[derive(Debug)]
pub struct Landed {
    /// The folder name the box landed in.
    pub slot: String,
    /// True when this move created the profile.
    pub created: bool,
    pub applied: Applied,
}

/// The file a routed landing carries inside its profile folder, naming the
/// source profile it was created for (`origin`, `browser`, `slot` from the
/// box's manifest). The app surface checks it before merging a later delivery
/// into that profile.
pub const LANDING_MARKER: &str = ".moveit-landing";

/// Land several boxes in one browser folder under ONE journal: either every box is
/// in and the folder has one undo point for the whole move, or the folder is exactly
/// as it was. Creating a profile (its folder, its Preferences, its empty stores and
/// its `Local State` registration) happens inside the same journal, so undo and
/// crash recovery take a created profile back out whole.
pub fn import_many(
    root: &std::path::Path,
    keys: &Keys,
    login_tag: HostTag,
    jobs: &[Job],
    now_us: i64,
    browser: &str,
    display: &str,
) -> Result<Vec<Landed>> {
    import_many_preserving(root, keys, login_tag, jobs, now_us, None, browser, display)
}

pub(crate) fn import_many_preserving(
    root: &std::path::Path,
    keys: &Keys,
    login_tag: HostTag,
    jobs: &[Job],
    now_us: i64,
    previous: Option<&str>,
    browser: &str,
    display: &str,
) -> Result<Vec<Landed>> {
    if jobs.is_empty() {
        return Ok(Vec::new());
    }
    std::fs::create_dir_all(root).map_err(|e| Error::Io(format!("cannot create {}: {e}", root.display())))?;
    // Finish any crashed move in this folder before starting another.
    txn::recover(root)?;

    // Decode every box up front, before touching disk.
    let decoded: Vec<Decoded> = jobs.iter().map(|j| decode(j.payload)).collect::<Result<_>>()?;

    // A registration write needs a Local State we can read. A damaged one refuses
    // the whole move up front rather than being overwritten.
    let ls_path = paths::local_state(root);
    let ls_now: Option<Value> = if ls_path.exists() {
        let bytes = std::fs::read(&ls_path).map_err(|e| Error::Io(format!("cannot read {}: {e}", ls_path.display())))?;
        Some(
            serde_json::from_slice(&bytes).map_err(|_| {
                Error::Corrupt("the browser's Local State is damaged; Move It will not touch its profile list".into())
            })?,
        )
    } else {
        None
    };

    // Resolve each job's slot, and whether this move creates it.
    // A SingleProfile target is special in both halves: its one slot IS
    // the root, so "created" is whether the root itself already holds a
    // profile (a folder named after the slot never exists, and testing
    // for one reported every existing Opera profile as brand new), and
    // a created single profile is never registered in Local State (the
    // root has no slot list to extend; registering would plant a bogus
    // profile entry named after the slot).
    let single = crate::browsers::by_id(browser)
        .is_some_and(|d| d.layout == crate::browsers::LayoutKind::SingleProfile);
    let mut reserved: Vec<String> = Vec::new();
    let mut slots: Vec<String> = Vec::new();
    let mut displays: Vec<String> = Vec::new();
    let mut created: Vec<bool> = Vec::new();
    let mut register: Vec<bool> = Vec::new();
    for job in jobs {
        match &job.target {
            Target::Slot(name) => {
                reserved.push(name.clone());
                let is_single_slot = single && name == paths::SINGLE_SLOT;
                let was_created = if is_single_slot {
                    !crate::browsers::has_single_profile_markers(root)
                } else {
                    !root.join(name).is_dir()
                };
                created.push(was_created);
                register.push(was_created && !is_single_slot);
                displays.push(
                    job.payload
                        .manifest
                        .get("profile_name")
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| {
                            if is_single_slot && !display.is_empty() {
                                display.to_string()
                            } else {
                                name.clone()
                            }
                        }),
                );
                slots.push(name.clone());
            }
            Target::Fresh { display: fresh_display } => {
                if single {
                    // A routed box for a single-profile browser lands in
                    // its one slot, never in an invented subfolder.
                    reserved.push(paths::SINGLE_SLOT.to_string());
                    let was_created = !crate::browsers::has_single_profile_markers(root);
                    created.push(was_created);
                    register.push(false);
                    displays.push(fresh_display.clone());
                    slots.push(paths::SINGLE_SLOT.to_string());
                } else {
                    let name = profiles::fresh_slot_name(root, &reserved);
                    reserved.push(name.clone());
                    created.push(true);
                    register.push(true);
                    displays.push(fresh_display.clone());
                    slots.push(name);
                }
            }
        }
    }
    // Slot names become folder paths. A name that did not come from this engine
    // (a box can carry one) must be a name Chromium itself would use, nothing else:
    // no separators, no dots, no traversal.
    let layout = crate::browsers::by_id(browser)
        .map(|d| d.layout)
        .unwrap_or(crate::browsers::LayoutKind::Standard);
    for s in &slots {
        if !profiles::is_slot_name_for(s, layout) {
            return Err(Error::Refused(format!("{s:?} is not a profile name Move It will write to")));
        }
    }
    // Two boxes landing in the same profile in one move would merge into each other
    // in job order without the person ever choosing that. Refuse instead.
    let mut seen = std::collections::BTreeSet::new();
    for s in &slots {
        if !seen.insert(s.clone()) {
            return Err(Error::Refused(format!(
                "two profiles in one move cannot land in the same profile ({s})"
            )));
        }
    }
    let any_created = created.iter().any(|c| *c);
    let any_registered = register.iter().any(|c| *c);

    // Every store every job would touch, snapshotted together. A created profile's
    // folder itself is a store (absent before, so undo removes the whole folder),
    // and so is Local State when any registration will be written into it.
    // A created single profile is the exception: its folder is the root
    // itself, which contains the journal, so snapshotting it as a store
    // would hash and copy the journal into its own snapshot. Its created
    // files are snapshotted individually instead (Preferences and the
    // landing marker; the stores below cover the databases), and undo
    // takes those back out, leaving the (possibly pre-existing) root
    // folder in place.
    let mut stores: Vec<(String, PathBuf)> = Vec::new();
    if any_registered {
        stores.push(("localstate".into(), ls_path.clone()));
    }
    for (i, slot) in slots.iter().enumerate() {
        if created[i] {
            if single && slot == paths::SINGLE_SLOT {
                stores.push((format!("prefs{i}"), root.join("Preferences")));
                stores.push((format!("marker{i}"), root.join(LANDING_MARKER)));
            } else {
                stores.push((format!("slotdir{i}"), paths::slot_dir(root, slot)));
            }
        }
        stores.push((format!("cookies{i}"), paths::cookies_in(root, slot)));
        stores.push((format!("history{i}"), paths::history_in(root, slot)));
        stores.push((format!("logins{i}"), paths::login_data_in(root, slot)));
        stores.push((format!("bookmarks{i}"), paths::bookmarks_in(root, slot)));
        if let Some(lp) = localstorage::store_path_in(root, slot)? {
            stores.push((format!("localstorage{i}"), lp));
        }
        let d = &decoded[i];
        let mut ext_t = extstate::target_dirs_in(root, slot, &d.ext_manifest, &d.payload.ext_files)?;
        ext_t.extend(extinstall::target_paths(
            root,
            slot,
            &install_ids(&d.ext_manifest, &registrations_of(d.payload)),
            &d.payload.ext_bins,
        ));
        for (j, dir) in ext_t.into_iter().enumerate() {
            stores.push((format!("ext{i}_{j}"), dir));
        }
        if d.payload.manifest.contains_key("extensions") {
            for (name, path) in extinstall::registration_store_paths(root, slot).into_iter().enumerate() {
                stores.push((
                    if name == 0 {
                        format!("extprefs{i}")
                    } else {
                        format!("extsecureprefs{i}")
                    },
                    path,
                ));
            }
        }
    }
    let store_refs: Vec<(&str, &std::path::Path)> = stores.iter().map(|(n, p)| (n.as_str(), p.as_path())).collect();
    let tx = txn::Txn::begin(root, &store_refs)?;
    // From here any `?` drops `tx`, which rolls everything back.
    let applied = (|| -> Result<Vec<Landed>> {
        if any_created {
            for (i, slot) in slots.iter().enumerate() {
                if !created[i] {
                    continue;
                }
                let dir = paths::slot_dir(root, slot);
                std::fs::create_dir_all(&dir).map_err(|e| Error::Io(format!("cannot create {}: {e}", dir.display())))?;
                let prefs = dir.join("Preferences");
                if !prefs.exists() {
                    let bytes = serde_json::to_vec(&profiles::new_preferences(&displays[i]))
                        .map_err(|e| Error::Io(e.to_string()))?;
                    std::fs::write(&prefs, bytes).map_err(|e| Error::Io(format!("cannot write {}: {e}", prefs.display())))?;
                }
                profiles::create_empty_stores(&dir)?;
                // A profile created for a routed box carries its landing
                // marker: the source identity from the box itself. Later
                // deliveries find their home by this marker, never by a
                // bookkeeping entry alone, so no state file can redirect a
                // merge into a profile that was not created for it. Written
                // inside the transaction, so undo takes it out with the folder.
                if matches!(jobs[i].target, Target::Fresh { .. }) {
                    let m = &jobs[i].payload.manifest;
                    let get = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or_default();
                    // The marker names the source the way the app surface
                    // looks it up: the stable device id when the box carries
                    // one (the name otherwise), and the browser lowercased,
                    // matching the case-insensitive read.
                    let origin = match get("origin_id") {
                        "" => get("origin"),
                        id => id,
                    };
                    let marker = serde_json::json!({
                        "origin": origin,
                        "browser": get("profile_browser").to_lowercase(),
                        "slot": get("profile_slot"),
                    });
                    let bytes = serde_json::to_vec(&marker).map_err(|e| Error::Io(e.to_string()))?;
                    let mp = dir.join(LANDING_MARKER);
                    std::fs::write(&mp, bytes)
                        .map_err(|e| Error::Io(format!("cannot write {}: {e}", mp.display())))?;
                }
            }
            if any_registered {
                let mut ls = ls_now.clone().unwrap_or_else(|| Value::Object(Map::new()));
                for (i, slot) in slots.iter().enumerate() {
                    if register[i] {
                        ls = profiles::local_state_with_slot(&ls, slot, &displays[i], (now_us / 1_000_000) as u64);
                    }
                }
                let bytes = serde_json::to_vec(&ls).map_err(|e| Error::Io(e.to_string()))?;
                let tmp = root.join("Local State.moveit-tmp");
                std::fs::write(&tmp, bytes).map_err(|e| Error::Io(format!("cannot write {}: {e}", tmp.display())))?;
                std::fs::rename(&tmp, &ls_path).map_err(|e| Error::Io(format!("cannot write {}: {e}", ls_path.display())))?;
            }
        }
        let mut out = Vec::new();
        for (i, d) in decoded.iter().enumerate() {
            let applied = apply_one(root, &slots[i], d, keys, login_tag, now_us, browser, display)?;
            out.push(Landed { slot: slots[i].clone(), created: created[i], applied });
        }
        Ok(out)
    })();
    match applied {
        Ok(a) => {
            tx.commit_preserving(previous)?;
            Ok(a)
        }
        Err(e) => {
            tx.rollback()?;
            Err(e)
        }
    }
}

fn ser(e: serde_json::Error) -> Error {
    Error::Io(format!("cannot shape a section: {e}"))
}

fn section<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T> {
    serde_json::from_value(v.clone()).map_err(|e| Error::Corrupt(format!("a box section is malformed: {e}")))
}

fn from_section<T: serde::de::DeserializeOwned>(m: &Map<String, Value>, key: &str) -> Result<Vec<T>> {
    match m.get(key) {
        Some(v @ Value::Array(_)) => section(v),
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err(Error::Corrupt(format!("box section {key:?} is not a list"))),
    }
}

/// Convenience for a round trip test or a real sync: seal into bytes / open from bytes.
pub fn seal_box(p: &Profile, origin: &str, key: &crate::sealed::SyncKey) -> Result<Vec<u8>> {
    let payload = export(p, origin, None)?;
    let env = crate::sealed::seal(&payload, key)?;
    serde_json::to_vec(&env).map_err(ser)
}

pub fn open_box(bytes: &[u8], key: &crate::sealed::SyncKey) -> Result<Payload> {
    let env: Value = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt("the box is not valid JSON".into()))?;
    crate::sealed::unseal(&env, key)
}

/// Build the per-profile `Keys` for Linux/Mac from a known password (what the harness and tests
/// use; live discovery of that password is the caller's job).
pub fn cbc_keys(lock: crate::oscrypt::Lock, from_libsecret_v2: bool) -> Keys {
    let _ = &lock;
    Keys::Cbc { lock, from_libsecret_v2 }
}
