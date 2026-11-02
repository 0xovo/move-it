//! The glue: one full read of a profile into a sealed box, and one full write of a box into a
//! profile. Every write is wrapped in the atomic journal (txn.rs), so a box is applied whole or
//! not at all, across all the stores at once.
//!
//! Finding the browser's own password is deliberately NOT here: the caller passes [`cookies::Keys`]
//! and the Linux/Mac/Windows password discovery lives above this (and, for now, in the Python
//! reference). Everything else, the actual moving of a person's browser life, is here.


use serde_json::{Map, Value};

use crate::cookies::{self, Cookie, Keys};
use crate::oscrypt::HostTag;
use crate::sealed::{Payload, BUNDLE_VERSION_2};
use crate::{bookmarks, extstate, history, localstorage, logins, paths, txn};
use crate::{Error, Result};

/// A profile on this machine.
pub struct Profile<'a> {
    pub dir: &'a std::path::Path,
    pub keys: &'a Keys,
    /// Logins: whether to write SHA256(host) in front (see oscrypt). Default: Without.
    pub login_tag: HostTag,
}

/// Read everything movable out of a profile and build a v2 payload.
pub fn export(p: &Profile, origin: &str) -> Result<Payload> {
    let cookies = cookies::export(&paths::cookies(p.dir), p.keys)?;
    let logins = logins::export(&paths::login_data(p.dir), p.keys)?;
    let hist = history::export(&paths::history(p.dir))?;
    let (bm_manifest, bm_bytes) = bookmarks::export(&paths::bookmarks(p.dir))?;
    let ext = extstate::collect(p.dir)?;
    let ls = localstorage::export(p.dir)?;

    let mut m = Map::new();
    m.insert("v".into(), BUNDLE_VERSION_2.into());
    m.insert("origin".into(), origin.into());
    m.insert("cookies".into(), serde_json::to_value(&cookies).map_err(ser)?);
    m.insert("passwords".into(), serde_json::to_value(&logins).map_err(ser)?);
    m.insert("history".into(), serde_json::to_value(&hist).map_err(ser)?);
    m.insert("bookmarks".into(), serde_json::to_value(&bm_manifest).map_err(ser)?);
    // The extensions manifest object is built by extstate; carry it through as-is.
    m.insert("extensions".into(), Value::Object(ext.manifest));
    m.insert("ext_localstorage".into(), serde_json::to_value(&ls).map_err(ser)?);

    Ok(Payload { manifest: m, ext_files: ext.files, bookmarks: bm_bytes })
}

/// What a box write changed.
#[derive(Debug, Default)]
pub struct Applied {
    pub cookies: cookies::Stats,
    pub logins: logins::Stats,
    pub history: Option<history::Stats>,
    pub bookmarks: bookmarks::Report,
    pub extensions: extstate::Stats,
    pub localstorage: localstorage::Report,
}

/// Write a box into a profile, all stores at once, all-or-nothing.
pub fn import(p: &Profile, box_payload: &Payload, now_us: i64) -> Result<Applied> {
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
    let cookies_p = paths::cookies(p.dir);
    let history_p = paths::history(p.dir);
    let logins_p = paths::login_data(p.dir);
    let bookmarks_p = paths::bookmarks(p.dir);
    let ls_p = localstorage::store_path(p.dir)?;
    let ext_dirs = extstate::target_dirs(p.dir, ext_manifest, &box_payload.ext_files)?;

    let mut stores: Vec<(String, std::path::PathBuf)> = vec![
        ("cookies".into(), cookies_p.clone()),
        ("history".into(), history_p.clone()),
        ("logins".into(), logins_p.clone()),
        ("bookmarks".into(), bookmarks_p.clone()),
    ];
    if let Some(ref lp) = ls_p {
        stores.push(("localstorage".into(), lp.clone()));
    }
    for (i, d) in ext_dirs.iter().enumerate() {
        stores.push((format!("ext{i}"), d.clone()));
    }
    let store_refs: Vec<(&str, &std::path::Path)> = stores.iter().map(|(n, p)| (n.as_str(), p.as_path())).collect();

    let tx = txn::Txn::begin(p.dir, &store_refs)?;
    // From here any `?` drops `tx`, which rolls every store back.
    let applied = (|| -> Result<Applied> {
        let mut a = Applied::default();
        if cookies_p.exists() {
            a.cookies = cookies::import(&cookies_p, &cookies_in, p.keys)?;
        }
        if logins_p.exists() {
            a.logins = logins::import(&logins_p, &logins_in, p.keys, p.login_tag)?;
        }
        a.history = history::import(&history_p, &hist_in)?;
        a.bookmarks = bookmarks::import(&bookmarks_p, &bm_manifest, box_payload.bookmarks.as_deref())?;
        a.extensions = extstate::import(p.dir, ext_manifest, &box_payload.ext_files)?;
        a.localstorage = localstorage::import(p.dir, &ls_in, now_us)?;
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

fn ser(e: serde_json::Error) -> Error {
    Error::Io(format!("cannot shape a section: {e}"))
}

fn section<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T> {
    serde_json::from_value(v.clone()).map_err(|e| Error::Corrupt(format!("a box section is malformed: {e}")))
}

fn from_section<T: serde::de::DeserializeOwned>(m: &Map<String, Value>, key: &str) -> Result<Vec<T>> {
    match m.get(key) {
        Some(Value::Array(_)) => section(m.get(key).unwrap()),
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err(Error::Corrupt(format!("box section {key:?} is not a list"))),
    }
}

/// Convenience for a round trip test or a real sync: seal into bytes / open from bytes.
pub fn seal_box(p: &Profile, origin: &str, key: &crate::sealed::SyncKey) -> Result<Vec<u8>> {
    let payload = export(p, origin)?;
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
