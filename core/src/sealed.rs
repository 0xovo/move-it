//! The sealed box: the one file that travels between devices.
//!
//! Wire format, same as the Python prototype:
//! a JSON envelope `{"v": N, "nonce": b64(12 bytes), "data": b64(ciphertext + 16-byte tag)}`,
//! AES-256-GCM with no associated data.
//!   v1: the plaintext is JSON `{"v":1, "origin", "exported_at", "cookies":[...]}`.
//!   v2: the plaintext is a ZIP holding `manifest.json`, one `extstate/<logical path>`
//!       entry per extension state file, and `bundlefiles/Bookmarks` when present.
//! In memory a v2 [`Payload`] keeps file bytes beside the manifest, never inside it.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const BUNDLE_VERSION_1: u64 = 1;
pub const BUNDLE_VERSION_2: u64 = 2;
pub const EXT_STATE_FOLDERS: [&str; 2] = ["Local Extension Settings", "Sync Extension Settings"];
pub const INDEXEDDB_STATE_FOLDER: &str = "IndexedDB";
pub const EXT_ZIP_PREFIX: &str = "extstate/";
pub const BOOKMARKS_ZIP_ENTRY: &str = "bundlefiles/Bookmarks";
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// A 32-byte sync key. Never travels with the box.
#[derive(Clone)]
pub struct SyncKey([u8; 32]);

impl std::fmt::Debug for SyncKey {
    /// Never print the key, not even in logs or panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncKey(hidden)")
    }
}

impl SyncKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SyncKey(bytes)
    }

    pub fn generate() -> Result<Self> {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).map_err(|e| Error::Io(format!("no randomness: {e}")))?;
        Ok(SyncKey(k))
    }

    /// Key file format: base64 of the 32 bytes, optional trailing newline.
    pub fn from_key_file_text(text: &str) -> Result<Self> {
        let raw = B64
            .decode(text.trim())
            .map_err(|_| Error::Corrupt("key file does not hold valid base64".into()))?;
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::Corrupt(format!("key file decoded to {} bytes, expected 32", raw.len())))?;
        Ok(SyncKey(arr))
    }

    pub fn to_key_file_text(&self) -> String {
        format!("{}\n", B64.encode(self.0))
    }

    /// Write a new key file with owner-only permissions; refuses to overwrite.
    pub fn write_new_key_file(&self, path: &Path) -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Refused(format!("key file already exists, refusing to overwrite: {}", path.display()))
            } else {
                Error::Io(e.to_string())
            }
        })?;
        f.write_all(self.to_key_file_text().as_bytes()).map_err(|e| Error::Io(e.to_string()))?;
        f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
        Ok(())
    }

    pub fn read_key_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Io(format!("cannot read key file {}: {e}", path.display())))?;
        Self::from_key_file_text(&text)
    }

    /// Seal a small note (pairing). `nonce` must be fresh random 12 bytes.
    pub fn seal_small(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        self.cipher().encrypt(Nonce::from_slice(nonce), data).map_err(|_| Error::Io("sealing failed".into()))
    }

    pub fn open_small(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_LEN {
            return Err(Error::Corrupt("bad nonce length".into()));
        }
        self.cipher().decrypt(Nonce::from_slice(nonce), data).map_err(|_| Error::WrongKeyOrTampered)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0))
    }
}

/// What a box carries. `manifest` is the JSON object (v1: the whole payload);
/// `ext_files` and `bookmarks` hold the v2 file bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Payload {
    pub manifest: Map<String, Value>,
    pub ext_files: BTreeMap<String, Vec<u8>>,
    pub bookmarks: Option<Vec<u8>>,
}

impl Payload {
    pub fn version(&self) -> Option<u64> {
        self.manifest.get("v").and_then(Value::as_u64)
    }
}

/// True for exactly `chrome-extension_<id>_0` and `chrome-extension_<id>_0.indexeddb.leveldb`.
pub fn is_indexeddb_unit_name(name: &str) -> bool {
    let Some(mut rest) = name.strip_prefix("chrome-extension_") else { return false };
    if let Some(r) = rest.strip_suffix(".indexeddb.leveldb") {
        rest = r;
    }
    let Some(id) = rest.strip_suffix("_0") else { return false };
    !id.is_empty() && !id.contains("..") && id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

fn unsafe_seg(s: &str) -> bool {
    // `.`/`..`/empty traverse; a backslash or a drive colon would escape the folder on Windows,
    // where '\' is a separator, so reject those too (a box comes from another, possibly hostile,
    // paired device).
    s.is_empty() || s == "." || s == ".." || s.contains('\\') || s.contains(':')
}

/// Fail closed on any extension-state path outside the known shapes.
pub fn validate_ext_logical_path(logical: &str) -> Result<()> {
    let parts: Vec<&str> = logical.split('/').collect();
    let bad = |why: &str| Err(Error::Corrupt(format!("extension file path {logical:?} {why}")));
    if parts[0] == INDEXEDDB_STATE_FOLDER {
        if parts.len() < 3 || !is_indexeddb_unit_name(parts[1]) {
            return bad("is not a per-extension IndexedDB unit path");
        }
        if parts[2..].iter().any(|s| unsafe_seg(s)) {
            return bad("has unsafe segments");
        }
        return Ok(());
    }
    if parts.len() < 3 || !EXT_STATE_FOLDERS.contains(&parts[0]) {
        return bad("is outside the known extension state folders");
    }
    if unsafe_seg(parts[1]) || parts[1].contains('\\') {
        return bad("has an unsafe extension id segment");
    }
    if parts[2..].iter().any(|s| unsafe_seg(s)) {
        return bad("has unsafe segments");
    }
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn build_v2_zip(p: &Payload) -> Result<Vec<u8>> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let zerr = |e: zip::result::ZipError| Error::Io(e.to_string());
        zw.start_file("manifest.json", opts).map_err(zerr)?;
        let manifest = serde_json::to_vec(&p.manifest).map_err(|e| Error::Io(e.to_string()))?;
        zw.write_all(&manifest).map_err(|e| Error::Io(e.to_string()))?;
        for (logical, data) in &p.ext_files {
            validate_ext_logical_path(logical)?;
            zw.start_file(format!("{EXT_ZIP_PREFIX}{logical}"), opts).map_err(zerr)?;
            zw.write_all(data).map_err(|e| Error::Io(e.to_string()))?;
        }
        if let Some(b) = &p.bookmarks {
            zw.start_file(BOOKMARKS_ZIP_ENTRY, opts).map_err(zerr)?;
            zw.write_all(b).map_err(|e| Error::Io(e.to_string()))?;
        }
        zw.finish().map_err(zerr)?;
    }
    Ok(buf.into_inner())
}

fn read_entry(zr: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Option<Vec<u8>>> {
    match zr.by_name(name) {
        Ok(f) => {
            // Cap the decompressed size so a paired-but-hostile device can't OOM us with a zip bomb.
            const MAX_ENTRY: u64 = 512 * 1024 * 1024;
            if f.size() > MAX_ENTRY {
                return Err(Error::Corrupt(format!("bundle is corrupt ({name} is too large)")));
            }
            let mut out = Vec::new();
            f.take(MAX_ENTRY).read_to_end(&mut out)
                .map_err(|_| Error::Corrupt(format!("bundle is corrupt ({name} cannot be read)")))?;
            Ok(Some(out))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(_) => Err(Error::Corrupt(format!("bundle is corrupt ({name} cannot be read)"))),
    }
}

fn check_size_hash(data: &[u8], entry: &Value, what: &str) -> Result<()> {
    let size = entry.get("size").and_then(Value::as_u64);
    let hash = entry.get("sha256").and_then(Value::as_str);
    if size != Some(data.len() as u64) || hash != Some(sha256_hex(data).as_str()) {
        return Err(Error::Corrupt(format!("bundle is corrupt ({what} fails its size/hash check)")));
    }
    Ok(())
}

fn parse_v2_zip(raw: &[u8]) -> Result<Payload> {
    let mut zr = zip::ZipArchive::new(Cursor::new(raw))
        .map_err(|_| Error::Corrupt("bundle payload is corrupt (v2 container is not a readable zip)".into()))?;
    let mbytes = read_entry(&mut zr, "manifest.json")?
        .ok_or_else(|| Error::Corrupt("bundle payload is corrupt (v2 container has no manifest.json)".into()))?;
    let manifest: Map<String, Value> = serde_json::from_slice(&mbytes)
        .map_err(|_| Error::Corrupt("bundle payload is corrupt (v2 manifest is not valid JSON)".into()))?;
    if manifest.get("v").and_then(Value::as_u64) != Some(BUNDLE_VERSION_2) || !manifest.contains_key("cookies") {
        return Err(Error::Corrupt("bundle payload is not in the expected v2 shape".into()));
    }
    let mut ext_files = BTreeMap::new();
    let entries = manifest
        .get("extensions")
        .and_then(|e| e.get("files"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in &entries {
        let logical = entry
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Corrupt("bundle is corrupt (extension file entry has no path)".into()))?;
        validate_ext_logical_path(logical)?;
        let data = read_entry(&mut zr, &format!("{EXT_ZIP_PREFIX}{logical}"))?.ok_or_else(|| {
            Error::Corrupt(format!("bundle is corrupt (manifest lists {logical} but the container does not hold it)"))
        })?;
        check_size_hash(&data, entry, &format!("extension file {logical}"))?;
        ext_files.insert(logical.to_string(), data);
    }
    let bookmarks = match manifest.get("bookmarks") {
        Some(b) if b.get("present").and_then(Value::as_bool) == Some(true) => {
            let data = read_entry(&mut zr, BOOKMARKS_ZIP_ENTRY)?.ok_or_else(|| {
                Error::Corrupt(
                    "bundle is corrupt (manifest carries a Bookmarks file but the container does not hold it)".into(),
                )
            })?;
            check_size_hash(&data, b, "the Bookmarks file")?;
            Some(data)
        }
        _ => None,
    };
    Ok(Payload { manifest, ext_files, bookmarks })
}

/// Seal a payload into the JSON envelope.
pub fn seal(payload: &Payload, key: &SyncKey) -> Result<Value> {
    let version = payload.version();
    let raw = match version {
        Some(BUNDLE_VERSION_2) => build_v2_zip(payload)?,
        Some(BUNDLE_VERSION_1) => serde_json::to_vec(&payload.manifest).map_err(|e| Error::Io(e.to_string()))?,
        other => return Err(Error::Refused(format!("cannot seal a payload with version {other:?}"))),
    };
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| Error::Io(format!("no randomness: {e}")))?;
    let data = key
        .cipher()
        .encrypt(Nonce::from_slice(&nonce), raw.as_slice())
        .map_err(|_| Error::Io("sealing failed".into()))?;
    Ok(serde_json::json!({"v": version, "nonce": B64.encode(nonce), "data": B64.encode(data)}))
}

/// Open an envelope. A wrong key and a tampered box are the same error, on purpose.
pub fn unseal(envelope: &Value, key: &SyncKey) -> Result<Payload> {
    let v = envelope.get("v").and_then(Value::as_u64);
    if !matches!(v, Some(BUNDLE_VERSION_1) | Some(BUNDLE_VERSION_2)) {
        return Err(Error::Corrupt("not a Move It box (missing or bad version)".into()));
    }
    let field = |k: &str| {
        envelope
            .get(k)
            .and_then(Value::as_str)
            .and_then(|s| B64.decode(s).ok())
            .ok_or_else(|| Error::Corrupt("bundle is corrupt (bad base64)".into()))
    };
    let nonce = field("nonce")?;
    let data = field("data")?;
    if data.len() < TAG_LEN {
        return Err(Error::Corrupt("bundle is corrupt (too short)".into()));
    }
    if nonce.len() != NONCE_LEN {
        return Err(Error::Corrupt("bundle is corrupt (bad nonce length)".into()));
    }
    let raw = key
        .cipher()
        .decrypt(Nonce::from_slice(&nonce), data.as_slice())
        .map_err(|_| Error::WrongKeyOrTampered)?;
    if v == Some(BUNDLE_VERSION_2) {
        return parse_v2_zip(&raw);
    }
    let manifest: Map<String, Value> = serde_json::from_slice(&raw)
        .map_err(|_| Error::Corrupt("bundle payload is corrupt (v1 payload is not valid JSON)".into()))?;
    if manifest.get("v").and_then(Value::as_u64) != Some(BUNDLE_VERSION_1) || !manifest.contains_key("cookies") {
        return Err(Error::Corrupt("bundle payload is not in the expected shape".into()));
    }
    Ok(Payload { manifest, ext_files: BTreeMap::new(), bookmarks: None })
}

fn fsync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Write bytes to a file and fsync it, so a crash can't leave it truncated.
fn write_file_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = std::fs::File::create(path).map_err(|e| Error::Io(e.to_string()))?;
    f.write_all(bytes).map_err(|e| Error::Io(e.to_string()))?;
    f.sync_all().map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

pub fn write_box(path: &Path, payload: &Payload, key: &SyncKey) -> Result<()> {
    let env = seal(payload, key)?;
    let bytes = serde_json::to_vec(&env).map_err(|e| Error::Io(e.to_string()))?;
    // Per-box temp name so sibling boxes (a.x, a.y) don't collide on `a.tmp-moveit`.
    let fname = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "box".into());
    let tmp = path.with_file_name(format!("{fname}.tmp-moveit"));
    write_file_synced(&tmp, &bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| Error::Io(e.to_string()))?;
    if let Some(parent) = path.parent() {
        fsync_dir(parent);
    }
    Ok(())
}

pub fn read_box(path: &Path, key: &SyncKey) -> Result<Payload> {
    let text = std::fs::read(path).map_err(|e| Error::Io(format!("cannot read bundle {}: {e}", path.display())))?;
    let env: Value = serde_json::from_slice(&text)
        .map_err(|_| Error::Corrupt(format!("bundle {} is not valid JSON", path.display())))?;
    unseal(&env, key)
}
