//! Pairing: how your other device gets the sync key without anyone seeing or typing it.
//!
//! The two devices may never be awake at the same time (dual boot is the main case), so
//! pairing cannot be a live conversation. It goes through the place both already reach:
//!
//! 1. Device A makes a fresh sync key, shows a short code, and leaves an offer file in the
//!    shared place: the sync key sealed with a key stretched from the code by Argon2id
//!    (64 MiB, 3 passes, random salt). The code itself is never written anywhere.
//! 2. Device B, whenever it next runs, reads the offer, asks for the code, and opens it.
//!    A wrong code is a friendly "try again"; after [`MAX_TRIES`] wrong codes on this device
//!    the offer is refused and A must show a new code.
//! 3. B writes a small "paired" note sealed with the sync key itself. When A sees it, A deletes
//!    the offer, so the guessable file lives in the shared place only until B has paired.
//!    Offers also expire after [`OFFER_TTL_SECS`].
//!
//! Threat note: whoever holds the offer file can try codes offline, so the stretch is
//! deliberately slow and the code length is a parameter (6 digits by default, longer allowed).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::sealed::SyncKey;
use crate::{Error, Result};

pub const OFFER_FILE: &str = "moveit-pairing.json";
pub const PAIRED_FILE: &str = "moveit-paired.json";
pub const OFFER_TTL_SECS: u64 = 600;
pub const MAX_TRIES: u32 = 10;
const KDF_MIB: u32 = 64;
const KDF_PASSES: u32 = 3;

#[derive(Serialize, Deserialize)]
struct Offer {
    v: u32,
    from: String,
    created: u64,
    salt: String,
    nonce: String,
    data: String,
    m_kib: u32,
    t: u32,
}

#[derive(Serialize, Deserialize)]
struct Paired {
    v: u32,
    nonce: String,
    /// The paired device's name, sealed with the sync key.
    data: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| Error::Io(format!("no randomness: {e}")))?;
    Ok(b)
}

/// Normalise what a person types: keep digits and letters, drop spaces and dashes, lowercase.
pub fn normalise_code(typed: &str) -> String {
    typed.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

/// A fresh numeric code, shown as "482 913".
pub fn new_code(digits: usize) -> Result<String> {
    let digits = digits.clamp(6, 12);
    let mut out = String::new();
    while out.len() < digits {
        // Rejection sampling keeps every digit uniform.
        for b in random::<16>()? {
            if b < 250 && out.len() < digits {
                out.push(char::from(b'0' + b % 10));
            }
        }
    }
    Ok(out)
}

pub fn display_code(code: &str) -> String {
    let c: Vec<char> = code.chars().collect();
    c.chunks(3).map(|g| g.iter().collect::<String>()).collect::<Vec<_>>().join(" ")
}

fn stretch(code: &str, salt: &[u8], m_kib: u32, t: u32) -> Result<[u8; 32]> {
    let params = Params::new(m_kib, t, 1, Some(32)).map_err(|e| Error::Io(format!("kdf params: {e}")))?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(normalise_code(code).as_bytes(), salt, &mut out)
        .map_err(|e| Error::Io(format!("kdf: {e}")))?;
    Ok(out)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::util::atomic_write(path, bytes)
}

/// Device A: leave an offer in `place` for `key`, guarded by `code`.
pub fn offer(place: &Path, key: &SyncKey, code: &str, this_device: &str) -> Result<()> {
    offer_with_cost(place, key, code, this_device, KDF_MIB * 1024, KDF_PASSES)
}

fn offer_with_cost(place: &Path, key: &SyncKey, code: &str, from: &str, m_kib: u32, t: u32) -> Result<()> {
    let salt = random::<16>()?;
    let nonce = random::<12>()?;
    let k = stretch(code, &salt, m_kib, t)?;
    let data = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k))
        .encrypt(Nonce::from_slice(&nonce), key.to_key_file_text().trim().as_bytes())
        .map_err(|_| Error::Io("sealing the offer failed".into()))?;
    let o = Offer {
        v: 1,
        from: from.to_string(),
        created: now(),
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        data: B64.encode(data),
        m_kib,
        t,
    };
    let _ = std::fs::remove_file(place.join(PAIRED_FILE));
    write_atomic(&place.join(OFFER_FILE), &serde_json::to_vec(&o).map_err(|e| Error::Io(e.to_string()))?)
}

/// What device B finds in the shared place.
#[derive(Debug, PartialEq)]
pub enum Found {
    /// No offer: show "open Move It on your other device first".
    Nothing,
    /// An offer from this device name, waiting for the code.
    Waiting { from: String },
    /// Too old: ask the other device for a new code.
    Expired,
}

pub fn look(place: &Path) -> Result<Found> {
    match read_offer(place)? {
        None => Ok(Found::Nothing),
        Some(o) if now().saturating_sub(o.created) > OFFER_TTL_SECS => Ok(Found::Expired),
        Some(o) => Ok(Found::Waiting { from: o.from }),
    }
}

fn read_offer(place: &Path) -> Result<Option<Offer>> {
    match std::fs::read(place.join(OFFER_FILE)) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|_| Error::Corrupt("the pairing note is damaged".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e.to_string())),
    }
}

/// Counts wrong codes on this device, per offer.
pub struct Tries {
    pub path: PathBuf,
}

impl Tries {
    fn read(&self, offer_id: &str) -> Result<u32> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(Error::Io(format!(
                    "cannot read the pairing tries: {e}"
                )))
            }
        };
        let mut parts = text.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some(id), Some(n)) if id == offer_id => n
                .parse()
                .map_err(|_| Error::Io("the pairing tries file is damaged".into())),
            _ => Ok(0),
        }
    }

    fn write(&self, offer_id: &str, n: u32) -> Result<()> {
        // Fail closed: if the try count cannot be saved, refuse rather than letting
        // wrong codes be retried without limit.
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io(format!("cannot record pairing tries: {e}")))?;
        }
        crate::util::atomic_write(&self.path, format!("{offer_id} {n}").as_bytes())
            .map_err(|e| match e {
                Error::Io(m) => Error::Io(format!("cannot record pairing tries: {m}")),
                other => other,
            })
    }
}

/// Tell device A who paired, sealed with the key both devices now share,
/// so only A can read the name. Called by the accepting device only after
/// the key is safely stored on it: a note without a stored key would tell
/// A a pairing happened that this device cannot use.
pub fn leave_paired_note(place: &Path, key: &SyncKey, this_device: &str) -> Result<()> {
    let n = random::<12>()?;
    let note = key.seal_small(&n, this_device.as_bytes())?;
    let p = Paired { v: 1, nonce: B64.encode(n), data: B64.encode(note) };
    write_atomic(
        &place.join(PAIRED_FILE),
        &serde_json::to_vec(&p).map_err(|e| Error::Io(e.to_string()))?,
    )
}

/// Result of typing a code on device B.
#[derive(Debug)]
pub enum Accept {
    Paired(SyncKey),
    WrongCode { tries_left: u32 },
    /// Too many wrong codes, or the offer expired: ask for a new code.
    NeedNewCode,
    Nothing,
}

/// Device B: open an offer. Callers that store keys use [`accept_and_store`].
pub fn accept(place: &Path, code: &str, _this_device: &str, tries: &Tries) -> Result<Accept> {
    let Some(o) = read_offer(place)? else { return Ok(Accept::Nothing) };
    if now().saturating_sub(o.created) > OFFER_TTL_SECS {
        return Ok(Accept::NeedNewCode);
    }
    let used = tries.read(&o.salt)?;
    if used >= MAX_TRIES {
        return Ok(Accept::NeedNewCode);
    }
    // The try is spent before the expensive stretch runs: killing the
    // process mid-stretch must not hand the try back.
    tries.write(&o.salt, used + 1)?;
    let dec = |s: &str| B64.decode(s).map_err(|_| Error::Corrupt("the pairing note is damaged".into()));
    let (salt, nonce, data) = (dec(&o.salt)?, dec(&o.nonce)?, dec(&o.data)?);
    if nonce.len() != 12 {
        return Err(Error::Corrupt("the pairing note is damaged".into()));
    }
    // The offer file names its own Argon2 cost. A tampered offer could ask for gigabytes of
    // memory to stall or crash this device, so refuse anything past our own ceiling.
    if o.m_kib > KDF_MIB * 1024 || o.t > KDF_PASSES || o.m_kib == 0 || o.t == 0 {
        return Err(Error::Corrupt("the pairing note is damaged".into()));
    }
    let k = stretch(code, &salt, o.m_kib, o.t)?;
    let Ok(plain) = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k)).decrypt(Nonce::from_slice(&nonce), data.as_slice())
    else {
        let left = MAX_TRIES - used - 1;
        return Ok(if left == 0 { Accept::NeedNewCode } else { Accept::WrongCode { tries_left: left } });
    };
    let key = SyncKey::from_key_file_text(std::str::from_utf8(&plain).unwrap_or_default())?;
    Ok(Accept::Paired(key))
}

/// Accept and spend an offer only after the caller has durably stored its key.
pub fn accept_and_store(
    place: &Path,
    code: &str,
    this_device: &str,
    tries: &Tries,
    store: &dyn Fn(&SyncKey) -> Result<()>,
) -> Result<Accept> {
    let accepted = accept(place, code, this_device, tries)?;
    if let Accept::Paired(key) = &accepted {
        store(key)?;
        let _ = std::fs::remove_file(place.join(OFFER_FILE));
        let _ = std::fs::remove_file(&tries.path);
    }
    Ok(accepted)
}

/// Device A, on every start: if the other device has paired, delete the offer and return its name.
pub fn check_paired(place: &Path, key: &SyncKey) -> Result<Option<String>> {
    let raw = match std::fs::read(place.join(PAIRED_FILE)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Clean up an expired, unused offer.
            if let Some(o) = read_offer(place)? {
                if now().saturating_sub(o.created) > OFFER_TTL_SECS {
                    let _ = std::fs::remove_file(place.join(OFFER_FILE));
                }
            }
            return Ok(None);
        }
        Err(e) => return Err(Error::Io(e.to_string())),
    };
    let p: Paired = serde_json::from_slice(&raw).map_err(|_| Error::Corrupt("the paired note is damaged".into()))?;
    let dec = |s: &str| B64.decode(s).map_err(|_| Error::Corrupt("the paired note is damaged".into()));
    let name = key.open_small(&dec(&p.nonce)?, &dec(&p.data)?)?;
    let _ = std::fs::remove_file(place.join(OFFER_FILE));
    let _ = std::fs::remove_file(place.join(PAIRED_FILE));
    Ok(Some(String::from_utf8_lossy(&name).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap KDF cost in tests; the shipped cost is checked separately.
    fn offer_cheap(place: &Path, key: &SyncKey, code: &str) {
        offer_with_cost(place, key, code, "fedora", 64, 1).unwrap();
    }

    #[test]
    fn a_failed_key_store_keeps_the_offer_for_a_retry() {
        let shared = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let key = SyncKey::generate().unwrap();
        offer_cheap(shared.path(), &key, "482913");
        let tries = Tries { path: state.path().join("tries") };
        let fail = |_: &SyncKey| Err(Error::KeychainUnavailable("locked".into()));
        assert!(accept_and_store(shared.path(), "482913", "b", &tries, &fail).is_err());
        assert!(shared.path().join(OFFER_FILE).exists());
        assert!(tries.path.exists());
        let store = crate::keychain::MemoryStore::default();
        let save = |key: &SyncKey| crate::keychain::KeyStore::store(&store, "b", key);
        assert!(matches!(accept_and_store(shared.path(), "482913", "b", &tries, &save).unwrap(), Accept::Paired(_)));
        assert!(crate::keychain::KeyStore::load(&store, "b").unwrap().is_some());
        assert!(!shared.path().join(OFFER_FILE).exists());
        assert!(!tries.path.exists());
    }

    #[test]
    fn full_pairing_through_a_shared_folder() {
        let shared = tempfile::tempdir().unwrap();
        let b_state = tempfile::tempdir().unwrap();
        let key = SyncKey::generate().unwrap();
        offer_cheap(shared.path(), &key, "482913");
        assert!(!std::fs::read_to_string(shared.path().join(OFFER_FILE)).unwrap().contains("482913"));
        assert_eq!(look(shared.path()).unwrap(), Found::Waiting { from: "fedora".into() });
        let tries = Tries { path: b_state.path().join("tries") };
        let Accept::Paired(got) = accept(shared.path(), "482 913", "windows", &tries).unwrap() else { panic!() };
        assert_eq!(got.to_key_file_text(), key.to_key_file_text());
        // The caller leaves the note only after the key is stored on its side.
        leave_paired_note(shared.path(), &got, "windows").unwrap();
        assert_eq!(check_paired(shared.path(), &key).unwrap(), Some("windows".into()));
        assert_eq!(look(shared.path()).unwrap(), Found::Nothing, "offer is gone once paired");
    }

    #[test]
    fn wrong_codes_count_down_then_need_a_new_code() {
        let shared = tempfile::tempdir().unwrap();
        let b_state = tempfile::tempdir().unwrap();
        let key = SyncKey::generate().unwrap();
        offer_cheap(shared.path(), &key, "482913");
        let tries = Tries { path: b_state.path().join("tries") };
        for left in (1..MAX_TRIES).rev() {
            match accept(shared.path(), "000000", "b", &tries).unwrap() {
                Accept::WrongCode { tries_left } => assert_eq!(tries_left, left),
                other => panic!("{other:?}"),
            }
        }
        assert!(matches!(accept(shared.path(), "000000", "b", &tries).unwrap(), Accept::NeedNewCode));
        assert!(matches!(accept(shared.path(), "482913", "b", &tries).unwrap(), Accept::NeedNewCode), "locked out even with the right code");
        // A new offer (new salt) resets the count.
        offer_cheap(shared.path(), &key, "111222");
        assert!(matches!(accept(shared.path(), "111222", "b", &tries).unwrap(), Accept::Paired(_)));
    }

    #[test]
    fn codes_are_uniform_digits_and_display_in_groups() {
        let c = new_code(6).unwrap();
        assert_eq!(c.len(), 6);
        assert!(c.chars().all(|ch| ch.is_ascii_digit()));
        assert_eq!(display_code("482913"), "482 913");
        assert_eq!(normalise_code(" 482-913 "), "482913");
    }

    #[test]
    fn shipped_kdf_cost_is_the_slow_one() {
        assert_eq!((KDF_MIB, KDF_PASSES), (64, 3));
    }

    #[test]
    fn unwritable_try_count_fails_closed() {
        let shared = tempfile::tempdir().unwrap();
        let key = SyncKey::generate().unwrap();
        offer_cheap(shared.path(), &key, "482913");
        // Point the try counter at a path whose parent is a file: create_dir_all fails.
        let blocker = shared.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let tries = Tries { path: blocker.join("tries") };
        let err = accept(shared.path(), "000000", "b", &tries).unwrap_err();
        assert!(matches!(err, Error::Io(ref m) if m.contains("pairing tries")), "{err:?}");
        // A later attempt with a working counter still sees zero used tries (nothing was stored).
        let ok_state = tempfile::tempdir().unwrap();
        let tries = Tries { path: ok_state.path().join("tries") };
        assert!(matches!(accept(shared.path(), "000000", "b", &tries).unwrap(), Accept::WrongCode { tries_left: 9 }));
    }
}
