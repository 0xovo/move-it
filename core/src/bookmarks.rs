//! Bookmarks store: the Bookmarks file is carried byte for byte, never interpreted.
//!
//! Manifest JSON matches the reference engine: `{"present": false}` or
//! `{"present": true, "size": N, "sha256": "..."}`; the bytes travel separately in the box.
//!
//! Keep-both rule on import:
//! - no local file: write the incoming bytes.
//! - local file with the same hash: nothing to do.
//! - otherwise the local file is left untouched and the incoming bytes are written beside it
//!   as `Bookmarks.moveit-incoming-<UTC stamp>` for a person to reconcile. If a sibling already
//!   holds exactly those bytes, it is reused rather than writing another copy.
//!
//! Nothing is ever replaced, so there is nothing to back up. The rule is symmetric: A into B
//! and B into A each keep their own file and gain the other's as a sibling.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const SIBLING_MARK: &str = ".moveit-incoming-";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Written,
    Identical,
    Conflict,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub carried: bool,
    pub action: Option<Action>,
    pub path: Option<PathBuf>,
}

fn io(e: std::io::Error) -> Error {
    Error::Io(format!("bookmarks file error: {e}"))
}

fn hex_sha256(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the Bookmarks file for the box. A missing file is `{"present": false}` and no bytes.
pub fn export(path: &Path) -> Result<(Manifest, Option<Vec<u8>>)> {
    match fs::read(path) {
        Ok(data) => Ok((
            Manifest { present: true, size: Some(data.len() as u64), sha256: Some(hex_sha256(&data)) },
            Some(data),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((Manifest::default(), None)),
        Err(e) => Err(io(e)),
    }
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time (civil-from-days, proleptic Gregorian).
fn utc_stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io)?;
    }
    fs::write(path, data).map_err(io)
}

/// Place the box's Bookmarks file under the keep-both rule. `data` must match `manifest`.
pub fn import(target: &Path, manifest: &Manifest, data: Option<&[u8]>) -> Result<Report> {
    let mut report = Report::default();
    if !manifest.present {
        return Ok(report);
    }
    let data = data.ok_or_else(|| Error::Corrupt("bundle payload is missing the bytes for its Bookmarks file".into()))?;
    let sha = hex_sha256(data);
    if manifest.size != Some(data.len() as u64) || manifest.sha256.as_deref() != Some(sha.as_str()) {
        return Err(Error::Corrupt("the Bookmarks file in the box does not match its manifest".into()));
    }
    report.carried = true;
    if !target.exists() {
        write_file(target, data)?;
        report.action = Some(Action::Written);
        report.path = Some(target.to_path_buf());
        return Ok(report);
    }
    let local = fs::read(target).map_err(io)?;
    if hex_sha256(&local) == sha {
        report.action = Some(Action::Identical);
        report.path = Some(target.to_path_buf());
        return Ok(report);
    }
    report.action = Some(Action::Conflict);

    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let base = target.file_name().and_then(|n| n.to_str()).unwrap_or("Bookmarks").to_string();
    let prefix = format!("{base}{SIBLING_MARK}");
    // A sibling that already holds exactly these bytes is reused (sorted so the pick is stable).
    let mut siblings: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(io)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect();
    siblings.sort();
    for s in siblings {
        if s.is_file() && fs::read(&s).map(|b| b == data).unwrap_or(false) {
            report.path = Some(s);
            return Ok(report);
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let stamp = utc_stamp(now);
    let mut incoming = dir.join(format!("{prefix}{stamp}"));
    let mut counter = 1;
    while incoming.exists() {
        incoming = dir.join(format!("{prefix}{stamp}-{counter}"));
        counter += 1;
    }
    write_file(&incoming, data)?;
    report.path = Some(incoming);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BM_D: &[u8] = br#"{"checksum": "dummy-d", "roots": {"bookmark_bar": {"children": [], "name": "D"}}}"#;
    const BM_LOCAL: &[u8] = br#"{"checksum": "dummy-local", "roots": {"bookmark_bar": {"children": [], "name": "L"}}}"#;

    fn siblings(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().contains(SIBLING_MARK))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn export_missing_and_present() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Default").join("Bookmarks");
        assert_eq!(export(&p).unwrap(), (Manifest { present: false, size: None, sha256: None }, None));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, BM_D).unwrap();
        let (m, data) = export(&p).unwrap();
        assert!(m.present);
        assert_eq!(m.size, Some(BM_D.len() as u64));
        assert_eq!(m.sha256.as_deref(), Some(hex_sha256(BM_D).as_str()));
        assert_eq!(data.unwrap(), BM_D);
    }

    #[test]
    fn manifest_json_shape_matches_the_reference() {
        assert_eq!(serde_json::to_string(&Manifest::default()).unwrap(), r#"{"present":false}"#);
        let m: Manifest = serde_json::from_str(r#"{"present": true, "size": 3, "sha256": "ab"}"#).unwrap();
        assert_eq!(m, Manifest { present: true, size: Some(3), sha256: Some("ab".into()) });
        assert_eq!(serde_json::to_string(&m).unwrap(), r#"{"present":true,"size":3,"sha256":"ab"}"#);
    }

    #[test]
    fn missing_local_file_is_written() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        fs::write(&src, BM_D).unwrap();
        let (m, data) = export(&src).unwrap();
        let target = t.path().join("Default").join("Bookmarks");
        let r = import(&target, &m, data.as_deref()).unwrap();
        assert_eq!(r.action, Some(Action::Written));
        assert_eq!(fs::read(&target).unwrap(), BM_D);
    }

    #[test]
    fn identical_local_file_is_a_no_op() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        fs::write(&target, BM_D).unwrap();
        let (m, data) = export(&target).unwrap();
        let r = import(&target, &m, data.as_deref()).unwrap();
        assert_eq!(r.action, Some(Action::Identical));
        assert!(siblings(t.path()).is_empty());
    }

    #[test]
    fn conflict_keeps_both_and_does_not_pile_up_copies() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        fs::write(&src, BM_D).unwrap();
        let (m, data) = export(&src).unwrap();
        let target = t.path().join("Bookmarks");
        fs::write(&target, BM_LOCAL).unwrap();
        let r = import(&target, &m, data.as_deref()).unwrap();
        assert_eq!(r.action, Some(Action::Conflict));
        assert_eq!(fs::read(&target).unwrap(), BM_LOCAL, "local file untouched");
        let sib = r.path.unwrap();
        assert_eq!(fs::read(&sib).unwrap(), BM_D);
        // Same bytes again: the same sibling is pointed at, no second copy.
        let r2 = import(&target, &m, data.as_deref()).unwrap();
        assert_eq!(r2.path.unwrap(), sib);
        assert_eq!(siblings(t.path()).len(), 1);
        // Different conflicting bytes get their own sibling, even within the same second.
        let other = br#"{"other": 1}"#;
        let m2 = Manifest { present: true, size: Some(other.len() as u64), sha256: Some(hex_sha256(other)) };
        import(&target, &m2, Some(other)).unwrap();
        assert_eq!(siblings(t.path()).len(), 2);
    }

    #[test]
    fn conflict_is_symmetric_both_directions() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::write(a.join("Bookmarks"), BM_D).unwrap();
        fs::write(b.join("Bookmarks"), BM_LOCAL).unwrap();
        let (ma, da) = export(&a.join("Bookmarks")).unwrap();
        let (mb, db) = export(&b.join("Bookmarks")).unwrap();
        import(&b.join("Bookmarks"), &ma, da.as_deref()).unwrap();
        import(&a.join("Bookmarks"), &mb, db.as_deref()).unwrap();
        assert_eq!(fs::read(siblings(&b)[0].clone()).unwrap(), BM_D);
        assert_eq!(fs::read(siblings(&a)[0].clone()).unwrap(), BM_LOCAL);
        assert_eq!(fs::read(a.join("Bookmarks")).unwrap(), BM_D);
        assert_eq!(fs::read(b.join("Bookmarks")).unwrap(), BM_LOCAL);
    }

    #[test]
    fn absent_in_box_changes_nothing_and_missing_bytes_or_bad_hash_refuse() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("Bookmarks");
        let r = import(&target, &Manifest::default(), None).unwrap();
        assert_eq!(r, Report::default());
        assert!(!target.exists());
        let m = Manifest { present: true, size: Some(BM_D.len() as u64), sha256: Some(hex_sha256(BM_D)) };
        assert!(matches!(import(&target, &m, None), Err(Error::Corrupt(_))));
        assert!(matches!(import(&target, &m, Some(BM_LOCAL)), Err(Error::Corrupt(_))));
        assert!(!target.exists());
    }

    #[test]
    fn stamp_formats_utc() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(1_709_210_096), "20240229T123456Z");
    }
}
