//! The Rust sealed box must read what the Python prototype wrote, and the reverse.
//! Fixtures come from tests/make_fixtures.py (run it after any format change).

use std::path::PathBuf;
use std::process::Command;

use base64::Engine;
use moveit_core::sealed::{self, Payload, SyncKey};
use moveit_core::Error;
use serde_json::{Map, Value};

fn fx(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn key() -> SyncKey {
    SyncKey::read_key_file(&fx("key.txt")).unwrap()
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Same flattened shape make_fixtures.py prints.
fn flatten(p: &Payload) -> Value {
    let mut m = p.manifest.clone();
    let files: Map<String, Value> = p.ext_files.iter().map(|(k, v)| (k.clone(), Value::String(b64(v)))).collect();
    m.insert("_ext_files".into(), Value::Object(files));
    m.insert("_bookmarks_b64".into(), p.bookmarks.as_deref().map(|b| Value::String(b64(b))).unwrap_or(Value::Null));
    Value::Object(m)
}

#[test]
fn opens_python_v1_box() {
    let p = sealed::read_box(&fx("v1.box"), &key()).unwrap();
    assert_eq!(p.version(), Some(1));
    assert_eq!(p.manifest["cookies"][0]["name"], "sid");
}

#[test]
fn opens_python_v2_box_exactly() {
    let p = sealed::read_box(&fx("v2.box"), &key()).unwrap();
    let expect: Value = serde_json::from_slice(&std::fs::read(fx("v2.expect.json")).unwrap()).unwrap();
    assert_eq!(flatten(&p), expect);
}

#[test]
fn wrong_key_and_tamper_are_one_error() {
    let wrong = SyncKey::from_bytes([7u8; 32]);
    assert_eq!(sealed::read_box(&fx("v2.box"), &wrong).unwrap_err(), Error::WrongKeyOrTampered);
    let mut env: Value = serde_json::from_slice(&std::fs::read(fx("v2.box")).unwrap()).unwrap();
    let data = env["data"].as_str().unwrap().to_string();
    let mut raw = base64::engine::general_purpose::STANDARD.decode(data).unwrap();
    raw[5] ^= 1;
    env["data"] = Value::String(b64(&raw));
    assert_eq!(sealed::unseal(&env, &key()).unwrap_err(), Error::WrongKeyOrTampered);
}

#[test]
fn round_trip_in_rust() {
    let p = sealed::read_box(&fx("v2.box"), &key()).unwrap();
    let env = sealed::seal(&p, &key()).unwrap();
    assert_eq!(sealed::unseal(&env, &key()).unwrap(), p);
}

#[test]
fn refuses_path_escape_in_manifest() {
    for bad in [
        "Local Extension Settings/../../etc/passwd",
        "Local Extension Settings/id",
        "Cookies/x/y",
        "IndexedDB/https_example.com_0/x",
        "IndexedDB/chrome-extension_a..b_0/x",
        "Local Extension Settings/id//x",
    ] {
        assert!(sealed::validate_ext_logical_path(bad).is_err(), "{bad} should be refused");
    }
    assert!(sealed::validate_ext_logical_path("IndexedDB/chrome-extension_abc_0/x/y").is_ok());
}

/// Python must open a box Rust sealed. Skipped (with a note) when the reference is not on this machine.
#[test]
fn python_opens_rust_box() {
    let (Ok(py), Ok(refdir)) = (std::env::var("MOVEIT_REF_PY"), std::env::var("MOVEIT_REF_DIR")) else {
        eprintln!("skip: set MOVEIT_REF_PY and MOVEIT_REF_DIR to cross-check against the Python prototype");
        return;
    };
    let p = sealed::read_box(&fx("v2.box"), &key()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("rust.box");
    sealed::write_box(&out, &p, &key()).unwrap();
    let res = Command::new(py)
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/make_fixtures.py"))
        .arg(refdir)
        .arg("--verify")
        .arg(&out)
        .output()
        .unwrap();
    assert!(res.status.success(), "python failed: {}", String::from_utf8_lossy(&res.stderr));
    let got: Value = serde_json::from_slice(&res.stdout).unwrap();
    assert_eq!(got, flatten(&p));
}
