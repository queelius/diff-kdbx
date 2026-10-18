//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use kdbx_core::capture::keepass_0_15::capture;
use kdbx_core::fingerprint::FingerprintKey;
use kdbx_core::model::{Sealing, Snapshot};

/// The published master password of every synthetic fixture.
pub const PW: &str = "test-password-do-not-use";

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Every fixture pair directory (holding `before.kdbx` and `after.kdbx`),
/// by name, sorted.
pub fn pairs() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("before.kdbx").is_file() && p.join("after.kdbx").is_file())
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The fixed key the snapshot tests seal with, so fingerprints in committed
/// snapshots are stable without running the KDF.
pub fn test_key() -> FingerprintKey {
    FingerprintKey::from_bytes([7; 32])
}

/// Open a fixture with the published password and capture it sealed.
pub fn open(relative: &str) -> Snapshot {
    let mut file = std::fs::File::open(fixtures().join(relative)).unwrap();
    let key = keepass::DatabaseKey::new().with_password(PW);
    let db = keepass::Database::open(&mut file, key).unwrap();
    capture(&db, &Sealing::Fingerprint(&test_key()))
}
