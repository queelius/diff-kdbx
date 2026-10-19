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

/// A new database with a cheap Argon2id KDF (1 MiB, 2 passes, 1 lane), so
/// the fingerprint key derivation runs at the 64 MiB / 3 / 1 floor and the
/// tests stay fast.
pub fn cheap_db(root: uuid::Uuid) -> keepass::Database {
    db_with_kdf(root, 1 << 20, 2)
}

/// A new database whose KDF is Argon2id with `memory` bytes and `iterations`
/// passes on one lane.
pub fn db_with_kdf(root: uuid::Uuid, memory: u64, iterations: u64) -> keepass::Database {
    let mut db = keepass::Database::new_with_root_id(keepass::db::GroupId::from_uuid(root));
    db.config.kdf_config = keepass::config::KdfConfig::Argon2id {
        iterations,
        memory,
        parallelism: 1,
        version: rust_argon2::Version::Version13,
    };
    db
}

/// Save `db` to `path` under `key`.
pub fn save(db: &keepass::Database, path: &Path, key: keepass::DatabaseKey) {
    let mut f = std::fs::File::create(path).unwrap();
    db.save(&mut f, key).unwrap();
}

/// Every `<Times>` value pinned to 2026-01-01T09:00:00Z, so vaults built at
/// different moments compare equal.
pub fn fixed_times() -> keepass::db::Times {
    let when = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
        .and_then(|d| d.and_hms_opt(9, 0, 0))
        .unwrap();
    let mut times = keepass::db::Times::default();
    times.creation = Some(when);
    times.last_modification = Some(when);
    times.last_access = Some(when);
    times.location_changed = Some(when);
    times.expiry = Some(when);
    times.expires = Some(false);
    times.usage_count = Some(0);
    times
}
