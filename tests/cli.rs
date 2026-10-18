//! CLI behavior beyond the fixture pairs: key resolution, the fingerprint
//! subcommand, flags. Each test builds its own cheap vault in a tempdir.

mod common;

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use keepass::DatabaseKey;
use keepass::db::{EntryId, fields};
use predicates::prelude::*;
use tempfile::TempDir;
use uuid::Uuid;

const ROOT: u128 = 0x0000_0001_c11c_4000_8000_0000_0000_0000;
const BANK: u128 = 0x0000_0011_c11c_4000_8000_0000_0000_0000;

fn cmd() -> Command {
    let mut c = Command::cargo_bin("diff-kdbx").unwrap();
    c.env_remove("KDBX_DIFF_PASSWORD")
        .env_remove("KDBX_DIFF_PASSWORD_A")
        .env_remove("KDBX_DIFF_PASSWORD_B");
    c
}

/// A one-entry vault: Root / Bank (Password "hunter2", protected).
fn bank_vault(dir: &Path, name: &str, key: DatabaseKey) -> PathBuf {
    bank_vault_with(dir, name, key, common::cheap_db(Uuid::from_u128(ROOT)))
}

fn bank_vault_with(dir: &Path, name: &str, key: DatabaseKey, db: keepass::Database) -> PathBuf {
    bank_vault_full(dir, name, key, db, "hunter2")
}

fn bank_vault_full(
    dir: &Path,
    name: &str,
    key: DatabaseKey,
    mut db: keepass::Database,
    password: &str,
) -> PathBuf {
    db.root_mut().name = "Root".into();
    {
        let mut root = db.root_mut();
        let mut bank = root
            .add_entry_with_id(EntryId::from_uuid(Uuid::from_u128(BANK)))
            .unwrap();
        bank.set_unprotected(fields::TITLE, "Bank");
        bank.set_protected(fields::PASSWORD, password);
        bank.times = common::fixed_times();
    }
    db.root_mut().times = common::fixed_times();
    let path = dir.join(name);
    common::save(&db, &path, key);
    path
}

fn keyfile(dir: &Path) -> PathBuf {
    let path = dir.join("vault.key");
    std::fs::write(&path, b"a key file with arbitrary content\n").unwrap();
    path
}

fn keyfile_key(path: &Path) -> DatabaseKey {
    let bytes = std::fs::read(path).unwrap();
    DatabaseKey::new()
        .with_keyfile(&mut bytes.as_slice())
        .unwrap()
}

fn stdout(c: &mut Command) -> String {
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "exit {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn key_file_only_vault_opens_without_a_password() {
    let tmp = TempDir::new().unwrap();
    let kf = keyfile(tmp.path());
    let vault = bank_vault(tmp.path(), "v.kdbx", keyfile_key(&kf));
    // Non-interactive (textconv): a key file alone is the key.
    let out = stdout(
        cmd()
            .arg("--textconv")
            .arg(&vault)
            .arg("--key-file")
            .arg(&kf),
    );
    assert!(out.contains("ENTRY \"/Bank\" [uuid:"), "{out}");
    // --no-password makes it explicit, even with a password in the
    // environment.
    let out = stdout(
        cmd()
            .env("KDBX_DIFF_PASSWORD", "ignored")
            .args(["--no-password", "--key-file"])
            .arg(&kf)
            .arg("--textconv")
            .arg(&vault),
    );
    assert!(out.contains("  Password: <sealed:"), "{out}");
}

#[test]
fn no_password_requires_a_key_file() {
    let tmp = TempDir::new().unwrap();
    let vault = bank_vault(tmp.path(), "v.kdbx", DatabaseKey::new().with_password("pw"));
    cmd()
        .arg("--no-password")
        .arg("--textconv")
        .arg(&vault)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("--no-password needs --key-file"));
}

#[test]
fn password_and_key_file_together() {
    let tmp = TempDir::new().unwrap();
    let kf = keyfile(tmp.path());
    let vault = bank_vault(tmp.path(), "v.kdbx", keyfile_key(&kf).with_password("pw"));
    cmd()
        .env("KDBX_DIFF_PASSWORD", "pw")
        .arg("--key-file")
        .arg(&kf)
        .arg("--textconv")
        .arg(&vault)
        .assert()
        .success();
    // The key file alone does not open it.
    cmd()
        .arg("--key-file")
        .arg(&kf)
        .arg("--textconv")
        .arg(&vault)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());
}

#[test]
fn fingerprint_subcommand_matches_the_dump() {
    let tmp = TempDir::new().unwrap();
    let vault = bank_vault(tmp.path(), "v.kdbx", DatabaseKey::new().with_password("pw"));
    let by_path = stdout(
        cmd()
            .env("KDBX_DIFF_PASSWORD", "pw")
            .args(["fingerprint", "--field", "Password", "--entry", "/Bank"])
            .arg(&vault),
    );
    let hex = by_path.trim_end();
    assert_eq!(hex.len(), 64, "{by_path:?}");
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    let by_uuid = stdout(
        cmd()
            .env("KDBX_DIFF_PASSWORD", "pw")
            .args(["fingerprint", "--field", "Password", "--entry"])
            .arg(Uuid::from_u128(BANK).to_string())
            .arg(&vault),
    );
    assert_eq!(by_path, by_uuid);
    let dump = stdout(
        cmd()
            .env("KDBX_DIFF_PASSWORD", "pw")
            .arg("--textconv")
            .arg(&vault),
    );
    assert!(
        dump.contains(&format!("  Password: <sealed:{}>\n", &hex[..8])),
        "{hex}\n{dump}"
    );
    // A plain field has a fingerprint too (it is just never needed).
    stdout(
        cmd()
            .env("KDBX_DIFF_PASSWORD", "pw")
            .args(["fingerprint", "--field", "Title", "--entry", "/Bank"])
            .arg(&vault),
    );
}

#[test]
fn fingerprint_subcommand_errors() {
    let tmp = TempDir::new().unwrap();
    let vault = bank_vault(tmp.path(), "v.kdbx", DatabaseKey::new().with_password("pw"));
    for (field, entry, message) in [
        ("PIN", "/Bank", "has no field"),
        ("Password", "/Nope", "entry \"/Nope\""),
        ("Password", "Bank", "invalid entry path"),
        ("Password", "/Bank/", "addresses a group"),
    ] {
        cmd()
            .env("KDBX_DIFF_PASSWORD", "pw")
            .args(["fingerprint", "--field", field, "--entry", entry])
            .arg(&vault)
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(message));
    }
}

#[test]
fn separate_keys_compare_unchanged_secrets_equal() {
    let tmp = TempDir::new().unwrap();
    let a = bank_vault(
        tmp.path(),
        "a.kdbx",
        DatabaseKey::new().with_password("pw-a"),
    );
    let b = bank_vault(
        tmp.path(),
        "b.kdbx",
        DatabaseKey::new().with_password("pw-b"),
    );
    let out = cmd()
        .env("KDBX_DIFF_PASSWORD_A", "pw-a")
        .env("KDBX_DIFF_PASSWORD_B", "pw-b")
        .arg("--separate-keys")
        .args([&a, &b])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("(no changes)"));
    // One shared key cannot open both, and the error says what to try.
    cmd()
        .env("KDBX_DIFF_PASSWORD", "pw-a")
        .args([&a, &b])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--separate-keys"));
}

#[test]
fn json_records_how_the_fingerprint_key_was_derived() {
    let tmp = TempDir::new().unwrap();
    let a = bank_vault(tmp.path(), "a.kdbx", DatabaseKey::new().with_password("pw"));
    let out = cmd()
        .env("KDBX_DIFF_PASSWORD", "pw")
        .arg("--format=json")
        .args([&a, &a])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["format_version"], 1);
    assert_eq!(
        v["fingerprint_key"],
        serde_json::json!({
            "params": "argon2id$v=19$m=65536,t=3,p=1",
            "salt": Uuid::from_u128(ROOT).to_string()
        })
    );
}

#[test]
fn show_secrets_reveals_and_warns_on_a_pipe() {
    let tmp = TempDir::new().unwrap();
    let vault = bank_vault(tmp.path(), "v.kdbx", DatabaseKey::new().with_password("pw"));
    cmd()
        .env("KDBX_DIFF_PASSWORD", "pw")
        .args(["--show-secrets", "--dump"])
        .arg(&vault)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "  Password: \"hunter2\" (protected)\n",
        ))
        .stderr(predicate::str::contains(
            "--show-secrets with non-TTY stdout",
        ));
}

#[test]
fn color_flag_is_gone() {
    cmd().args(["--color", "a.kdbx", "b.kdbx"]).assert().code(2);
}

/// A two-file diff derives its key with the costlier of the two vaults'
/// parameters as a whole (memory x passes), never a per-component mix that
/// neither vault uses.
#[test]
fn two_file_key_uses_the_stronger_vaults_parameters() {
    let tmp = TempDir::new().unwrap();
    let a = bank_vault(tmp.path(), "a.kdbx", DatabaseKey::new().with_password("pw"));
    // 32 MiB x 8 passes costs more than the 64 MiB x 3 floor.
    let strong = common::db_with_kdf(Uuid::from_u128(ROOT), 32 << 20, 8);
    let b = bank_vault_with(
        tmp.path(),
        "b.kdbx",
        DatabaseKey::new().with_password("pw"),
        strong,
    );
    for (x, y) in [(&a, &b), (&b, &a)] {
        let out = cmd()
            .env("KDBX_DIFF_PASSWORD", "pw")
            .arg("--format=json")
            .args([x, y])
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            v["fingerprint_key"]["params"],
            "argon2id$v=19$m=32768,t=8,p=1"
        );
    }
}

/// --key-file names one key for both files; with --separate-keys that is
/// ambiguous, so it is refused instead of silently ignored.
#[test]
fn separate_keys_reject_a_shared_key_file() {
    let tmp = TempDir::new().unwrap();
    let kf = keyfile(tmp.path());
    let a = bank_vault(tmp.path(), "a.kdbx", keyfile_key(&kf));
    cmd()
        .arg("--separate-keys")
        .arg("--key-file")
        .arg(&kf)
        .args([&a, &a])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("--key-file-a"));
    // Per-side key files work.
    cmd()
        .arg("--separate-keys")
        .arg("--key-file-a")
        .arg(&kf)
        .arg("--key-file-b")
        .arg(&kf)
        .args([&a, &a])
        .assert()
        .code(0);
}

/// An empty password variable with a key file means "no password", as an
/// empty interactive answer does.
#[test]
fn empty_password_variable_with_a_key_file_means_no_password() {
    let tmp = TempDir::new().unwrap();
    let kf = keyfile(tmp.path());
    let vault = bank_vault(tmp.path(), "v.kdbx", keyfile_key(&kf));
    cmd()
        .env("KDBX_DIFF_PASSWORD", "")
        .arg("--key-file")
        .arg(&kf)
        .arg("--textconv")
        .arg(&vault)
        .assert()
        .success();
    // Without a key file, an empty variable is an empty password.
    let empty = bank_vault(tmp.path(), "e.kdbx", DatabaseKey::new().with_password(""));
    cmd()
        .env("KDBX_DIFF_PASSWORD", "")
        .arg("--textconv")
        .arg(&empty)
        .assert()
        .success();
}

/// Every `"sealed"` string in a JSON document, in document order.
fn sealed_values(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                match (k.as_str(), child) {
                    ("sealed", serde_json::Value::String(s)) => out.push(s.clone()),
                    _ => sealed_values(child, out),
                }
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| sealed_values(i, out)),
        _ => {}
    }
}

/// A two-file diff seals B's values with A's key: its params and salt are
/// recorded in the JSON, and `fingerprint --params --salt` reproduces them.
#[test]
fn fingerprint_subcommand_verifies_a_two_file_diff() {
    let tmp = TempDir::new().unwrap();
    let a = bank_vault(tmp.path(), "a.kdbx", DatabaseKey::new().with_password("pw"));
    let other_root = common::cheap_db(Uuid::from_u128(ROOT + 1));
    let b = bank_vault_full(
        tmp.path(),
        "b.kdbx",
        DatabaseKey::new().with_password("pw"),
        other_root,
        "rotated",
    );
    let out = cmd()
        .env("KDBX_DIFF_PASSWORD", "pw")
        .arg("--format=json")
        .args([&a, &b])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut sealed = Vec::new();
    sealed_values(&v["changes"], &mut sealed);
    assert_eq!(sealed.len(), 2, "A's and B's sealed passwords: {v}");
    // The recorded parameters are exactly what --params accepts.
    let params = v["fingerprint_key"]["params"].as_str().unwrap().to_owned();
    let salt = v["fingerprint_key"]["salt"].as_str().unwrap().to_owned();
    let verify = |extra: &[&str]| {
        stdout(
            cmd()
                .env("KDBX_DIFF_PASSWORD", "pw")
                .args(["fingerprint", "--field", "Password", "--entry", "/Bank"])
                .args(extra)
                .arg(&b),
        )
        .trim_end()
        .to_owned()
    };
    // B's password, under A's recorded key.
    let b_value = verify(&["--params", &params, "--salt", &salt]);
    assert!(sealed.contains(&b_value), "{b_value} not in {sealed:?}");
    // B's own salt (its root UUID) gives a different key.
    assert!(!sealed.contains(&verify(&["--params", &params])));
}

#[test]
fn fingerprint_subcommand_rejects_bad_params() {
    let tmp = TempDir::new().unwrap();
    let vault = bank_vault(tmp.path(), "v.kdbx", DatabaseKey::new().with_password("pw"));
    for (params, message) in [
        ("argon2id$v=19$m=1024,t=1,p=1", "below the floor"),
        ("argon2id$v=19$m=65536,t=3,p=0", "below the floor"),
        (
            "argon2d$v=19$m=65536,t=3,p=1",
            "argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>",
        ),
        (
            "argon2id$v=19$m=65536,t=3",
            "argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>",
        ),
        (
            "argon2id$v=19$m=x,t=3,p=1",
            "argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>",
        ),
    ] {
        cmd()
            .env("KDBX_DIFF_PASSWORD", "pw")
            .args([
                "fingerprint",
                "--field",
                "Password",
                "--entry",
                "/Bank",
                "--params",
                params,
            ])
            .arg(&vault)
            .assert()
            .code(2)
            .stderr(predicate::str::contains(message));
    }
    cmd()
        .env("KDBX_DIFF_PASSWORD", "pw")
        .args([
            "fingerprint",
            "--field",
            "Password",
            "--entry",
            "/Bank",
            "--salt",
            "nope",
        ])
        .arg(&vault)
        .assert()
        .code(2);
}
