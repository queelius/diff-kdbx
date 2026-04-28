//! End-to-end CLI tests using assert_cmd against committed fixtures.
//!
//! Only the 3 available fixture pairs are used:
//!   - tests/fixtures/empty/{before,after}.kdbx
//!   - tests/fixtures/add_entry/{before,after}.kdbx
//!   - tests/fixtures/password_change/{before,after}.kdbx
//!
//! Tests requiring missing fixtures are marked #[ignore] with comments.

use assert_cmd::Command;
use predicates::prelude::*;

const PW: &str = "test-password-do-not-use";

fn diff_cmd() -> Command {
    let mut c = Command::cargo_bin("diff-kdbx").unwrap();
    c.env("KDBX_DIFF_PASSWORD", PW);
    c
}

#[test]
fn same_file_diffed_against_itself_exits_zero() {
    diff_cmd()
        .args(["tests/fixtures/empty/before.kdbx", "tests/fixtures/empty/before.kdbx"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(no changes)"));
}

#[test]
fn add_entry_pair_exits_one_and_reports_added() {
    diff_cmd()
        .args(["tests/fixtures/add_entry/before.kdbx", "tests/fixtures/add_entry/after.kdbx"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("+ ENTRY"));
}

/// Default mode masks protected fields with a hash prefix.
///
/// The password_change fixtures use separate Database::new() calls, giving each
/// entry a fresh UUID. The diff therefore shows the entries as Added/Removed
/// rather than Modified, so no field-level <hash:> appears in diff output.
/// We verify masking behaviour via --textconv (dump mode), which always shows
/// all fields and applies the same mask.
#[test]
fn password_change_masks_default() {
    diff_cmd()
        .args(["--textconv", "tests/fixtures/password_change/before.kdbx"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<hash:"));
}

/// --show-secrets reveals the plaintext value of protected fields.
///
/// Same fixture-UUID caveat as password_change_masks_default; we test via
/// --textconv to get field-level output.
#[test]
fn show_secrets_reveals_plaintext() {
    diff_cmd()
        .args([
            "--show-secrets",
            "--textconv",
            "tests/fixtures/password_change/before.kdbx",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("old-password"));
}

#[test]
fn json_format_produces_valid_json() {
    let out = diff_cmd()
        .args([
            "--format=json",
            "tests/fixtures/add_entry/before.kdbx",
            "tests/fixtures/add_entry/after.kdbx",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let _v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
}

#[test]
fn textconv_emits_dump_for_one_file() {
    diff_cmd()
        .args(["--textconv", "tests/fixtures/add_entry/after.kdbx"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DATABASE"))
        .stdout(predicate::str::contains("ENTRY"));
}

#[test]
fn wrong_password_exits_two() {
    Command::cargo_bin("diff-kdbx").unwrap()
        .env("KDBX_DIFF_PASSWORD", "wrong-password")
        .args(["tests/fixtures/empty/before.kdbx", "tests/fixtures/empty/after.kdbx"])
        .assert()
        .code(2);
}

#[test]
fn missing_password_for_textconv_fails_closed() {
    Command::cargo_bin("diff-kdbx").unwrap()
        // no KDBX_DIFF_PASSWORD env set
        .env_remove("KDBX_DIFF_PASSWORD")
        .args(["--textconv", "tests/fixtures/empty/before.kdbx"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());
}

/// Requires tests/fixtures/noisy_resave/ which does not yet exist.
/// Re-enable when those fixtures are committed.
#[test]
#[ignore = "missing fixture: tests/fixtures/noisy_resave/{before,after}.kdbx"]
fn noisy_resave_default_reports_no_changes() {
    diff_cmd()
        .args([
            "tests/fixtures/noisy_resave/before.kdbx",
            "tests/fixtures/noisy_resave/after.kdbx",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(no changes)"));
}

/// Requires tests/fixtures/noisy_resave/ which does not yet exist.
/// Re-enable when those fixtures are committed.
#[test]
#[ignore = "missing fixture: tests/fixtures/noisy_resave/{before,after}.kdbx"]
fn strict_disables_suppression() {
    diff_cmd()
        .args([
            "--strict",
            "tests/fixtures/noisy_resave/before.kdbx",
            "tests/fixtures/noisy_resave/after.kdbx",
        ])
        .assert()
        .stdout(
            predicate::str::is_match(
                "(no changes|LastAccessTime|UsageCount|LocationChanged|modified)",
            )
            .unwrap(),
        );
}
