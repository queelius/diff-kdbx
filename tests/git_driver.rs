//! Git driver integration tests.
//!
//! Exercises the diff-kdbx textconv driver against a real `git` binary in a
//! tempdir. No network, no GitHub, no state on the test machine outside the
//! tempdir.
//!
//! Each test sets up a fresh tempdir-backed git repo, configures the textconv
//! driver, commits one or more KDBX fixtures, and asserts on the output of
//! real `git diff` / `git log -p` / `git show` invocations.
//!
//! Layer 4 of the test pyramid (see docs/testing.md).

use assert_cmd::cargo::cargo_bin;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const PW: &str = "test-password-do-not-use";

/// Run `git` in the given directory with KDBX_DIFF_PASSWORD set, panicking on
/// nonzero exit. Returns stdout/stderr captured.
fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("KDBX_DIFF_PASSWORD", PW)
        .output()
        .expect("git command failed to spawn");
    if !out.status.success() {
        panic!(
            "git {:?} failed (exit={:?})\nstdout:\n{}\nstderr:\n{}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    out
}

/// Like `git()` but tolerates nonzero exit (returns whatever git did).
fn git_no_panic(repo: &Path, args: &[&str], password: &str) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("KDBX_DIFF_PASSWORD", password)
        .output()
        .expect("git command failed to spawn")
}

/// Initialize a fresh repo in `dir` and configure the diff-kdbx textconv driver
/// for *.kdbx files. The driver path is set to the test-built diff-kdbx binary.
fn setup_repo(dir: &Path) {
    let bin = cargo_bin("diff-kdbx");
    let bin_str = bin.to_str().expect("binary path is UTF-8");

    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["config", "user.email", "test@example.com"]);
    git(dir, &["config", "user.name", "Test"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
    git(
        dir,
        &[
            "config",
            "diff.kdbx.textconv",
            &format!("{} --textconv", bin_str),
        ],
    );
    git(dir, &["config", "diff.kdbx.binary", "true"]);
    // Disable cache so each git diff actually re-runs the driver. Otherwise
    // git would cache textconv output keyed by blob hash, masking driver bugs
    // in tests that re-encrypt the same logical content.
    git(dir, &["config", "diff.kdbx.cachetextconv", "false"]);

    std::fs::write(dir.join(".gitattributes"), "*.kdbx diff=kdbx\n").unwrap();
    git(dir, &["add", ".gitattributes"]);
    git(dir, &["commit", "-q", "-m", "configure diff driver"]);
}

/// Copy a fixture KDBX into the repo at the given relative path, returning
/// the absolute path to the copy.
fn copy_fixture(repo: &Path, fixture_relative: &str, dest_name: &str) {
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_relative);
    let dst = repo.join(dest_name);
    std::fs::copy(&src, &dst).expect("copy fixture");
}

#[test]
fn diff_between_fixtures_shows_textconv_output() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    setup_repo(repo);

    // Commit "before" version
    copy_fixture(repo, "add_entry/before.kdbx", "vault.kdbx");
    git(repo, &["add", "vault.kdbx"]);
    git(repo, &["commit", "-q", "-m", "v1"]);

    // Replace with "after" version (entry added)
    copy_fixture(repo, "add_entry/after.kdbx", "vault.kdbx");

    // git diff should now invoke our textconv driver and produce a meaningful
    // line-diff (not "Binary files differ").
    let out = git(repo, &["diff", "vault.kdbx"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !stdout.is_empty(),
        "git diff produced no output; expected textconv'd diff"
    );
    assert!(
        !stdout.contains("Binary files"),
        "git diff fell back to binary-files-differ; textconv driver may not have been invoked.\nstdout:\n{}",
        stdout
    );
    // The "after" fixture has a Chase entry. The textconv dump should include it.
    assert!(
        stdout.contains("ENTRY") || stdout.contains("Chase"),
        "git diff output didn't contain expected entry markers.\nstdout:\n{}",
        stdout
    );
}

#[test]
fn diff_on_identical_content_is_empty() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    setup_repo(repo);

    copy_fixture(repo, "empty/before.kdbx", "vault.kdbx");
    git(repo, &["add", "vault.kdbx"]);
    git(repo, &["commit", "-q", "-m", "v1"]);

    // Replace with byte-identical content (empty/before.kdbx and empty/after.kdbx
    // have the same logical content; the textconv output should match).
    copy_fixture(repo, "empty/after.kdbx", "vault.kdbx");

    let out = git(repo, &["diff", "vault.kdbx"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    // git diff prints nothing when textconv outputs are identical, even if the
    // raw blobs differ. That's the whole point of the textconv driver.
    assert!(
        stdout.trim().is_empty(),
        "git diff on logically-identical fixtures was nonempty.\nstdout:\n{}",
        stdout
    );
}

#[test]
fn git_log_p_shows_textconv_for_each_commit() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    setup_repo(repo);

    // Commit two versions
    copy_fixture(repo, "add_entry/before.kdbx", "vault.kdbx");
    git(repo, &["add", "vault.kdbx"]);
    git(repo, &["commit", "-q", "-m", "v1: empty"]);

    copy_fixture(repo, "add_entry/after.kdbx", "vault.kdbx");
    git(repo, &["add", "vault.kdbx"]);
    git(repo, &["commit", "-q", "-m", "v2: add Chase entry"]);

    // git log -p over the whole history should include the textconv'd diff
    let out = git(repo, &["log", "-p", "--", "vault.kdbx"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("v1: empty"),
        "log missing v1 commit message"
    );
    assert!(
        stdout.contains("v2: add Chase entry"),
        "log missing v2 commit message"
    );
    assert!(
        !stdout.contains("Binary files"),
        "log fell back to binary-files-differ; textconv driver not engaged.\nstdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("ENTRY") || stdout.contains("DATABASE"),
        "log -p output missing textconv structural markers.\nstdout:\n{}",
        stdout
    );
}

#[test]
fn git_show_for_commit_includes_textconv_diff() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    setup_repo(repo);

    copy_fixture(repo, "add_entry/before.kdbx", "vault.kdbx");
    git(repo, &["add", "vault.kdbx"]);
    git(repo, &["commit", "-q", "-m", "v1"]);

    copy_fixture(repo, "add_entry/after.kdbx", "vault.kdbx");
    git(repo, &["add", "vault.kdbx"]);
    git(repo, &["commit", "-q", "-m", "v2"]);

    let out = git(repo, &["show", "HEAD", "--", "vault.kdbx"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(stdout.contains("v2"), "show missing commit message");
    assert!(
        !stdout.contains("Binary files"),
        "show fell back to binary-files-differ.\nstdout:\n{}",
        stdout
    );
}

#[test]
fn wrong_password_does_not_corrupt_diff_output() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    setup_repo(repo);

    copy_fixture(repo, "password_change/before.kdbx", "vault.kdbx");
    git(repo, &["add", "vault.kdbx"]);
    git(repo, &["commit", "-q", "-m", "v1"]);

    copy_fixture(repo, "password_change/after.kdbx", "vault.kdbx");

    // Run git diff with the WRONG password. The textconv driver should fail
    // closed (empty stdout, nonzero exit), and git should NOT corrupt its
    // own diff display by mixing partial output. Acceptable git behaviors:
    //   - empty diff output (driver failed, nothing to compare)
    //   - "Binary files differ" fallback
    //   - explicit error message
    // Unacceptable: mid-stream truncation that produces a malformed diff.
    let out = git_no_panic(repo, &["diff", "vault.kdbx"], "wrong-password");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The output should not contain a half-formed entry. If "ENTRY" appears,
    // it means partial-decrypt-then-fail occurred and git showed corrupt
    // textconv output. Our all-or-nothing stdout discipline should prevent this.
    assert!(
        !stdout.contains("ENTRY"),
        "wrong-password run leaked partial textconv content into diff output.\nstdout:\n{}",
        stdout
    );
}
