//! Remote roundtrip tests.
//!
//! Exercises the full push/fetch/clone workflow against a *local bare repo*
//! used as a remote. No network, no GitHub, no auth.
//!
//! Verifies that the textconv driver works after cloning a repo whose
//! `.gitattributes` declares `*.kdbx diff=kdbx`. The driver definition itself
//! lives in `.git/config` and is NOT cloned; each fresh clone must configure
//! it locally. These tests reflect that real-world workflow.
//!
//! Layer 5 of the test pyramid (see docs/testing.md).

use assert_cmd::cargo::cargo_bin;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const PW: &str = "test-password-do-not-use";

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("KDBX_DIFF_PASSWORD", PW)
        .output()
        .expect("git command failed to spawn");
    if !out.status.success() {
        panic!(
            "git {:?} (in {:?}) failed (exit={:?})\nstdout:\n{}\nstderr:\n{}",
            args,
            repo,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    out
}

/// Configure the diff-kdbx textconv driver in an existing repo (clone or init).
fn configure_driver(repo: &Path) {
    let bin = cargo_bin("diff-kdbx");
    let bin_str = bin.to_str().expect("binary path is UTF-8");
    git(repo, &["config", "user.email", "test@example.com"]);
    git(repo, &["config", "user.name", "Test"]);
    git(repo, &["config", "commit.gpgsign", "false"]);
    git(
        repo,
        &[
            "config",
            "diff.kdbx.textconv",
            &format!("{} --textconv", bin_str),
        ],
    );
    git(repo, &["config", "diff.kdbx.binary", "true"]);
    git(repo, &["config", "diff.kdbx.cachetextconv", "false"]);
}

fn copy_fixture(repo: &Path, fixture_relative: &str, dest_name: &str) {
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_relative);
    let dst = repo.join(dest_name);
    std::fs::copy(&src, &dst).expect("copy fixture");
}

/// Set up the standard remote-roundtrip world:
///   tmp/origin.git  (bare, acts as the "remote")
///   tmp/clone-a     (working clone, source side)
///
/// Returns (tempdir, origin_path, clone_a_path). The tempdir owns all paths;
/// dropping it cleans everything up.
fn setup_world() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let origin = tmp.path().join("origin.git");
    let clone_a = tmp.path().join("clone-a");

    // Create the bare remote
    std::fs::create_dir(&origin).unwrap();
    let init_bare = Command::new("git")
        .args(["init", "--bare", "-q", "-b", "main"])
        .current_dir(&origin)
        .status()
        .expect("git init --bare");
    assert!(init_bare.success());

    // Create the source-side working clone
    let clone = Command::new("git")
        .args(["clone", "-q", origin.to_str().unwrap(), clone_a.to_str().unwrap()])
        .status()
        .expect("git clone of bare remote");
    assert!(clone.success());

    configure_driver(&clone_a);
    std::fs::write(clone_a.join(".gitattributes"), "*.kdbx diff=kdbx\n").unwrap();
    git(&clone_a, &["add", ".gitattributes"]);
    git(&clone_a, &["commit", "-q", "-m", "configure diff driver"]);

    (tmp, origin, clone_a)
}

#[test]
fn push_and_clone_back_preserves_textconv_diffs() {
    let (tmp, origin, clone_a) = setup_world();

    // In clone-a: commit two versions of the vault, push to origin
    copy_fixture(&clone_a, "add_entry/before.kdbx", "vault.kdbx");
    git(&clone_a, &["add", "vault.kdbx"]);
    git(&clone_a, &["commit", "-q", "-m", "v1: empty"]);

    copy_fixture(&clone_a, "add_entry/after.kdbx", "vault.kdbx");
    git(&clone_a, &["add", "vault.kdbx"]);
    git(&clone_a, &["commit", "-q", "-m", "v2: add entry"]);

    git(&clone_a, &["push", "-q", "origin", "main"]);

    // Now clone fresh into clone-b and verify the textconv driver works there
    let clone_b = tmp.path().join("clone-b");
    let clone_status = Command::new("git")
        .args([
            "clone",
            "-q",
            origin.to_str().unwrap(),
            clone_b.to_str().unwrap(),
        ])
        .status()
        .expect("git clone of bare remote");
    assert!(clone_status.success());

    // The .gitattributes is in the tree (committed in clone-a), so it landed
    // in the bare remote and now in clone-b. But the driver config in
    // .git/config is per-clone and is NOT carried via git clone, so we must
    // configure it again here. This reflects the real-world workflow:
    // "after cloning a vault repo on a new machine, run the diff-kdbx setup."
    configure_driver(&clone_b);

    // log -p in clone-b should show the textconv'd diffs for each commit
    let out = git(&clone_b, &["log", "-p", "--", "vault.kdbx"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(stdout.contains("v1: empty"), "missing v1 commit msg");
    assert!(stdout.contains("v2: add entry"), "missing v2 commit msg");
    assert!(
        !stdout.contains("Binary files"),
        "clone-b fell back to binary-files-differ; driver not engaged.\nstdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("ENTRY") || stdout.contains("DATABASE"),
        "clone-b log -p output missing textconv markers.\nstdout:\n{}",
        stdout
    );
}

#[test]
fn diff_output_is_consistent_across_clones() {
    let (tmp, origin, clone_a) = setup_world();

    // Two commits in clone-a; capture the diff output between them
    copy_fixture(&clone_a, "add_entry/before.kdbx", "vault.kdbx");
    git(&clone_a, &["add", "vault.kdbx"]);
    git(&clone_a, &["commit", "-q", "-m", "v1"]);

    copy_fixture(&clone_a, "add_entry/after.kdbx", "vault.kdbx");
    git(&clone_a, &["add", "vault.kdbx"]);
    git(&clone_a, &["commit", "-q", "-m", "v2"]);

    git(&clone_a, &["push", "-q", "origin", "main"]);

    let diff_a = git(&clone_a, &["diff", "HEAD~1..HEAD", "--", "vault.kdbx"])
        .stdout;

    // Fresh clone, configure driver, take the same diff
    let clone_b = tmp.path().join("clone-b");
    let _ = Command::new("git")
        .args([
            "clone",
            "-q",
            origin.to_str().unwrap(),
            clone_b.to_str().unwrap(),
        ])
        .status()
        .expect("git clone");
    configure_driver(&clone_b);

    let diff_b = git(&clone_b, &["diff", "HEAD~1..HEAD", "--", "vault.kdbx"])
        .stdout;

    assert_eq!(
        diff_a,
        diff_b,
        "diff output diverged between source clone and fresh clone.\n\
         clone-a:\n{}\n\nclone-b:\n{}",
        String::from_utf8_lossy(&diff_a),
        String::from_utf8_lossy(&diff_b),
    );
}

#[test]
fn pull_after_push_shows_new_commits_diff() {
    let (tmp, origin, clone_a) = setup_world();

    // Initial commit in clone-a, push
    copy_fixture(&clone_a, "add_entry/before.kdbx", "vault.kdbx");
    git(&clone_a, &["add", "vault.kdbx"]);
    git(&clone_a, &["commit", "-q", "-m", "v1"]);
    git(&clone_a, &["push", "-q", "origin", "main"]);

    // Clone-b fetches the initial state
    let clone_b = tmp.path().join("clone-b");
    let _ = Command::new("git")
        .args([
            "clone",
            "-q",
            origin.to_str().unwrap(),
            clone_b.to_str().unwrap(),
        ])
        .status()
        .expect("git clone");
    configure_driver(&clone_b);

    // Clone-a adds a new version, pushes
    copy_fixture(&clone_a, "add_entry/after.kdbx", "vault.kdbx");
    git(&clone_a, &["add", "vault.kdbx"]);
    git(&clone_a, &["commit", "-q", "-m", "v2: new entry"]);
    git(&clone_a, &["push", "-q", "origin", "main"]);

    // Clone-b pulls
    git(&clone_b, &["pull", "-q", "--ff-only"]);

    // Clone-b's log -p should now include the v2 commit's textconv diff
    let out = git(&clone_b, &["log", "-p", "--", "vault.kdbx"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(stdout.contains("v2: new entry"), "missing pulled commit");
    assert!(
        !stdout.contains("Binary files"),
        "post-pull log -p fell back to binary-files-differ.\nstdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("ENTRY") || stdout.contains("DATABASE"),
        "post-pull log -p missing textconv markers.\nstdout:\n{}",
        stdout
    );
}
