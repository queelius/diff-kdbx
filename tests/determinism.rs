//! Determinism guarantees:
//!   1. dump(db) is byte-stable across separate processes
//!   2. compute(a, b) is byte-stable across separate processes

use assert_cmd::Command;

const PW: &str = "test-password-do-not-use";

#[test]
fn dump_textconv_is_byte_stable_across_processes() {
    fn run() -> Vec<u8> {
        let out = Command::cargo_bin("diff-kdbx")
            .unwrap()
            .env("KDBX_DIFF_PASSWORD", PW)
            .args(["--textconv", "tests/fixtures/add_entry/after.kdbx"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "textconv failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }
    let a = run();
    let b = run();
    let c = run();
    assert_eq!(a, b, "textconv output differed between run 1 and run 2");
    assert_eq!(b, c, "textconv output differed between run 2 and run 3");
}

#[test]
fn json_diff_is_byte_stable_across_processes() {
    fn run() -> Vec<u8> {
        let out = Command::cargo_bin("diff-kdbx")
            .unwrap()
            .env("KDBX_DIFF_PASSWORD", PW)
            .args([
                "--format=json",
                "tests/fixtures/password_change/before.kdbx",
                "tests/fixtures/password_change/after.kdbx",
            ])
            .output()
            .unwrap();
        out.stdout
    }
    let a = run();
    let b = run();
    assert_eq!(a, b, "json diff output differed between runs");
}

#[test]
fn text_diff_is_byte_stable_across_processes() {
    fn run() -> Vec<u8> {
        let out = Command::cargo_bin("diff-kdbx")
            .unwrap()
            .env("KDBX_DIFF_PASSWORD", PW)
            .args([
                "tests/fixtures/add_entry/before.kdbx",
                "tests/fixtures/add_entry/after.kdbx",
            ])
            .output()
            .unwrap();
        out.stdout
    }
    let a = run();
    let b = run();
    assert_eq!(a, b, "text diff output differed between runs");
}
