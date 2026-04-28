//! Generates canonical .kdbx fixture pairs for integration tests.
//!
//! Run with:
//!   cargo run --features cli --bin gen-fixtures
//!
//! Fixtures are written to tests/fixtures/<name>/before.kdbx and after.kdbx.
//! Master password for all fixtures: `test-password-do-not-use`

use std::fs;
use std::fs::File;
use std::path::Path;

use anyhow::Result;
use keepass::{Database, DatabaseKey};

const MASTER: &str = "test-password-do-not-use";
const FIXTURES_ROOT: &str = "tests/fixtures";

fn key() -> DatabaseKey {
    DatabaseKey::new().with_password(MASTER)
}

/// Save a `Database` to the given path, creating parent dirs as needed.
fn save_db(db: &Database, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = File::create(path)?;
    db.save(&mut f, key())?;
    Ok(())
}

/// Fixture 1: empty/before.kdbx and empty/after.kdbx
/// Both are empty databases — no semantic difference.
/// Used for "no changes" exit-code-0 test.
fn write_empty() -> Result<()> {
    let root = Path::new(FIXTURES_ROOT).join("empty");

    let before = Database::new();
    save_db(&before, &root.join("before.kdbx"))?;

    let after = Database::new();
    save_db(&after, &root.join("after.kdbx"))?;

    println!("  wrote empty/before.kdbx and empty/after.kdbx");
    Ok(())
}

/// Fixture 2: add_entry/before.kdbx and add_entry/after.kdbx
/// before is empty; after has one entry.
/// Used for "diff reports added entry" test.
fn write_add_entry() -> Result<()> {
    let root = Path::new(FIXTURES_ROOT).join("add_entry");

    let before = Database::new();
    save_db(&before, &root.join("before.kdbx"))?;

    let mut after = Database::new();
    {
        let mut root_group = after.root_mut();
        let mut entry = root_group.add_entry();
        entry.set_unprotected("Title", "Test Entry");
        entry.set_unprotected("UserName", "alice");
        entry.set_protected("Password", "hunter2");
        entry.set_unprotected("URL", "https://example.com");
    }
    save_db(&after, &root.join("after.kdbx"))?;

    println!("  wrote add_entry/before.kdbx and add_entry/after.kdbx");
    Ok(())
}

/// Fixture 3: password_change/before.kdbx and password_change/after.kdbx
/// Both have one entry; the password field differs.
/// Used for masking/redaction test.
fn write_password_change() -> Result<()> {
    let root = Path::new(FIXTURES_ROOT).join("password_change");

    let mut before = Database::new();
    {
        let mut root_group = before.root_mut();
        let mut entry = root_group.add_entry();
        entry.set_unprotected("Title", "Test Entry");
        entry.set_unprotected("UserName", "alice");
        entry.set_protected("Password", "old-password");
        entry.set_unprotected("URL", "https://example.com");
    }
    save_db(&before, &root.join("before.kdbx"))?;

    let mut after = Database::new();
    {
        let mut root_group = after.root_mut();
        let mut entry = root_group.add_entry();
        entry.set_unprotected("Title", "Test Entry");
        entry.set_unprotected("UserName", "alice");
        entry.set_protected("Password", "new-password");
        entry.set_unprotected("URL", "https://example.com");
    }
    save_db(&after, &root.join("after.kdbx"))?;

    println!("  wrote password_change/before.kdbx and password_change/after.kdbx");
    Ok(())
}

// TODO: remaining 7 fixture pairs (filed for post-v0.1):
//   4. rename_entry   — entry title changes
//   5. delete_entry   — entry removed in after
//   6. move_entry     — entry moved to different group
//   7. add_group      — new group added
//   8. delete_group   — group removed
//   9. multiple_changes — several changes at once
//  10. nested_groups  — deep group hierarchy

fn main() -> Result<()> {
    println!("Generating fixture pairs (master password: {MASTER})");
    println!("Output directory: {FIXTURES_ROOT}/");

    write_empty()?;
    write_add_entry()?;
    write_password_change()?;

    println!("Done. 6 files written (3 fixture pairs).");
    Ok(())
}
