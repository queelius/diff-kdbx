//! Stable text dump of a KDBX database, used as a git textconv driver.
//!
//! The dump format must be deterministic and produce localized changes for localized edits.
//! Each line is independently diffable. Indentation is 2 spaces.

use crate::options::DumpOptions;
use std::fmt::Write as _;

/// Generate a stable text representation of a KDBX database.
///
/// This output is suitable for use as a git textconv driver: two databases
/// diffed via `dump` will show semantically meaningful line-by-line changes.
pub fn dump(db: &keepass::Database, opts: &DumpOptions) -> String {
    let mut out = String::new();
    dump_header(db, &mut out);
    dump_groups(db, opts, &mut out);
    out
}

/// Emit database header: metadata and version.
fn dump_header(db: &keepass::Database, out: &mut String) {
    let _ = writeln!(out, "DATABASE");
    let _ = writeln!(out, "  name: {}", db.meta.database_name.as_deref().unwrap_or(""));
    let _ = writeln!(out, "  version: {}", db.config.version);
    let bin = db
        .meta
        .recyclebin_uuid
        .map(|u| u.to_string())
        .unwrap_or_else(|| "none".to_string());
    let _ = writeln!(out, "  recycle_bin: {}", bin);
}

/// Emit all groups and entries (recursively from root).
///
/// Stub for Task 17. Real impl will recurse through groups.
fn dump_groups(_db: &keepass::Database, _opts: &DumpOptions, _out: &mut String) {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn header_contains_required_lines() {
        let db = keepass::Database::new();
        let s = dump(&db, &DumpOptions::default());
        assert!(s.contains("DATABASE\n"), "dump should contain DATABASE header");
        assert!(s.contains("  version:"), "dump should contain version field");
        assert!(s.contains("  recycle_bin:"), "dump should contain recycle_bin field");
    }

    #[test]
    fn header_includes_name_field() {
        let db = keepass::Database::new();
        let s = dump(&db, &DumpOptions::default());
        assert!(s.contains("  name:"), "dump should contain name field");
    }
}
