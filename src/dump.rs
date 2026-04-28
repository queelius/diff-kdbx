//! Stable text dump of a KDBX database, used as a git textconv driver.
//!
//! The dump format must be deterministic and produce localized changes for localized edits.
//! Each line is independently diffable. Indentation is 2 spaces.

use crate::change_set::ValueDisplay;
use crate::compute::{tree_walk, NodeKind};
use crate::options::{DiffOptions, DumpOptions};
use crate::path::Path;
use std::fmt::Write as _;
use uuid::Uuid;

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

/// Emit all groups and entries in path-sorted order.
///
/// Uses `tree_walk` (which visits the whole tree) and sorts nodes by their
/// display path, so a small database edit produces a small line diff.
/// When `opts.include_recycle_bin` is false, the recycle bin and its
/// descendants are omitted.
fn dump_groups(db: &keepass::Database, opts: &DumpOptions, out: &mut String) {
    // Build a DiffOptions that carries the include_recycle_bin flag so
    // tree_walk can apply the suppression consistently.
    let walk_opts = DiffOptions {
        strict: opts.strict,
        show_secrets: opts.show_secrets,
        include_recycle_bin: opts.include_recycle_bin,
    };
    let map = tree_walk(db, &walk_opts);
    let mut keys: Vec<&Uuid> = map.keys().collect();
    // Sort by display path for a stable, human-readable ordering.
    keys.sort_by(|a, b| {
        let pa = &map[a].path.display;
        let pb = &map[b].path.display;
        pa.cmp(pb)
    });
    for uuid in keys {
        let node = &map[uuid];
        match node.kind {
            NodeKind::Group => {
                let _ = writeln!(out, "GROUP {}", node.path.display);
            }
            NodeKind::Entry => {
                // Resolve the EntryRef so we can both read Entry fields (via Deref)
                // and call EntryRef::attachments() for an accurate attachment count
                // (entry.attachments is pub(crate) and not directly accessible here).
                if let Some(er) = lookup_entry_ref(db, *uuid) {
                    dump_entry(&er, *uuid, &node.path, opts, out);
                }
            }
        }
    }
}

/// Find an `EntryRef` by UUID.  Returns `None` if the UUID is not present
/// (should never happen in practice since the UUID came from `tree_walk`).
fn lookup_entry_ref(db: &keepass::Database, uuid: Uuid) -> Option<keepass::db::EntryRef<'_>> {
    db.iter_all_entries().find(|er| er.id().uuid() == uuid)
}

/// Emit one entry block.
///
/// Fields are emitted in a fixed order so that a single-field change produces
/// a single changed line in `git diff --word-diff`.
fn dump_entry(
    er: &keepass::db::EntryRef<'_>,
    uuid: Uuid,
    path: &Path,
    opts: &DumpOptions,
    out: &mut String,
) {
    // Use the first 8 hex chars as a short UUID tag.
    let short = &uuid.to_string()[..8];
    let _ = writeln!(out, "ENTRY {} [uuid:{}]", path.display, short);

    // Standard KeePass fields in a canonical order.
    for &name in &["Title", "UserName", "Password", "URL", "Notes"] {
        let raw = er.get(name).unwrap_or("").to_string();
        // Password is always treated as protected; other fields defer to the
        // Value::is_protected() flag stored in entry.fields.
        let protected = name == "Password"
            || er.fields.get(name).map(|v| v.is_protected()).unwrap_or(false);
        let display = ValueDisplay::from_value(&raw, protected, opts.show_secrets);
        match display {
            ValueDisplay::Plain { value } => {
                let _ = writeln!(out, "  {}: {}", name.to_lowercase(), value);
            }
            ValueDisplay::Masked { hash } => {
                let _ = writeln!(out, "  {}: <hash:{}>", name.to_lowercase(), hash);
            }
        }
    }

    // Tags (sorted for stability).
    if !er.tags.is_empty() {
        let mut tags = er.tags.clone();
        tags.sort();
        let _ = writeln!(out, "  tags: {}", tags.join(", "));
    }

    // Attachment count via EntryRef::attachments() — public iterator that
    // avoids the pub(crate) entry.attachments field.
    let att_count = er.attachments().count();
    let _ = writeln!(out, "  attachments: {}", att_count);

    // History length.
    let hist_len = er.history.as_ref().map(|h| h.get_entries().len()).unwrap_or(0);
    let _ = writeln!(out, "  history: {} entries", hist_len);

    // Modification timestamp (omitted in --strict mode to reduce noise).
    // Times.last_modification is pub Option<NaiveDateTime> in keepass 0.12.
    if !opts.strict {
        if let Some(t) = entry_modification_time(er) {
            let _ = writeln!(out, "  modified: {}", t);
        }
    }
}

/// Format the `LastModification` timestamp of an entry as an RFC 3339-style
/// string (without timezone, since KDBX stores naive datetimes).
///
/// `entry.times.last_modification` is `pub Option<NaiveDateTime>` in
/// keepass 0.12, so this is a direct field access, no accessor needed.
fn entry_modification_time(entry: &keepass::db::Entry) -> Option<String> {
    entry
        .times
        .last_modification
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

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

    #[test]
    fn dump_is_byte_stable_across_calls() {
        let db = keepass::Database::new();
        let s1 = dump(&db, &DumpOptions::default());
        let s2 = dump(&db, &DumpOptions::default());
        assert_eq!(s1, s2);
    }

    /// Build a database with one live entry and a recycle bin group containing
    /// a trashed entry. Used by the suppression tests below.
    fn db_with_recycle_bin() -> keepass::Database {
        let mut db = keepass::Database::new();
        db.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "Live"));
        let rb_id = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Recycle Bin".into())
            .id();
        db.group_mut(rb_id)
            .unwrap()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "Trashed"));
        db.meta.recyclebin_uuid = Some(rb_id.uuid());
        db
    }

    #[test]
    fn dump_hides_recycle_bin_by_default() {
        let db = db_with_recycle_bin();
        let s = dump(&db, &DumpOptions::default());
        assert!(s.contains("Live"), "Live entry should appear in dump");
        assert!(!s.contains("Trashed"), "Trashed entry should be suppressed by default");
        // The recycle bin group line looks like "GROUP .../Recycle Bin".
        assert!(
            !s.lines().any(|l| l.starts_with("GROUP") && l.ends_with("Recycle Bin")),
            "Recycle Bin group should be suppressed"
        );
    }

    #[test]
    fn dump_shows_recycle_bin_when_opted_in() {
        let db = db_with_recycle_bin();
        let opts = DumpOptions { include_recycle_bin: true, ..DumpOptions::default() };
        let s = dump(&db, &opts);
        assert!(s.contains("Trashed"), "Trashed entry should appear with include_recycle_bin = true");
        assert!(s.contains("Recycle Bin"), "Recycle Bin group should appear with include_recycle_bin = true");
    }
}
