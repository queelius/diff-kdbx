//! Tree-shaped text rendering of a ChangeSet.

use crate::change_set::{
    Change, ChangeSet, DatabaseChange, EntryChangeKind, FieldChange, GroupChangeKind,
    Summary, ValueChange, ValueDisplay,
};
use crate::options::RenderOptions;
use std::fmt::Write as _;

pub fn render(cs: &ChangeSet, _opts: &RenderOptions) -> String {
    let mut out = String::new();
    render_summary(&cs.summary, &mut out);
    render_warnings(&cs.warnings, &mut out);
    if cs.changes.is_empty() {
        let _ = writeln!(out, "(no changes)");
        return out;
    }
    for change in &cs.changes {
        render_change(change, &mut out);
    }
    out
}

fn render_summary(s: &Summary, out: &mut String) {
    let _ = writeln!(
        out,
        "summary: +{}/-{}/~{} entries, +{}/-{}/~{} groups, {} fields, {} suppressed",
        s.entries_added, s.entries_removed, s.entries_modified,
        s.groups_added, s.groups_removed, s.groups_modified,
        s.fields_changed, s.suppressed,
    );
}

fn render_warnings(warnings: &[crate::change_set::DiffWarning], out: &mut String) {
    for w in warnings {
        let _ = writeln!(out, "warning: {:?}", w);
    }
}

fn render_change(c: &Change, out: &mut String) {
    match c {
        Change::Database(d) => render_database(d, out),
        Change::Group { path, kind, .. } => render_group(path, kind, out),
        Change::Entry { path, kind, .. } => render_entry(path, kind, out),
    }
}

fn render_database(d: &DatabaseChange, out: &mut String) {
    match d {
        DatabaseChange::NameChanged { from, to } => {
            let _ = writeln!(out, "DATABASE name: {} -> {}", from, to);
        }
        DatabaseChange::ColorChanged { from, to } => {
            let _ = writeln!(out, "DATABASE color: {:?} -> {:?}", from, to);
        }
        DatabaseChange::RecycleBinChanged { from, to } => {
            let _ = writeln!(out, "DATABASE recycle_bin: {:?} -> {:?}", from, to);
        }
        DatabaseChange::CustomDataModified { key, change } => {
            let _ = writeln!(out, "DATABASE custom_data[{}]: {}", key, fmt_value_change(change));
        }
        DatabaseChange::CustomDataAdded { key, value } => {
            let _ = writeln!(out, "DATABASE custom_data[{}] = {}", key, fmt_value_display(value));
        }
        DatabaseChange::CustomDataRemoved { key, value } => {
            let _ = writeln!(
                out,
                "DATABASE custom_data[{}] removed (was {})",
                key,
                fmt_value_display(value)
            );
        }
    }
}

fn render_group(path: &crate::path::Path, kind: &GroupChangeKind, out: &mut String) {
    match kind {
        GroupChangeKind::Added => {
            let _ = writeln!(out, "+ GROUP {}", path.display);
        }
        GroupChangeKind::Removed => {
            let _ = writeln!(out, "- GROUP {}", path.display);
        }
        GroupChangeKind::Moved { to } => {
            let _ = writeln!(out, "~ GROUP {} -> {}", path.display, to.display);
        }
        GroupChangeKind::Renamed { from, to } => {
            let _ = writeln!(out, "~ GROUP {} (renamed: {} -> {})", path.display, from, to);
        }
        GroupChangeKind::PropertiesChanged { fields } => {
            let _ = writeln!(out, "~ GROUP {}", path.display);
            for f in fields {
                render_field(f, out);
            }
        }
    }
}

fn render_entry(path: &crate::path::Path, kind: &EntryChangeKind, out: &mut String) {
    match kind {
        EntryChangeKind::Added => {
            let _ = writeln!(out, "+ ENTRY {}", path.display);
        }
        EntryChangeKind::Removed => {
            let _ = writeln!(out, "- ENTRY {}", path.display);
        }
        EntryChangeKind::Moved { to } => {
            let _ = writeln!(out, "~ ENTRY {} -> {}", path.display, to.display);
        }
        EntryChangeKind::Modified { fields } => {
            let _ = writeln!(out, "~ ENTRY {}", path.display);
            for f in fields {
                render_field(f, out);
            }
        }
    }
}

fn render_field(f: &FieldChange, out: &mut String) {
    match f {
        FieldChange::Added { name, value } => {
            let _ = writeln!(out, "  + {}: {}", name, fmt_value_display(value));
        }
        FieldChange::Removed { name, value } => {
            let _ = writeln!(out, "  - {}: {}", name, fmt_value_display(value));
        }
        FieldChange::Modified { name, change } => {
            let _ = writeln!(out, "  ~ {}: {}", name, fmt_value_change(change));
        }
        FieldChange::TagAdded { tag } => {
            let _ = writeln!(out, "  + tag: {}", tag);
        }
        FieldChange::TagRemoved { tag } => {
            let _ = writeln!(out, "  - tag: {}", tag);
        }
        FieldChange::AttachmentAdded { name, hash } => {
            let _ = writeln!(out, "  + attachment {} <hash:{}>", name, hash);
        }
        FieldChange::AttachmentRemoved { name, hash } => {
            let _ = writeln!(out, "  - attachment {} <hash:{}>", name, hash);
        }
        FieldChange::AttachmentModified { name, from_hash, to_hash } => {
            let _ = writeln!(
                out,
                "  ~ attachment {} [<hash:{}> -> <hash:{}>]",
                name, from_hash, to_hash
            );
        }
        FieldChange::HistoryGrew { added } => {
            let _ = writeln!(out, "  H {} history entries added", added);
        }
        FieldChange::HistoryRewritten { from_len, to_len } => {
            let _ = writeln!(out, "  H history rewritten: {} -> {}", from_len, to_len);
        }
    }
}

fn fmt_value_display(v: &ValueDisplay) -> String {
    match v {
        ValueDisplay::Plain { value } => value.clone(),
        ValueDisplay::Masked { hash } => format!("<hash:{}>", hash),
    }
}

fn fmt_value_change(c: &ValueChange) -> String {
    format!("{} -> {}", fmt_value_display(&c.from), fmt_value_display(&c.to))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::change_set::{Change, DatabaseChange};

    #[test]
    fn empty_change_set_renders_no_changes_line() {
        let cs = ChangeSet::default();
        let out = render(&cs, &RenderOptions::default());
        assert!(out.contains("(no changes)"));
    }

    #[test]
    fn database_rename_renders() {
        let cs = ChangeSet {
            changes: vec![Change::Database(DatabaseChange::NameChanged {
                from: "old".into(),
                to: "new".into(),
            })],
            summary: Summary {
                metadata_changed: 1,
                ..Default::default()
            },
            warnings: vec![],
        };
        let out = render(&cs, &RenderOptions::default());
        assert!(out.contains("DATABASE name: old -> new"));
    }

    #[test]
    fn summary_line_contains_change_counts() {
        let cs = ChangeSet {
            changes: vec![],
            summary: Summary {
                entries_added: 5,
                entries_removed: 2,
                entries_modified: 3,
                groups_added: 1,
                groups_removed: 0,
                groups_modified: 2,
                fields_changed: 10,
                suppressed: 1,
                ..Default::default()
            },
            warnings: vec![],
        };
        let out = render(&cs, &RenderOptions::default());
        assert!(out.contains("+5/-2/~3"));
        assert!(out.contains("+1/-0/~2"));
        assert!(out.contains("10 fields"));
        assert!(out.contains("1 suppressed"));
    }

    #[test]
    fn field_addition_renders() {
        let cs = ChangeSet {
            changes: vec![Change::Entry {
                uuid: uuid::Uuid::nil(),
                path: crate::path::Path {
                    display: "/test".into(),
                    uuids: vec![],
                },
                kind: EntryChangeKind::Modified {
                    fields: vec![FieldChange::Added {
                        name: "Title".into(),
                        value: ValueDisplay::Plain {
                            value: "MyEntry".into(),
                        },
                    }],
                },
            }],
            summary: Summary::default(),
            warnings: vec![],
        };
        let out = render(&cs, &RenderOptions::default());
        assert!(out.contains("+ Title: MyEntry"));
    }
}
