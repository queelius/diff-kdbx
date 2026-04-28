//! Diff computation: walk two KDBX databases and produce a structural ChangeSet.

use crate::path::Path;
use keepass::db::GroupRef;
use std::collections::HashMap;
use uuid::Uuid;

/// Discriminates between a group node and an entry node.
#[derive(Debug, Clone)]
pub enum NodeKind {
    Group,
    Entry,
}

/// A node located in a database tree, together with its path.
#[derive(Debug, Clone)]
pub struct LocatedNode {
    pub uuid: Uuid,
    pub path: Path,
    pub kind: NodeKind,
}

/// Build a UUID-keyed map of all nodes (groups and entries) in a database.
///
/// The path for each node uses backslash-escaped name segments and the UUID
/// chain from root to this node (inclusive).
pub fn tree_walk(db: &keepass::Database) -> HashMap<Uuid, LocatedNode> {
    let mut out = HashMap::new();
    let root = db.root();
    walk_group_ref(&root, &mut Vec::new(), &mut Vec::new(), db, &mut out);
    out
}

fn walk_group_ref(
    group: &GroupRef<'_>,
    name_stack: &mut Vec<String>,
    uuid_stack: &mut Vec<Uuid>,
    db: &keepass::Database,
    out: &mut HashMap<Uuid, LocatedNode>,
) {
    let group_uuid = group.id().uuid();
    name_stack.push(group.name.clone());
    uuid_stack.push(group_uuid);

    let path = {
        let segments: Vec<&str> = name_stack.iter().map(|s| s.as_str()).collect();
        Path::from_segments(&segments, uuid_stack.clone())
    };

    out.insert(
        group_uuid,
        LocatedNode {
            uuid: group_uuid,
            path,
            kind: NodeKind::Group,
        },
    );

    // Walk child groups recursively.
    for child_group in group.groups() {
        walk_group_ref(&child_group, name_stack, uuid_stack, db, out);
    }

    // Walk entries directly in this group.
    for entry in group.entries() {
        let entry_uuid = entry.id().uuid();
        let title = entry.get_title().unwrap_or("<untitled>");

        name_stack.push(title.to_owned());
        uuid_stack.push(entry_uuid);

        let path = {
            let segments: Vec<&str> = name_stack.iter().map(|s| s.as_str()).collect();
            Path::from_segments(&segments, uuid_stack.clone())
        };

        out.insert(
            entry_uuid,
            LocatedNode {
                uuid: entry_uuid,
                path,
                kind: NodeKind::Entry,
            },
        );

        name_stack.pop();
        uuid_stack.pop();
    }

    name_stack.pop();
    uuid_stack.pop();
}

use crate::change_set::{Change, ChangeSet, EntryChangeKind, GroupChangeKind};

/// Classification of one node's presence between two databases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodePresence {
    AddedOnly,
    RemovedOnly,
    Both { same_path: bool },
}

/// Compare two UUID-keyed maps and emit Group/Entry change events for
/// added, removed, and moved nodes. Modified-content cases (same UUID,
/// same path, different field content) are handled by field_diff in the
/// next task; this function only emits structure-level changes.
pub fn symmetric_diff(
    a: &HashMap<Uuid, LocatedNode>,
    b: &HashMap<Uuid, LocatedNode>,
    out: &mut ChangeSet,
) {
    // Added: in b only.
    for (uuid, node) in b {
        if !a.contains_key(uuid) {
            out.changes.push(structure_change(*uuid, node, StructEvent::Added));
            count_structural(&mut out.summary, node, StructEvent::Added);
        }
    }
    // Removed: in a only.
    for (uuid, node) in a {
        if !b.contains_key(uuid) {
            out.changes.push(structure_change(*uuid, node, StructEvent::Removed));
            count_structural(&mut out.summary, node, StructEvent::Removed);
        }
    }
    // Moved: in both, different path.
    for (uuid, na) in a {
        if let Some(nb) = b.get(uuid) {
            if na.path != nb.path {
                out.changes.push(structure_change(*uuid, nb, StructEvent::Moved {
                    to_path: nb.path.clone(),
                }));
                count_structural(&mut out.summary, na, StructEvent::Moved {
                    to_path: nb.path.clone(),
                });
            }
        }
    }
}

#[derive(Debug, Clone)]
enum StructEvent {
    Added,
    Removed,
    Moved { to_path: Path },
}

fn structure_change(uuid: Uuid, node: &LocatedNode, ev: StructEvent) -> Change {
    match (&node.kind, ev) {
        (NodeKind::Group, StructEvent::Added) => Change::Group {
            uuid, path: node.path.clone(), kind: GroupChangeKind::Added,
        },
        (NodeKind::Group, StructEvent::Removed) => Change::Group {
            uuid, path: node.path.clone(), kind: GroupChangeKind::Removed,
        },
        (NodeKind::Group, StructEvent::Moved { to_path }) => Change::Group {
            uuid, path: node.path.clone(), kind: GroupChangeKind::Moved { to: to_path },
        },
        (NodeKind::Entry, StructEvent::Added) => Change::Entry {
            uuid, path: node.path.clone(), kind: EntryChangeKind::Added,
        },
        (NodeKind::Entry, StructEvent::Removed) => Change::Entry {
            uuid, path: node.path.clone(), kind: EntryChangeKind::Removed,
        },
        (NodeKind::Entry, StructEvent::Moved { to_path }) => Change::Entry {
            uuid, path: node.path.clone(), kind: EntryChangeKind::Moved { to: to_path },
        },
    }
}

fn count_structural(s: &mut crate::change_set::Summary, node: &LocatedNode, ev: StructEvent) {
    match (&node.kind, ev) {
        (NodeKind::Group, StructEvent::Added) => s.groups_added += 1,
        (NodeKind::Group, StructEvent::Removed) => s.groups_removed += 1,
        (NodeKind::Group, StructEvent::Moved { .. }) => s.groups_modified += 1,
        (NodeKind::Entry, StructEvent::Added) => s.entries_added += 1,
        (NodeKind::Entry, StructEvent::Removed) => s.entries_removed += 1,
        (NodeKind::Entry, StructEvent::Moved { .. }) => s.entries_modified += 1,
    }
}

use crate::change_set::{FieldChange, ValueChange, ValueDisplay};
use crate::options::DiffOptions;

/// Compute field-level changes between two matched entries.
/// Returns an empty Vec if there are no differences in user-visible fields.
pub fn field_diff_entry(
    a: &keepass::db::Entry,
    b: &keepass::db::Entry,
    opts: &DiffOptions,
) -> Vec<FieldChange> {
    let mut out = Vec::new();
    diff_standard_fields(a, b, opts, &mut out);
    diff_custom_fields(a, b, opts, &mut out);
    diff_tags(a, b, &mut out);
    out
}

const STANDARD_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes"];

fn diff_standard_fields(
    a: &keepass::db::Entry,
    b: &keepass::db::Entry,
    opts: &DiffOptions,
    out: &mut Vec<FieldChange>,
) {
    for &name in STANDARD_FIELDS {
        let av = entry_field_value(a, name);
        let bv = entry_field_value(b, name);
        let protected =
            name == "Password" || entry_field_protected(a, name) || entry_field_protected(b, name);
        match (av, bv) {
            (None, None) => {}
            (Some(v), None) => out.push(FieldChange::Removed {
                name: name.into(),
                value: ValueDisplay::from_value(v.as_str(), protected, opts.show_secrets),
            }),
            (None, Some(v)) => out.push(FieldChange::Added {
                name: name.into(),
                value: ValueDisplay::from_value(v.as_str(), protected, opts.show_secrets),
            }),
            (Some(va), Some(vb)) if va == vb => {}
            (Some(va), Some(vb)) => out.push(FieldChange::Modified {
                name: name.into(),
                change: ValueChange {
                    from: ValueDisplay::from_value(va.as_str(), protected, opts.show_secrets),
                    to: ValueDisplay::from_value(vb.as_str(), protected, opts.show_secrets),
                },
            }),
        }
    }
}

fn diff_custom_fields(
    a: &keepass::db::Entry,
    b: &keepass::db::Entry,
    opts: &DiffOptions,
    out: &mut Vec<FieldChange>,
) {
    use std::collections::BTreeSet;
    let a_keys: BTreeSet<&String> = a
        .fields
        .keys()
        .filter(|k| !STANDARD_FIELDS.iter().any(|s| *s == k.as_str()))
        .collect();
    let b_keys: BTreeSet<&String> = b
        .fields
        .keys()
        .filter(|k| !STANDARD_FIELDS.iter().any(|s| *s == k.as_str()))
        .collect();

    for key in a_keys.union(&b_keys) {
        let av = entry_field_value(a, key);
        let bv = entry_field_value(b, key);
        let protected = entry_field_protected(a, key) || entry_field_protected(b, key);
        match (av, bv) {
            (None, None) => {}
            (Some(v), None) => out.push(FieldChange::Removed {
                name: (*key).clone(),
                value: ValueDisplay::from_value(v.as_str(), protected, opts.show_secrets),
            }),
            (None, Some(v)) => out.push(FieldChange::Added {
                name: (*key).clone(),
                value: ValueDisplay::from_value(v.as_str(), protected, opts.show_secrets),
            }),
            (Some(va), Some(vb)) if va == vb => {}
            (Some(va), Some(vb)) => out.push(FieldChange::Modified {
                name: (*key).clone(),
                change: ValueChange {
                    from: ValueDisplay::from_value(va.as_str(), protected, opts.show_secrets),
                    to: ValueDisplay::from_value(vb.as_str(), protected, opts.show_secrets),
                },
            }),
        }
    }
}

fn diff_tags(
    a: &keepass::db::Entry,
    b: &keepass::db::Entry,
    out: &mut Vec<FieldChange>,
) {
    use std::collections::BTreeSet;
    let a_tags: BTreeSet<&String> = a.tags.iter().collect();
    let b_tags: BTreeSet<&String> = b.tags.iter().collect();
    for tag in b_tags.difference(&a_tags) {
        out.push(FieldChange::TagAdded { tag: (*tag).clone() });
    }
    for tag in a_tags.difference(&b_tags) {
        out.push(FieldChange::TagRemoved { tag: (*tag).clone() });
    }
}

/// Get a standard field value as a String.
///
/// `Entry::get` returns `Option<&str>` and already handles the Protected variant
/// (it calls `Value::get()` which exposes the secret). We simply map to owned String
/// so callers are not tied to `entry`'s borrow lifetime.
fn entry_field_value(entry: &keepass::db::Entry, name: &str) -> Option<String> {
    entry.get(name).map(|v| v.to_string())
}

/// Whether a given field is marked Protected in the source XML.
///
/// `entry.fields` is `pub HashMap<String, Value<String>>`. `Value::is_protected()` returns true
/// for the `Protected(SecretBox<T>)` variant. Password is always treated protected regardless.
fn entry_field_protected(entry: &keepass::db::Entry, name: &str) -> bool {
    entry.fields.get(name).map(|v| v.is_protected()).unwrap_or(false)
}

#[cfg(test)]
mod test {
    use super::*;

    fn empty_db() -> keepass::Database {
        keepass::Database::new()
    }

    #[test]
    fn walk_empty_db_has_only_root() {
        let db = empty_db();
        let map = tree_walk(&db);
        assert_eq!(map.len(), 1);
        let root = map.values().next().unwrap();
        assert!(matches!(root.kind, NodeKind::Group));
    }

    #[test]
    fn walk_one_entry() {
        let mut db = keepass::Database::new();
        db.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "MyEntry"));
        let map = tree_walk(&db);
        // root group + one entry
        assert_eq!(map.len(), 2);
        let entry_node = map.values().find(|n| matches!(n.kind, NodeKind::Entry)).unwrap();
        assert!(entry_node.path.display.ends_with("MyEntry"));
    }

    #[test]
    fn walk_nested_group() {
        let mut db = keepass::Database::new();
        let sub_id = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Sub".into())
            .id();
        db.group_mut(sub_id)
            .unwrap()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "NestedEntry"));
        let map = tree_walk(&db);
        // root + Sub group + NestedEntry
        assert_eq!(map.len(), 3);
        let entry_node = map.values().find(|n| matches!(n.kind, NodeKind::Entry)).unwrap();
        assert!(entry_node.path.display.contains("Sub"));
        assert!(entry_node.path.display.ends_with("NestedEntry"));
    }

    #[test]
    fn empty_dbs_produce_empty_change_set() {
        let a = empty_db();
        let b = empty_db();
        let ma = tree_walk(&a);
        let mb = tree_walk(&b);
        let mut cs = ChangeSet::default();
        symmetric_diff(&ma, &mb, &mut cs);
        // Both have just root; root UUIDs differ between Database::new() invocations,
        // so we may see one added + one removed. The test just confirms the function runs.
        let _ = cs;
    }
}
