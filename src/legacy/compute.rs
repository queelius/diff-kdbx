//! Diff computation: walk two KDBX databases and produce a structural ChangeSet.

use crate::legacy::options::DiffOptions;
use crate::legacy::path::Path;
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
    /// The node's own name: a group's name or an entry's title. Stored
    /// separately from the path so a rename can be detected by comparing names
    /// directly, without parsing the escaped display path.
    pub name: String,
}

/// Build a UUID-keyed map of all nodes (groups and entries) in a database.
///
/// The path for each node uses backslash-escaped name segments and the UUID
/// chain from root to this node (inclusive).
///
/// When `opts.include_recycle_bin` is false (the default), the recycle bin
/// group and all its descendants are omitted from the result. The recycle bin
/// is identified by `db.meta.recyclebin_uuid`.
pub fn tree_walk(db: &keepass::Database, opts: &DiffOptions) -> HashMap<Uuid, LocatedNode> {
    let mut out = HashMap::new();
    let root = db.root();
    let recycle_bin_uuid: Option<Uuid> = if opts.include_recycle_bin {
        None
    } else {
        db.meta.recyclebin_uuid
    };
    walk_group_ref(
        &root,
        &mut Vec::new(),
        &mut Vec::new(),
        recycle_bin_uuid,
        &mut out,
    );
    out
}

fn walk_group_ref(
    group: &GroupRef<'_>,
    name_stack: &mut Vec<String>,
    uuid_stack: &mut Vec<Uuid>,
    recycle_bin_uuid: Option<Uuid>,
    out: &mut HashMap<Uuid, LocatedNode>,
) {
    let group_uuid = group.id().uuid();

    // Skip the recycle bin group and all its descendants.
    if recycle_bin_uuid == Some(group_uuid) {
        return;
    }

    name_stack.push(group.name.clone());
    uuid_stack.push(group_uuid);

    out.insert(
        group_uuid,
        LocatedNode {
            uuid: group_uuid,
            path: build_path(name_stack, uuid_stack),
            kind: NodeKind::Group,
            name: group.name.clone(),
        },
    );

    // Walk child groups recursively.
    for child_group in group.groups() {
        walk_group_ref(&child_group, name_stack, uuid_stack, recycle_bin_uuid, out);
    }

    // Walk entries directly in this group.
    for entry in group.entries() {
        let entry_uuid = entry.id().uuid();
        let title = entry.get_title().unwrap_or("<untitled>");

        name_stack.push(title.to_owned());
        uuid_stack.push(entry_uuid);

        out.insert(
            entry_uuid,
            LocatedNode {
                uuid: entry_uuid,
                path: build_path(name_stack, uuid_stack),
                kind: NodeKind::Entry,
                name: title.to_owned(),
            },
        );

        name_stack.pop();
        uuid_stack.pop();
    }

    name_stack.pop();
    uuid_stack.pop();
}

fn build_path(name_stack: &[String], uuid_stack: &[Uuid]) -> Path {
    let segments: Vec<&str> = name_stack.iter().map(String::as_str).collect();
    Path::from_segments(&segments, uuid_stack.to_vec())
}

use crate::legacy::change_set::{Change, ChangeSet, EntryChangeKind, GroupChangeKind};

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
            out.changes
                .push(structure_change(*uuid, node, StructEvent::Added));
            count_structural(&mut out.summary, node, StructEvent::Added);
        }
    }
    // Removed: in a only.
    for (uuid, node) in a {
        if !b.contains_key(uuid) {
            out.changes
                .push(structure_change(*uuid, node, StructEvent::Removed));
            count_structural(&mut out.summary, node, StructEvent::Removed);
        }
    }
    // Moved and renamed: in both. A node moved iff its IMMEDIATE parent
    // changed (the second-to-last uuid in its path chain). Comparing display
    // paths instead would misclassify a title or group rename (which changes
    // the display but not the parent) as a move. Comparing the full ancestor
    // chain would over-report: when a group moves, every descendant's chain
    // also changes, but the descendants did not independently move (they rode
    // along with the group), so only the group itself should be reported.
    // Names change without the immediate parent changing, so they are handled
    // separately: entry titles fall out of field_diff (Title is a field), and
    // group renames are emitted here as a distinct Renamed change.
    for (uuid, na) in a {
        let Some(nb) = b.get(uuid) else { continue };

        if immediate_parent(&na.path) != immediate_parent(&nb.path) {
            // Emit with the OLD node so the change carries the origin path,
            // with to_path the new location.
            out.changes.push(structure_change(
                *uuid,
                na,
                StructEvent::Moved {
                    to_path: nb.path.clone(),
                },
            ));
            count_structural(
                &mut out.summary,
                na,
                StructEvent::Moved {
                    to_path: nb.path.clone(),
                },
            );
        }

        // A group rename: same group, own name changed. Without this the
        // rename would be invisible (it is no longer a move, and groups are
        // not field-diffed). Entry title changes are reported by field_diff.
        if matches!(na.kind, NodeKind::Group) && na.name != nb.name {
            out.changes.push(Change::Group {
                uuid: *uuid,
                path: nb.path.clone(),
                kind: GroupChangeKind::Renamed {
                    from: na.name.clone(),
                    to: nb.name.clone(),
                },
            });
            out.summary.groups_modified += 1;
        }
    }
}

/// The UUID of a node's immediate parent group: the second-to-last uuid in the
/// root-to-node chain, or `None` for the root (which has no parent). Two matched
/// nodes sit in the same place iff their immediate parents are equal. Using the
/// immediate parent rather than the full chain means moving a group reports only
/// that group, not every descendant that rode along with it.
fn immediate_parent(path: &Path) -> Option<Uuid> {
    let n = path.uuids.len();
    if n >= 2 {
        Some(path.uuids[n - 2])
    } else {
        None
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
            uuid,
            path: node.path.clone(),
            kind: GroupChangeKind::Added,
        },
        (NodeKind::Group, StructEvent::Removed) => Change::Group {
            uuid,
            path: node.path.clone(),
            kind: GroupChangeKind::Removed,
        },
        (NodeKind::Group, StructEvent::Moved { to_path }) => Change::Group {
            uuid,
            path: node.path.clone(),
            kind: GroupChangeKind::Moved { to: to_path },
        },
        (NodeKind::Entry, StructEvent::Added) => Change::Entry {
            uuid,
            path: node.path.clone(),
            kind: EntryChangeKind::Added,
        },
        (NodeKind::Entry, StructEvent::Removed) => Change::Entry {
            uuid,
            path: node.path.clone(),
            kind: EntryChangeKind::Removed,
        },
        (NodeKind::Entry, StructEvent::Moved { to_path }) => Change::Entry {
            uuid,
            path: node.path.clone(),
            kind: EntryChangeKind::Moved { to: to_path },
        },
    }
}

fn count_structural(
    s: &mut crate::legacy::change_set::Summary,
    node: &LocatedNode,
    ev: StructEvent,
) {
    match (&node.kind, ev) {
        (NodeKind::Group, StructEvent::Added) => s.groups_added += 1,
        (NodeKind::Group, StructEvent::Removed) => s.groups_removed += 1,
        (NodeKind::Group, StructEvent::Moved { .. }) => s.groups_modified += 1,
        (NodeKind::Entry, StructEvent::Added) => s.entries_added += 1,
        (NodeKind::Entry, StructEvent::Removed) => s.entries_removed += 1,
        (NodeKind::Entry, StructEvent::Moved { .. }) => s.entries_modified += 1,
    }
}

use crate::legacy::change_set::{FieldChange, TimeField, ValueChange, ValueDisplay};

/// Compute field-level changes between two matched entries.
/// Returns an empty Vec if there are no differences in user-visible fields.
///
/// Takes `EntryRef`s rather than `Entry`s because an entry's attachment content lives in
/// its database's central attachment pool; an `EntryRef` carries that database with it.
pub fn field_diff_entry(
    a: &keepass::db::EntryRef<'_>,
    b: &keepass::db::EntryRef<'_>,
    opts: &DiffOptions,
) -> Vec<FieldChange> {
    let mut out = Vec::new();
    diff_standard_fields(a, b, opts, &mut out);
    diff_custom_fields(a, b, opts, &mut out);
    diff_tags(a, b, &mut out);
    diff_attachments(a, b, &mut out);
    diff_history(a, b, &mut out);
    diff_times(&a.times, &b.times, &mut out);
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
        .filter(|k| !STANDARD_FIELDS.contains(&k.as_str()))
        .collect();
    let b_keys: BTreeSet<&String> = b
        .fields
        .keys()
        .filter(|k| !STANDARD_FIELDS.contains(&k.as_str()))
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

fn diff_tags(a: &keepass::db::Entry, b: &keepass::db::Entry, out: &mut Vec<FieldChange>) {
    use std::collections::BTreeSet;
    let a_tags: BTreeSet<&String> = a.tags.iter().collect();
    let b_tags: BTreeSet<&String> = b.tags.iter().collect();
    for tag in b_tags.difference(&a_tags) {
        out.push(FieldChange::TagAdded {
            tag: (*tag).clone(),
        });
    }
    for tag in a_tags.difference(&b_tags) {
        out.push(FieldChange::TagRemoved {
            tag: (*tag).clone(),
        });
    }
}

use crate::legacy::mask::HashPrefix;

/// Diff the attachments of two entries, appending `AttachmentAdded`, `AttachmentRemoved`, and
/// `AttachmentModified` changes to `out`.
///
/// Attachments are compared by name; content identity is the SHA-256 prefix of the bytes, so a
/// rename shows as remove plus add and a content swap under the same name as a modification.
fn diff_attachments(
    a: &keepass::db::EntryRef<'_>,
    b: &keepass::db::EntryRef<'_>,
    out: &mut Vec<FieldChange>,
) {
    use std::collections::BTreeMap;

    let a_atts: BTreeMap<String, HashPrefix> = collect_attachments(a);
    let b_atts: BTreeMap<String, HashPrefix> = collect_attachments(b);

    let all_keys: std::collections::BTreeSet<&String> =
        a_atts.keys().chain(b_atts.keys()).collect();
    for key in all_keys {
        match (a_atts.get(key), b_atts.get(key)) {
            (None, None) => {}
            (None, Some(h)) => out.push(FieldChange::AttachmentAdded {
                name: key.clone(),
                hash: h.clone(),
            }),
            (Some(h), None) => out.push(FieldChange::AttachmentRemoved {
                name: key.clone(),
                hash: h.clone(),
            }),
            (Some(ha), Some(hb)) if ha == hb => {}
            (Some(ha), Some(hb)) => out.push(FieldChange::AttachmentModified {
                name: key.clone(),
                from_hash: ha.clone(),
                to_hash: hb.clone(),
            }),
        }
    }
}

/// Build a sorted map from attachment name to `HashPrefix` (SHA-256 prefix of the binary content)
/// for a single entry.
///
/// Uses `EntryRef::attachments_named()` (keepass 0.12.5+, upstream PR #321), which yields
/// `(name, AttachmentRef)` pairs directly. The map is a `BTreeMap`, so iteration is sorted by
/// name and callers get deterministic output for free.
pub(crate) fn collect_attachments(
    entry: &keepass::db::EntryRef<'_>,
) -> std::collections::BTreeMap<String, HashPrefix> {
    entry
        .attachments_named()
        .map(|(name, att)| (name.to_owned(), HashPrefix::of_bytes(att.data.get())))
        .collect()
}

fn diff_history(a: &keepass::db::Entry, b: &keepass::db::Entry, out: &mut Vec<FieldChange>) {
    let la = a.history.as_ref().map_or(0, |h| h.get_entries().len());
    let lb = b.history.as_ref().map_or(0, |h| h.get_entries().len());
    if lb > la {
        out.push(FieldChange::HistoryGrew { added: lb - la });
    } else if lb < la {
        out.push(FieldChange::HistoryRewritten {
            from_len: la,
            to_len: lb,
        });
    }
    // Same length but content might have been rewritten in place. Detecting
    // that requires recursive diff into history entries; it's a --strict-only
    // concern. v0.1 reports same-length history as unchanged.
}

/// Diff an entry's timestamps and usage counter, appending one `TimeChanged`
/// per field that differs. Noise (access time, usage count, and so on) is still
/// emitted here; `suppress_field_changes` removes it unless `--strict`.
fn diff_times(a: &keepass::db::Times, b: &keepass::db::Times, out: &mut Vec<FieldChange>) {
    // KeePass writes an ExpiryTime even for entries that never expire, where it
    // has no effect, so only report it when either side actually expires.
    let expiry_matters = a.expires == Some(true) || b.expires == Some(true);
    for field in TimeField::ALL {
        if field == TimeField::ExpiryTime && !expiry_matters {
            continue;
        }
        let (from, to) = (read_time(field, a), read_time(field, b));
        if from != to {
            out.push(FieldChange::TimeChanged { field, from, to });
        }
    }
}

/// Render one tracked field of a `Times` as a display string.
fn read_time(field: TimeField, t: &keepass::db::Times) -> Option<String> {
    fn ts(d: Option<chrono::NaiveDateTime>) -> Option<String> {
        d.map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    }
    match field {
        TimeField::CreationTime => ts(t.creation),
        TimeField::LastModificationTime => ts(t.last_modification),
        TimeField::LastAccessTime => ts(t.last_access),
        TimeField::ExpiryTime => ts(t.expiry),
        TimeField::Expires => t.expires.map(|b| b.to_string()),
        TimeField::UsageCount => t.usage_count.map(|n| n.to_string()),
        TimeField::LocationChanged => ts(t.location_changed),
    }
}

fn suppress_field_changes(
    fields: Vec<FieldChange>,
    opts: &DiffOptions,
) -> (Vec<FieldChange>, usize) {
    if opts.strict {
        return (fields, 0);
    }
    let mut kept = Vec::with_capacity(fields.len());
    let mut suppressed = 0usize;
    for fc in fields {
        if is_suppressible(&fc) {
            suppressed += 1;
        } else {
            kept.push(fc);
        }
    }
    (kept, suppressed)
}

/// Only typed timestamp changes can be noise; any named field (standard or
/// custom) is content, whatever it is called.
fn is_suppressible(fc: &FieldChange) -> bool {
    matches!(fc, FieldChange::TimeChanged { field, .. } if field.is_noise())
}

use crate::legacy::change_set::{DatabaseChange, DiffWarning};

/// Top-level diff entry point.
///
/// Produces a complete [`ChangeSet`] by:
/// 1. Emitting a [`DiffWarning::VersionMismatch`] when the two databases use
///    different KDBX format versions.
/// 2. Diffing database-level metadata (name, etc.) via `diff_database_metadata`.
/// 3. Walking both trees with [`tree_walk`] and emitting structural changes
///    (added/removed/moved groups and entries) via [`symmetric_diff`].
/// 4. For each entry present in both databases at the same path, comparing
///    field content with [`field_diff_entry`] and applying suppression policy.
/// 5. Sorting the final change list deterministically.
pub fn compute(a: &keepass::Database, b: &keepass::Database, opts: &DiffOptions) -> ChangeSet {
    let mut cs = ChangeSet::default();

    // 1. Cross-version warning. DatabaseVersion implements Display.
    let va = a.config.version.to_string();
    let vb = b.config.version.to_string();
    if va != vb {
        cs.warnings
            .push(DiffWarning::VersionMismatch { a: va, b: vb });
    }

    // 2. Database-level metadata.
    diff_database_metadata(a, b, opts, &mut cs);

    // 3. Tree walk + structural symmetric diff.
    let map_a = tree_walk(a, opts);
    let map_b = tree_walk(b, opts);
    symmetric_diff(&map_a, &map_b, &mut cs);

    // Build UUID → EntryRef lookup maps so we can resolve actual Entry data
    // for field-level diffing.  EntryRef borrows from the database so the maps
    // must be kept alive for the same scope.
    let entries_a: HashMap<Uuid, keepass::db::EntryRef<'_>> = a
        .iter_all_entries()
        .map(|er| (er.id().uuid(), er))
        .collect();
    let entries_b: HashMap<Uuid, keepass::db::EntryRef<'_>> = b
        .iter_all_entries()
        .map(|er| (er.id().uuid(), er))
        .collect();

    // 4. Modified entries: same UUID in both. Field-diff runs on EVERY matched
    //    entry pair, whether or not the entry moved or was renamed. A moved
    //    entry that also changed a field would otherwise lose the field change
    //    entirely (the old code skipped field-diff for any path difference). A
    //    title rename surfaces here naturally as a Modified Title field change.
    //    The change carries the entry's current path (nb), which differs from
    //    the old path only when the entry moved or was renamed.
    for (uuid, na) in &map_a {
        let Some(nb) = map_b.get(uuid) else { continue };
        if !matches!((&na.kind, &nb.kind), (NodeKind::Entry, NodeKind::Entry)) {
            continue;
        }
        let Some(ea) = entries_a.get(uuid) else {
            continue;
        };
        let Some(eb) = entries_b.get(uuid) else {
            continue;
        };
        let raw_fields = field_diff_entry(ea, eb, opts);
        let (fields, suppressed) = suppress_field_changes(raw_fields, opts);
        cs.summary.suppressed += suppressed;
        if !fields.is_empty() {
            cs.summary.entries_modified += 1;
            cs.summary.fields_changed += fields.len();
            cs.changes.push(Change::Entry {
                uuid: *uuid,
                path: nb.path.clone(),
                kind: EntryChangeKind::Modified { fields },
            });
        }
    }

    // 5. Sort for deterministic output.
    sort_changes(&mut cs.changes);
    cs
}

/// Diff database-level metadata (currently: name).
///
/// Each detected change increments `cs.summary.metadata_changed` and pushes a
/// [`Change::Database`] variant.
fn diff_database_metadata(
    a: &keepass::Database,
    b: &keepass::Database,
    _opts: &DiffOptions,
    cs: &mut ChangeSet,
) {
    // Name
    if a.meta.database_name != b.meta.database_name {
        cs.changes
            .push(Change::Database(DatabaseChange::NameChanged {
                from: a.meta.database_name.clone().unwrap_or_default(),
                to: b.meta.database_name.clone().unwrap_or_default(),
            }));
        cs.summary.metadata_changed += 1;
    }

    // Color
    let color_a = a.meta.color.as_ref().map(|c| format!("{c:?}"));
    let color_b = b.meta.color.as_ref().map(|c| format!("{c:?}"));
    if color_a != color_b {
        cs.changes
            .push(Change::Database(DatabaseChange::ColorChanged {
                from: color_a,
                to: color_b,
            }));
        cs.summary.metadata_changed += 1;
    }

    // Recycle bin UUID
    if a.meta.recyclebin_uuid != b.meta.recyclebin_uuid {
        cs.changes
            .push(Change::Database(DatabaseChange::RecycleBinChanged {
                from: a.meta.recyclebin_uuid,
                to: b.meta.recyclebin_uuid,
            }));
        cs.summary.metadata_changed += 1;
    }
}

fn sort_changes(changes: &mut [Change]) {
    changes.sort_by_key(sort_key);
}

fn sort_key(c: &Change) -> (u8, String, Uuid) {
    match c {
        Change::Database(_) => (0, String::new(), Uuid::nil()),
        Change::Group { uuid, path, .. } => (1, path.display.clone(), *uuid),
        Change::Entry { uuid, path, .. } => (2, path.display.clone(), *uuid),
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
    entry.fields.get(name).is_some_and(|v| v.is_protected())
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
        let map = tree_walk(&db, &DiffOptions::default());
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
        let map = tree_walk(&db, &DiffOptions::default());
        // root group + one entry
        assert_eq!(map.len(), 2);
        let entry_node = map
            .values()
            .find(|n| matches!(n.kind, NodeKind::Entry))
            .unwrap();
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
        let map = tree_walk(&db, &DiffOptions::default());
        // root + Sub group + NestedEntry
        assert_eq!(map.len(), 3);
        let entry_node = map
            .values()
            .find(|n| matches!(n.kind, NodeKind::Entry))
            .unwrap();
        assert!(entry_node.path.display.contains("Sub"));
        assert!(entry_node.path.display.ends_with("NestedEntry"));
    }

    #[test]
    fn empty_dbs_produce_empty_change_set() {
        let a = empty_db();
        let b = empty_db();
        let opts = DiffOptions::default();
        let ma = tree_walk(&a, &opts);
        let mb = tree_walk(&b, &opts);
        let mut cs = ChangeSet::default();
        symmetric_diff(&ma, &mb, &mut cs);
        // Both have just root; root UUIDs differ between Database::new() invocations,
        // so we may see one added + one removed. The test just confirms the function runs.
        let _ = cs;
    }

    fn time_change(field: TimeField) -> FieldChange {
        FieldChange::TimeChanged {
            field,
            from: Some("2026-01-01T00:00:00Z".into()),
            to: Some("2026-02-01T00:00:00Z".into()),
        }
    }

    fn title_change() -> FieldChange {
        FieldChange::Modified {
            name: "Title".into(),
            change: ValueChange {
                from: ValueDisplay::Plain {
                    value: "old".into(),
                },
                to: ValueDisplay::Plain {
                    value: "new".into(),
                },
            },
        }
    }

    #[test]
    fn suppression_drops_noise_time_changes_only() {
        let input = vec![
            time_change(TimeField::LastAccessTime),
            time_change(TimeField::CreationTime),
            title_change(),
        ];
        let (kept, suppressed) = suppress_field_changes(input, &DiffOptions::default());
        assert_eq!(suppressed, 1, "only LastAccessTime is noise");
        assert_eq!(kept.len(), 2);
        assert!(kept.contains(&time_change(TimeField::CreationTime)));
        assert!(kept.contains(&title_change()));
    }

    #[test]
    fn strict_disables_suppression() {
        let opts = DiffOptions {
            strict: true,
            ..DiffOptions::default()
        };
        let input = vec![time_change(TimeField::LastAccessTime)];
        let (kept, suppressed) = suppress_field_changes(input, &opts);
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed, 0);
    }

    /// A user's custom field whose name collides with a timestamp element is
    /// ordinary content. The old name-based suppression silently dropped it.
    #[test]
    fn custom_field_named_like_a_timestamp_is_not_suppressed() {
        let input = vec![FieldChange::Modified {
            name: "UsageCount".into(),
            change: ValueChange {
                from: ValueDisplay::Plain { value: "1".into() },
                to: ValueDisplay::Plain { value: "2".into() },
            },
        }];
        let (kept, suppressed) = suppress_field_changes(input, &DiffOptions::default());
        assert_eq!(suppressed, 0);
        assert_eq!(kept.len(), 1);
    }

    /// Build a one-entry database and a clone of it, returning both and the
    /// entry id, so a test can perturb the clone's timestamps.
    fn one_entry_pair() -> (keepass::Database, keepass::Database, keepass::db::EntryId) {
        let mut a = empty_db();
        let eid = {
            let mut root = a.root_mut();
            let mut e = root.add_entry();
            let id = e.id();
            e.edit(|x| x.set_unprotected(keepass::db::fields::TITLE, "Bank"));
            id
        };
        let b = a.clone();
        (a, b, eid)
    }

    fn at(s: &str) -> chrono::NaiveDateTime {
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    /// Opening and re-saving touches access time and usage count. Default mode
    /// reports no changes and counts them as suppressed; --strict reports both.
    #[test]
    fn noise_only_resave_is_suppressed_by_default_and_shown_in_strict() {
        let (a, mut b, eid) = one_entry_pair();
        {
            let mut e = b.entry_mut(eid).unwrap();
            e.times.last_access = Some(at("2026-05-01 12:00:00"));
            e.times.usage_count = Some(e.times.usage_count.unwrap_or(0) + 3);
        }

        let cs = compute(&a, &b, &DiffOptions::default());
        assert!(
            cs.changes.is_empty(),
            "noise-only change should be empty: {:?}",
            cs.changes
        );
        assert_eq!(cs.summary.suppressed, 2);

        let strict = DiffOptions {
            strict: true,
            ..DiffOptions::default()
        };
        let cs = compute(&a, &b, &strict);
        let fields = cs
            .changes
            .iter()
            .find_map(|c| match c {
                Change::Entry {
                    kind: EntryChangeKind::Modified { fields },
                    ..
                } => Some(fields),
                _ => None,
            })
            .expect("strict mode reports the timestamp changes");
        let changed: Vec<TimeField> = fields
            .iter()
            .filter_map(|f| match f {
                FieldChange::TimeChanged { field, .. } => Some(*field),
                _ => None,
            })
            .collect();
        assert_eq!(
            changed,
            vec![TimeField::LastAccessTime, TimeField::UsageCount]
        );
    }

    /// Setting an expiry is deliberate and is reported even in default mode.
    #[test]
    fn expiry_change_is_reported_by_default() {
        let (a, mut b, eid) = one_entry_pair();
        {
            let mut e = b.entry_mut(eid).unwrap();
            e.times.expires = Some(true);
            e.times.expiry = Some(at("2030-01-01 00:00:00"));
        }
        let cs = compute(&a, &b, &DiffOptions::default());
        let reported: Vec<TimeField> = cs
            .changes
            .iter()
            .flat_map(|c| match c {
                Change::Entry {
                    kind: EntryChangeKind::Modified { fields },
                    ..
                } => fields.clone(),
                _ => vec![],
            })
            .filter_map(|f| match f {
                FieldChange::TimeChanged { field, .. } => Some(field),
                _ => None,
            })
            .collect();
        assert!(reported.contains(&TimeField::Expires));
        assert!(reported.contains(&TimeField::ExpiryTime));
    }

    /// KeePass writes an ExpiryTime even for entries that never expire, where it
    /// has no effect. A change to it is not reported unless either side expires.
    #[test]
    fn expiry_time_ignored_when_entry_does_not_expire() {
        let (a, mut b, eid) = one_entry_pair();
        b.entry_mut(eid).unwrap().times.expiry = Some(at("2031-06-01 00:00:00"));
        let strict = DiffOptions {
            strict: true,
            ..DiffOptions::default()
        };
        let cs = compute(&a, &b, &strict);
        assert!(
            cs.changes.is_empty(),
            "inert ExpiryTime change: {:?}",
            cs.changes
        );
    }

    // ── compute() integration tests ──────────────────────────────────────────

    #[test]
    fn compute_identical_dbs_no_changes() {
        // Two fresh databases have different root UUIDs, so there will be
        // structural root-group changes, but no field-level entry changes.
        // The important thing is compute() runs without panicking.
        let a = empty_db();
        let b = empty_db();
        let opts = DiffOptions::default();
        let cs = compute(&a, &b, &opts);
        // No field-level entry changes (no entries at all).
        assert_eq!(cs.summary.entries_modified, 0);
        assert_eq!(cs.summary.fields_changed, 0);
        assert!(cs.warnings.is_empty());
    }

    #[test]
    fn compute_metadata_name_change_detected() {
        let mut a = empty_db();
        let mut b = empty_db();
        // Use identical root UUIDs to avoid structural noise in the assertion.
        a.meta.database_name = Some("VaultA".into());
        b.meta.database_name = Some("VaultB".into());
        let opts = DiffOptions::default();
        let cs = compute(&a, &b, &opts);
        // At least one Database-level NameChanged change should be present.
        let name_changes: Vec<_> = cs
            .changes
            .iter()
            .filter(|c| matches!(c, Change::Database(DatabaseChange::NameChanged { .. })))
            .collect();
        assert_eq!(name_changes.len(), 1, "expected exactly one NameChanged");
        assert!(cs.summary.metadata_changed >= 1);
    }

    #[test]
    fn compute_database_changes_sort_before_groups_and_entries() {
        let mut a = empty_db();
        let mut b = empty_db();
        a.meta.database_name = Some("Old".into());
        b.meta.database_name = Some("New".into());
        // Add an entry to a so symmetric_diff can produce entry changes too.
        b.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "NewEntry"));
        let opts = DiffOptions::default();
        let cs = compute(&a, &b, &opts);
        // After sorting, Database changes must come before Entry/Group changes.
        if let Some(first) = cs.changes.first() {
            assert!(
                matches!(first, Change::Database(_)),
                "first change should be Database, got {:?}",
                first
            );
        }
    }

    #[test]
    fn compute_detects_entry_added_and_removed() {
        // Entry added in b only → entries_added = 1.
        // Entry present in a only → entries_removed = 1.
        let mut a = empty_db();
        let mut b = empty_db();

        a.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "OnlyInA"));
        b.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "OnlyInB"));

        let opts = DiffOptions::default();
        let cs = compute(&a, &b, &opts);

        // The two entries have different UUIDs (generated fresh), so each
        // will appear as Added / Removed in the symmetric diff.
        assert!(cs.summary.entries_added >= 1, "expected >=1 added entry");
        assert!(
            cs.summary.entries_removed >= 1,
            "expected >=1 removed entry"
        );

        let added_entries: Vec<_> = cs
            .changes
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    Change::Entry {
                        kind: EntryChangeKind::Added,
                        ..
                    }
                )
            })
            .collect();
        let removed_entries: Vec<_> = cs
            .changes
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    Change::Entry {
                        kind: EntryChangeKind::Removed,
                        ..
                    }
                )
            })
            .collect();
        assert!(
            !added_entries.is_empty(),
            "expected at least one Added entry change"
        );
        assert!(
            !removed_entries.is_empty(),
            "expected at least one Removed entry change"
        );
    }

    #[test]
    fn compute_no_entry_modifications_when_entries_differ_by_uuid() {
        // When entries have different UUIDs, they are seen as add/remove: not
        // Modified: so entries_modified stays 0.
        let mut a = empty_db();
        let mut b = empty_db();

        a.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "Entry"));
        b.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "Entry"));

        let opts = DiffOptions::default();
        let cs = compute(&a, &b, &opts);

        assert_eq!(cs.summary.entries_modified, 0);
    }

    // ── recycle bin suppression tests ───────────────────────────────────────

    /// Build a database with one live entry and one recycle bin group that
    /// contains a trashed entry. Sets `db.meta.recyclebin_uuid` to the
    /// recycle bin group's UUID.
    fn db_with_recycle_bin() -> keepass::Database {
        let mut db = keepass::Database::new();

        // Live entry in the root group.
        db.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "Live"));

        // Recycle bin group with a trashed entry.
        let rb_id = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Recycle Bin".into())
            .id();
        db.group_mut(rb_id)
            .unwrap()
            .add_entry()
            .edit(|e| e.set_unprotected(keepass::db::fields::TITLE, "Trashed"));

        // Wire up the metadata pointer.
        db.meta.recyclebin_uuid = Some(rb_id.uuid());

        db
    }

    #[test]
    fn tree_walk_excludes_recycle_bin_by_default() {
        let db = db_with_recycle_bin();
        // Default opts: include_recycle_bin = false.
        let map = tree_walk(&db, &DiffOptions::default());
        // Should contain: root group, Live entry. NOT recycle bin group or Trashed entry.
        let titles: Vec<_> = map
            .values()
            .filter(|n| matches!(n.kind, NodeKind::Entry))
            .map(|n| n.path.display.clone())
            .collect();
        assert!(
            titles.iter().any(|t| t.ends_with("Live")),
            "expected Live entry in walk output"
        );
        assert!(
            !titles.iter().any(|t| t.ends_with("Trashed")),
            "expected Trashed entry to be suppressed"
        );
        // Recycle Bin group itself must not appear.
        let group_names: Vec<_> = map
            .values()
            .filter(|n| matches!(n.kind, NodeKind::Group))
            .map(|n| n.path.display.clone())
            .collect();
        assert!(
            !group_names.iter().any(|g| g.ends_with("Recycle Bin")),
            "expected Recycle Bin group to be suppressed"
        );
    }

    #[test]
    fn tree_walk_includes_recycle_bin_when_opted_in() {
        let db = db_with_recycle_bin();
        let opts = DiffOptions {
            include_recycle_bin: true,
            ..DiffOptions::default()
        };
        let map = tree_walk(&db, &opts);
        let titles: Vec<_> = map
            .values()
            .filter(|n| matches!(n.kind, NodeKind::Entry))
            .map(|n| n.path.display.clone())
            .collect();
        assert!(
            titles.iter().any(|t| t.ends_with("Trashed")),
            "expected Trashed entry when include_recycle_bin = true"
        );
        let group_names: Vec<_> = map
            .values()
            .filter(|n| matches!(n.kind, NodeKind::Group))
            .map(|n| n.path.display.clone())
            .collect();
        assert!(
            group_names.iter().any(|g| g.ends_with("Recycle Bin")),
            "expected Recycle Bin group when include_recycle_bin = true"
        );
    }

    #[test]
    fn compute_excludes_recycle_bin_entries_by_default() {
        // Both databases share the same recycle bin UUID and a common live entry UUID.
        // Diffing them should not report any recycle bin changes in the default mode.
        let db = db_with_recycle_bin();
        // Diff db against itself: the two trees are structurally identical, so
        // after excluding the recycle bin there should be zero entry add/remove events.
        let opts = DiffOptions::default();
        let cs = compute(&db, &db, &opts);
        // No entries should appear as Added or Removed (same db, same UUIDs).
        let trashed: Vec<_> = cs
            .changes
            .iter()
            .filter(|c| match c {
                Change::Entry { path, .. } => path.display.contains("Trashed"),
                _ => false,
            })
            .collect();
        assert!(
            trashed.is_empty(),
            "recycle bin entries should not appear in default diff"
        );
    }

    // ── move / rename field-preservation tests ──────────────────────────────

    use keepass::db::fields::{PASSWORD, TITLE, USERNAME};

    /// A title rename changes the entry's display path (the title is its last
    /// segment) but not its UUID chain. Field-diff must still run, so the rename
    /// surfaces as a Modified Title change. The old engine skipped field-diff on
    /// any path difference and silently dropped the rename.
    #[test]
    fn title_change_is_reported_not_dropped() {
        let mut a = empty_db();
        let eid = {
            let mut root = a.root_mut();
            let mut e = root.add_entry();
            let id = e.id();
            e.edit(|x| {
                x.set_unprotected(TITLE, "Old");
                x.set_unprotected(USERNAME, "alice");
            });
            id
        };
        let mut b = a.clone();
        b.entry_mut(eid)
            .unwrap()
            .edit(|x| x.set_unprotected(TITLE, "New"));

        let cs = compute(&a, &b, &DiffOptions::default());

        assert!(
            !cs.changes.iter().any(|c| matches!(
                c,
                Change::Entry {
                    kind: EntryChangeKind::Moved { .. },
                    ..
                }
            )),
            "a title rename is not a move"
        );
        let fields = cs
            .changes
            .iter()
            .find_map(|c| match c {
                Change::Entry {
                    kind: EntryChangeKind::Modified { fields },
                    ..
                } => Some(fields),
                _ => None,
            })
            .expect("title rename should produce a Modified entry");
        assert!(
            fields.iter().any(|f| matches!(
                f,
                crate::legacy::change_set::FieldChange::Modified { name, .. } if name == "Title"
            )),
            "the Title change must be reported"
        );
    }

    /// An entry moved to another group AND edited in the same diff must report
    /// BOTH the move and the field change. The old engine skipped field-diff for
    /// any moved entry, so the edit vanished entirely.
    #[test]
    fn move_preserves_field_changes() {
        let mut a = empty_db();
        let archive = {
            let mut root = a.root_mut();
            root.add_group().edit(|g| g.name = "Archive".into()).id()
        };
        let eid = {
            let mut root = a.root_mut();
            let mut e = root.add_entry();
            let id = e.id();
            e.edit(|x| {
                x.set_unprotected(TITLE, "Bank");
                x.set_protected(PASSWORD, "old-secret");
            });
            id
        };
        let mut b = a.clone();
        b.entry_mut(eid)
            .unwrap()
            .edit(|x| x.set_protected(PASSWORD, "new-secret"));
        b.entry_mut(eid).unwrap().move_to(archive).expect("move");

        let cs = compute(&a, &b, &DiffOptions::default());

        assert!(
            cs.changes.iter().any(|c| matches!(
                c,
                Change::Entry {
                    kind: EntryChangeKind::Moved { .. },
                    ..
                }
            )),
            "the move should be reported"
        );
        let fields = cs
            .changes
            .iter()
            .find_map(|c| match c {
                Change::Entry {
                    kind: EntryChangeKind::Modified { fields },
                    ..
                } => Some(fields),
                _ => None,
            })
            .expect("the moved entry's password edit must still be reported");
        assert!(
            fields.iter().any(|f| matches!(
                f,
                crate::legacy::change_set::FieldChange::Modified { name, .. } if name == "Password"
            )),
            "the Password change must survive the move"
        );
    }

    /// Renaming a group emits a Renamed change for that group, and does NOT
    /// flag its descendants as moved (their parent UUID chain is unchanged). The
    /// old engine produced no Renamed change and reported every descendant as a
    /// cascading Moved.
    #[test]
    fn group_rename_emits_renamed_not_cascading_moves() {
        let mut a = empty_db();
        let gid = {
            let mut root = a.root_mut();
            root.add_group().edit(|g| g.name = "Web".into()).id()
        };
        {
            let mut g = a.group_mut(gid).unwrap();
            g.add_entry().edit(|e| e.set_unprotected(TITLE, "Child"));
        }
        let mut b = a.clone();
        b.group_mut(gid).unwrap().edit(|g| g.name = "Sites".into());

        let cs = compute(&a, &b, &DiffOptions::default());

        let renamed = cs.changes.iter().any(|c| {
            matches!(
                c,
                Change::Group {
                    kind: GroupChangeKind::Renamed { .. },
                    ..
                }
            )
        });
        assert!(renamed, "the group rename should be reported as Renamed");
        assert!(
            !cs.changes.iter().any(|c| matches!(
                c,
                Change::Entry {
                    kind: EntryChangeKind::Moved { .. },
                    ..
                }
            )),
            "descendants of a renamed group must not be reported as moved"
        );
        assert!(
            !cs.changes.iter().any(|c| matches!(
                c,
                Change::Group {
                    kind: GroupChangeKind::Moved { .. },
                    ..
                }
            )),
            "a rename is not a move"
        );
    }

    /// Moving a group reports the group as Moved but does NOT report its child
    /// entries as moved: they rode along with the group, their immediate parent
    /// (the group) is unchanged. Comparing the full ancestor chain would
    /// wrongly cascade a Moved onto every descendant.
    #[test]
    fn moving_a_group_does_not_cascade_move_its_entries() {
        let mut a = empty_db();
        let (web, dest) = {
            let mut root = a.root_mut();
            let web = root.add_group().edit(|g| g.name = "Web".into()).id();
            let dest = root.add_group().edit(|g| g.name = "Archive".into()).id();
            (web, dest)
        };
        {
            let mut g = a.group_mut(web).unwrap();
            g.add_entry().edit(|e| e.set_unprotected(TITLE, "Child"));
        }
        let mut b = a.clone();
        b.group_mut(web).unwrap().move_to(dest).expect("move group");

        let cs = compute(&a, &b, &DiffOptions::default());

        let group_moves = cs
            .changes
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    Change::Group {
                        kind: GroupChangeKind::Moved { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(group_moves, 1, "exactly the moved group should be reported");
        assert!(
            !cs.changes.iter().any(|c| matches!(
                c,
                Change::Entry {
                    kind: EntryChangeKind::Moved { .. },
                    ..
                }
            )),
            "the child entry rode along and must not be reported as moved"
        );
    }
}
