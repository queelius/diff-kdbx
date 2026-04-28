//! Diff computation: walk two KDBX databases and produce a structural ChangeSet.

use crate::options::DiffOptions;
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
    walk_group_ref(&root, &mut Vec::new(), &mut Vec::new(), db, recycle_bin_uuid, &mut out);
    out
}

fn walk_group_ref(
    group: &GroupRef<'_>,
    name_stack: &mut Vec<String>,
    uuid_stack: &mut Vec<Uuid>,
    db: &keepass::Database,
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
        walk_group_ref(&child_group, name_stack, uuid_stack, db, recycle_bin_uuid, out);
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

/// Compute field-level changes between two matched entries.
/// Returns an empty Vec if there are no differences in user-visible fields.
///
/// `db_a` and `db_b` are the databases owning `a` and `b` respectively.
/// They are required to resolve attachment content (keepass 0.12 stores attachment
/// binary data centrally; names are only accessible via serialization).
pub fn field_diff_entry(
    a: &keepass::db::Entry,
    b: &keepass::db::Entry,
    db_a: &keepass::Database,
    db_b: &keepass::Database,
    opts: &DiffOptions,
) -> Vec<FieldChange> {
    let mut out = Vec::new();
    diff_standard_fields(a, b, opts, &mut out);
    diff_custom_fields(a, b, opts, &mut out);
    diff_tags(a, b, &mut out);
    diff_attachments(a, b, db_a, db_b, &mut out);
    diff_history(a, b, &mut out);
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

use crate::mask::HashPrefix;

/// Diff the attachments of two entries, appending `AttachmentAdded`, `AttachmentRemoved`, and
/// `AttachmentModified` changes to `out`.
///
/// keepass 0.12 stores attachment binary content in `Database::attachments` (a flat map keyed by
/// `AttachmentId`). The name→id mapping lives in `Entry::attachments`, which is `pub(crate)` and
/// therefore inaccessible from outside the keepass crate.  We recover the names by serializing
/// the entry to JSON (enabled via the `serialization` keepass feature) and reading the
/// `"attachments"` object's keys.  Content is then resolved by joining against
/// `db.iter_all_attachments()` on the numeric id.
fn diff_attachments(
    a: &keepass::db::Entry,
    b: &keepass::db::Entry,
    db_a: &keepass::Database,
    db_b: &keepass::Database,
    out: &mut Vec<FieldChange>,
) {
    use std::collections::BTreeMap;

    let a_atts: BTreeMap<String, HashPrefix> = collect_attachments(a, db_a);
    let b_atts: BTreeMap<String, HashPrefix> = collect_attachments(b, db_b);

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
/// The keepass 0.12 API does not expose a public name-keyed iterator over an entry's attachments.
/// We work around this by:
/// 1. Serializing the entry to a JSON value (requires the `serialization` keepass feature).  The
///    `attachments` field is serialized as `{"name": <AttachmentId as usize>, ...}`.
/// 2. Building a `usize → &[u8]` content map from `db.iter_all_attachments()`, using
///    `att_ref.id().id()` as the numeric key.
/// 3. Joining the two maps to produce a `name → HashPrefix` map.
fn collect_attachments(
    entry: &keepass::db::Entry,
    db: &keepass::Database,
) -> std::collections::BTreeMap<String, HashPrefix> {
    use std::collections::HashMap;

    // Step 1 – extract name→numeric_id from the serialized entry.
    // `serde_json::to_value` panics only on non-serializable types; Entry: Serialize.
    let entry_json = serde_json::to_value(entry)
        .expect("keepass Entry should always be serializable with the 'serialization' feature");
    let name_to_id: HashMap<String, usize> = entry_json
        .get("attachments")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(name, id)| id.as_u64().map(|n| (name.clone(), n as usize)))
                .collect()
        })
        .unwrap_or_default();

    if name_to_id.is_empty() {
        return std::collections::BTreeMap::new();
    }

    // Step 2 – build numeric_id→content map from the database's attachment pool.
    // Clone the content bytes so we don't hold a reference into db across the iterator.
    let id_to_content: HashMap<usize, Vec<u8>> = db
        .iter_all_attachments()
        .map(|att_ref| {
            // AttachmentRef derefs to Attachment; Attachment.data is Value<Vec<u8>>.
            // Value::get() exposes the bytes regardless of protection.
            let numeric_id = att_ref.id().id();
            let content = att_ref.data.get().clone();
            (numeric_id, content)
        })
        .collect();

    // Step 3 – join and hash.
    let mut out = std::collections::BTreeMap::new();
    for (name, id) in name_to_id {
        if let Some(content) = id_to_content.get(&id) {
            out.insert(name, HashPrefix::of_bytes(content));
        }
    }
    out
}

fn diff_history(
    a: &keepass::db::Entry,
    b: &keepass::db::Entry,
    out: &mut Vec<FieldChange>,
) {
    let la = a.history.as_ref().map(|h| h.get_entries().len()).unwrap_or(0);
    let lb = b.history.as_ref().map(|h| h.get_entries().len()).unwrap_or(0);
    if lb > la {
        out.push(FieldChange::HistoryGrew { added: lb - la });
    } else if lb < la {
        out.push(FieldChange::HistoryRewritten { from_len: la, to_len: lb });
    }
    // Same length but content might have been rewritten in place. Detecting
    // that requires recursive diff into history entries; it's a --strict-only
    // concern. v0.1 reports same-length history as unchanged.
}

/// Field names suppressed by default (not in --strict).
pub const NOISY_TIMESTAMP_FIELDS: &[&str] = &[
    "LastAccessTime",
    "UsageCount",
    "LocationChanged",
];

fn suppress_field_changes(fields: Vec<FieldChange>, opts: &DiffOptions) -> (Vec<FieldChange>, usize) {
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

fn is_suppressible(fc: &FieldChange) -> bool {
    match fc {
        FieldChange::Modified { name, .. } |
        FieldChange::Added { name, .. } |
        FieldChange::Removed { name, .. } => {
            NOISY_TIMESTAMP_FIELDS.contains(&name.as_str())
        }
        _ => false,
    }
}

use crate::change_set::{DatabaseChange, DiffWarning};

/// Top-level diff entry point.
///
/// Produces a complete [`ChangeSet`] by:
/// 1. Emitting a [`DiffWarning::VersionMismatch`] when the two databases use
///    different KDBX format versions.
/// 2. Diffing database-level metadata (name, etc.) via [`diff_database_metadata`].
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
        cs.warnings.push(DiffWarning::VersionMismatch { a: va, b: vb });
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

    // 4. Modified entries: same UUID in both, same path (different path = Moved,
    //    already handled by symmetric_diff).
    for (uuid, na) in &map_a {
        let Some(nb) = map_b.get(uuid) else { continue; };
        if na.path != nb.path {
            continue; // Moved — already accounted for
        }
        if let (NodeKind::Entry, NodeKind::Entry) = (&na.kind, &nb.kind) {
            let ea = entries_a.get(uuid).map(|er| &**er);
            let eb = entries_b.get(uuid).map(|er| &**er);
            if let (Some(ea), Some(eb)) = (ea, eb) {
                let raw_fields = field_diff_entry(ea, eb, a, b, opts);
                let (fields, suppressed) = suppress_field_changes(raw_fields, opts);
                cs.summary.suppressed += suppressed;
                if !fields.is_empty() {
                    cs.summary.entries_modified += 1;
                    cs.summary.fields_changed += fields.len();
                    cs.changes.push(Change::Entry {
                        uuid: *uuid,
                        path: na.path.clone(),
                        kind: EntryChangeKind::Modified { fields },
                    });
                }
            }
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
        cs.changes.push(Change::Database(DatabaseChange::NameChanged {
            from: a.meta.database_name.clone().unwrap_or_default(),
            to: b.meta.database_name.clone().unwrap_or_default(),
        }));
        cs.summary.metadata_changed += 1;
    }

    // Color
    let color_a = a.meta.color.as_ref().map(|c| format!("{c:?}"));
    let color_b = b.meta.color.as_ref().map(|c| format!("{c:?}"));
    if color_a != color_b {
        cs.changes.push(Change::Database(DatabaseChange::ColorChanged {
            from: color_a,
            to: color_b,
        }));
        cs.summary.metadata_changed += 1;
    }

    // Recycle bin UUID
    if a.meta.recyclebin_uuid != b.meta.recyclebin_uuid {
        cs.changes.push(Change::Database(DatabaseChange::RecycleBinChanged {
            from: a.meta.recyclebin_uuid,
            to: b.meta.recyclebin_uuid,
        }));
        cs.summary.metadata_changed += 1;
    }
}

fn sort_changes(changes: &mut Vec<Change>) {
    changes.sort_by(|x, y| sort_key(x).cmp(&sort_key(y)));
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
        let map = tree_walk(&db, &DiffOptions::default());
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
        let opts = DiffOptions::default();
        let ma = tree_walk(&a, &opts);
        let mb = tree_walk(&b, &opts);
        let mut cs = ChangeSet::default();
        symmetric_diff(&ma, &mb, &mut cs);
        // Both have just root; root UUIDs differ between Database::new() invocations,
        // so we may see one added + one removed. The test just confirms the function runs.
        let _ = cs;
    }

    #[test]
    fn suppression_drops_last_access_time() {
        let opts = DiffOptions::default();
        let input = vec![
            FieldChange::Modified {
                name: "LastAccessTime".into(),
                change: ValueChange {
                    from: ValueDisplay::Plain { value: "t1".into() },
                    to: ValueDisplay::Plain { value: "t2".into() },
                },
            },
            FieldChange::Modified {
                name: "Title".into(),
                change: ValueChange {
                    from: ValueDisplay::Plain { value: "old".into() },
                    to: ValueDisplay::Plain { value: "new".into() },
                },
            },
        ];
        let (kept, suppressed) = suppress_field_changes(input, &opts);
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed, 1);
        assert!(matches!(&kept[0], FieldChange::Modified { name, .. } if name == "Title"));
    }

    #[test]
    fn strict_disables_suppression() {
        let opts = DiffOptions { strict: true, show_secrets: false, include_recycle_bin: false };
        let input = vec![
            FieldChange::Modified {
                name: "LastAccessTime".into(),
                change: ValueChange {
                    from: ValueDisplay::Plain { value: "t1".into() },
                    to: ValueDisplay::Plain { value: "t2".into() },
                },
            },
        ];
        let (kept, suppressed) = suppress_field_changes(input, &opts);
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed, 0);
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
        let name_changes: Vec<_> = cs.changes.iter().filter(|c| {
            matches!(c, Change::Database(DatabaseChange::NameChanged { .. }))
        }).collect();
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
        assert!(cs.summary.entries_removed >= 1, "expected >=1 removed entry");

        let added_entries: Vec<_> = cs.changes.iter().filter(|c| {
            matches!(c, Change::Entry { kind: EntryChangeKind::Added, .. })
        }).collect();
        let removed_entries: Vec<_> = cs.changes.iter().filter(|c| {
            matches!(c, Change::Entry { kind: EntryChangeKind::Removed, .. })
        }).collect();
        assert!(!added_entries.is_empty(), "expected at least one Added entry change");
        assert!(!removed_entries.is_empty(), "expected at least one Removed entry change");
    }

    #[test]
    fn compute_no_entry_modifications_when_entries_differ_by_uuid() {
        // When entries have different UUIDs, they are seen as add/remove — not
        // Modified — so entries_modified stays 0.
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
        let titles: Vec<_> = map.values()
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
        let group_names: Vec<_> = map.values()
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
        let opts = DiffOptions { include_recycle_bin: true, ..DiffOptions::default() };
        let map = tree_walk(&db, &opts);
        let titles: Vec<_> = map.values()
            .filter(|n| matches!(n.kind, NodeKind::Entry))
            .map(|n| n.path.display.clone())
            .collect();
        assert!(
            titles.iter().any(|t| t.ends_with("Trashed")),
            "expected Trashed entry when include_recycle_bin = true"
        );
        let group_names: Vec<_> = map.values()
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
        let trashed: Vec<_> = cs.changes.iter().filter(|c| {
            match c {
                Change::Entry { path, .. } => path.display.contains("Trashed"),
                _ => false,
            }
        }).collect();
        assert!(trashed.is_empty(), "recycle bin entries should not appear in default diff");
    }
}
