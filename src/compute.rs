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
}
