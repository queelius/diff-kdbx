//! The nodes of one snapshot that a diff or dump covers, with their paths
//! and parents, and the canonical path order.

use std::collections::{BTreeMap, HashSet};

use kdbx_core::model::{NodeKind, NodeRef, Snapshot};
use kdbx_core::path::{PathIndex, VaultPath};
use uuid::Uuid;

use crate::options::RecycleBin;

/// One group or entry, located.
#[derive(Debug, Clone)]
pub(crate) struct Node<'a> {
    pub(crate) node: NodeRef<'a>,
    /// The parent group's UUID (`None` for the root).
    pub(crate) parent: Option<Uuid>,
    /// The node's vault path (`None` when it or an ancestor has an empty
    /// name).
    pub(crate) path: Option<VaultPath>,
}

/// Every covered node of a snapshot, by UUID.
#[derive(Debug, Clone)]
pub(crate) struct Nodes<'a> {
    by_uuid: BTreeMap<Uuid, Node<'a>>,
}

impl<'a> Nodes<'a> {
    /// The nodes of `snap`, leaving out the recycle bin's subtree unless
    /// `recycle_bin` includes it. For a UUID that occurs twice (a malformed
    /// file), the first node in walk order wins, as in `PathIndex`.
    pub(crate) fn new(snap: &'a Snapshot, recycle_bin: RecycleBin) -> Self {
        let excluded_root = match recycle_bin {
            RecycleBin::Exclude => snap.meta.recycle_bin.filter(|&rb| rb != snap.root.uuid),
            RecycleBin::Include => None,
        };
        let paths = PathIndex::new(snap);
        let mut excluded: HashSet<Uuid> = HashSet::new();
        let mut by_uuid = BTreeMap::new();
        for (node, parent) in snap.walk() {
            let uuid = node.uuid();
            let parent = parent.map(|g| g.uuid);
            if Some(uuid) == excluded_root || parent.is_some_and(|p| excluded.contains(&p)) {
                if node.kind() == NodeKind::Group {
                    excluded.insert(uuid);
                }
                continue;
            }
            by_uuid.entry(uuid).or_insert_with(|| Node {
                node,
                parent,
                path: paths.get(uuid).cloned(),
            });
        }
        Nodes { by_uuid }
    }

    pub(crate) fn get(&self, uuid: &Uuid) -> Option<&Node<'a>> {
        self.by_uuid.get(uuid)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Uuid, &Node<'a>)> {
        self.by_uuid.iter()
    }
}

/// The order of paths: segment by segment (name, then ordinal), so a group
/// sorts directly before its contents; pathless nodes sort last.
pub(crate) fn path_key(path: Option<&VaultPath>) -> (bool, Vec<(&str, usize)>) {
    match path {
        Some(p) => (
            false,
            p.segments()
                .iter()
                .map(|s| (s.name(), s.ordinal().unwrap_or(1)))
                .collect(),
        ),
        None => (true, Vec::new()),
    }
}
