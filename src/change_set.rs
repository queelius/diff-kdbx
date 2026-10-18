//! The change set: one record per changed node, with every summary counter
//! computed from the records.

use kdbx_core::model::FormatVersion;
use kdbx_core::path::VaultPath;
use uuid::Uuid;

use crate::properties::{KdfKind, Property, Shown};

/// The result of [`compute`](crate::compute): what changed between two
/// snapshots.
///
/// The JSON form (see [`render_json`](crate::render_json)) is a documented
/// contract versioned by `format_version`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChangeSet {
    /// The changed nodes: the database record first (if any), then groups,
    /// then entries, each ordered by path and then UUID.
    pub changes: Vec<Change>,
    /// Counts derived from `changes` (plus the suppressed-noise count).
    pub summary: Summary,
    /// Non-fatal observations about the comparison itself.
    pub warnings: Vec<DiffWarning>,
}

/// One changed node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// Database-level properties (format, header, `<Meta>`, tombstones).
    #[non_exhaustive]
    Database {
        /// The property changes, in canonical order.
        changes: Vec<PropertyChange>,
    },
    /// A group.
    Group(NodeChange),
    /// An entry.
    Entry(NodeChange),
}

/// A group or entry that was added, removed, or modified.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NodeChange {
    /// Record identity (the match key between the two snapshots).
    pub uuid: Uuid,
    /// The node's path after the change (before it, for a removal). `None`
    /// when the node or an ancestor has an empty name: such nodes have no
    /// path and are identified by `uuid`.
    pub path: Option<VaultPath>,
    /// What happened to it.
    pub status: NodeStatus,
}

/// What happened to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeStatus {
    /// Present only after.
    Added,
    /// Present only before.
    Removed,
    /// Present in both, and moved, edited, or both. A move is `moved_from`,
    /// not a second record, so a moved-and-edited node is one record.
    #[non_exhaustive]
    Modified {
        /// The path before, when the node changed parent group (`None` when
        /// it stayed, or when its old path does not exist).
        moved_from: Option<VaultPath>,
        /// The property changes, in canonical order (empty for a pure move).
        changes: Vec<PropertyChange>,
    },
}

/// One property that differs.
///
/// `before` is `None` for an added property, `after` is `None` for a removed
/// one; both are present for a modified one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PropertyChange {
    /// Which property.
    pub property: Property,
    /// Its value before, if it existed.
    pub before: Option<Shown>,
    /// Its value after, if it exists.
    pub after: Option<Shown>,
}

/// Counts over a change set. Every counter is computed from the records
/// ([`ChangeSet::new`]), except `suppressed`, which counts what noise
/// suppression removed before the records were built.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Summary {
    /// Entries present only after.
    pub entries_added: usize,
    /// Entries present only before.
    pub entries_removed: usize,
    /// Entries moved, edited, or both (each counted once).
    pub entries_modified: usize,
    /// Of `entries_modified`, those that changed parent group.
    pub entries_moved: usize,
    /// Groups present only after.
    pub groups_added: usize,
    /// Groups present only before.
    pub groups_removed: usize,
    /// Groups moved, edited (renamed included), or both.
    pub groups_modified: usize,
    /// Of `groups_modified`, those that changed parent group.
    pub groups_moved: usize,
    /// Property changes of groups and entries.
    pub node_properties: usize,
    /// Property changes of the database itself.
    pub database_properties: usize,
    /// Noise property changes left out (see
    /// [`Property::is_noise`]); zero under [`Noise::Show`](crate::Noise::Show).
    pub suppressed: usize,
}

/// A non-fatal observation about a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiffWarning {
    /// The two files use different KDBX versions, so some properties exist
    /// on one side only (KDBX 4.1 added group tags, for example).
    #[non_exhaustive]
    VersionMismatch {
        /// The version before.
        before: FormatVersion,
        /// The version after.
        after: FormatVersion,
    },
    /// The key derivation function got cheaper to attack.
    #[non_exhaustive]
    KdfWeakened {
        /// How.
        weakening: KdfWeakening,
    },
}

/// How a key derivation function got cheaper to attack.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfWeakening {
    /// A memory-hard KDF (Argon2) was replaced by one that is not (AES-KDF).
    #[non_exhaustive]
    NoLongerMemoryHard {
        /// The KDF before.
        before: KdfKind,
        /// The KDF after.
        after: KdfKind,
    },
    /// A recognized KDF was replaced by one this version does not
    /// recognize, so its strength cannot be compared.
    #[non_exhaustive]
    Unrecognized {
        /// The KDF before.
        before: KdfKind,
    },
    /// Argon2 memory cost lowered (bytes).
    #[non_exhaustive]
    MemoryLowered {
        /// Before.
        before: u64,
        /// After.
        after: u64,
    },
    /// Argon2 passes lowered.
    #[non_exhaustive]
    IterationsLowered {
        /// Before.
        before: u64,
        /// After.
        after: u64,
    },
    /// AES-KDF rounds lowered.
    #[non_exhaustive]
    RoundsLowered {
        /// Before.
        before: u64,
        /// After.
        after: u64,
    },
}

impl ChangeSet {
    /// A change set over `changes`, with the summary computed from them.
    pub fn new(changes: Vec<Change>, warnings: Vec<DiffWarning>, suppressed: usize) -> Self {
        let summary = Summary::of(&changes, suppressed);
        ChangeSet {
            changes,
            summary,
            warnings,
        }
    }

    /// True when nothing changed (warnings do not count).
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

impl Summary {
    fn of(changes: &[Change], suppressed: usize) -> Self {
        let mut s = Summary {
            suppressed,
            ..Summary::default()
        };
        for change in changes {
            let (node, is_entry) = match change {
                Change::Database { changes } => {
                    s.database_properties += changes.len();
                    continue;
                }
                Change::Group(node) => (node, false),
                Change::Entry(node) => (node, true),
            };
            let (added, removed, modified, moved) = if is_entry {
                (
                    &mut s.entries_added,
                    &mut s.entries_removed,
                    &mut s.entries_modified,
                    &mut s.entries_moved,
                )
            } else {
                (
                    &mut s.groups_added,
                    &mut s.groups_removed,
                    &mut s.groups_modified,
                    &mut s.groups_moved,
                )
            };
            match &node.status {
                NodeStatus::Added => *added += 1,
                NodeStatus::Removed => *removed += 1,
                NodeStatus::Modified {
                    moved_from,
                    changes,
                } => {
                    *modified += 1;
                    *moved += usize::from(moved_from.is_some());
                    s.node_properties += changes.len();
                }
            }
        }
        s
    }
}

impl Change {
    /// The database-level record.
    pub fn database(changes: Vec<PropertyChange>) -> Self {
        Change::Database { changes }
    }
}

impl NodeStatus {
    /// A modified node: `moved_from` its old path when it changed parent.
    pub fn modified(moved_from: Option<VaultPath>, changes: Vec<PropertyChange>) -> Self {
        NodeStatus::Modified {
            moved_from,
            changes,
        }
    }
}

impl DiffWarning {
    /// The two files use different KDBX versions.
    pub fn version_mismatch(before: FormatVersion, after: FormatVersion) -> Self {
        DiffWarning::VersionMismatch { before, after }
    }

    /// The key derivation function got cheaper to attack.
    pub fn kdf_weakened(weakening: KdfWeakening) -> Self {
        DiffWarning::KdfWeakened { weakening }
    }
}

impl KdfWeakening {
    /// Argon2 replaced by a KDF that is not memory-hard.
    pub fn no_longer_memory_hard(before: KdfKind, after: KdfKind) -> Self {
        KdfWeakening::NoLongerMemoryHard { before, after }
    }

    /// A recognized KDF replaced by an unrecognized one.
    pub fn unrecognized(before: KdfKind) -> Self {
        KdfWeakening::Unrecognized { before }
    }

    /// Argon2 memory lowered (bytes).
    pub fn memory_lowered(before: u64, after: u64) -> Self {
        KdfWeakening::MemoryLowered { before, after }
    }

    /// Argon2 passes lowered.
    pub fn iterations_lowered(before: u64, after: u64) -> Self {
        KdfWeakening::IterationsLowered { before, after }
    }

    /// AES-KDF rounds lowered.
    pub fn rounds_lowered(before: u64, after: u64) -> Self {
        KdfWeakening::RoundsLowered { before, after }
    }
}

impl NodeChange {
    /// A node record.
    pub fn new(uuid: Uuid, path: Option<VaultPath>, status: NodeStatus) -> Self {
        NodeChange { uuid, path, status }
    }
}

impl PropertyChange {
    /// A property change.
    pub fn new(property: Property, before: Option<Shown>, after: Option<Shown>) -> Self {
        PropertyChange {
            property,
            before,
            after,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::properties::FieldName;

    fn path(s: &str) -> Option<VaultPath> {
        Some(VaultPath::parse(s).unwrap())
    }

    fn field_change(name: &str) -> PropertyChange {
        PropertyChange::new(
            Property::Field(FieldName::new(name)),
            Some(Shown::Text("a".into())),
            Some(Shown::Text("b".into())),
        )
    }

    fn entry(n: u128, status: NodeStatus) -> Change {
        Change::Entry(NodeChange::new(Uuid::from_u128(n), path("/x"), status))
    }

    #[test]
    fn summary_counts_are_computed_from_the_records() {
        let cs = ChangeSet::new(
            vec![
                Change::Database {
                    changes: vec![field_change("x")],
                },
                Change::Group(NodeChange::new(
                    Uuid::from_u128(1),
                    path("/g/"),
                    NodeStatus::Modified {
                        moved_from: path("/old/g/"),
                        changes: vec![PropertyChange::new(
                            Property::Name,
                            Some(Shown::Text("old".into())),
                            Some(Shown::Text("g".into())),
                        )],
                    },
                )),
                entry(2, NodeStatus::Added),
                entry(3, NodeStatus::Removed),
                // Moved and edited: one record, counted once.
                entry(
                    4,
                    NodeStatus::Modified {
                        moved_from: path("/y"),
                        changes: vec![field_change("URL"), field_change("Notes")],
                    },
                ),
                entry(
                    5,
                    NodeStatus::Modified {
                        moved_from: None,
                        changes: vec![field_change("URL")],
                    },
                ),
            ],
            vec![],
            7,
        );
        let mut expected = Summary {
            entries_added: 1,
            entries_removed: 1,
            entries_modified: 2,
            entries_moved: 1,
            groups_modified: 1,
            groups_moved: 1,
            node_properties: 4,
            database_properties: 1,
            suppressed: 7,
            ..Summary::default()
        };
        assert_eq!(cs.summary, expected);
        expected.suppressed = 0;
        assert_eq!(
            ChangeSet::new(cs.changes.clone(), vec![], 0).summary,
            expected
        );
    }

    #[test]
    fn warnings_do_not_make_a_change_set_non_empty() {
        let cs = ChangeSet::new(
            vec![],
            vec![DiffWarning::VersionMismatch {
                before: FormatVersion::KDBX_4_0,
                after: FormatVersion::KDBX_4_1,
            }],
            3,
        );
        assert!(cs.is_empty());
        assert!(!ChangeSet::new(vec![entry(1, NodeStatus::Added)], vec![], 0).is_empty());
    }
}
