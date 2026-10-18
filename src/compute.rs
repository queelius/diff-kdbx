//! The diff engine: match nodes by UUID and merge-join their property maps.

use std::cmp::Ordering;
use std::iter::Peekable;

use kdbx_core::model::{KdfInfo, NodeKind, NodeRef, Snapshot};
use uuid::Uuid;

use crate::change_set::{
    Change, ChangeSet, DiffWarning, KdfWeakening, NodeChange, NodeStatus, PropertyChange,
};
use crate::nodes::{Node, Nodes, path_key};
use crate::options::{DiffOptions, Noise};
use crate::properties::{
    KdfKind, PropertyMap, database_properties, entry_properties, group_properties,
};

/// Compare two snapshots.
///
/// Nodes match by UUID. A matched node yields one record holding every
/// property that differs and, when its parent group changed, the path it
/// moved from. Noise is left out (and counted) unless `opts` shows it; the
/// recycle bin is left out unless `opts` includes it. The result is a pure
/// function of the inputs, ordered: the database record, then groups, then
/// entries, each by path and then UUID.
pub fn compute(before: &Snapshot, after: &Snapshot, opts: &DiffOptions) -> ChangeSet {
    let mut suppressed = 0;
    let mut changes = Vec::new();

    let db = diff_maps(
        database_properties(before),
        database_properties(after),
        opts.noise,
        &mut suppressed,
    );
    if !db.is_empty() {
        changes.push(Change::Database { changes: db });
    }

    let a = Nodes::new(before, opts.recycle_bin);
    let b = Nodes::new(after, opts.recycle_bin);
    let mut records: Vec<(NodeKind, Change)> = Vec::new();
    for (uuid, na) in a.iter() {
        match b.get(uuid).filter(|nb| nb.node.kind() == na.node.kind()) {
            Some(nb) => {
                let props = diff_maps(
                    properties(na.node),
                    properties(nb.node),
                    opts.noise,
                    &mut suppressed,
                );
                let moved = na.parent != nb.parent;
                if moved || !props.is_empty() {
                    let moved_from = if moved { na.path.clone() } else { None };
                    let status = NodeStatus::Modified {
                        moved_from,
                        changes: props,
                    };
                    records.push(record(*uuid, nb, status));
                }
            }
            None => records.push(record(*uuid, na, NodeStatus::Removed)),
        }
    }
    for (uuid, nb) in b.iter() {
        let matched = a
            .get(uuid)
            .is_some_and(|na| na.node.kind() == nb.node.kind());
        if !matched {
            records.push(record(*uuid, nb, NodeStatus::Added));
        }
    }
    records.sort_by(|(ka, ca), (kb, cb)| {
        let (na, nb) = (node_of(ca), node_of(cb));
        ka.cmp(kb)
            .then_with(|| path_key(na.path.as_ref()).cmp(&path_key(nb.path.as_ref())))
            .then_with(|| na.uuid.cmp(&nb.uuid))
    });
    changes.extend(records.into_iter().map(|(_, c)| c));

    ChangeSet::new(changes, warnings(before, after), suppressed)
}

fn properties(node: NodeRef<'_>) -> PropertyMap {
    match node {
        NodeRef::Group(g) => group_properties(g),
        NodeRef::Entry(e) => entry_properties(e),
    }
}

fn record(uuid: Uuid, node: &Node<'_>, status: NodeStatus) -> (NodeKind, Change) {
    let kind = node.node.kind();
    let change = NodeChange::new(uuid, node.path.clone(), status);
    let change = match kind {
        NodeKind::Group => Change::Group(change),
        NodeKind::Entry => Change::Entry(change),
    };
    (kind, change)
}

fn node_of(change: &Change) -> &NodeChange {
    match change {
        Change::Group(n) | Change::Entry(n) => n,
        Change::Database { .. } => unreachable!("records hold only nodes"),
    }
}

/// Merge-join two property maps into the changes from `a` to `b`, leaving out
/// (and counting) noise when `noise` suppresses it.
fn diff_maps(
    a: PropertyMap,
    b: PropertyMap,
    noise: Noise,
    suppressed: &mut usize,
) -> Vec<PropertyChange> {
    let mut out = Vec::new();
    for change in MergeJoin::new(a.into_iter(), b.into_iter()) {
        if noise == Noise::Suppress && change.property.is_noise() {
            *suppressed += 1;
        } else {
            out.push(change);
        }
    }
    out
}

/// The changes between two sorted property streams, in key order.
struct MergeJoin<A: Iterator, B: Iterator> {
    a: Peekable<A>,
    b: Peekable<B>,
}

impl<A, B> MergeJoin<A, B>
where
    A: Iterator<Item = (crate::Property, crate::Shown)>,
    B: Iterator<Item = (crate::Property, crate::Shown)>,
{
    fn new(a: A, b: B) -> Self {
        MergeJoin {
            a: a.peekable(),
            b: b.peekable(),
        }
    }
}

impl<A, B> Iterator for MergeJoin<A, B>
where
    A: Iterator<Item = (crate::Property, crate::Shown)>,
    B: Iterator<Item = (crate::Property, crate::Shown)>,
{
    type Item = PropertyChange;

    fn next(&mut self) -> Option<PropertyChange> {
        loop {
            let order = match (self.a.peek(), self.b.peek()) {
                (None, None) => return None,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some((ka, _)), Some((kb, _))) => ka.cmp(kb),
            };
            match order {
                Ordering::Less => {
                    let (k, v) = self.a.next()?;
                    return Some(PropertyChange::new(k, Some(v), None));
                }
                Ordering::Greater => {
                    let (k, v) = self.b.next()?;
                    return Some(PropertyChange::new(k, None, Some(v)));
                }
                Ordering::Equal => {
                    let (k, va) = self.a.next()?;
                    let (_, vb) = self.b.next()?;
                    if va != vb {
                        return Some(PropertyChange::new(k, Some(va), Some(vb)));
                    }
                }
            }
        }
    }
}

fn warnings(before: &Snapshot, after: &Snapshot) -> Vec<DiffWarning> {
    let mut out = Vec::new();
    if before.format != after.format {
        out.push(DiffWarning::VersionMismatch {
            before: before.format,
            after: after.format,
        });
    }
    if let (Some(a), Some(b)) = (&before.header, &after.header) {
        out.extend(
            kdf_weakenings(&a.kdf, &b.kdf)
                .into_iter()
                .map(|weakening| DiffWarning::KdfWeakened { weakening }),
        );
    }
    out
}

/// The ways `after` is cheaper to attack than `before`.
fn kdf_weakenings(before: &KdfInfo, after: &KdfInfo) -> Vec<KdfWeakening> {
    let (kind_before, kind_after) = (KdfKind::of(before), KdfKind::of(after));
    if kind_after == KdfKind::Unrecognized && kind_before != KdfKind::Unrecognized {
        return vec![KdfWeakening::Unrecognized {
            before: kind_before,
        }];
    }
    let lowered = |a: u64, b: u64| b < a;
    match (before, after) {
        (KdfInfo::Argon2(a), KdfInfo::Argon2(b)) => {
            let mut out = Vec::new();
            if lowered(a.memory_bytes, b.memory_bytes) {
                out.push(KdfWeakening::MemoryLowered {
                    before: a.memory_bytes,
                    after: b.memory_bytes,
                });
            }
            if lowered(a.iterations, b.iterations) {
                out.push(KdfWeakening::IterationsLowered {
                    before: a.iterations,
                    after: b.iterations,
                });
            }
            out
        }
        (KdfInfo::Argon2(_), KdfInfo::Aes { .. }) => vec![KdfWeakening::NoLongerMemoryHard {
            before: kind_before,
            after: kind_after,
        }],
        (KdfInfo::Aes { rounds: a }, KdfInfo::Aes { rounds: b }) if lowered(*a, *b) => {
            vec![KdfWeakening::RoundsLowered {
                before: *a,
                after: *b,
            }]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
