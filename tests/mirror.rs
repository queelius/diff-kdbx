//! Property tests over generated snapshots: `compute(a, a)` is empty, and
//! `compute(a, b)` and `compute(b, a)` are mirror images (added and removed
//! swap, before and after swap, a move's origin and destination swap).
//!
//! Generated vaults vary the tree (same-named siblings, moves), field
//! content (sealed and unprotected secrets, multi-line notes, tags), entry
//! history (items sharing or lacking modification times), the recycle bin
//! (none, a group, or the root), the KDBX version and the outer header (KDF
//! kind and parameters, ciphers).

use std::collections::BTreeMap;

use diff_kdbx::kdbx_core::fingerprint::FingerprintKey;
use diff_kdbx::kdbx_core::model::{
    Argon2Info, Argon2Variant, Compression, Entry, Field, FormatVersion, Group, HeaderInfo,
    InnerCipher, KdfInfo, Meta, OuterCipher, Sealing, Snapshot, Timestamp,
};
use diff_kdbx::{
    Change, ChangeSet, DiffOptions, DiffWarning, DumpOptions, KdfWeakening, NodeChange, NodeStatus,
    Noise, PropertyChange, RecycleBin, compute, dump,
};
use proptest::prelude::*;
use uuid::Uuid;

const GROUPS: u128 = 4;
const ENTRIES: u128 = 6;
const NAMES: [&str; 4] = ["A", "B", "Dup", "Dup"];

fn group_id(i: u128) -> Uuid {
    Uuid::from_u128(0x100 + i)
}

fn entry_id(i: u128) -> Uuid {
    Uuid::from_u128(0x200 + i)
}

/// One generated node: present or not, its parent slot, and some content.
#[derive(Debug, Clone)]
struct NodeSpec {
    present: bool,
    parent: usize,
    name: usize,
    secret: Option<(bool, u8)>,
    notes: Option<u8>,
    tags: Vec<usize>,
    usage: u8,
    /// History items: (modification time choice, URL choice).
    history: Vec<(u8, u8)>,
}

/// One generated vault.
#[derive(Debug, Clone)]
struct World {
    groups: Vec<NodeSpec>,
    entries: Vec<NodeSpec>,
    v40: bool,
    /// 0: no recycle bin, 1: the root, 2..: group `n - 2`.
    recycle_bin: usize,
    /// KDF choice and cipher choice, or no header.
    header: Option<(u8, bool)>,
}

fn node_spec() -> impl Strategy<Value = NodeSpec> {
    (
        any::<bool>(),
        0usize..8,
        0usize..NAMES.len(),
        proptest::option::of((any::<bool>(), 0u8..3)),
        proptest::option::of(0u8..3),
        proptest::collection::vec(0usize..3, 0..3),
        0u8..3,
        proptest::collection::vec((0u8..3, 0u8..3), 0..4),
    )
        .prop_map(
            |(present, parent, name, secret, notes, tags, usage, history)| NodeSpec {
                present,
                parent,
                name,
                secret,
                notes,
                tags,
                usage,
                history,
            },
        )
}

fn world() -> impl Strategy<Value = World> {
    (
        proptest::collection::vec(node_spec(), GROUPS as usize),
        proptest::collection::vec(node_spec(), ENTRIES as usize),
        any::<bool>(),
        0usize..(2 + GROUPS as usize),
        proptest::option::of((0u8..6, any::<bool>())),
    )
        .prop_map(|(groups, entries, v40, recycle_bin, header)| World {
            groups,
            entries,
            v40,
            recycle_bin,
            header,
        })
}

fn header((kdf, cipher): (u8, bool)) -> HeaderInfo {
    let argon2 = |memory: u64, iterations: u64| {
        KdfInfo::Argon2(Argon2Info::new(
            Argon2Variant::Argon2id,
            memory,
            iterations,
            1,
            0x13,
        ))
    };
    let kdf = match kdf {
        0 => KdfInfo::Aes { rounds: 6_000 },
        1 => KdfInfo::Aes { rounds: 60_000 },
        2 => argon2(1 << 20, 2),
        3 => argon2(2 << 20, 2),
        4 => argon2(1 << 20, 4),
        _ => KdfInfo::Unrecognized,
    };
    let (outer, inner) = if cipher {
        (OuterCipher::ChaCha20, InnerCipher::ChaCha20)
    } else {
        (OuterCipher::Aes256, InnerCipher::Salsa20)
    };
    HeaderInfo::new(kdf, outer, inner, Compression::GZip)
}

/// Build a snapshot from specs. Group `i` hangs under the root or under an
/// earlier present group, so the tree is always acyclic.
fn build(world: &World) -> Snapshot {
    let (groups, entries) = (&world.groups, &world.entries);
    let key = FingerprintKey::from_bytes([5; 32]);
    let seal = Sealing::Fingerprint(&key);
    let mut built: Vec<Option<Group>> = (0..GROUPS)
        .map(|i| {
            let spec = &groups[i as usize];
            spec.present.then(|| {
                let mut g = Group::new(group_id(i), NAMES[spec.name]);
                g.notes = spec.notes.map(|n| format!("note {n}\nline"));
                g.tags = spec.tags.iter().map(|t| format!("t{t}")).collect();
                g
            })
        })
        .collect();
    let parent_of = |slot: usize, limit: usize, built: &[Option<Group>]| -> Option<usize> {
        let candidate = slot % (limit + 1);
        (candidate > 0 && built[candidate - 1].is_some()).then(|| candidate - 1)
    };
    let mut root = Group::new(Uuid::from_u128(1), "Root");
    for (i, spec) in entries.iter().enumerate() {
        if !spec.present {
            continue;
        }
        let mut e = Entry::new(entry_id(i as u128))
            .with_field("Title", Field::plain(NAMES[spec.name]))
            .with_field("UserName", Field::plain(format!("u{}", spec.usage)));
        if let Some((protected, value)) = spec.secret {
            e = e.with_field("PIN", seal.field("PIN", protected, &format!("pin{value}")));
        }
        e.tags = spec.tags.iter().map(|t| format!("t{t}")).collect();
        e.times.usage_count = Some(spec.usage.into());
        e.times.creation = Timestamp::from_unix(1_767_258_000);
        e.history = spec
            .history
            .iter()
            .map(|(when, url)| {
                let mut h = Entry::new(entry_id(i as u128))
                    .with_field("Title", Field::plain(NAMES[spec.name]))
                    .with_field("URL", Field::plain(format!("https://{url}.example")));
                h.times.last_modification = match when {
                    0 => None,
                    n => Timestamp::from_unix(1_767_258_000 + i64::from(*n)),
                };
                h
            })
            .collect();
        match parent_of(spec.parent, GROUPS as usize, &built) {
            Some(g) => built[g].as_mut().unwrap().entries.push(e),
            None => root.entries.push(e),
        }
    }
    // Attach groups children-first (highest index first), each under an
    // earlier group or the root.
    for i in (0..GROUPS as usize).rev() {
        let Some(g) = built[i].take() else { continue };
        let parent = parent_of(groups[i].parent, i, &built);
        match parent {
            Some(p) => built[p].as_mut().unwrap().groups.push(g),
            None => root.groups.push(g),
        }
    }
    let format = if world.v40 {
        FormatVersion::KDBX_4_0
    } else {
        FormatVersion::KDBX_4_1
    };
    let mut meta = Meta::default();
    meta.recycle_bin = match world.recycle_bin {
        0 => None,
        1 => Some(Uuid::from_u128(1)),
        n => Some(group_id((n - 2) as u128)),
    };
    let mut snap = Snapshot::new(format, meta, root);
    snap.header = world.header.map(header);
    snap
}

fn swap(c: &PropertyChange) -> (String, Option<String>, Option<String>) {
    let s = |v: &Option<diff_kdbx::Shown>| v.as_ref().map(|v| format!("{v:?}"));
    (c.property.to_string(), s(&c.after), s(&c.before))
}

fn plain(c: &PropertyChange) -> (String, Option<String>, Option<String>) {
    let s = |v: &Option<diff_kdbx::Shown>| v.as_ref().map(|v| format!("{v:?}"));
    (c.property.to_string(), s(&c.before), s(&c.after))
}

fn records(cs: &ChangeSet) -> BTreeMap<(u8, Uuid), &NodeChange> {
    cs.changes
        .iter()
        .filter_map(|c| match c {
            Change::Group(n) => Some(((0, n.uuid), n)),
            Change::Entry(n) => Some(((1, n.uuid), n)),
            _ => None,
        })
        .collect()
}

fn database(cs: &ChangeSet) -> Vec<&PropertyChange> {
    cs.changes
        .iter()
        .filter_map(|c| match c {
            Change::Database { changes, .. } => Some(changes.iter()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn assert_mirror(ab: &ChangeSet, ba: &ChangeSet) -> Result<(), TestCaseError> {
    let (ra, rb) = (records(ab), records(ba));
    prop_assert_eq!(ra.keys().collect::<Vec<_>>(), rb.keys().collect::<Vec<_>>());
    for (key, x) in &ra {
        let y = rb[key];
        match (&x.status, &y.status) {
            (NodeStatus::Added, NodeStatus::Removed) | (NodeStatus::Removed, NodeStatus::Added) => {
                prop_assert_eq!(&x.path, &y.path);
            }
            (
                NodeStatus::Modified {
                    moved_from: mx,
                    changes: cx,
                    ..
                },
                NodeStatus::Modified {
                    moved_from: my,
                    changes: cy,
                    ..
                },
            ) => {
                if mx.is_some() {
                    prop_assert_eq!(mx, &y.path);
                }
                if my.is_some() {
                    prop_assert_eq!(my, &x.path);
                }
                if x.path.is_some() && y.path.is_some() {
                    prop_assert_eq!(mx.is_some(), my.is_some());
                }
                let cx: Vec<_> = cx.iter().map(swap).collect();
                let cy: Vec<_> = cy.iter().map(plain).collect();
                prop_assert_eq!(cx, cy);
            }
            other => prop_assert!(false, "not mirrored: {:?}", other),
        }
    }
    let da: Vec<_> = database(ab).into_iter().map(swap).collect();
    let db: Vec<_> = database(ba).into_iter().map(plain).collect();
    prop_assert_eq!(da, db);
    let (s, t) = (&ab.summary, &ba.summary);
    prop_assert_eq!(
        (
            s.entries_added,
            s.entries_removed,
            s.groups_added,
            s.groups_removed
        ),
        (
            t.entries_removed,
            t.entries_added,
            t.groups_removed,
            t.groups_added
        )
    );
    prop_assert_eq!(
        (
            s.entries_modified,
            s.entries_moved,
            s.groups_modified,
            s.groups_moved
        ),
        (
            t.entries_modified,
            t.entries_moved,
            t.groups_modified,
            t.groups_moved
        )
    );
    prop_assert_eq!(
        (s.node_properties, s.database_properties, s.suppressed),
        (t.node_properties, t.database_properties, t.suppressed)
    );
    // A version mismatch mirrors; a KDF weakening is directional (the reverse
    // is a strengthening), so the same aspect never weakens both ways.
    let versions = |cs: &ChangeSet| -> Vec<(String, String)> {
        cs.warnings
            .iter()
            .filter_map(|w| match w {
                DiffWarning::VersionMismatch { before, after, .. } => {
                    Some((before.to_string(), after.to_string()))
                }
                _ => None,
            })
            .collect()
    };
    let swapped: Vec<(String, String)> = versions(ba).into_iter().map(|(x, y)| (y, x)).collect();
    prop_assert_eq!(versions(ab), swapped);
    let aspects = |cs: &ChangeSet| -> Vec<std::mem::Discriminant<KdfWeakening>> {
        cs.warnings
            .iter()
            .filter_map(|w| match w {
                DiffWarning::KdfWeakened { weakening, .. } => {
                    Some(std::mem::discriminant(weakening))
                }
                _ => None,
            })
            .collect()
    };
    let (wa, wb) = (aspects(ab), aspects(ba));
    prop_assert!(
        wa.iter().all(|a| !wb.contains(a)),
        "{:?} vs {:?}",
        ab.warnings,
        ba.warnings
    );
    Ok(())
}

fn all_options() -> [DiffOptions; 2] {
    [
        DiffOptions::default(),
        DiffOptions::new(Noise::Show, RecycleBin::Exclude),
    ]
}

proptest! {
    #[test]
    fn a_snapshot_against_itself_is_empty(w in world()) {
        let a = build(&w);
        for opts in all_options() {
            let cs = compute(&a, &a, &opts);
            prop_assert!(cs.is_empty(), "{:#?}", cs);
            prop_assert!(cs.warnings.is_empty());
        }
        prop_assert_eq!(dump(&a, &DumpOptions::default()), dump(&a.clone(), &DumpOptions::default()));
    }

    #[test]
    fn swapping_the_sides_mirrors_the_change_set(wa in world(), wb in world()) {
        let (a, b) = (build(&wa), build(&wb));
        for opts in all_options() {
            assert_mirror(&compute(&a, &b, &opts), &compute(&b, &a, &opts))?;
        }
    }
}
