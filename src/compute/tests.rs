use kdbx_core::model::{
    Argon2Info, Argon2Variant, AutoType, AutoTypeAssociation, AutoTypeObfuscation, Compression,
    CustomValue, Entry, Field, FormatVersion, Group, HeaderInfo, Icon, InnerCipher, OuterCipher,
    Rgb, Sealing, Snapshot, Value,
};
use kdbx_core::path::VaultPath;

use super::*;
use crate::change_set::Summary;
use crate::options::RecycleBin;
use crate::properties::{ColorRole, FieldName, HistoryKey, Property, Shown};
use crate::test_support::*;

fn strict() -> DiffOptions {
    DiffOptions::new(Noise::Show, RecycleBin::Exclude)
}

fn path(s: &str) -> Option<VaultPath> {
    Some(VaultPath::parse(s).unwrap())
}

fn node(cs: &ChangeSet, uuid: Uuid) -> &NodeChange {
    cs.changes
        .iter()
        .find_map(|c| match c {
            Change::Group(n) | Change::Entry(n) if n.uuid == uuid => Some(n),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no record for {uuid}: {cs:#?}"))
}

/// The property changes of a modified record.
fn props(cs: &ChangeSet, uuid: Uuid) -> &[PropertyChange] {
    match &node(cs, uuid).status {
        NodeStatus::Modified { changes, .. } => changes,
        other => panic!("{uuid} is {other:?}, not modified"),
    }
}

fn changed(cs: &ChangeSet, uuid: Uuid) -> Vec<String> {
    props(cs, uuid)
        .iter()
        .map(|c| c.property.to_string())
        .collect()
}

fn database_changes(cs: &ChangeSet) -> Vec<String> {
    cs.changes
        .iter()
        .find_map(|c| match c {
            Change::Database { changes } => {
                Some(changes.iter().map(|c| c.property.to_string()).collect())
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn edit(snap: &mut Snapshot, uuid: Uuid) -> &mut Entry {
    entry_mut(&mut snap.root, uuid).unwrap()
}

fn plain(s: &str) -> Shown {
    Shown::Field {
        protected: false,
        value: Value::Plain(s.into()),
    }
}

// ---------------------------------------------------------------------------
// Identity, structure, ordering.

#[test]
fn a_snapshot_against_itself_is_empty() {
    let a = base();
    for opts in [DiffOptions::default(), strict()] {
        let cs = compute(&a, &a, &opts);
        assert!(cs.is_empty(), "{cs:#?}");
        assert_eq!(cs.summary, Summary::default());
        assert!(cs.warnings.is_empty());
    }
}

#[test]
fn added_and_removed_entries() {
    let a = base();
    let mut b = a.clone();
    take_entry(&mut b.root, id(0x12)).unwrap();
    group_mut(&mut b.root, id(3))
        .unwrap()
        .entries
        .push(titled(0x14, "GitHub"));
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(node(&cs, id(0x12)).status, NodeStatus::Removed);
    assert_eq!(node(&cs, id(0x12)).path, path("/Personal/Email"));
    assert_eq!(node(&cs, id(0x14)).status, NodeStatus::Added);
    assert_eq!(node(&cs, id(0x14)).path, path("/Work/GitHub"));
    assert_eq!(cs.summary.entries_added, 1);
    assert_eq!(cs.summary.entries_removed, 1);
    assert_eq!(cs.summary.entries_modified, 0);
}

#[test]
fn entries_differing_only_by_uuid_are_added_and_removed_not_modified() {
    let a = snapshot(Group::new(id(1), "Root").with_entry(titled(0x20, "Entry")));
    let b = snapshot(Group::new(id(1), "Root").with_entry(titled(0x21, "Entry")));
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(cs.summary.entries_modified, 0);
    assert_eq!(
        (cs.summary.entries_added, cs.summary.entries_removed),
        (1, 1)
    );
}

#[test]
fn a_uuid_that_changes_kind_is_removed_and_added() {
    let a = snapshot(Group::new(id(1), "Root").with_entry(titled(0x20, "X")));
    let b = snapshot(Group::new(id(1), "Root").with_group(Group::new(id(0x20), "X")));
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(cs.summary.entries_removed, 1);
    assert_eq!(cs.summary.groups_added, 1);
}

#[test]
fn records_are_ordered_database_groups_entries_then_path_then_uuid() {
    let a = base();
    let mut b = a.clone();
    b.meta.database_name = Some("New".into());
    let root = &mut b.root;
    root.entries.push(titled(0x31, "Dup"));
    root.entries.push(titled(0x30, "Dup"));
    root.entries.push(titled(0x32, "Alpha"));
    group_mut(root, id(3)).unwrap().name = "Office".into();
    group_mut(root, id(2)).unwrap().notes = Some("n".into());
    let cs = compute(&a, &b, &DiffOptions::default());
    let order: Vec<String> = cs
        .changes
        .iter()
        .map(|c| match c {
            Change::Database { .. } => "database".to_string(),
            Change::Group(n) | Change::Entry(n) => n.path.as_ref().unwrap().format(),
        })
        .collect();
    // Same-named siblings: ordinals follow UUID order (/Dup is 0x30).
    assert_eq!(
        order,
        [
            "database",
            "/Office/",
            "/Personal/",
            "/Alpha",
            "/Dup",
            "/Dup:2"
        ]
    );
}

#[test]
fn a_node_without_a_path_is_identified_by_uuid() {
    let a = snapshot(Group::new(id(1), "Root"));
    let mut b = a.clone();
    b.root.entries.push(Entry::new(id(0x40)));
    let cs = compute(&a, &b, &DiffOptions::default());
    let n = node(&cs, id(0x40));
    assert_eq!((n.path.clone(), &n.status), (None, &NodeStatus::Added));
}

// ---------------------------------------------------------------------------
// Moves and renames (one record per node).

#[test]
fn title_change_is_a_field_change_not_a_move() {
    let a = base();
    let mut b = a.clone();
    edit(&mut b, id(0x11))
        .fields
        .insert("Title".into(), Field::plain("Bank2"));
    let cs = compute(&a, &b, &DiffOptions::default());
    let n = node(&cs, id(0x11));
    assert_eq!(n.path, path("/Personal/Bank2"));
    assert_eq!(
        n.status,
        NodeStatus::Modified {
            moved_from: None,
            changes: vec![PropertyChange::new(
                Property::Field(FieldName::new("Title")),
                Some(plain("Bank")),
                Some(plain("Bank2")),
            )],
        }
    );
}

#[test]
fn moved_and_edited_entry_is_one_record_counted_once() {
    let a = base();
    let mut b = a.clone();
    let mut vpn = take_entry(&mut b.root, id(0x13)).unwrap();
    vpn.fields
        .insert("Password".into(), sealed("Password", true, "new"));
    group_mut(&mut b.root, id(2)).unwrap().entries.push(vpn);
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(cs.changes.len(), 1, "{cs:#?}");
    let n = node(&cs, id(0x13));
    assert_eq!(n.path, path("/Personal/VPN"));
    match &n.status {
        NodeStatus::Modified {
            moved_from,
            changes,
        } => {
            assert_eq!(moved_from, &path("/Work/VPN"));
            assert_eq!(changes.len(), 1);
            assert_eq!(
                changes[0].property,
                Property::Field(FieldName::new("Password"))
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(cs.summary.entries_modified, 1);
    assert_eq!(cs.summary.entries_moved, 1);
}

#[test]
fn pure_move_is_a_modified_record_without_property_changes() {
    let a = base();
    let mut b = a.clone();
    let vpn = take_entry(&mut b.root, id(0x13)).unwrap();
    group_mut(&mut b.root, id(2)).unwrap().entries.push(vpn);
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(
        node(&cs, id(0x13)).status,
        NodeStatus::Modified {
            moved_from: path("/Work/VPN"),
            changes: vec![],
        }
    );
    assert_eq!(cs.summary.node_properties, 0);
}

#[test]
fn group_rename_is_a_name_change_without_cascading_moves() {
    let a = base();
    let mut b = a.clone();
    group_mut(&mut b.root, id(3)).unwrap().name = "Office".into();
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(cs.changes.len(), 1, "children ride along: {cs:#?}");
    assert_eq!(node(&cs, id(3)).path, path("/Office/"));
    assert_eq!(changed(&cs, id(3)), ["Name"]);
    assert_eq!(cs.summary.entries_modified, 0);
}

#[test]
fn moved_and_renamed_group_is_one_record() {
    let a = base();
    let mut b = a.clone();
    let mut work = take_group(&mut b.root, id(3)).unwrap();
    work.name = "Office".into();
    group_mut(&mut b.root, id(2)).unwrap().groups.push(work);
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(cs.changes.len(), 1, "{cs:#?}");
    let n = node(&cs, id(3));
    assert_eq!(n.path, path("/Personal/Office/"));
    match &n.status {
        NodeStatus::Modified {
            moved_from,
            changes,
        } => {
            assert_eq!(moved_from, &path("/Work/"));
            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].property, Property::Name);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        (cs.summary.groups_modified, cs.summary.groups_moved),
        (1, 1)
    );
}

// ---------------------------------------------------------------------------
// Properties the old engine missed.

#[test]
fn protection_toggle_on_an_unchanged_value_is_reported() {
    let a = base();
    let mut b = a.clone();
    let mut a2 = a.clone();
    // A custom field turned unprotected: its value leaves the sealed form.
    edit(&mut a2, id(0x12))
        .fields
        .insert("otp".into(), sealed("otp", true, "otpauth://x"));
    edit(&mut b, id(0x12))
        .fields
        .insert("otp".into(), sealed("otp", false, "otpauth://x"));
    let cs = compute(&a2, &b, &DiffOptions::default());
    assert_eq!(changed(&cs, id(0x12)), ["\"otp\""]);
    // A Password stays sealed either way; the flag alone still shows.
    let mut c = a.clone();
    edit(&mut c, id(0x11))
        .fields
        .insert("Password".into(), sealed("Password", false, "old-password"));
    let cs = compute(&a, &c, &DiffOptions::default());
    let change = &props(&cs, id(0x11))[0];
    assert!(matches!(
        (&change.before, &change.after),
        (
            Some(Shown::Field { protected: true, value: Value::Sealed(x) }),
            Some(Shown::Field { protected: false, value: Value::Sealed(y) })
        ) if x == y
    ));
}

#[test]
fn every_entry_property_kind_is_reported() {
    let a = base();
    let mut b = a.clone();
    let e = edit(&mut b, id(0x11));
    e.override_url = Some("cmd://x".into());
    e.quality_check = false;
    e.icon = Some(Icon::Standard(12));
    e.foreground = Some(Rgb {
        r: 0x0A,
        g: 0x0B,
        b: 0x0C,
    });
    e.background = Some(Rgb { r: 1, g: 2, b: 3 });
    let mut at = AutoType::default();
    at.enabled = true;
    at.default_sequence = Some("{PASSWORD}".into());
    at.obfuscation = AutoTypeObfuscation::UseClipboard;
    at.associations = vec![AutoTypeAssociation::new("Bank*", "{USERNAME}")];
    e.autotype = Some(at);
    e.custom_data.insert(
        "KPXC_KEY".into(),
        CustomValue::new(Value::Plain("v".into()), None),
    );
    e.tags.insert("money".into());
    e.attachments.insert(
        "codes.txt".into(),
        Sealing::Fingerprint(&key()).attachment(b"codes", false),
    );
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(
        changed(&cs, id(0x11)),
        [
            "Tag[\"money\"]",
            "Attachment[\"codes.txt\"]",
            "OverrideURL",
            "QualityCheck",
            "Icon",
            "ForegroundColor",
            "BackgroundColor",
            "AutoType.Enabled",
            "AutoType.DefaultSequence",
            "AutoType.DataTransferObfuscation",
            "AutoType.Association[\"Bank*\"]",
            "CustomData[\"KPXC_KEY\"]",
        ]
    );
    let fg = props(&cs, id(0x11))
        .iter()
        .find(|c| c.property == Property::Color(ColorRole::Foreground))
        .unwrap();
    assert_eq!(
        serde_json::to_value(&fg.after).unwrap()["value"],
        serde_json::json!("#0A0B0C")
    );
}

#[test]
fn group_properties_are_reported() {
    let a = base();
    let mut b = a.clone();
    let g = group_mut(&mut b.root, id(2)).unwrap();
    g.notes = Some("personal stuff".into());
    g.tags.insert("home".into());
    g.icon = Some(Icon::Standard(48));
    g.flags.enable_searching = Some(false);
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(
        changed(&cs, id(2)),
        ["Notes", "Tag[\"home\"]", "Icon", "EnableSearching"]
    );
}

#[test]
fn meta_and_header_properties_are_reported() {
    let a = base();
    let mut b = a.clone();
    b.meta.database_name = Some("Vault".into());
    b.meta.color = Some(Rgb { r: 255, g: 0, b: 0 });
    b.meta.history_max_items = Some(5);
    b.meta.master_key_changed = Some(t(9));
    b.meta.settings_changed = Some(t(9));
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(
        database_changes(&cs),
        [
            "DatabaseName",
            "Color",
            "MasterKeyChanged",
            "HistoryMaxItems"
        ],
        "SettingsChanged is noise"
    );
    assert_eq!(cs.summary.database_properties, 4);
    assert_eq!(cs.summary.suppressed, 1);
}

// ---------------------------------------------------------------------------
// History.

fn history_item(secs: i64, url: &str) -> Entry {
    let mut h = titled(0x11, "Bank").with_field("URL", Field::plain(url));
    h.times.last_modification = Some(t(secs));
    h
}

fn history_keys(changes: &[PropertyChange]) -> Vec<(Option<i64>, bool)> {
    let mut keys: Vec<(Option<i64>, bool)> = changes
        .iter()
        .filter_map(|c| match &c.property {
            Property::History { item, .. } => Some((
                item.modified.map(|m| m.unix() - t(0).unix()),
                c.after.is_some(),
            )),
            _ => None,
        })
        .collect();
    keys.dedup();
    keys
}

#[test]
fn history_trimmed_at_the_cap_is_a_removal_and_an_addition() {
    let mut a = base();
    edit(&mut a, id(0x11)).history = vec![
        history_item(0, "u0"),
        history_item(10, "u1"),
        history_item(20, "u2"),
    ];
    let mut b = a.clone();
    let e = edit(&mut b, id(0x11));
    e.history.remove(0);
    e.history.push(history_item(30, "u3"));
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(
        history_keys(props(&cs, id(0x11))),
        [(Some(0), false), (Some(30), true)]
    );
}

#[test]
fn history_item_edited_in_place_at_the_cap_is_reported() {
    let mut a = base();
    edit(&mut a, id(0x11)).history = vec![history_item(0, "u0"), history_item(10, "u1")];
    let mut b = a.clone();
    edit(&mut b, id(0x11)).history[1] = history_item(10, "rewritten");
    let cs = compute(&a, &b, &DiffOptions::default());
    let changes = props(&cs, id(0x11));
    assert_eq!(changes.len(), 1, "{changes:#?}");
    assert_eq!(
        changes[0].property,
        Property::History {
            item: HistoryKey {
                modified: Some(t(10)),
                index: 0
            },
            property: Box::new(Property::Field(FieldName::new("URL"))),
        }
    );
    assert_eq!(changes[0].before, Some(plain("u1")));
    assert_eq!(changes[0].after, Some(plain("rewritten")));
}

// ---------------------------------------------------------------------------
// Noise.

#[test]
fn noise_only_resave_is_suppressed_by_default_and_shown_in_strict() {
    let mut a = base();
    edit(&mut a, id(0x11)).times.usage_count = Some(0);
    let mut b = a.clone();
    let e = edit(&mut b, id(0x11));
    e.times.last_access = Some(t(100));
    e.times.usage_count = Some(3);
    let cs = compute(&a, &b, &DiffOptions::default());
    assert!(cs.is_empty(), "{cs:#?}");
    assert_eq!(cs.summary.suppressed, 2);
    let cs = compute(&a, &b, &strict());
    assert_eq!(changed(&cs, id(0x11)), ["LastAccessTime", "UsageCount"]);
    assert_eq!(cs.summary.suppressed, 0);
}

#[test]
fn custom_field_named_like_a_timestamp_is_not_suppressed() {
    let a = base();
    let mut b = a.clone();
    edit(&mut b, id(0x11))
        .fields
        .insert("UsageCount".into(), Field::plain("2"));
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(changed(&cs, id(0x11)), ["\"UsageCount\""]);
    assert_eq!(cs.summary.suppressed, 0);
}

#[test]
fn expiry_change_is_reported_by_default() {
    let a = base();
    let mut b = a.clone();
    let e = edit(&mut b, id(0x11));
    e.times.expires = Some(true);
    e.times.expiry = Some(t(1_000));
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(changed(&cs, id(0x11)), ["ExpiryTime", "Expires"]);
}

#[test]
fn inert_expiry_time_is_not_reported_even_in_strict() {
    let mut a = base();
    edit(&mut a, id(0x11)).times.expires = Some(false);
    let mut b = a.clone();
    edit(&mut b, id(0x11)).times.expiry = Some(t(1_000));
    assert!(compute(&a, &b, &strict()).is_empty());
}

#[test]
fn group_expansion_is_noise() {
    let a = base();
    let mut b = a.clone();
    group_mut(&mut b.root, id(2)).unwrap().flags.is_expanded = false;
    let cs = compute(&a, &b, &DiffOptions::default());
    assert!(cs.is_empty());
    assert_eq!(cs.summary.suppressed, 1);
    let cs = compute(&a, &b, &strict());
    assert_eq!(changed(&cs, id(2)), ["IsExpanded"]);
}

#[test]
fn location_changed_on_a_move_is_noise() {
    let a = base();
    let mut b = a.clone();
    let mut vpn = take_entry(&mut b.root, id(0x13)).unwrap();
    vpn.times.location_changed = Some(t(50));
    vpn.previous_parent = Some(id(3));
    group_mut(&mut b.root, id(2)).unwrap().entries.push(vpn);
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(cs.summary.suppressed, 2);
    assert_eq!(cs.summary.node_properties, 0);
    let cs = compute(&a, &b, &strict());
    assert_eq!(
        changed(&cs, id(0x13)),
        ["LocationChanged", "PreviousParentGroup"]
    );
}

// ---------------------------------------------------------------------------
// Recycle bin.

fn with_recycle_bin(rb: u128) -> Snapshot {
    let mut s = base();
    s.root
        .groups
        .push(Group::new(id(0x50), "Recycle Bin").with_entry(titled(0x51, "Trashed")));
    s.meta.recycle_bin = Some(id(rb));
    s
}

#[test]
fn recycle_bin_is_excluded_by_default_and_included_on_request() {
    let a = base();
    let b = with_recycle_bin(0x50);
    let cs = compute(&a, &b, &DiffOptions::default());
    assert!(
        cs.changes
            .iter()
            .all(|c| !matches!(c, Change::Group(_) | Change::Entry(_))),
        "{cs:#?}"
    );
    assert_eq!(database_changes(&cs), ["RecycleBinUUID"]);
    let include = DiffOptions::new(Noise::Suppress, RecycleBin::Include);
    let cs = compute(&a, &b, &include);
    assert_eq!(node(&cs, id(0x50)).status, NodeStatus::Added);
    assert_eq!(node(&cs, id(0x51)).path, path("/Recycle Bin/Trashed"));
}

#[test]
fn recycle_bin_uuid_pointing_at_the_root_does_not_hide_the_tree() {
    let a = with_recycle_bin(1);
    let mut b = a.clone();
    edit(&mut b, id(0x11))
        .fields
        .insert("UserName".into(), Field::plain("bob"));
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(changed(&cs, id(0x11)), ["UserName"]);
}

#[test]
fn trashing_an_entry_reads_as_a_removal_by_default() {
    let a = with_recycle_bin(0x50);
    let mut b = a.clone();
    let email = take_entry(&mut b.root, id(0x12)).unwrap();
    group_mut(&mut b.root, id(0x50))
        .unwrap()
        .entries
        .push(email);
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(node(&cs, id(0x12)).status, NodeStatus::Removed);
    let include = DiffOptions::new(Noise::Suppress, RecycleBin::Include);
    let cs = compute(&a, &b, &include);
    assert!(matches!(
        &node(&cs, id(0x12)).status,
        NodeStatus::Modified {
            moved_from: Some(_),
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Warnings.

fn with_header(kdf: KdfInfo) -> Snapshot {
    let mut s = base();
    s.header = Some(HeaderInfo::new(
        kdf,
        OuterCipher::Aes256,
        InnerCipher::ChaCha20,
        Compression::GZip,
    ));
    s
}

fn argon2(memory: u64, iterations: u64) -> KdfInfo {
    KdfInfo::Argon2(Argon2Info::new(
        Argon2Variant::Argon2id,
        memory,
        iterations,
        2,
        0x13,
    ))
}

fn weakenings(a: KdfInfo, b: KdfInfo) -> Vec<KdfWeakening> {
    compute(&with_header(a), &with_header(b), &DiffOptions::default())
        .warnings
        .into_iter()
        .map(|w| match w {
            DiffWarning::KdfWeakened { weakening } => weakening,
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn kdf_downgrades_are_warned() {
    assert_eq!(
        weakenings(argon2(64 << 20, 3), argon2(16 << 20, 2)),
        [
            KdfWeakening::MemoryLowered {
                before: 64 << 20,
                after: 16 << 20
            },
            KdfWeakening::IterationsLowered {
                before: 3,
                after: 2
            },
        ]
    );
    assert_eq!(
        weakenings(argon2(64 << 20, 3), KdfInfo::Aes { rounds: 1_000_000 }),
        [KdfWeakening::NoLongerMemoryHard {
            before: KdfKind::Argon2id,
            after: KdfKind::AesKdf
        }]
    );
    assert_eq!(
        weakenings(
            KdfInfo::Aes { rounds: 60_000 },
            KdfInfo::Aes { rounds: 6_000 }
        ),
        [KdfWeakening::RoundsLowered {
            before: 60_000,
            after: 6_000
        }]
    );
    assert_eq!(
        weakenings(argon2(1 << 20, 2), KdfInfo::Unrecognized),
        [KdfWeakening::Unrecognized {
            before: KdfKind::Argon2id
        }]
    );
}

#[test]
fn kdf_upgrades_are_not_warned_but_are_reported() {
    let (a, b) = (
        with_header(argon2(16 << 20, 2)),
        with_header(argon2(64 << 20, 3)),
    );
    assert!(weakenings(argon2(16 << 20, 2), argon2(64 << 20, 3)).is_empty());
    assert!(weakenings(KdfInfo::Aes { rounds: 1 }, argon2(1 << 20, 2)).is_empty());
    let cs = compute(&a, &b, &DiffOptions::default());
    assert_eq!(database_changes(&cs), ["KdfMemory", "KdfIterations"]);
}

#[test]
fn version_mismatch_is_warned_and_reported() {
    let a = base();
    let mut b = a.clone();
    b.format = FormatVersion::KDBX_4_0;
    let cs = compute(&b, &a, &DiffOptions::default());
    assert_eq!(
        cs.warnings,
        [DiffWarning::VersionMismatch {
            before: FormatVersion::KDBX_4_0,
            after: FormatVersion::KDBX_4_1
        }]
    );
    assert_eq!(database_changes(&cs), ["Version"]);
}

/// History items sharing a modification time (or all lacking one) are
/// matched by content first: trimming one and adding one must not read as
/// every item edited.
#[test]
fn history_items_sharing_a_time_match_by_content_first() {
    for when in [Some(t(0)), None] {
        let item = |url: &str| {
            let mut h = titled(0x11, "Bank").with_field("URL", Field::plain(url));
            h.times.last_modification = when;
            h
        };
        let mut a = base();
        edit(&mut a, id(0x11)).history = vec![item("u1"), item("u2"), item("u3")];
        let mut b = a.clone();
        edit(&mut b, id(0x11)).history = vec![item("u2"), item("u3"), item("u4")];
        let cs = compute(&a, &b, &DiffOptions::default());
        let changes = props(&cs, id(0x11));
        // The trimmed u1 and the added u4 pair up as one changed item; u2 and
        // u3 match by content and report nothing.
        assert_eq!(changes.len(), 1, "{changes:#?}");
        assert_eq!(
            changes[0].property,
            Property::History {
                item: HistoryKey::new(when, 0),
                property: Box::new(Property::Field(FieldName::new("URL"))),
            }
        );
        assert_eq!(changes[0].before, Some(plain("u1")));
        assert_eq!(changes[0].after, Some(plain("u4")));
        // Reordering equal items is no change at all.
        let mut c = a.clone();
        edit(&mut c, id(0x11)).history.reverse();
        assert!(compute(&a, &c, &DiffOptions::default()).is_empty());
    }
}
