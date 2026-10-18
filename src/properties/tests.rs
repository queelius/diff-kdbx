use std::collections::BTreeSet;

use kdbx_core::fingerprint::FingerprintKey;
use kdbx_core::model::{
    Argon2Info, Argon2Variant, AttachmentInfo, AutoType, AutoTypeAssociation, CustomIconInfo,
    Field, HeaderInfo, MemoryProtection, Sealing,
};
use serde::de::DeserializeOwned;
use serde_json::Value as Json;

use super::*;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn t(secs: i64) -> Timestamp {
    Timestamp::from_unix(1_767_258_000 + secs).unwrap()
}

/// A fingerprint whose hex form contains digits (the leaf mutator bumps one).
fn fp(n: u8) -> Fingerprint {
    Fingerprint::from_bytes([n; 32])
}

fn full_times(base: i64) -> Times {
    let mut times = Times::default();
    times.creation = Some(t(base));
    times.last_modification = Some(t(base + 1));
    times.last_access = Some(t(base + 2));
    times.expiry = Some(t(base + 3));
    times.location_changed = Some(t(base + 4));
    times.expires = Some(true);
    times.usage_count = Some(5);
    times
}

/// An entry with every model field set (and no `null` anywhere in its JSON).
fn maximal_entry(uuid: Uuid, base: i64, with_history: bool) -> Entry {
    let key = FingerprintKey::from_bytes([3; 32]);
    let seal = Sealing::Fingerprint(&key);
    let mut e = Entry::new(uuid)
        .with_field("Title", Field::plain("Bank"))
        .with_field("UserName", Field::plain("alice"))
        .with_field("Password", seal.field("Password", true, "hunter2"))
        .with_field("URL", Field::plain("https://bank.example"))
        .with_field("Notes", Field::plain("line one\nline two"))
        .with_field("PIN", seal.field("PIN", true, "1234"));
    e.tags = ["finance", "money"].map(String::from).into();
    e.attachments
        .insert("codes.txt".into(), AttachmentInfo::new(8, fp(0x12), true));
    e.times = full_times(base);
    e.icon = Some(Icon::Standard(3));
    e.foreground = Some(Rgb { r: 1, g: 2, b: 3 });
    e.background = Some(Rgb { r: 4, g: 5, b: 6 });
    e.override_url = Some("cmd://open 1".into());
    e.quality_check = false;
    let mut at = AutoType::default();
    at.enabled = true;
    at.default_sequence = Some("{USERNAME}{TAB}1".into());
    at.obfuscation = AutoTypeObfuscation::UseClipboard;
    at.associations = vec![
        AutoTypeAssociation::new("Bank 1", "{PASSWORD}1"),
        AutoTypeAssociation::new("Bank 1", "{PASSWORD}2"),
        AutoTypeAssociation::new("Mail 1", "{PASSWORD}3"),
    ];
    e.autotype = Some(at);
    e.custom_data.insert(
        "browser-key".into(),
        CustomValue::new(Value::Sealed(fp(0x34)), Some(t(base + 9))),
    );
    e.previous_parent = Some(id(0x51));
    if with_history {
        e.history = vec![
            maximal_entry(uuid, base - 200, false),
            maximal_entry(uuid, base - 100, false),
        ];
    }
    e
}

fn maximal_group() -> Group {
    let mut g = Group::new(id(2), "Web 1");
    g.notes = Some("group notes 1".into());
    g.tags = ["a1", "b1"].map(String::from).into();
    g.icon = Some(Icon::Custom(id(0x77)));
    g.times = full_times(0);
    g.custom_data.insert(
        "plugin".into(),
        CustomValue::new(Value::Plain("v1".into()), Some(t(7))),
    );
    g.flags.is_expanded = false;
    g.flags.enable_autotype = Some(false);
    g.flags.enable_searching = Some(true);
    g.flags.default_autotype_sequence = Some("{PASSWORD}1".into());
    g.previous_parent = Some(id(0x52));
    g
}

fn maximal_snapshot() -> Snapshot {
    let mut m = Meta::default();
    m.generator = Some("KeePassXC 1".into());
    m.database_name = Some("Vault 1".into());
    m.database_name_changed = Some(t(1));
    m.database_description = Some("desc 1\nmore".into());
    m.database_description_changed = Some(t(2));
    m.default_username = Some("alice1".into());
    m.default_username_changed = Some(t(3));
    m.maintenance_history_days = Some(365);
    m.color = Some(Rgb {
        r: 10,
        g: 20,
        b: 30,
    });
    m.master_key_changed = Some(t(4));
    m.master_key_change_rec = Some(-1);
    m.master_key_change_force = Some(-1);
    m.memory_protection = Some(MemoryProtection::default());
    m.recycle_bin_enabled = Some(true);
    m.recycle_bin = Some(id(0x61));
    m.recycle_bin_changed = Some(t(5));
    m.entry_templates_group = Some(id(0x62));
    m.entry_templates_group_changed = Some(t(6));
    m.last_selected_group = Some(id(0x63));
    m.last_top_visible_group = Some(id(0x64));
    m.history_max_items = Some(10);
    m.history_max_size = Some(6_291_456);
    m.settings_changed = Some(t(8));
    m.custom_data.insert(
        "KPXC_DECRYPTION_TIME_PREFERENCE".into(),
        CustomValue::new(Value::Sealed(fp(0x56)), Some(t(9))),
    );
    m.custom_icons.insert(
        id(0x77),
        CustomIconInfo::new(16, fp(0x78), Some("icon 1".into()), Some(t(10))),
    );
    let mut snap = Snapshot::new(FormatVersion::KDBX_4_1, m, Group::new(id(1), "Root"));
    let mut header = HeaderInfo::new(
        KdfInfo::Argon2(Argon2Info::new(
            Argon2Variant::Argon2id,
            64 << 20,
            3,
            2,
            0x13,
        )),
        OuterCipher::ChaCha20,
        InnerCipher::ChaCha20,
        Compression::GZip,
    );
    header.public_custom_data.insert("plugin1".into());
    snap.header = Some(header);
    snap.deleted_objects.insert(id(0x99), Some(t(11)));
    snap
}

// ---------------------------------------------------------------------------
// Every model field maps to a property.

#[test]
fn maximal_entry_property_count() {
    let entry = maximal_entry(id(10), 0, true);
    // 6 fields, 2 tags, 1 attachment, override URL, quality check, icon,
    // 2 colors, 3 auto-type settings, 3 associations, 7 times (ExpiryTime
    // because the entry expires), previous parent, custom data value and
    // time: 30. Each of the two history items has the same 30.
    assert_eq!(entry_properties(&entry).len(), 30 * 3);
}

#[test]
fn maximal_group_property_count() {
    // Name, Notes, 2 tags, icon, 4 flags, 7 times, previous parent, custom
    // data value and time.
    assert_eq!(group_properties(&maximal_group()).len(), 19);
}

#[test]
fn maximal_database_property_count() {
    // Format; Kdf + 4 Argon2 parameters + 2 ciphers + compression; 1 public
    // custom data key; 22 meta settings + 5 memory-protection flags; custom
    // data value and time; custom icon image, name and time; 1 tombstone.
    assert_eq!(database_properties(&maximal_snapshot()).len(), 43);
}

/// The JSON keys of a serialized model value. A field kdbx-core adds later
/// shows up here and fails the matching tripwire below, so it cannot be
/// silently left out of the property map.
fn json_keys<T: Serialize>(value: &T) -> BTreeSet<String> {
    match serde_json::to_value(value).unwrap() {
        Json::Object(map) => map.keys().cloned().collect(),
        other => panic!("not an object: {other}"),
    }
}

fn keys(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[test]
fn tripwire_model_fields_are_all_mapped() {
    let entry = maximal_entry(id(10), 0, true);
    assert_eq!(
        json_keys(&entry),
        keys(&[
            "uuid",
            "fields",
            "tags",
            "attachments",
            "times",
            "icon",
            "foreground",
            "background",
            "override_url",
            "quality_check",
            "autotype",
            "custom_data",
            "previous_parent",
            "history"
        ])
    );
    assert_eq!(
        json_keys(&entry.times),
        keys(&[
            "creation",
            "last_modification",
            "last_access",
            "expiry",
            "location_changed",
            "expires",
            "usage_count"
        ])
    );
    assert_eq!(
        json_keys(&entry.fields["Title"]),
        keys(&["protected", "value"])
    );
    assert_eq!(
        json_keys(&entry.attachments["codes.txt"]),
        keys(&["size", "fingerprint", "protected"])
    );
    assert_eq!(
        json_keys(entry.autotype.as_ref().unwrap()),
        keys(&["enabled", "default_sequence", "obfuscation", "associations"])
    );
    assert_eq!(
        json_keys(&entry.custom_data["browser-key"]),
        keys(&["value", "modified"])
    );
    let group = maximal_group();
    assert_eq!(
        json_keys(&group),
        keys(&[
            "uuid",
            "name",
            "notes",
            "tags",
            "icon",
            "times",
            "custom_data",
            "flags",
            "previous_parent",
            "groups",
            "entries"
        ])
    );
    assert_eq!(
        json_keys(&group.flags),
        keys(&[
            "is_expanded",
            "enable_autotype",
            "enable_searching",
            "default_autotype_sequence"
        ])
    );
    let snap = maximal_snapshot();
    assert_eq!(
        json_keys(&snap),
        keys(&["format", "meta", "root", "deleted_objects", "header"])
    );
    assert_eq!(
        json_keys(&snap.meta).len(),
        25,
        "22 settings, memory protection, custom data, custom icons"
    );
    assert_eq!(
        json_keys(snap.header.as_ref().unwrap()),
        keys(&[
            "kdf",
            "outer_cipher",
            "inner_cipher",
            "compression",
            "public_custom_data"
        ])
    );
    assert_eq!(
        json_keys(&snap.meta.custom_icons[&id(0x77)]),
        keys(&["size", "fingerprint", "name", "modified"])
    );
    assert_eq!(
        json_keys(snap.meta.memory_protection.as_ref().unwrap()).len(),
        StandardField::ALL.len()
    );
}

/// JSON pointers to every leaf (scalar) of `v`, skipping `excluded`
/// pointers and their subtrees.
fn leaves(v: &Json, at: String, excluded: &[&str], out: &mut Vec<String>) {
    if excluded.iter().any(|e| at == *e) {
        return;
    }
    match v {
        Json::Object(map) => {
            for (k, child) in map {
                let k = k.replace('~', "~0").replace('/', "~1");
                leaves(child, format!("{at}/{k}"), excluded, out);
            }
        }
        Json::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                leaves(child, format!("{at}/{i}"), excluded, out);
            }
        }
        _ => out.push(at),
    }
}

/// Candidate replacements for a leaf, most generic first.
fn mutations(v: &Json) -> Vec<Json> {
    let mut out = vec![Json::Null];
    match v {
        Json::Bool(b) => out.push(Json::Bool(!b)),
        Json::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push(Json::from(u + 1));
            } else if let Some(i) = n.as_i64() {
                out.push(Json::from(i + 1));
            }
        }
        Json::String(s) => {
            if let Some(pos) = s.find(|c: char| c.is_ascii_digit()) {
                let mut bumped = s.clone();
                let d = s.as_bytes()[pos] - b'0';
                bumped.replace_range(pos..=pos, &((d + 1) % 10).to_string());
                out.push(Json::String(bumped));
            }
            out.push(Json::String(format!("{s}x")));
            // Unit-variant enum names: switch to another variant.
            for name in ["none", "aes256", "plain", "argon2d"] {
                out.push(Json::String(name.into()));
            }
        }
        Json::Null | Json::Array(_) | Json::Object(_) => {}
    }
    out
}

/// Every leaf of `value` (but `excluded`) changes `props` when mutated.
fn assert_every_leaf_is_a_property<T, P>(value: &T, excluded: &[&str], props: P)
where
    T: Serialize + DeserializeOwned,
    P: Fn(&T) -> PropertyMap,
{
    let json = serde_json::to_value(value).unwrap();
    let base = props(value);
    let mut ptrs = Vec::new();
    leaves(&json, String::new(), excluded, &mut ptrs);
    assert!(!ptrs.is_empty());
    for ptr in ptrs {
        let original = json.pointer(&ptr).unwrap().clone();
        assert!(
            !original.is_null(),
            "{ptr} is null: set it in the maximal value"
        );
        let mutated = mutations(&original).into_iter().find_map(|m| {
            if m == original {
                return None;
            }
            let mut j = json.clone();
            *j.pointer_mut(&ptr).unwrap() = m;
            serde_json::from_value::<T>(j).ok()
        });
        let mutated = mutated.unwrap_or_else(|| panic!("no valid mutation for {ptr}"));
        assert_ne!(
            props(&mutated),
            base,
            "model leaf {ptr} does not reach the property map"
        );
    }
}

#[test]
fn every_entry_leaf_reaches_a_property() {
    let entry = maximal_entry(id(10), 0, true);
    assert_every_leaf_is_a_property(
        &entry,
        &["/uuid", "/history/0/uuid", "/history/1/uuid"],
        entry_properties,
    );
}

#[test]
fn every_group_leaf_reaches_a_property() {
    assert_every_leaf_is_a_property(&maximal_group(), &["/uuid"], group_properties);
}

#[test]
fn every_database_leaf_reaches_a_property() {
    assert_every_leaf_is_a_property(&maximal_snapshot(), &["/root"], database_properties);
}

#[test]
fn aes_kdf_reports_rounds() {
    let mut snap = maximal_snapshot();
    snap.header.as_mut().unwrap().kdf = KdfInfo::Aes { rounds: 60_000 };
    let map = database_properties(&snap);
    assert_eq!(
        map.get(&Property::Header(HeaderKey::Kdf)),
        Some(&Shown::Kdf(KdfKind::AesKdf))
    );
    assert_eq!(
        map.get(&Property::Header(HeaderKey::KdfRounds)),
        Some(&Shown::Uint(60_000))
    );
    assert!(!map.contains_key(&Property::Header(HeaderKey::KdfMemory)));
}

// ---------------------------------------------------------------------------
// Order, keys and rules.

#[test]
fn order_is_canonical() {
    let entry = maximal_entry(id(10), 0, true);
    let order: Vec<String> = entry_properties(&entry)
        .keys()
        .take(9)
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        order,
        [
            "Title",
            "UserName",
            "Password",
            "URL",
            "Notes",
            "PIN",
            "Tag[finance]",
            "Tag[money]",
            "Attachment[codes.txt]"
        ]
    );
    let last = entry_properties(&entry).keys().last().unwrap().clone();
    assert!(
        matches!(last, Property::History { .. }),
        "history comes last"
    );
}

#[test]
fn field_names_classify_exactly() {
    assert_eq!(
        FieldName::new("URL"),
        FieldName::Standard(StandardField::Url)
    );
    assert_eq!(FieldName::new("url"), FieldName::Custom("url".into()));
    assert!(FieldName::new("Notes") < FieldName::new("A custom field"));
    assert_eq!(FieldName::new("otp").as_str(), "otp");
}

#[test]
fn expiry_time_is_a_property_only_while_the_node_expires() {
    let mut e = Entry::new(id(1));
    e.times.expiry = Some(t(0));
    e.times.expires = Some(false);
    let map = entry_properties(&e);
    assert!(!map.contains_key(&Property::Time(TimeField::ExpiryTime)));
    assert_eq!(
        map.get(&Property::Time(TimeField::Expires)),
        Some(&Shown::Bool(false))
    );
    e.times.expires = Some(true);
    assert_eq!(
        entry_properties(&e).get(&Property::Time(TimeField::ExpiryTime)),
        Some(&Shown::Time(t(0)))
    );
}

#[test]
fn history_items_are_keyed_by_time_with_an_index_tiebreak() {
    let item = |secs: i64, url: &str| {
        let mut h = Entry::new(id(1)).with_field("URL", Field::plain(url));
        h.times.last_modification = Some(t(secs));
        h
    };
    let mut e = Entry::new(id(1));
    e.history = vec![item(0, "a"), item(0, "b"), item(5, "c")];
    let urls: Vec<(String, Shown)> = entry_properties(&e)
        .into_iter()
        .filter(|(p, _)| p.to_string().ends_with(".URL"))
        .map(|(p, v)| (p.to_string(), v))
        .collect();
    let shown = |s: &str| Shown::Field {
        protected: false,
        value: Value::Plain(s.into()),
    };
    assert_eq!(
        urls,
        [
            ("History[2026-01-01T09:00:00Z].URL".to_string(), shown("a")),
            (
                "History[2026-01-01T09:00:00Z#2].URL".to_string(),
                shown("b")
            ),
            ("History[2026-01-01T09:00:05Z].URL".to_string(), shown("c")),
        ]
    );
}

#[test]
fn trimming_history_at_the_cap_removes_exactly_the_oldest_item() {
    let item = |secs: i64| {
        let mut h = Entry::new(id(1)).with_field("Title", Field::plain("T"));
        h.times.last_modification = Some(t(secs));
        h
    };
    let mut before = Entry::new(id(1));
    before.history = vec![item(0), item(10), item(20)];
    let mut after = before.clone();
    after.history.remove(0);
    after.history.push(item(30));
    let a = entry_properties(&before);
    let b = entry_properties(&after);
    let only_a: Vec<String> = a
        .keys()
        .filter(|k| !b.contains_key(*k))
        .map(ToString::to_string)
        .collect();
    let only_b: Vec<String> = b
        .keys()
        .filter(|k| !a.contains_key(*k))
        .map(ToString::to_string)
        .collect();
    assert!(
        only_a
            .iter()
            .all(|k| k.starts_with("History[2026-01-01T09:00:00Z].")),
        "{only_a:?}"
    );
    assert!(
        only_b
            .iter()
            .all(|k| k.starts_with("History[2026-01-01T09:00:30Z].")),
        "{only_b:?}"
    );
    assert!(!only_a.is_empty() && !only_b.is_empty());
}

#[test]
fn auto_type_associations_are_keyed_by_window_and_occurrence() {
    let entry = maximal_entry(id(10), 0, false);
    let labels: Vec<String> = entry_properties(&entry)
        .keys()
        .filter(|p| matches!(p, Property::AutoTypeAssociation { .. }))
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        labels,
        [
            "AutoType.Association[Bank 1]",
            "AutoType.Association[Bank 1#2]",
            "AutoType.Association[Mail 1]"
        ]
    );
}

#[test]
fn noise_is_a_property_of_the_key_never_of_a_name() {
    assert!(Property::Time(TimeField::LastAccessTime).is_noise());
    assert!(!Property::Time(TimeField::CreationTime).is_noise());
    // A custom field named like a timestamp is content.
    assert!(!Property::Field(FieldName::new("UsageCount")).is_noise());
    assert!(Property::GroupFlag(GroupFlag::IsExpanded).is_noise());
    assert!(!Property::Meta(MetaKey::MasterKeyChanged).is_noise());
    assert!(Property::Meta(MetaKey::SettingsChanged).is_noise());
    let in_history = |p: Property| Property::History {
        item: HistoryKey {
            modified: None,
            index: 0,
        },
        property: Box::new(p),
    };
    assert!(in_history(Property::Time(TimeField::UsageCount)).is_noise());
    assert!(!in_history(Property::Field(FieldName::new("URL"))).is_noise());
}

#[test]
fn labels_are_single_printable_lines() {
    let p = Property::Tag("evil\n+ ENTRY /x".into());
    assert_eq!(p.to_string(), "Tag[evil\\n+ ENTRY /x]");
    let f = Property::Field(FieldName::new("a\u{202E}b"));
    assert_eq!(f.to_string(), "a\\u{202E}b");
    assert_eq!(
        Property::Meta(MetaKey::MemoryProtection(StandardField::Url)).to_string(),
        "ProtectURL"
    );
}

#[test]
fn property_json_shape() {
    let json = |p: &Property| serde_json::to_value(p).unwrap();
    assert_eq!(
        json(&Property::Field(FieldName::new("Password"))),
        serde_json::json!({"kind": "field", "key": "Password"})
    );
    assert_eq!(json(&Property::Name), serde_json::json!({"kind": "name"}));
    assert_eq!(
        json(&Property::Time(TimeField::UsageCount)),
        serde_json::json!({"kind": "time", "key": "UsageCount"})
    );
    assert_eq!(
        json(&Property::History {
            item: HistoryKey {
                modified: Some(t(0)),
                index: 1
            },
            property: Box::new(Property::Tag("x".into())),
        }),
        serde_json::json!({"kind": "history", "key": {
            "item": {"modified": "2026-01-01T09:00:00Z", "index": 1},
            "property": {"kind": "tag", "key": "x"}
        }})
    );
    assert_eq!(
        serde_json::to_value(Shown::Field {
            protected: true,
            value: Value::Sealed(fp(0x12)),
        })
        .unwrap(),
        serde_json::json!({"type": "field", "value": {
            "protected": true,
            "value": {"sealed": "12".repeat(32)}
        }})
    );
}
