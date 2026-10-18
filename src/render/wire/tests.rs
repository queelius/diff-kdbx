//! The JSON wire format, leaf by leaf, through `render_json`.

use kdbx_core::fields::StandardField;
use kdbx_core::fingerprint::{DeriveParams, Fingerprint};
use kdbx_core::model::{
    AutoTypeObfuscation, Compression, FormatVersion, Icon, InnerCipher, OuterCipher, Rgb, Value,
};
use kdbx_core::path::VaultPath;
use serde_json::{Value as Json, json};

use crate::change_set::{
    Change, ChangeSet, DiffWarning, KdfWeakening, NodeChange, NodeStatus, PropertyChange,
};
use crate::properties::{
    AutoTypeKey, ColorRole, FieldName, GroupFlag, HeaderKey, HistoryKey, KdfKind, MetaKey,
    Property, Shown, TimeField,
};
use crate::render::json::{FingerprintKeyInfo, JsonOptions, render_json};
use crate::test_support::{id, t};

fn doc(cs: &ChangeSet) -> Json {
    serde_json::from_str(&render_json(cs, &JsonOptions::default())).unwrap()
}

/// The JSON of one property change on an entry.
fn one(property: Property, before: Option<Shown>, after: Option<Shown>) -> Json {
    let cs = ChangeSet::new(
        vec![Change::Entry(NodeChange::new(
            id(1),
            Some(VaultPath::parse("/x").unwrap()),
            NodeStatus::modified(None, vec![PropertyChange::new(property, before, after)]),
        ))],
        vec![],
        0,
    );
    doc(&cs)["changes"][0]["changes"][0].clone()
}

fn value(v: Shown) -> Json {
    one(Property::Name, None, Some(v))["after"].clone()
}

fn property(p: Property) -> Json {
    one(p, None, Some(Shown::Present))["property"].clone()
}

const HEX: &str = "1212121212121212121212121212121212121212121212121212121212121212";

fn fp() -> Fingerprint {
    Fingerprint::from_bytes([0x12; 32])
}

#[test]
fn value_leaves() {
    assert_eq!(
        value(Shown::Text("a\nb".into())),
        json!({"type": "text", "text": "a\nb"})
    );
    assert_eq!(
        value(Shown::Sealed(fp())),
        json!({"type": "sealed", "sealed": HEX})
    );
    assert_eq!(
        value(Shown::field(true, Value::Sealed(fp()))),
        json!({"type": "field", "protected": true, "sealed": HEX})
    );
    assert_eq!(
        value(Shown::field(false, Value::Plain("alice".into()))),
        json!({"type": "field", "protected": false, "text": "alice"})
    );
    assert_eq!(
        value(Shown::Bool(true)),
        json!({"type": "bool", "value": true})
    );
    assert_eq!(value(Shown::Int(-1)), json!({"type": "int", "value": -1}));
    assert_eq!(value(Shown::Uint(7)), json!({"type": "uint", "value": 7}));
    assert_eq!(
        value(Shown::Time(t(0))),
        json!({"type": "time", "value": "2026-01-01T09:00:00Z"})
    );
    assert_eq!(
        value(Shown::Uuid(id(0x51))),
        json!({"type": "uuid", "value": "00000000-0000-0000-0000-000000000051"})
    );
    assert_eq!(
        value(Shown::Color(Rgb {
            r: 10,
            g: 11,
            b: 255
        })),
        json!({"type": "color", "value": "#0A0BFF"})
    );
    assert_eq!(
        value(Shown::Icon(Icon::Standard(3))),
        json!({"type": "icon", "standard": 3})
    );
    assert_eq!(
        value(Shown::Icon(Icon::Custom(id(0x77)))),
        json!({"type": "icon", "custom": "00000000-0000-0000-0000-000000000077"})
    );
    assert_eq!(
        value(Shown::attachment(8, fp(), true)),
        json!({"type": "attachment", "size": 8, "sealed": HEX, "protected": true})
    );
    assert_eq!(
        value(Shown::blob(16, fp())),
        json!({"type": "blob", "size": 16, "sealed": HEX})
    );
    assert_eq!(value(Shown::Present), json!({"type": "present"}));
    assert_eq!(
        value(Shown::Format(FormatVersion::KDBX_4_0)),
        json!({"type": "format", "value": "4.0"})
    );
    for (kind, name) in [
        (KdfKind::AesKdf, "aes_kdf"),
        (KdfKind::Argon2d, "argon2d"),
        (KdfKind::Argon2id, "argon2id"),
        (KdfKind::Unrecognized, "unrecognized"),
    ] {
        assert_eq!(
            value(Shown::Kdf(kind)),
            json!({"type": "kdf", "value": name})
        );
    }
    for (c, name) in [
        (OuterCipher::Aes256, "aes256"),
        (OuterCipher::Twofish, "twofish"),
        (OuterCipher::ChaCha20, "chacha20"),
        (OuterCipher::Unrecognized, "unrecognized"),
    ] {
        assert_eq!(
            value(Shown::OuterCipher(c)),
            json!({"type": "outer_cipher", "value": name})
        );
    }
    for (c, name) in [
        (InnerCipher::Plain, "plain"),
        (InnerCipher::Salsa20, "salsa20"),
        (InnerCipher::ChaCha20, "chacha20"),
        (InnerCipher::Unrecognized, "unrecognized"),
    ] {
        assert_eq!(
            value(Shown::InnerCipher(c)),
            json!({"type": "inner_cipher", "value": name})
        );
    }
    for (c, name) in [
        (Compression::None, "none"),
        (Compression::GZip, "gzip"),
        (Compression::Unrecognized, "unrecognized"),
    ] {
        assert_eq!(
            value(Shown::Compression(c)),
            json!({"type": "compression", "value": name})
        );
    }
    for (o, name) in [
        (AutoTypeObfuscation::None, "none"),
        (AutoTypeObfuscation::UseClipboard, "use_clipboard"),
    ] {
        assert_eq!(
            value(Shown::Obfuscation(o)),
            json!({"type": "obfuscation", "value": name})
        );
    }
}

#[test]
fn property_leaves() {
    assert_eq!(property(Property::Name), json!({"kind": "name"}));
    assert_eq!(property(Property::Format), json!({"kind": "format"}));
    assert_eq!(
        property(Property::Field(FieldName::new("Password"))),
        json!({"kind": "field", "key": "Password"})
    );
    assert_eq!(
        property(Property::Field(FieldName::new("Tag[x]"))),
        json!({"kind": "field", "key": "Tag[x]"})
    );
    assert_eq!(
        property(Property::Tag("a]b".into())),
        json!({"kind": "tag", "key": "a]b"})
    );
    assert_eq!(
        property(Property::Time(TimeField::UsageCount)),
        json!({"kind": "time", "key": "UsageCount"})
    );
    assert_eq!(
        property(Property::Meta(MetaKey::MemoryProtection(
            StandardField::Url
        ))),
        json!({"kind": "meta", "key": "ProtectURL"})
    );
    assert_eq!(
        property(Property::Header(HeaderKey::KdfMemory)),
        json!({"kind": "header", "key": "KdfMemory"})
    );
    assert_eq!(
        property(Property::Color(ColorRole::Foreground)),
        json!({"kind": "color", "key": "ForegroundColor"})
    );
    assert_eq!(
        property(Property::AutoType(AutoTypeKey::DataTransferObfuscation)),
        json!({"kind": "auto_type", "key": "DataTransferObfuscation"})
    );
    assert_eq!(
        property(Property::GroupFlag(GroupFlag::IsExpanded)),
        json!({"kind": "group_flag", "key": "IsExpanded"})
    );
    assert_eq!(
        property(Property::auto_type_association("Bank*", 1)),
        json!({"kind": "auto_type_association", "window": "Bank*", "occurrence": 1})
    );
    assert_eq!(
        property(Property::CustomDataModified("k".into())),
        json!({"kind": "custom_data_modified", "key": "k"})
    );
    assert_eq!(
        property(Property::CustomIcon(id(0x77))),
        json!({"kind": "custom_icon", "key": "00000000-0000-0000-0000-000000000077"})
    );
    assert_eq!(
        property(Property::history(
            HistoryKey::new(Some(t(0)), 1),
            Property::Field(FieldName::new("URL"))
        )),
        json!({"kind": "history", "modified": "2026-01-01T09:00:00Z", "index": 1,
               "property": {"kind": "field", "key": "URL"}})
    );
    assert_eq!(
        property(Property::history(HistoryKey::new(None, 0), Property::Notes)),
        json!({"kind": "history", "modified": null, "index": 0, "property": {"kind": "notes"}})
    );
    for (p, kind) in [
        (Property::Notes, "notes"),
        (Property::OverrideUrl, "override_url"),
        (Property::QualityCheck, "quality_check"),
        (Property::Icon, "icon"),
        (Property::PreviousParent, "previous_parent"),
    ] {
        assert_eq!(property(p), json!({"kind": kind}));
    }
}

#[test]
fn records_and_warnings() {
    let path = |s: &str| Some(VaultPath::parse(s).unwrap());
    let cs = ChangeSet::new(
        vec![
            Change::database(vec![]),
            Change::Group(NodeChange::new(id(2), None, NodeStatus::Removed)),
            Change::Entry(NodeChange::new(
                id(3),
                path("/a\\/b"),
                NodeStatus::modified(path("/Old/a\\/b"), vec![]),
            )),
            Change::Entry(NodeChange::new(id(4), path("/n"), NodeStatus::Added)),
        ],
        vec![
            DiffWarning::version_mismatch(FormatVersion::KDBX_4_0, FormatVersion::KDBX_4_1),
            DiffWarning::kdf_weakened(KdfWeakening::memory_lowered(2, 1)),
            DiffWarning::kdf_weakened(KdfWeakening::no_longer_memory_hard(
                KdfKind::Argon2id,
                KdfKind::AesKdf,
            )),
            DiffWarning::kdf_weakened(KdfWeakening::unrecognized(KdfKind::Argon2d)),
        ],
        2,
    );
    let v = doc(&cs);
    assert_eq!(
        v["changes"],
        json!([
            {"scope": "database", "changes": []},
            {"scope": "group", "uuid": "00000000-0000-0000-0000-000000000002", "path": null,
             "status": "removed"},
            {"scope": "entry", "uuid": "00000000-0000-0000-0000-000000000003", "path": "/a\\/b",
             "status": "modified", "moved_from": "/Old/a\\/b", "changes": []},
            {"scope": "entry", "uuid": "00000000-0000-0000-0000-000000000004", "path": "/n",
             "status": "added"}
        ])
    );
    assert_eq!(
        v["warnings"],
        json!([
            {"kind": "version_mismatch", "before": "4.0", "after": "4.1"},
            {"kind": "kdf_weakened", "aspect": "memory_lowered", "before": 2, "after": 1},
            {"kind": "kdf_weakened", "aspect": "no_longer_memory_hard",
             "before": "argon2id", "after": "aes_kdf"},
            {"kind": "kdf_weakened", "aspect": "unrecognized", "before": "argon2d"}
        ])
    );
    assert_eq!(v["summary"]["suppressed"], 2);
    assert_eq!(v["summary"]["entries_moved"], 1);
}

#[test]
fn document_envelope() {
    let opts = JsonOptions::with_fingerprint_key(FingerprintKeyInfo::new(
        DeriveParams::new(32 * 1024, 8, 2),
        id(1),
    ));
    let v: Json = serde_json::from_str(&render_json(&ChangeSet::default(), &opts)).unwrap();
    assert_eq!(
        v,
        json!({
            "format_version": 1,
            "fingerprint_key": {
                "params": "argon2id$v=19$m=32768,t=8,p=2",
                "salt": "00000000-0000-0000-0000-000000000001"
            },
            "changes": [],
            "summary": {
                "entries_added": 0, "entries_removed": 0, "entries_modified": 0,
                "entries_moved": 0, "groups_added": 0, "groups_removed": 0,
                "groups_modified": 0, "groups_moved": 0, "node_properties": 0,
                "database_properties": 0, "suppressed": 0
            },
            "warnings": []
        })
    );
    assert_eq!(doc(&ChangeSet::default())["fingerprint_key"], Json::Null);
}
