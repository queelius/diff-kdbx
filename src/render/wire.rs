//! The JSON wire format, `format_version` 1, owned here.
//!
//! These private types are the one definition of the JSON shape: every leaf
//! is spelled by this module (no serde output of another crate's types
//! reaches the document), and nested envelopes are flattened. Public types
//! carry no `Serialize`; [`render_json`](super::json::render_json) is the one
//! way to get JSON.
//!
//! | Leaf | JSON |
//! |---|---|
//! | UUID | lowercase hyphenated string |
//! | path | string in the ecosystem path grammar (`/Group/Entry:2`) |
//! | timestamp | `"YYYY-MM-DDTHH:MM:SSZ"` |
//! | fingerprint | 64 lowercase hex characters |
//! | color | `"#RRGGBB"` |
//! | format version | `"major.minor"` |
//! | key derivation parameters | `"argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>"` |
//! | enum names | `snake_case` strings spelled below |

use chrono::DateTime;
use kdbx_core::fingerprint::Fingerprint;
use kdbx_core::model::{
    AutoTypeObfuscation, Compression, FormatVersion, Icon, InnerCipher, OuterCipher, Rgb,
    Timestamp, Value,
};
use kdbx_core::path::VaultPath;
use serde::Serialize;
use uuid::Uuid;

use crate::change_set::{
    Change, ChangeSet, DiffWarning, KdfWeakening, NodeChange, NodeStatus, PropertyChange, Summary,
};
use crate::properties::{FieldName, HistoryKey, KdfKind, Property, Shown};

use super::json::{FingerprintKeyInfo, JSON_FORMAT_VERSION};

#[derive(Serialize)]
pub(super) struct Document {
    format_version: u32,
    fingerprint_key: Option<KeyInfo>,
    changes: Vec<WireChange>,
    summary: WireSummary,
    warnings: Vec<WireWarning>,
}

#[derive(Serialize)]
struct KeyInfo {
    /// `DeriveParams`' recorded form, `argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>`:
    /// exactly what `diff-kdbx fingerprint --params` accepts.
    params: String,
    salt: String,
}

#[derive(Serialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
enum WireChange {
    Database { changes: Vec<WireProperty> },
    Group(WireNode),
    Entry(WireNode),
}

#[derive(Serialize)]
struct WireNode {
    uuid: String,
    path: Option<String>,
    #[serde(flatten)]
    status: WireStatus,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WireStatus {
    Added,
    Removed,
    Modified {
        moved_from: Option<String>,
        changes: Vec<WireProperty>,
    },
}

#[derive(Serialize)]
struct WireProperty {
    property: WireKey,
    before: Option<WireValue>,
    after: Option<WireValue>,
}

/// A property: its kind, and its key (a name, a UUID) when the kind has one.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireKey {
    Name,
    Format,
    Header {
        key: String,
    },
    PublicCustomData {
        key: String,
    },
    Meta {
        key: String,
    },
    Field {
        key: String,
    },
    Notes,
    Tag {
        key: String,
    },
    Attachment {
        key: String,
    },
    OverrideUrl,
    QualityCheck,
    Icon,
    Color {
        key: String,
    },
    AutoType {
        key: String,
    },
    AutoTypeAssociation {
        window: String,
        occurrence: usize,
    },
    GroupFlag {
        key: String,
    },
    Time {
        key: String,
    },
    PreviousParent,
    CustomData {
        key: String,
    },
    CustomDataModified {
        key: String,
    },
    CustomIcon {
        key: String,
    },
    CustomIconName {
        key: String,
    },
    CustomIconModified {
        key: String,
    },
    DeletedObject {
        key: String,
    },
    History {
        modified: Option<String>,
        index: usize,
        property: Box<WireKey>,
    },
}

/// A value: its type, and its content under a name that says what it is.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireValue {
    Text {
        text: String,
    },
    Sealed {
        sealed: String,
    },
    Field {
        protected: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sealed: Option<String>,
    },
    Bool {
        value: bool,
    },
    Int {
        value: i64,
    },
    Uint {
        value: u64,
    },
    Time {
        value: String,
    },
    Uuid {
        value: String,
    },
    Color {
        value: String,
    },
    Icon {
        #[serde(skip_serializing_if = "Option::is_none")]
        standard: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        custom: Option<String>,
    },
    Attachment {
        size: u64,
        sealed: String,
        protected: bool,
    },
    Blob {
        size: u64,
        sealed: String,
    },
    Present,
    Format {
        value: String,
    },
    Kdf {
        value: &'static str,
    },
    OuterCipher {
        value: &'static str,
    },
    InnerCipher {
        value: &'static str,
    },
    Compression {
        value: &'static str,
    },
    Obfuscation {
        value: &'static str,
    },
}

#[derive(Serialize)]
struct WireSummary {
    entries_added: usize,
    entries_removed: usize,
    entries_modified: usize,
    entries_moved: usize,
    groups_added: usize,
    groups_removed: usize,
    groups_modified: usize,
    groups_moved: usize,
    node_properties: usize,
    database_properties: usize,
    suppressed: usize,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireWarning {
    VersionMismatch {
        before: String,
        after: String,
    },
    KdfWeakened {
        #[serde(flatten)]
        weakening: WireWeakening,
    },
}

#[derive(Serialize)]
#[serde(tag = "aspect", rename_all = "snake_case")]
enum WireWeakening {
    NoLongerMemoryHard {
        before: &'static str,
        after: &'static str,
    },
    Unrecognized {
        before: &'static str,
    },
    MemoryLowered {
        before: u64,
        after: u64,
    },
    IterationsLowered {
        before: u64,
        after: u64,
    },
    RoundsLowered {
        before: u64,
        after: u64,
    },
}

impl Document {
    pub(super) fn new(cs: &ChangeSet, key: Option<&FingerprintKeyInfo>) -> Self {
        Document {
            format_version: JSON_FORMAT_VERSION,
            fingerprint_key: key.map(|k| KeyInfo {
                params: k.params.to_string(),
                salt: uuid(k.salt),
            }),
            changes: cs.changes.iter().map(change).collect(),
            summary: summary(&cs.summary),
            warnings: cs.warnings.iter().map(warning).collect(),
        }
    }
}

fn uuid(u: Uuid) -> String {
    u.hyphenated().to_string()
}

fn path(p: &VaultPath) -> String {
    p.format()
}

fn timestamp(t: Timestamp) -> String {
    DateTime::from_timestamp(t.unix(), 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        // Unreachable: a Timestamp is always in chrono's range.
        .unwrap_or_default()
}

fn hex(fp: &Fingerprint) -> String {
    fp.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn color(c: Rgb) -> String {
    format!("#{:02X}{:02X}{:02X}", c.r, c.g, c.b)
}

fn format_version(v: FormatVersion) -> String {
    format!("{}.{}", v.major, v.minor)
}

fn kdf(k: KdfKind) -> &'static str {
    match k {
        KdfKind::AesKdf => "aes_kdf",
        KdfKind::Argon2d => "argon2d",
        KdfKind::Argon2id => "argon2id",
        KdfKind::Unrecognized => "unrecognized",
    }
}

fn change(c: &Change) -> WireChange {
    match c {
        Change::Database { changes } => WireChange::Database {
            changes: changes.iter().map(property_change).collect(),
        },
        Change::Group(n) => WireChange::Group(node(n)),
        Change::Entry(n) => WireChange::Entry(node(n)),
    }
}

fn node(n: &NodeChange) -> WireNode {
    WireNode {
        uuid: uuid(n.uuid),
        path: n.path.as_ref().map(path),
        status: match &n.status {
            NodeStatus::Added => WireStatus::Added,
            NodeStatus::Removed => WireStatus::Removed,
            NodeStatus::Modified {
                moved_from,
                changes,
            } => WireStatus::Modified {
                moved_from: moved_from.as_ref().map(path),
                changes: changes.iter().map(property_change).collect(),
            },
        },
    }
}

fn property_change(c: &PropertyChange) -> WireProperty {
    WireProperty {
        property: key(&c.property),
        before: c.before.as_ref().map(value),
        after: c.after.as_ref().map(value),
    }
}

fn key(p: &Property) -> WireKey {
    let s = |x: &dyn ToString| x.to_string();
    match p {
        Property::Name => WireKey::Name,
        Property::Format => WireKey::Format,
        Property::Header(k) => WireKey::Header { key: s(k) },
        Property::PublicCustomData(k) => WireKey::PublicCustomData { key: k.clone() },
        Property::Meta(k) => WireKey::Meta { key: s(k) },
        Property::Field(name) => WireKey::Field {
            key: match name {
                FieldName::Standard(f) => f.kdbx_name().to_owned(),
                FieldName::Custom(n) => n.clone(),
            },
        },
        Property::Notes => WireKey::Notes,
        Property::Tag(t) => WireKey::Tag { key: t.clone() },
        Property::Attachment(n) => WireKey::Attachment { key: n.clone() },
        Property::OverrideUrl => WireKey::OverrideUrl,
        Property::QualityCheck => WireKey::QualityCheck,
        Property::Icon => WireKey::Icon,
        Property::Color(role) => WireKey::Color { key: s(role) },
        Property::AutoType(k) => WireKey::AutoType { key: s(k) },
        Property::AutoTypeAssociation { window, occurrence } => WireKey::AutoTypeAssociation {
            window: window.clone(),
            occurrence: *occurrence,
        },
        Property::GroupFlag(f) => WireKey::GroupFlag { key: s(f) },
        Property::Time(t) => WireKey::Time { key: s(t) },
        Property::PreviousParent => WireKey::PreviousParent,
        Property::CustomData(k) => WireKey::CustomData { key: k.clone() },
        Property::CustomDataModified(k) => WireKey::CustomDataModified { key: k.clone() },
        Property::CustomIcon(id) => WireKey::CustomIcon { key: uuid(*id) },
        Property::CustomIconName(id) => WireKey::CustomIconName { key: uuid(*id) },
        Property::CustomIconModified(id) => WireKey::CustomIconModified { key: uuid(*id) },
        Property::DeletedObject(id) => WireKey::DeletedObject { key: uuid(*id) },
        Property::History { item, property } => history(item, property),
    }
}

fn history(item: &HistoryKey, property: &Property) -> WireKey {
    WireKey::History {
        modified: item.modified.map(timestamp),
        index: item.index,
        property: Box::new(key(property)),
    }
}

fn value(v: &Shown) -> WireValue {
    match v {
        Shown::Text(s) => WireValue::Text { text: s.clone() },
        Shown::Sealed(fp) => WireValue::Sealed { sealed: hex(fp) },
        Shown::Field { protected, value } => {
            let (text, sealed) = match value {
                Value::Plain(s) => (Some(s.clone()), None),
                Value::Sealed(fp) => (None, Some(hex(fp))),
                _ => (None, None),
            };
            WireValue::Field {
                protected: *protected,
                text,
                sealed,
            }
        }
        Shown::Bool(b) => WireValue::Bool { value: *b },
        Shown::Int(n) => WireValue::Int { value: *n },
        Shown::Uint(n) => WireValue::Uint { value: *n },
        Shown::Time(t) => WireValue::Time {
            value: timestamp(*t),
        },
        Shown::Uuid(u) => WireValue::Uuid { value: uuid(*u) },
        Shown::Color(c) => WireValue::Color { value: color(*c) },
        Shown::Icon(icon) => match icon {
            Icon::Standard(n) => WireValue::Icon {
                standard: Some(*n),
                custom: None,
            },
            Icon::Custom(u) => WireValue::Icon {
                standard: None,
                custom: Some(uuid(*u)),
            },
            _ => WireValue::Icon {
                standard: None,
                custom: None,
            },
        },
        Shown::Attachment {
            size,
            fingerprint,
            protected,
        } => WireValue::Attachment {
            size: *size,
            sealed: hex(fingerprint),
            protected: *protected,
        },
        Shown::Blob { size, fingerprint } => WireValue::Blob {
            size: *size,
            sealed: hex(fingerprint),
        },
        Shown::Present => WireValue::Present,
        Shown::Format(f) => WireValue::Format {
            value: format_version(*f),
        },
        Shown::Kdf(k) => WireValue::Kdf { value: kdf(*k) },
        Shown::OuterCipher(c) => WireValue::OuterCipher {
            value: match c {
                OuterCipher::Aes256 => "aes256",
                OuterCipher::Twofish => "twofish",
                OuterCipher::ChaCha20 => "chacha20",
                _ => "unrecognized",
            },
        },
        Shown::InnerCipher(c) => WireValue::InnerCipher {
            value: match c {
                InnerCipher::Plain => "plain",
                InnerCipher::Salsa20 => "salsa20",
                InnerCipher::ChaCha20 => "chacha20",
                _ => "unrecognized",
            },
        },
        Shown::Compression(c) => WireValue::Compression {
            value: match c {
                Compression::None => "none",
                Compression::GZip => "gzip",
                _ => "unrecognized",
            },
        },
        Shown::Obfuscation(o) => WireValue::Obfuscation {
            value: match o {
                AutoTypeObfuscation::None => "none",
                AutoTypeObfuscation::UseClipboard => "use_clipboard",
                _ => "unrecognized",
            },
        },
    }
}

fn summary(s: &Summary) -> WireSummary {
    WireSummary {
        entries_added: s.entries_added,
        entries_removed: s.entries_removed,
        entries_modified: s.entries_modified,
        entries_moved: s.entries_moved,
        groups_added: s.groups_added,
        groups_removed: s.groups_removed,
        groups_modified: s.groups_modified,
        groups_moved: s.groups_moved,
        node_properties: s.node_properties,
        database_properties: s.database_properties,
        suppressed: s.suppressed,
    }
}

fn warning(w: &DiffWarning) -> WireWarning {
    match w {
        DiffWarning::VersionMismatch { before, after } => WireWarning::VersionMismatch {
            before: format_version(*before),
            after: format_version(*after),
        },
        DiffWarning::KdfWeakened { weakening } => WireWarning::KdfWeakened {
            weakening: match weakening {
                KdfWeakening::NoLongerMemoryHard { before, after } => {
                    WireWeakening::NoLongerMemoryHard {
                        before: kdf(*before),
                        after: kdf(*after),
                    }
                }
                KdfWeakening::Unrecognized { before } => WireWeakening::Unrecognized {
                    before: kdf(*before),
                },
                KdfWeakening::MemoryLowered { before, after } => WireWeakening::MemoryLowered {
                    before: *before,
                    after: *after,
                },
                KdfWeakening::IterationsLowered { before, after } => {
                    WireWeakening::IterationsLowered {
                        before: *before,
                        after: *after,
                    }
                }
                KdfWeakening::RoundsLowered { before, after } => WireWeakening::RoundsLowered {
                    before: *before,
                    after: *after,
                },
            },
        },
    }
}

#[cfg(test)]
mod tests;
