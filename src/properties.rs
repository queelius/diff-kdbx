//! Properties: one ordered map per node, the single source both `dump` and
//! `compute` derive from.
//!
//! Every node of a snapshot (the database itself, each group, each entry)
//! exposes its state as a `BTreeMap<Property, Shown>` built from the
//! `kdbx-core` model. The dump prints the map in order; the diff merge-joins
//! the two maps of each matched node. Because both read the same map, the
//! dump and the diff cannot disagree, and adding a model field means adding
//! one [`Property`] variant and one line here.
//!
//! Map order is the canonical order: [`Property`] variants are declared in
//! dump order, and within a variant keys order naturally (standard fields in
//! KDBX order before custom fields, tags and names lexicographically, history
//! items by modification time).

use std::collections::BTreeMap;
use std::fmt;

use kdbx_core::fields::StandardField;
use kdbx_core::fingerprint::Fingerprint;
use kdbx_core::model::{
    AutoTypeObfuscation, Compression, CustomValue, Entry, FormatVersion, Group, Icon, InnerCipher,
    KdfInfo, Meta, OuterCipher, Rgb, Snapshot, Times, Timestamp, Value,
};
use kdbx_core::text::escape_inline;
use serde::{Serialize, Serializer};
use uuid::Uuid;

/// One property of a node: a model field, or one element of a keyed model
/// collection (a field, a tag, an attachment, a history item's property).
///
/// Variants are declared in canonical (dump) order. The JSON form is
/// `{"kind": "<variant>", "key": <key>}`; `Display` gives the line-safe text
/// label used by the text renderer and the dump.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind", content = "key", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Property {
    /// A group's name (an entry's name is its `Title` field).
    Name,
    /// The KDBX file format version.
    Format,
    /// A setting in the outer KDBX header.
    Header(HeaderKey),
    /// A key of the outer header's public custom data (present or absent).
    PublicCustomData(String),
    /// A `<Meta>` setting.
    Meta(MetaKey),
    /// An entry field, standard or custom.
    Field(FieldName),
    /// A group's notes.
    Notes,
    /// A tag (present or absent).
    Tag(String),
    /// An attachment, by name.
    Attachment(String),
    /// An entry's URL override.
    OverrideUrl,
    /// Whether an entry's password counts toward quality reports.
    QualityCheck,
    /// The node's icon.
    Icon,
    /// An entry color.
    Color(ColorRole),
    /// An entry auto-type setting.
    AutoType(AutoTypeKey),
    /// A window-specific auto-type sequence: the `occurrence`-th association
    /// (0-based, document order) for `window`.
    AutoTypeAssociation {
        /// Window title pattern.
        window: String,
        /// Which of several associations for the same window (0-based).
        occurrence: usize,
    },
    /// A group behavior flag.
    GroupFlag(GroupFlag),
    /// A `<Times>` value.
    Time(TimeField),
    /// The group a node was moved out of.
    PreviousParent,
    /// A custom-data value, by key.
    CustomData(String),
    /// When a custom-data item last changed, by key.
    CustomDataModified(String),
    /// A custom icon's image, by UUID.
    CustomIcon(Uuid),
    /// A custom icon's name, by UUID.
    CustomIconName(Uuid),
    /// When a custom icon last changed, by UUID.
    CustomIconModified(Uuid),
    /// A `<DeletedObjects>` tombstone, by the deleted record's UUID.
    DeletedObject(Uuid),
    /// A property of one of an entry's history items.
    History {
        /// Which history item.
        item: HistoryKey,
        /// The item's property.
        property: Box<Property>,
    },
}

/// An entry field name: one of the five KDBX standard fields, or a custom
/// field.
///
/// Orders the standard fields first, in KDBX order (Title, UserName,
/// Password, URL, Notes), then custom fields by name. Serializes as the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum FieldName {
    /// A standard field.
    Standard(StandardField),
    /// A custom field (never one of the standard names).
    Custom(String),
}

/// Identifies a history item within its entry: its last-modification time,
/// and an index among items sharing that time (0-based, document order).
///
/// Keying by time rather than by position makes trimming at the history cap
/// and pushing a new item two precise changes (one item removed, one added)
/// instead of a shift of every position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub struct HistoryKey {
    /// The item's last-modification time (`None` when absent).
    pub modified: Option<Timestamp>,
    /// Index among the entry's items with the same `modified` (0-based).
    pub index: usize,
}

/// Which entry color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ColorRole {
    /// `ForegroundColor`.
    Foreground,
    /// `BackgroundColor`.
    Background,
}

/// An entry auto-type setting (window associations are
/// [`Property::AutoTypeAssociation`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AutoTypeKey {
    /// Whether auto-type is enabled for the entry.
    Enabled,
    /// The default keystroke sequence.
    DefaultSequence,
    /// How keystrokes are transferred.
    DataTransferObfuscation,
}

/// A group behavior flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum GroupFlag {
    /// Expanded in the tree view (UI state).
    IsExpanded,
    /// Auto-type enabled (absent: inherited).
    EnableAutoType,
    /// Searching enabled (absent: inherited).
    EnableSearching,
    /// Default auto-type sequence for the group's entries.
    DefaultAutoTypeSequence,
}

/// A `<Times>` value. Variants mirror the KDBX elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TimeField {
    /// `CreationTime`.
    CreationTime,
    /// `LastModificationTime`.
    LastModificationTime,
    /// `LastAccessTime`.
    LastAccessTime,
    /// `ExpiryTime`, a property only while the node expires.
    ExpiryTime,
    /// `Expires`.
    Expires,
    /// `UsageCount`.
    UsageCount,
    /// `LocationChanged`.
    LocationChanged,
}

/// A setting in the outer KDBX header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum HeaderKey {
    /// The key derivation function.
    Kdf,
    /// AES-KDF transformation rounds.
    KdfRounds,
    /// Argon2 memory cost in bytes.
    KdfMemory,
    /// Argon2 passes.
    KdfIterations,
    /// Argon2 lanes.
    KdfParallelism,
    /// Argon2 version.
    KdfVersion,
    /// The payload cipher.
    OuterCipher,
    /// The protected-value stream cipher.
    InnerCipher,
    /// Payload compression.
    Compression,
}

/// A `<Meta>` setting. Names are the KDBX element names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MetaKey {
    /// `Generator`: the application that last wrote the file.
    Generator,
    /// `DatabaseName`.
    DatabaseName,
    /// `DatabaseNameChanged`.
    DatabaseNameChanged,
    /// `DatabaseDescription`.
    DatabaseDescription,
    /// `DatabaseDescriptionChanged`.
    DatabaseDescriptionChanged,
    /// `DefaultUserName`.
    DefaultUserName,
    /// `DefaultUserNameChanged`.
    DefaultUserNameChanged,
    /// `MaintenanceHistoryDays`.
    MaintenanceHistoryDays,
    /// `Color`.
    Color,
    /// `MasterKeyChanged`.
    MasterKeyChanged,
    /// `MasterKeyChangeRec`.
    MasterKeyChangeRec,
    /// `MasterKeyChangeForce`.
    MasterKeyChangeForce,
    /// A `<MemoryProtection>` flag (`ProtectTitle` and so on).
    MemoryProtection(StandardField),
    /// `RecycleBinEnabled`.
    RecycleBinEnabled,
    /// `RecycleBinUUID`.
    RecycleBinUuid,
    /// `RecycleBinChanged`.
    RecycleBinChanged,
    /// `EntryTemplatesGroup`.
    EntryTemplatesGroup,
    /// `EntryTemplatesGroupChanged`.
    EntryTemplatesGroupChanged,
    /// `LastSelectedGroup` (UI state).
    LastSelectedGroup,
    /// `LastTopVisibleGroup` (UI state).
    LastTopVisibleGroup,
    /// `HistoryMaxItems`.
    HistoryMaxItems,
    /// `HistoryMaxSize`.
    HistoryMaxSize,
    /// `SettingsChanged`.
    SettingsChanged,
}

/// The kind of key derivation function, without its parameters (those are
/// separate [`HeaderKey`] properties).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KdfKind {
    /// AES-KDF.
    AesKdf,
    /// Argon2d.
    Argon2d,
    /// Argon2id.
    Argon2id,
    /// A KDF the capturing keepass version does not name.
    Unrecognized,
}

/// A property value, as the change set and the dump show it.
///
/// Secret values are already [`Value::Sealed`] fingerprints in the snapshot
/// (sealing happens at capture), so nothing here can hold a protected
/// plaintext unless the snapshot was captured with `Sealing::Reveal`.
///
/// The JSON form is `{"type": "<variant>", "value": <value>}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Shown {
    /// Plain metadata text (a name, a URL, notes).
    Text(String),
    /// A fingerprint standing in for a sealed value.
    Sealed(Fingerprint),
    /// An entry field: its value and its KDBX protection flag, so a
    /// protection toggle on an unchanged value is a visible change.
    Field {
        /// The stored protection flag.
        protected: bool,
        /// The value, plain or sealed.
        value: Value,
    },
    /// A flag.
    Bool(bool),
    /// A signed number (`-1` often means "unlimited" or "never").
    Int(i64),
    /// An unsigned number (counts, sizes, KDF parameters).
    Uint(u64),
    /// A UTC timestamp.
    Time(Timestamp),
    /// A record identity.
    Uuid(Uuid),
    /// A color, `#RRGGBB`.
    Color(Rgb),
    /// An icon.
    Icon(Icon),
    /// An attachment, described without its content.
    Attachment {
        /// Content length in bytes.
        size: u64,
        /// Fingerprint of the content.
        fingerprint: Fingerprint,
        /// The stored protection flag.
        protected: bool,
    },
    /// Binary content (a custom icon), described without the bytes.
    Blob {
        /// Length in bytes.
        size: u64,
        /// Fingerprint of the bytes.
        fingerprint: Fingerprint,
    },
    /// Presence alone (a tag, a header custom-data key, a tombstone without a
    /// time).
    Present,
    /// A KDBX format version.
    Format(FormatVersion),
    /// A key derivation function.
    Kdf(KdfKind),
    /// A payload cipher.
    OuterCipher(OuterCipher),
    /// A protected-value stream cipher.
    InnerCipher(InnerCipher),
    /// A payload compression.
    Compression(Compression),
    /// An auto-type keystroke transfer mode.
    Obfuscation(AutoTypeObfuscation),
}

/// A node's properties in canonical order.
pub(crate) type PropertyMap = BTreeMap<Property, Shown>;

// ---------------------------------------------------------------------------
// Noise: which properties change without a deliberate edit.

impl Property {
    /// Whether a change to this property is noise: it moves on an
    /// open-and-save, or it only restates a change reported elsewhere (a
    /// `*Changed` timestamp beside the setting it times, a node's previous
    /// parent beside its move). Default mode suppresses noise in both the
    /// diff and the dump; `--strict` shows it.
    pub fn is_noise(&self) -> bool {
        match self {
            Property::Time(t) => t.is_noise(),
            Property::Meta(m) => m.is_noise(),
            Property::GroupFlag(f) => f.is_noise(),
            Property::PreviousParent
            | Property::CustomDataModified(_)
            | Property::CustomIconModified(_)
            | Property::DeletedObject(_) => true,
            Property::History { property, .. } => property.is_noise(),
            Property::Name
            | Property::Format
            | Property::Header(_)
            | Property::PublicCustomData(_)
            | Property::Field(_)
            | Property::Notes
            | Property::Tag(_)
            | Property::Attachment(_)
            | Property::OverrideUrl
            | Property::QualityCheck
            | Property::Icon
            | Property::Color(_)
            | Property::AutoType(_)
            | Property::AutoTypeAssociation { .. }
            | Property::CustomData(_)
            | Property::CustomIcon(_)
            | Property::CustomIconName(_) => false,
        }
    }

    /// Whether the value is multi-line text, rendered as continuation lines
    /// (Notes and the database description).
    pub(crate) fn is_multiline(&self) -> bool {
        match self {
            Property::Field(name) => kdbx_core::fields::traits_of(name.as_str()).multiline,
            Property::Notes | Property::Meta(MetaKey::DatabaseDescription) => true,
            Property::History { property, .. } => property.is_multiline(),
            _ => false,
        }
    }
}

impl TimeField {
    /// Every time field, in canonical order.
    pub const ALL: [TimeField; 7] = [
        TimeField::CreationTime,
        TimeField::LastModificationTime,
        TimeField::LastAccessTime,
        TimeField::ExpiryTime,
        TimeField::Expires,
        TimeField::UsageCount,
        TimeField::LocationChanged,
    ];

    /// The KDBX element name.
    pub fn kdbx_name(self) -> &'static str {
        match self {
            TimeField::CreationTime => "CreationTime",
            TimeField::LastModificationTime => "LastModificationTime",
            TimeField::LastAccessTime => "LastAccessTime",
            TimeField::ExpiryTime => "ExpiryTime",
            TimeField::Expires => "Expires",
            TimeField::UsageCount => "UsageCount",
            TimeField::LocationChanged => "LocationChanged",
        }
    }

    /// Whether default mode suppresses a change to this value.
    ///
    /// Opening and re-saving a vault touches the access time and usage count.
    /// Any edit moves the last-modification time, and a move updates the
    /// location-changed time, but the edit or move itself is already
    /// reported. Creation and expiry changes are deliberate and stay visible.
    pub fn is_noise(self) -> bool {
        match self {
            TimeField::LastModificationTime
            | TimeField::LastAccessTime
            | TimeField::UsageCount
            | TimeField::LocationChanged => true,
            TimeField::CreationTime | TimeField::ExpiryTime | TimeField::Expires => false,
        }
    }
}

impl MetaKey {
    /// Whether default mode suppresses a change to this setting: the
    /// application stamp, UI state, and the `*Changed` timestamps that only
    /// time a setting change reported on its own. `MasterKeyChanged` is not
    /// noise: it explains why every fingerprint changed.
    pub fn is_noise(self) -> bool {
        match self {
            MetaKey::Generator
            | MetaKey::DatabaseNameChanged
            | MetaKey::DatabaseDescriptionChanged
            | MetaKey::DefaultUserNameChanged
            | MetaKey::RecycleBinChanged
            | MetaKey::EntryTemplatesGroupChanged
            | MetaKey::LastSelectedGroup
            | MetaKey::LastTopVisibleGroup
            | MetaKey::SettingsChanged => true,
            MetaKey::DatabaseName
            | MetaKey::DatabaseDescription
            | MetaKey::DefaultUserName
            | MetaKey::MaintenanceHistoryDays
            | MetaKey::Color
            | MetaKey::MasterKeyChanged
            | MetaKey::MasterKeyChangeRec
            | MetaKey::MasterKeyChangeForce
            | MetaKey::MemoryProtection(_)
            | MetaKey::RecycleBinEnabled
            | MetaKey::RecycleBinUuid
            | MetaKey::EntryTemplatesGroup
            | MetaKey::HistoryMaxItems
            | MetaKey::HistoryMaxSize => false,
        }
    }
}

impl GroupFlag {
    /// Whether default mode suppresses a change: expanding a group in a
    /// client's tree view is UI state.
    pub fn is_noise(self) -> bool {
        match self {
            GroupFlag::IsExpanded => true,
            GroupFlag::EnableAutoType
            | GroupFlag::EnableSearching
            | GroupFlag::DefaultAutoTypeSequence => false,
        }
    }
}

impl FieldName {
    /// The field named `name` (standard when it is one of the five KDBX
    /// names, compared exactly).
    pub fn new(name: &str) -> Self {
        StandardField::from_kdbx_name(name)
            .map_or_else(|| FieldName::Custom(name.to_owned()), FieldName::Standard)
    }

    /// The KDBX field name.
    pub fn as_str(&self) -> &str {
        match self {
            FieldName::Standard(f) => f.kdbx_name(),
            FieldName::Custom(name) => name,
        }
    }
}

impl KdfKind {
    /// The kind of `kdf`.
    pub fn of(kdf: &KdfInfo) -> Self {
        match kdf {
            KdfInfo::Aes { .. } => KdfKind::AesKdf,
            KdfInfo::Argon2(a) => match a.variant {
                kdbx_core::model::Argon2Variant::Argon2d => KdfKind::Argon2d,
                kdbx_core::model::Argon2Variant::Argon2id => KdfKind::Argon2id,
                _ => KdfKind::Unrecognized,
            },
            _ => KdfKind::Unrecognized,
        }
    }
}

// ---------------------------------------------------------------------------
// Labels: one name per key, used by Display (text) and Serialize (JSON).

impl fmt::Display for FieldName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for ColorRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ColorRole::Foreground => "ForegroundColor",
            ColorRole::Background => "BackgroundColor",
        })
    }
}

impl fmt::Display for AutoTypeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AutoTypeKey::Enabled => "Enabled",
            AutoTypeKey::DefaultSequence => "DefaultSequence",
            AutoTypeKey::DataTransferObfuscation => "DataTransferObfuscation",
        })
    }
}

impl fmt::Display for GroupFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GroupFlag::IsExpanded => "IsExpanded",
            GroupFlag::EnableAutoType => "EnableAutoType",
            GroupFlag::EnableSearching => "EnableSearching",
            GroupFlag::DefaultAutoTypeSequence => "DefaultAutoTypeSequence",
        })
    }
}

impl fmt::Display for TimeField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kdbx_name())
    }
}

impl fmt::Display for HeaderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HeaderKey::Kdf => "Kdf",
            HeaderKey::KdfRounds => "KdfRounds",
            HeaderKey::KdfMemory => "KdfMemory",
            HeaderKey::KdfIterations => "KdfIterations",
            HeaderKey::KdfParallelism => "KdfParallelism",
            HeaderKey::KdfVersion => "KdfVersion",
            HeaderKey::OuterCipher => "OuterCipher",
            HeaderKey::InnerCipher => "InnerCipher",
            HeaderKey::Compression => "Compression",
        })
    }
}

impl fmt::Display for MetaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MetaKey::MemoryProtection(field) => return write!(f, "Protect{}", field.kdbx_name()),
            MetaKey::Generator => "Generator",
            MetaKey::DatabaseName => "DatabaseName",
            MetaKey::DatabaseNameChanged => "DatabaseNameChanged",
            MetaKey::DatabaseDescription => "DatabaseDescription",
            MetaKey::DatabaseDescriptionChanged => "DatabaseDescriptionChanged",
            MetaKey::DefaultUserName => "DefaultUserName",
            MetaKey::DefaultUserNameChanged => "DefaultUserNameChanged",
            MetaKey::MaintenanceHistoryDays => "MaintenanceHistoryDays",
            MetaKey::Color => "Color",
            MetaKey::MasterKeyChanged => "MasterKeyChanged",
            MetaKey::MasterKeyChangeRec => "MasterKeyChangeRec",
            MetaKey::MasterKeyChangeForce => "MasterKeyChangeForce",
            MetaKey::RecycleBinEnabled => "RecycleBinEnabled",
            MetaKey::RecycleBinUuid => "RecycleBinUUID",
            MetaKey::RecycleBinChanged => "RecycleBinChanged",
            MetaKey::EntryTemplatesGroup => "EntryTemplatesGroup",
            MetaKey::EntryTemplatesGroupChanged => "EntryTemplatesGroupChanged",
            MetaKey::LastSelectedGroup => "LastSelectedGroup",
            MetaKey::LastTopVisibleGroup => "LastTopVisibleGroup",
            MetaKey::HistoryMaxItems => "HistoryMaxItems",
            MetaKey::HistoryMaxSize => "HistoryMaxSize",
            MetaKey::SettingsChanged => "SettingsChanged",
        };
        f.write_str(name)
    }
}

impl fmt::Display for HistoryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.modified {
            Some(t) => write!(f, "{t}")?,
            None => f.write_str("unknown")?,
        }
        if self.index > 0 {
            write!(f, "#{}", self.index + 1)?;
        }
        Ok(())
    }
}

/// The line-safe text label: user-supplied parts (field names, tags, keys)
/// pass through [`escape_inline`], so a label is always one printable line.
impl fmt::Display for Property {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Property::Name => f.write_str("Name"),
            Property::Format => f.write_str("Version"),
            Property::Header(k) => write!(f, "{k}"),
            Property::PublicCustomData(k) => write!(f, "PublicCustomData[{}]", escape_inline(k)),
            Property::Meta(k) => write!(f, "{k}"),
            Property::Field(name) => f.write_str(&escape_inline(name.as_str())),
            Property::Notes => f.write_str("Notes"),
            Property::Tag(t) => write!(f, "Tag[{}]", escape_inline(t)),
            Property::Attachment(n) => write!(f, "Attachment[{}]", escape_inline(n)),
            Property::OverrideUrl => f.write_str("OverrideURL"),
            Property::QualityCheck => f.write_str("QualityCheck"),
            Property::Icon => f.write_str("Icon"),
            Property::Color(role) => write!(f, "{role}"),
            Property::AutoType(k) => write!(f, "AutoType.{k}"),
            Property::AutoTypeAssociation { window, occurrence } => {
                write!(f, "AutoType.Association[{}", escape_inline(window))?;
                if *occurrence > 0 {
                    write!(f, "#{}", occurrence + 1)?;
                }
                f.write_str("]")
            }
            Property::GroupFlag(flag) => write!(f, "{flag}"),
            Property::Time(t) => write!(f, "{t}"),
            Property::PreviousParent => f.write_str("PreviousParentGroup"),
            Property::CustomData(k) => write!(f, "CustomData[{}]", escape_inline(k)),
            Property::CustomDataModified(k) => {
                write!(f, "CustomData[{}].Modified", escape_inline(k))
            }
            Property::CustomIcon(id) => write!(f, "CustomIcon[{id}]"),
            Property::CustomIconName(id) => write!(f, "CustomIcon[{id}].Name"),
            Property::CustomIconModified(id) => write!(f, "CustomIcon[{id}].Modified"),
            Property::DeletedObject(id) => write!(f, "DeletedObject[{id}]"),
            Property::History { item, property } => write!(f, "History[{item}].{property}"),
        }
    }
}

macro_rules! serialize_as_label {
    ($($ty:ty),*) => {$(
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
    )*};
}

serialize_as_label!(
    FieldName,
    ColorRole,
    AutoTypeKey,
    GroupFlag,
    TimeField,
    HeaderKey,
    MetaKey
);

// ---------------------------------------------------------------------------
// The property maps.

/// The database-level properties: format, header, `<Meta>`, and tombstones.
pub(crate) fn database_properties(snap: &Snapshot) -> PropertyMap {
    let mut map = PropertyMap::new();
    map.insert(Property::Format, Shown::Format(snap.format));
    if let Some(header) = &snap.header {
        let h = |k| Property::Header(k);
        map.insert(h(HeaderKey::Kdf), Shown::Kdf(KdfKind::of(&header.kdf)));
        match &header.kdf {
            KdfInfo::Aes { rounds } => {
                map.insert(h(HeaderKey::KdfRounds), Shown::Uint(*rounds));
            }
            KdfInfo::Argon2(a) => {
                map.insert(h(HeaderKey::KdfMemory), Shown::Uint(a.memory_bytes));
                map.insert(h(HeaderKey::KdfIterations), Shown::Uint(a.iterations));
                map.insert(
                    h(HeaderKey::KdfParallelism),
                    Shown::Uint(a.parallelism.into()),
                );
                map.insert(h(HeaderKey::KdfVersion), Shown::Uint(a.version.into()));
            }
            _ => {}
        }
        map.insert(
            h(HeaderKey::OuterCipher),
            Shown::OuterCipher(header.outer_cipher),
        );
        map.insert(
            h(HeaderKey::InnerCipher),
            Shown::InnerCipher(header.inner_cipher),
        );
        map.insert(
            h(HeaderKey::Compression),
            Shown::Compression(header.compression),
        );
        for key in &header.public_custom_data {
            map.insert(Property::PublicCustomData(key.clone()), Shown::Present);
        }
    }
    meta_properties(&snap.meta, &mut map);
    for (id, when) in &snap.deleted_objects {
        map.insert(
            Property::DeletedObject(*id),
            when.map_or(Shown::Present, Shown::Time),
        );
    }
    map
}

fn meta_properties(m: &Meta, map: &mut PropertyMap) {
    let mut put = |key: MetaKey, value: Option<Shown>| {
        if let Some(v) = value {
            map.insert(Property::Meta(key), v);
        }
    };
    let text = |s: &Option<String>| s.clone().map(Shown::Text);
    put(MetaKey::Generator, text(&m.generator));
    put(MetaKey::DatabaseName, text(&m.database_name));
    put(
        MetaKey::DatabaseNameChanged,
        m.database_name_changed.map(Shown::Time),
    );
    put(MetaKey::DatabaseDescription, text(&m.database_description));
    put(
        MetaKey::DatabaseDescriptionChanged,
        m.database_description_changed.map(Shown::Time),
    );
    put(MetaKey::DefaultUserName, text(&m.default_username));
    put(
        MetaKey::DefaultUserNameChanged,
        m.default_username_changed.map(Shown::Time),
    );
    put(
        MetaKey::MaintenanceHistoryDays,
        m.maintenance_history_days.map(Shown::Uint),
    );
    put(MetaKey::Color, m.color.map(Shown::Color));
    put(
        MetaKey::MasterKeyChanged,
        m.master_key_changed.map(Shown::Time),
    );
    put(
        MetaKey::MasterKeyChangeRec,
        m.master_key_change_rec.map(Shown::Int),
    );
    put(
        MetaKey::MasterKeyChangeForce,
        m.master_key_change_force.map(Shown::Int),
    );
    if let Some(mp) = &m.memory_protection {
        for field in StandardField::ALL {
            put(
                MetaKey::MemoryProtection(field),
                Some(Shown::Bool(mp.protects(field))),
            );
        }
    }
    put(
        MetaKey::RecycleBinEnabled,
        m.recycle_bin_enabled.map(Shown::Bool),
    );
    put(MetaKey::RecycleBinUuid, m.recycle_bin.map(Shown::Uuid));
    put(
        MetaKey::RecycleBinChanged,
        m.recycle_bin_changed.map(Shown::Time),
    );
    put(
        MetaKey::EntryTemplatesGroup,
        m.entry_templates_group.map(Shown::Uuid),
    );
    put(
        MetaKey::EntryTemplatesGroupChanged,
        m.entry_templates_group_changed.map(Shown::Time),
    );
    put(
        MetaKey::LastSelectedGroup,
        m.last_selected_group.map(Shown::Uuid),
    );
    put(
        MetaKey::LastTopVisibleGroup,
        m.last_top_visible_group.map(Shown::Uuid),
    );
    put(
        MetaKey::HistoryMaxItems,
        m.history_max_items.map(Shown::Int),
    );
    put(MetaKey::HistoryMaxSize, m.history_max_size.map(Shown::Int));
    put(
        MetaKey::SettingsChanged,
        m.settings_changed.map(Shown::Time),
    );
    custom_data_properties(&m.custom_data, map);
    for (id, icon) in &m.custom_icons {
        map.insert(
            Property::CustomIcon(*id),
            Shown::Blob {
                size: icon.size,
                fingerprint: icon.fingerprint,
            },
        );
        if let Some(name) = &icon.name {
            map.insert(Property::CustomIconName(*id), Shown::Text(name.clone()));
        }
        if let Some(t) = icon.modified {
            map.insert(Property::CustomIconModified(*id), Shown::Time(t));
        }
    }
}

/// A group's own properties (not its children's).
pub(crate) fn group_properties(g: &Group) -> PropertyMap {
    let mut map = PropertyMap::new();
    map.insert(Property::Name, Shown::Text(g.name.clone()));
    if let Some(notes) = &g.notes {
        map.insert(Property::Notes, Shown::Text(notes.clone()));
    }
    tag_properties(&g.tags, &mut map);
    if let Some(icon) = g.icon {
        map.insert(Property::Icon, Shown::Icon(icon));
    }
    let flag = |f| Property::GroupFlag(f);
    map.insert(
        flag(GroupFlag::IsExpanded),
        Shown::Bool(g.flags.is_expanded),
    );
    if let Some(b) = g.flags.enable_autotype {
        map.insert(flag(GroupFlag::EnableAutoType), Shown::Bool(b));
    }
    if let Some(b) = g.flags.enable_searching {
        map.insert(flag(GroupFlag::EnableSearching), Shown::Bool(b));
    }
    if let Some(seq) = &g.flags.default_autotype_sequence {
        map.insert(
            flag(GroupFlag::DefaultAutoTypeSequence),
            Shown::Text(seq.clone()),
        );
    }
    time_properties(&g.times, &mut map);
    if let Some(parent) = g.previous_parent {
        map.insert(Property::PreviousParent, Shown::Uuid(parent));
    }
    custom_data_properties(&g.custom_data, &mut map);
    map
}

/// An entry's properties, including every property of every history item.
pub(crate) fn entry_properties(e: &Entry) -> PropertyMap {
    let mut map = PropertyMap::new();
    for (name, field) in &e.fields {
        map.insert(
            Property::Field(FieldName::new(name)),
            Shown::Field {
                protected: field.protected,
                value: field.value.clone(),
            },
        );
    }
    tag_properties(&e.tags, &mut map);
    for (name, att) in &e.attachments {
        map.insert(
            Property::Attachment(name.clone()),
            Shown::Attachment {
                size: att.size,
                fingerprint: att.fingerprint,
                protected: att.protected,
            },
        );
    }
    if let Some(url) = &e.override_url {
        map.insert(Property::OverrideUrl, Shown::Text(url.clone()));
    }
    map.insert(Property::QualityCheck, Shown::Bool(e.quality_check));
    if let Some(icon) = e.icon {
        map.insert(Property::Icon, Shown::Icon(icon));
    }
    for (role, color) in [
        (ColorRole::Foreground, e.foreground),
        (ColorRole::Background, e.background),
    ] {
        if let Some(c) = color {
            map.insert(Property::Color(role), Shown::Color(c));
        }
    }
    if let Some(at) = &e.autotype {
        map.insert(
            Property::AutoType(AutoTypeKey::Enabled),
            Shown::Bool(at.enabled),
        );
        if let Some(seq) = &at.default_sequence {
            map.insert(
                Property::AutoType(AutoTypeKey::DefaultSequence),
                Shown::Text(seq.clone()),
            );
        }
        map.insert(
            Property::AutoType(AutoTypeKey::DataTransferObfuscation),
            Shown::Obfuscation(at.obfuscation),
        );
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for assoc in &at.associations {
            let occurrence = seen.entry(assoc.window.as_str()).or_default();
            map.insert(
                Property::AutoTypeAssociation {
                    window: assoc.window.clone(),
                    occurrence: *occurrence,
                },
                Shown::Text(assoc.sequence.clone()),
            );
            *occurrence += 1;
        }
    }
    time_properties(&e.times, &mut map);
    if let Some(parent) = e.previous_parent {
        map.insert(Property::PreviousParent, Shown::Uuid(parent));
    }
    custom_data_properties(&e.custom_data, &mut map);
    let mut seen: BTreeMap<Option<Timestamp>, usize> = BTreeMap::new();
    for item in &e.history {
        let modified = item.times.last_modification;
        let index = seen.entry(modified).or_default();
        let key = HistoryKey {
            modified,
            index: *index,
        };
        *index += 1;
        for (property, value) in entry_properties(item) {
            map.insert(
                Property::History {
                    item: key,
                    property: Box::new(property),
                },
                value,
            );
        }
    }
    map
}

fn tag_properties<'a>(tags: impl IntoIterator<Item = &'a String>, map: &mut PropertyMap) {
    for tag in tags {
        map.insert(Property::Tag(tag.clone()), Shown::Present);
    }
}

fn custom_data_properties(items: &BTreeMap<String, CustomValue>, map: &mut PropertyMap) {
    for (key, item) in items {
        let value = match &item.value {
            Value::Plain(s) => Shown::Text(s.clone()),
            Value::Sealed(fp) => Shown::Sealed(*fp),
            // `Value` is non-exhaustive. A variant kdbx-core adds later is
            // shown by presence only, never by guessing at its content.
            _ => Shown::Present,
        };
        map.insert(Property::CustomData(key.clone()), value);
        if let Some(t) = item.modified {
            map.insert(Property::CustomDataModified(key.clone()), Shown::Time(t));
        }
    }
}

/// The `<Times>` values. `ExpiryTime` is a property only while the node
/// expires: KeePass writes an expiry time even for nodes that never expire,
/// where it has no effect.
fn time_properties(t: &Times, map: &mut PropertyMap) {
    for field in TimeField::ALL {
        let value = match field {
            TimeField::CreationTime => t.creation.map(Shown::Time),
            TimeField::LastModificationTime => t.last_modification.map(Shown::Time),
            TimeField::LastAccessTime => t.last_access.map(Shown::Time),
            TimeField::ExpiryTime if t.expires == Some(true) => t.expiry.map(Shown::Time),
            TimeField::ExpiryTime => None,
            TimeField::Expires => t.expires.map(Shown::Bool),
            TimeField::UsageCount => t.usage_count.map(Shown::Uint),
            TimeField::LocationChanged => t.location_changed.map(Shown::Time),
        };
        if let Some(v) = value {
            map.insert(Property::Time(field), v);
        }
    }
}

#[cfg(test)]
mod tests;
