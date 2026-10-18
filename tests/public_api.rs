//! The public API, pinned from outside the crate (`cargo public-api` is not
//! part of the toolchain here). Every public item is named; functions are
//! pinned by signature, structs by field types, enums by their variants. An
//! accidental rename, removal, signature or variant change fails to compile.
//! Additions are visible in review in `src/lib.rs`'s re-export list.

use diff_kdbx::kdbx_core::fields::StandardField;
use diff_kdbx::kdbx_core::fingerprint::{DeriveParams, Fingerprint};
use diff_kdbx::kdbx_core::model::{
    AutoTypeObfuscation, Compression, FormatVersion, Icon, InnerCipher, OuterCipher, Rgb, Snapshot,
    Timestamp, Value,
};
use diff_kdbx::kdbx_core::path::VaultPath;
use diff_kdbx::{
    AutoTypeKey, Change, ChangeSet, ColorRole, DiffOptions, DiffWarning, DumpOptions, FieldName,
    FingerprintKeyInfo, GroupFlag, HeaderKey, HistoryKey, JSON_FORMAT_VERSION, JsonOptions,
    KdfKind, KdfWeakening, MetaKey, NodeChange, NodeStatus, Noise, Property, PropertyChange,
    RecycleBin, Shown, Summary, TextOptions, TimeField, compute, dump, render_json, render_text,
};
use uuid::Uuid;

#[test]
fn functions_and_constants() {
    let _: fn(&Snapshot, &Snapshot, &DiffOptions) -> ChangeSet = compute;
    let _: fn(&Snapshot, &DumpOptions) -> String = dump;
    let _: fn(&ChangeSet, &TextOptions) -> String = render_text;
    let _ = TextOptions::default();
    let _: fn(&ChangeSet, &JsonOptions) -> String = render_json;
    let _: u32 = JSON_FORMAT_VERSION;
    let _: fn(Vec<Change>, Vec<DiffWarning>, usize) -> ChangeSet = ChangeSet::new;
    let _: fn(&ChangeSet) -> bool = ChangeSet::is_empty;
    let _: fn(Uuid, Option<VaultPath>, NodeStatus) -> NodeChange = NodeChange::new;
    let _: fn(Property, Option<Shown>, Option<Shown>) -> PropertyChange = PropertyChange::new;
    let _: fn(Noise, RecycleBin) -> DiffOptions = DiffOptions::new;
    let _: fn(Noise, RecycleBin) -> DumpOptions = DumpOptions::new;
    let _: fn(FingerprintKeyInfo) -> JsonOptions = JsonOptions::with_fingerprint_key;
    let _: fn(DeriveParams, Uuid) -> FingerprintKeyInfo = FingerprintKeyInfo::new;
    let _: fn(&Property) -> bool = Property::is_noise;
    let _: fn(TimeField) -> bool = TimeField::is_noise;
    let _: fn(TimeField) -> &'static str = TimeField::kdbx_name;
    let _: [TimeField; 7] = TimeField::ALL;
    let _: fn(MetaKey) -> bool = MetaKey::is_noise;
    let _: fn(GroupFlag) -> bool = GroupFlag::is_noise;
    let _: fn(&str) -> FieldName = FieldName::new;
    let _: fn(Option<Timestamp>, usize) -> HistoryKey = HistoryKey::new;
    let _: fn(&FieldName) -> &str = FieldName::as_str;
    let _: fn(&diff_kdbx::kdbx_core::model::KdfInfo) -> KdfKind = KdfKind::of;
}

#[test]
fn struct_fields() {
    let cs = ChangeSet::default();
    let _: &Vec<Change> = &cs.changes;
    let _: &Summary = &cs.summary;
    let _: &Vec<DiffWarning> = &cs.warnings;
    let s = &cs.summary;
    let _: [usize; 11] = [
        s.entries_added,
        s.entries_removed,
        s.entries_modified,
        s.entries_moved,
        s.groups_added,
        s.groups_removed,
        s.groups_modified,
        s.groups_moved,
        s.node_properties,
        s.database_properties,
        s.suppressed,
    ];
    let n = NodeChange::new(Uuid::nil(), None, NodeStatus::Added);
    let _: (&Uuid, &Option<VaultPath>, &NodeStatus) = (&n.uuid, &n.path, &n.status);
    let p = PropertyChange::new(Property::Name, None, None);
    let _: (&Property, &Option<Shown>, &Option<Shown>) = (&p.property, &p.before, &p.after);
    let d = DiffOptions::default();
    let _: (Noise, RecycleBin) = (d.noise, d.recycle_bin);
    let d = DumpOptions::default();
    let _: (Noise, RecycleBin) = (d.noise, d.recycle_bin);
    let j = JsonOptions::default();
    let _: Option<FingerprintKeyInfo> = j.fingerprint_key;
    let f = FingerprintKeyInfo::new(DeriveParams::FLOOR, Uuid::nil());
    let _: (DeriveParams, Uuid) = (f.params, f.salt);
    let h = HistoryKey::new(None, 0);
    let _: (Option<Timestamp>, usize) = (h.modified, h.index);
}

#[test]
fn enum_variants() {
    let fp = Fingerprint::from_bytes([1; 32]);
    // Variants that carry fields are #[non_exhaustive]: built through
    // constructors, matched with `..`.
    let _ = [
        Change::database(vec![]),
        Change::Group(NodeChange::new(Uuid::nil(), None, NodeStatus::Removed)),
        Change::Entry(NodeChange::new(
            Uuid::nil(),
            None,
            NodeStatus::modified(None, vec![]),
        )),
    ];
    let _ = [
        DiffWarning::version_mismatch(FormatVersion::KDBX_4_0, FormatVersion::KDBX_4_1),
        DiffWarning::kdf_weakened(KdfWeakening::unrecognized(KdfKind::AesKdf)),
    ];
    let weakenings = [
        KdfWeakening::no_longer_memory_hard(KdfKind::Argon2d, KdfKind::AesKdf),
        KdfWeakening::memory_lowered(2, 1),
        KdfWeakening::iterations_lowered(2, 1),
        KdfWeakening::rounds_lowered(2, 1),
    ];
    for w in &weakenings {
        match w {
            KdfWeakening::NoLongerMemoryHard { before, after, .. } => {
                let _: (&KdfKind, &KdfKind) = (before, after);
            }
            KdfWeakening::MemoryLowered { before, after, .. }
            | KdfWeakening::IterationsLowered { before, after, .. }
            | KdfWeakening::RoundsLowered { before, after, .. } => {
                let _: (&u64, &u64) = (before, after);
            }
            KdfWeakening::Unrecognized { before, .. } => {
                let _: &KdfKind = before;
            }
            _ => {}
        }
    }
    match NodeStatus::modified(None, vec![]) {
        NodeStatus::Modified {
            moved_from,
            changes,
            ..
        } => {
            let _: (Option<VaultPath>, Vec<PropertyChange>) = (moved_from, changes);
        }
        _ => unreachable!(),
    }
    let _ = [
        KdfKind::AesKdf,
        KdfKind::Argon2d,
        KdfKind::Argon2id,
        KdfKind::Unrecognized,
    ];
    let _ = [Noise::Suppress, Noise::Show];
    let _ = [RecycleBin::Exclude, RecycleBin::Include];
    let history = HistoryKey::new(None, 0);
    let _ = [
        Property::Name,
        Property::Format,
        Property::Header(HeaderKey::Kdf),
        Property::PublicCustomData(String::new()),
        Property::Meta(MetaKey::DatabaseName),
        Property::Field(FieldName::Standard(StandardField::Title)),
        Property::Field(FieldName::Custom(String::new())),
        Property::Notes,
        Property::Tag(String::new()),
        Property::Attachment(String::new()),
        Property::OverrideUrl,
        Property::QualityCheck,
        Property::Icon,
        Property::Color(ColorRole::Foreground),
        Property::AutoType(AutoTypeKey::Enabled),
        Property::auto_type_association(String::new(), 0),
        Property::GroupFlag(GroupFlag::IsExpanded),
        Property::Time(TimeField::CreationTime),
        Property::PreviousParent,
        Property::CustomData(String::new()),
        Property::CustomDataModified(String::new()),
        Property::CustomIcon(Uuid::nil()),
        Property::CustomIconName(Uuid::nil()),
        Property::CustomIconModified(Uuid::nil()),
        Property::DeletedObject(Uuid::nil()),
        Property::history(history, Property::Name),
    ];
    let _ = [
        Shown::Text(String::new()),
        Shown::Sealed(fp),
        Shown::field(true, Value::Sealed(fp)),
        Shown::Bool(true),
        Shown::Int(-1),
        Shown::Uint(1),
        Shown::Time(Timestamp::from_unix(0).unwrap()),
        Shown::Uuid(Uuid::nil()),
        Shown::Color(Rgb { r: 0, g: 0, b: 0 }),
        Shown::Icon(Icon::Standard(0)),
        Shown::attachment(0, fp, false),
        Shown::blob(0, fp),
        Shown::Present,
        Shown::Format(FormatVersion::KDBX_4_1),
        Shown::Kdf(KdfKind::Argon2id),
        Shown::OuterCipher(OuterCipher::Aes256),
        Shown::InnerCipher(InnerCipher::ChaCha20),
        Shown::Compression(Compression::GZip),
        Shown::Obfuscation(AutoTypeObfuscation::None),
    ];
    let _ = [ColorRole::Foreground, ColorRole::Background];
    let _ = [
        AutoTypeKey::Enabled,
        AutoTypeKey::DefaultSequence,
        AutoTypeKey::DataTransferObfuscation,
    ];
    let _ = [
        GroupFlag::IsExpanded,
        GroupFlag::EnableAutoType,
        GroupFlag::EnableSearching,
        GroupFlag::DefaultAutoTypeSequence,
    ];
    assert_eq!(TimeField::ALL.len(), 7);
    let _ = [
        HeaderKey::Kdf,
        HeaderKey::KdfRounds,
        HeaderKey::KdfMemory,
        HeaderKey::KdfIterations,
        HeaderKey::KdfParallelism,
        HeaderKey::KdfVersion,
        HeaderKey::OuterCipher,
        HeaderKey::InnerCipher,
        HeaderKey::Compression,
    ];
    let _ = [
        MetaKey::Generator,
        MetaKey::DatabaseName,
        MetaKey::DatabaseNameChanged,
        MetaKey::DatabaseDescription,
        MetaKey::DatabaseDescriptionChanged,
        MetaKey::DefaultUserName,
        MetaKey::DefaultUserNameChanged,
        MetaKey::MaintenanceHistoryDays,
        MetaKey::Color,
        MetaKey::MasterKeyChanged,
        MetaKey::MasterKeyChangeRec,
        MetaKey::MasterKeyChangeForce,
        MetaKey::MemoryProtection(StandardField::Password),
        MetaKey::RecycleBinEnabled,
        MetaKey::RecycleBinUuid,
        MetaKey::RecycleBinChanged,
        MetaKey::EntryTemplatesGroup,
        MetaKey::EntryTemplatesGroupChanged,
        MetaKey::LastSelectedGroup,
        MetaKey::LastTopVisibleGroup,
        MetaKey::HistoryMaxItems,
        MetaKey::HistoryMaxSize,
        MetaKey::SettingsChanged,
    ];
}
