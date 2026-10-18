//! Snapshot builders shared by the unit tests.

use kdbx_core::fingerprint::{Fingerprint, FingerprintKey};
use kdbx_core::model::{
    Argon2Info, Argon2Variant, AttachmentInfo, AutoType, AutoTypeAssociation, AutoTypeObfuscation,
    Compression, CustomIconInfo, CustomValue, Entry, Field, FormatVersion, Group, HeaderInfo, Icon,
    InnerCipher, KdfInfo, MemoryProtection, Meta, OuterCipher, Rgb, Sealing, Snapshot, Times,
    Timestamp, Value,
};
use uuid::Uuid;

pub(crate) fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

pub(crate) fn t(secs: i64) -> Timestamp {
    Timestamp::from_unix(1_767_258_000 + secs).unwrap()
}

/// The fixed key every unit test seals with.
pub(crate) fn key() -> FingerprintKey {
    FingerprintKey::from_bytes([7; 32])
}

/// A field captured the way kdbx-core captures it under fingerprint
/// sealing.
pub(crate) fn sealed(name: &str, protected: bool, plaintext: &str) -> Field {
    Sealing::Fingerprint(&key()).field(name, protected, plaintext)
}

pub(crate) fn titled(n: u128, title: &str) -> Entry {
    Entry::new(id(n)).with_field("Title", Field::plain(title))
}

pub(crate) fn snapshot(root: Group) -> Snapshot {
    Snapshot::new(FormatVersion::KDBX_4_1, Meta::default(), root)
}

/// The shared starting vault:
///
/// ```text
/// Root (1)
/// ├── Personal (2)
/// │   ├── Bank (0x11)   UserName alice, Password sealed
/// │   └── Email (0x12)
/// └── Work (3)
///     └── VPN (0x13)
/// ```
pub(crate) fn base() -> Snapshot {
    let bank = titled(0x11, "Bank")
        .with_field("UserName", Field::plain("alice"))
        .with_field("Password", sealed("Password", true, "old-password"));
    let personal = Group::new(id(2), "Personal")
        .with_entry(bank)
        .with_entry(titled(0x12, "Email"));
    let work = Group::new(id(3), "Work").with_entry(titled(0x13, "VPN"));
    snapshot(
        Group::new(id(1), "Root")
            .with_group(personal)
            .with_group(work),
    )
}

pub(crate) fn group_mut(g: &mut Group, uuid: Uuid) -> Option<&mut Group> {
    if g.uuid == uuid {
        return Some(g);
    }
    g.groups.iter_mut().find_map(|c| group_mut(c, uuid))
}

pub(crate) fn entry_mut(g: &mut Group, uuid: Uuid) -> Option<&mut Entry> {
    if let Some(i) = g.entries.iter().position(|e| e.uuid == uuid) {
        return g.entries.get_mut(i);
    }
    g.groups.iter_mut().find_map(|c| entry_mut(c, uuid))
}

pub(crate) fn take_entry(g: &mut Group, uuid: Uuid) -> Option<Entry> {
    if let Some(i) = g.entries.iter().position(|e| e.uuid == uuid) {
        return Some(g.entries.remove(i));
    }
    g.groups.iter_mut().find_map(|c| take_entry(c, uuid))
}

pub(crate) fn take_group(g: &mut Group, uuid: Uuid) -> Option<Group> {
    if let Some(i) = g.groups.iter().position(|c| c.uuid == uuid) {
        return Some(g.groups.remove(i));
    }
    g.groups.iter_mut().find_map(|c| take_group(c, uuid))
}

// ---------------------------------------------------------------------------
// Maximal values: every model field set, no `null` anywhere in their JSON.

/// A fingerprint whose hex form contains digits (the leaf mutator bumps one).
pub(crate) fn fp(n: u8) -> Fingerprint {
    Fingerprint::from_bytes([n; 32])
}

pub(crate) fn full_times(base: i64) -> Times {
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
pub(crate) fn maximal_entry(uuid: Uuid, base: i64, with_history: bool) -> Entry {
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

pub(crate) fn maximal_group() -> Group {
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

pub(crate) fn maximal_snapshot() -> Snapshot {
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
