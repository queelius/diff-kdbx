//! Snapshot builders shared by the unit tests.

use kdbx_core::fingerprint::FingerprintKey;
use kdbx_core::model::{Entry, Field, FormatVersion, Group, Meta, Sealing, Snapshot, Timestamp};
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
