use std::collections::BTreeMap;

use kdbx_core::model::{Entry, Field, Group, Meta, Snapshot};

use super::*;
use crate::change_set::{Change, NodeStatus, PropertyChange};
use crate::options::RecycleBin;
use crate::test_support::*;
use crate::{DiffOptions, compute};

fn strict() -> DumpOptions {
    DumpOptions::new(Noise::Show, RecycleBin::Exclude)
}

/// The dump split into blocks: structural line -> its property lines.
fn blocks(dump: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = None;
    for line in dump.lines() {
        if line.starts_with(' ') {
            let header: &String = current.as_ref().expect("property line before any block");
            out.get_mut(header).unwrap().push(line.to_owned());
        } else {
            assert!(
                out.insert(line.to_owned(), Vec::new()).is_none(),
                "duplicate {line}"
            );
            current = Some(line.to_owned());
        }
    }
    out
}

#[test]
fn small_vault_dump_is_pinned() {
    let mut snap = snapshot(
        Group::new(id(1), "Root").with_entry(
            titled(0x11, "Bank")
                .with_field("Password", sealed("Password", true, "pw"))
                .with_field("Notes", Field::plain("first\nsecond")),
        ),
    );
    snap.meta.database_name = Some("Vault".into());
    snap.root.entries[0].times.usage_count = Some(4);
    let fp = key().fingerprint(kdbx_core::fingerprint::Domain::Field, b"pw");
    let expected = format!(
        "DATABASE
  Version: 4.1
  DatabaseName: Vault
GROUP / [uuid:00000000-0000-0000-0000-000000000001]
  Name: Root
  IsExpanded: true
ENTRY /Bank [uuid:00000000-0000-0000-0000-000000000011]
  Title: Bank
  Password: <sealed:{}>
  Notes:
    | first
    | second
  QualityCheck: true
",
        fp.short()
    );
    // IsExpanded is noise: only --strict shows it.
    assert_eq!(
        dump(&snap, &strict()).replace("  UsageCount: 4\n", ""),
        expected
    );
    assert_eq!(
        dump(&snap, &DumpOptions::default()),
        expected.replace("  IsExpanded: true\n", "")
    );
}

#[test]
fn every_property_compute_can_report_appears_in_the_dump() {
    let mut maximal = maximal_snapshot();
    maximal.root = Group::new(id(1), "Root")
        .with_group(maximal_group().with_entry(maximal_entry(id(0x11), 0, true)))
        .with_entry(maximal_entry(id(0x12), 50, true));
    // The same nodes with nothing set: every property of `maximal` is an
    // addition.
    let bare = Snapshot::new(
        maximal.format,
        Meta::default(),
        Group::new(id(1), "Root")
            .with_group(Group::new(id(2), "Web 1").with_entry(Entry::new(id(0x11))))
            .with_entry(Entry::new(id(0x12))),
    );
    let cs = compute(
        &bare,
        &maximal,
        &DiffOptions::new(Noise::Show, RecycleBin::Exclude),
    );
    let dumped = blocks(&dump(&maximal, &strict()));
    let mut checked = 0;
    for change in &cs.changes {
        let (header, changes): (String, &[PropertyChange]) = match change {
            Change::Database { changes } => ("DATABASE".into(), changes),
            Change::Group(n) | Change::Entry(n) => {
                let keyword = if matches!(change, Change::Group(_)) {
                    "GROUP"
                } else {
                    "ENTRY"
                };
                let NodeStatus::Modified { changes, .. } = &n.status else {
                    panic!("{n:?}");
                };
                (
                    format!("{keyword} {}", address(n.path.as_ref(), n.uuid)),
                    changes,
                )
            }
        };
        let lines = dumped
            .get(&header)
            .unwrap_or_else(|| panic!("no block {header}"));
        for c in changes.iter().filter(|c| c.after.is_some()) {
            let label = format!("  {}", c.property);
            assert!(
                lines
                    .iter()
                    .any(|l| l == &label || l.starts_with(&format!("{label}:"))),
                "{header}: {label} is diffed but not dumped"
            );
            checked += 1;
        }
    }
    assert!(checked > 150, "only {checked} properties checked");
}

#[test]
fn values_cannot_forge_structural_lines() {
    let evil = "x\n+ ENTRY /forged\nGROUP /forged/\nENTRY /forged [uuid:0]";
    let mut entry = titled(0x11, evil)
        .with_field("Notes", Field::plain(evil))
        .with_field(evil, Field::plain(evil));
    entry.tags.insert(evil.into());
    entry.override_url = Some(evil.into());
    let mut snap = snapshot(
        Group::new(id(1), evil)
            .with_group(Group::new(id(2), evil))
            .with_entry(entry),
    );
    snap.meta.database_description = Some(evil.into());
    snap.meta.database_name = Some(evil.into());
    let out = dump(&snap, &strict());
    let structural: Vec<&str> = out.lines().filter(|l| !l.starts_with(' ')).collect();
    assert_eq!(
        structural.len(),
        4,
        "DATABASE, two groups, one entry:\n{out}"
    );
    assert!(structural.iter().all(|l| {
        ["DATABASE", "GROUP ", "ENTRY "]
            .iter()
            .any(|k| l.starts_with(k))
    }));
    assert!(!out.contains("\n+ ENTRY"), "{out}");
    for line in out.lines().filter(|l| l.starts_with("    ")) {
        assert!(
            line.starts_with("    | "),
            "continuation without prefix: {line:?}"
        );
    }
    assert!(
        out.contains("    | + ENTRY /forged"),
        "Notes stay line-diffable:\n{out}"
    );
}

#[test]
fn secrets_are_sealed_and_the_title_is_an_address() {
    let mut snap = base();
    entry_mut(&mut snap.root, id(0x11))
        .unwrap()
        .fields
        .insert("Title".into(), sealed("Title", true, "Bank"));
    let out = dump(&snap, &DumpOptions::default());
    assert!(!out.contains("old-password"), "{out}");
    assert!(out.contains("  Password: <sealed:"), "{out}");
    assert!(out.contains("ENTRY /Personal/Bank "), "{out}");
    assert!(out.contains("  Title: Bank (protected)"), "{out}");
}

#[test]
fn noise_is_shown_only_in_strict_mode() {
    let mut snap = base();
    let e = entry_mut(&mut snap.root, id(0x11)).unwrap();
    e.times.last_access = Some(t(1));
    e.times.creation = Some(t(0));
    let default = dump(&snap, &DumpOptions::default());
    assert!(default.contains("  CreationTime: 2026-01-01T09:00:00Z"));
    assert!(!default.contains("LastAccessTime"));
    assert!(dump(&snap, &strict()).contains("  LastAccessTime: 2026-01-01T09:00:01Z"));
}

#[test]
fn recycle_bin_is_hidden_by_default_and_shown_on_request() {
    let mut snap = base();
    snap.root
        .groups
        .push(Group::new(id(0x50), "Recycle Bin").with_entry(titled(0x51, "Trashed")));
    snap.meta.recycle_bin = Some(id(0x50));
    let default = dump(&snap, &DumpOptions::default());
    assert!(!default.contains("Trashed") && !default.contains("GROUP /Recycle Bin/"));
    assert!(default.contains("ENTRY /Personal/Bank"));
    let shown = dump(
        &snap,
        &DumpOptions::new(Noise::Suppress, RecycleBin::Include),
    );
    assert!(shown.contains("GROUP /Recycle Bin/ "));
    assert!(shown.contains("ENTRY /Recycle Bin/Trashed "));
    // A recycle-bin UUID naming the root hides nothing.
    snap.meta.recycle_bin = Some(id(1));
    assert!(dump(&snap, &DumpOptions::default()).contains("ENTRY /Recycle Bin/Trashed "));
}

#[test]
fn custom_fields_and_attachments_are_dumped() {
    let mut snap = base();
    let e = entry_mut(&mut snap.root, id(0x11)).unwrap();
    e.fields.insert("ApiKey".into(), Field::plain("key-1"));
    e.fields
        .insert("otp".into(), sealed("otp", true, "otpauth://x"));
    e.attachments.insert(
        "recovery.txt".into(),
        kdbx_core::model::Sealing::Fingerprint(&key()).attachment(b"codes", false),
    );
    let out = dump(&snap, &DumpOptions::default());
    assert!(out.contains("  ApiKey: key-1"), "{out}");
    assert!(out.contains("  otp: <sealed:"), "{out}");
    assert!(
        out.contains("  Attachment[recovery.txt]: <sealed:"),
        "{out}"
    );
    assert!(out.contains(" (5 bytes)"), "{out}");
}

#[test]
fn nodes_are_in_tree_order_with_same_named_siblings_by_uuid() {
    let mut snap = base();
    snap.root.entries.push(titled(0x31, "Dup"));
    snap.root.entries.push(titled(0x30, "Dup"));
    let out = dump(&snap, &DumpOptions::default());
    let headers: Vec<&str> = out
        .lines()
        .filter(|l| !l.starts_with(' '))
        .map(|l| l.split(" [uuid:").next().unwrap())
        .collect();
    assert_eq!(
        headers,
        [
            "DATABASE",
            "GROUP /",
            "ENTRY /Dup",
            "ENTRY /Dup:2",
            "GROUP /Personal/",
            "ENTRY /Personal/Bank",
            "ENTRY /Personal/Email",
            "GROUP /Work/",
            "ENTRY /Work/VPN",
        ]
    );
    assert!(out.contains("ENTRY /Dup [uuid:00000000-0000-0000-0000-000000000030]"));
    assert_eq!(
        out,
        dump(&snap.clone(), &DumpOptions::default()),
        "byte-stable"
    );
}

#[test]
fn an_empty_value_keeps_its_colon() {
    let snap = snapshot(Group::new(id(1), "").with_entry(titled(0x11, "")));
    let out = dump(&snap, &DumpOptions::default());
    assert!(out.contains("\n  Name:\n"), "{out}");
    assert!(out.contains("\n  Title:\n"), "{out}");
    assert!(out.contains("ENTRY (no path) [uuid:"), "{out}");
}
