//! Generates the canonical `.kdbx` fixture pairs for the integration tests.
//!
//! Run with:
//!   cargo run --features cli --bin gen-fixtures
//!
//! Each fixture is a directory `tests/fixtures/<name>/` holding `before.kdbx`
//! and `after.kdbx`. Master password for all of them: `test-password-do-not-use`.
//!
//! Content is reproducible: every group and entry has a fixed UUID and every
//! timestamp is fixed, so regenerating yields the same vault content (and the
//! same `--textconv` dumps). The encrypted bytes still differ between runs,
//! because KDBX draws fresh seeds and IVs on every save.
//!
//! Each `after` is built by cloning `before` and applying one realistic edit,
//! so entries stay matched by UUID the way they do when a vault is edited in a
//! KeePass client. Fixtures written by keepass 0.13+ are KDBX 4.1 (it cannot
//! save 4.0); `tests/fixtures/legacy_kdbx40/` is a frozen 4.0 file that this
//! generator does not touch. See `tests/fixtures/MANIFEST.md`.

use std::fs::{self, File};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use keepass::db::{EntryId, GroupId, Times, Value, fields};
use keepass::{Database, DatabaseKey};
use uuid::Uuid;

const MASTER: &str = "test-password-do-not-use";
const FIXTURES_ROOT: &str = "tests/fixtures";

// Fixed identities, `0000000n-d1ff-4000-8000-000000000000`. The varying part
// leads, because the dump's short tag is a UUID's first 8 hex digits and must
// tell entries apart; "d1ff" marks them as fixture IDs.
const fn id(n: u128) -> Uuid {
    Uuid::from_u128((n << 96) | 0x0000_0000_d1ff_4000_8000_0000_0000_0000)
}
const ROOT: GroupId = GroupId::from_uuid(id(0x01));
const PERSONAL: GroupId = GroupId::from_uuid(id(0x02));
const WORK: GroupId = GroupId::from_uuid(id(0x03));
const BANK: EntryId = EntryId::from_uuid(id(0x11));
const EMAIL: EntryId = EntryId::from_uuid(id(0x12));
const VPN: EntryId = EntryId::from_uuid(id(0x13));
const GITHUB: EntryId = EntryId::from_uuid(id(0x14));

/// When the base vault was "created", and when the edit in each `after` happened.
const CREATED: &str = "2026-01-01 09:00:00";
const EDITED: &str = "2026-02-01 09:00:00";

fn at(s: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").expect("valid fixture timestamp")
}

fn fixed_times(t: &str) -> Times {
    let mut times = Times::default();
    let when = at(t);
    times.creation = Some(when);
    times.last_modification = Some(when);
    times.last_access = Some(when);
    times.location_changed = Some(when);
    times.expiry = Some(when);
    times.expires = Some(false);
    times.usage_count = Some(0);
    times
}

fn key() -> DatabaseKey {
    DatabaseKey::new().with_password(MASTER)
}

/// The shared starting vault:
///
/// ```text
/// Root
/// ├── Personal
/// │   ├── Bank   (alice, protected Password "old-password", URL)
/// │   └── Email  (alice@example.com, protected Password, protected custom "otp")
/// └── Work
///     └── VPN    (alice, protected Password, URL)
/// ```
fn base() -> Result<Database> {
    let mut db = Database::new_with_root_id(ROOT);
    db.meta.database_name = Some("diff-kdbx fixture".into());
    {
        let mut root = db.root_mut();
        root.name = "Root".into();
        root.add_group_with_id(PERSONAL)?.name = "Personal".into();
        root.add_group_with_id(WORK)?.name = "Work".into();
    }
    {
        let mut personal = db.group_mut(PERSONAL).context("Personal group")?;
        let mut bank = personal.add_entry_with_id(BANK)?;
        bank.set_unprotected(fields::TITLE, "Bank");
        bank.set_unprotected(fields::USERNAME, "alice");
        bank.set_protected(fields::PASSWORD, "old-password");
        bank.set_unprotected(fields::URL, "https://bank.example");
    }
    {
        let mut personal = db.group_mut(PERSONAL).context("Personal group")?;
        let mut email = personal.add_entry_with_id(EMAIL)?;
        email.set_unprotected(fields::TITLE, "Email");
        email.set_unprotected(fields::USERNAME, "alice@example.com");
        email.set_protected(fields::PASSWORD, "mail-password");
        email.set_protected("otp", "otpauth://totp/Email?secret=JBSWY3DPEHPK3PXP");
    }
    {
        let mut work = db.group_mut(WORK).context("Work group")?;
        let mut vpn = work.add_entry_with_id(VPN)?;
        vpn.set_unprotected(fields::TITLE, "VPN");
        vpn.set_unprotected(fields::USERNAME, "alice");
        vpn.set_protected(fields::PASSWORD, "vpn-password");
        vpn.set_unprotected(fields::URL, "https://vpn.example");
    }
    freeze_all_times(&mut db, CREATED);
    Ok(db)
}

/// Pin every group's and entry's timestamps, so content is reproducible.
fn freeze_all_times(db: &mut Database, t: &str) {
    let groups: Vec<GroupId> = db.iter_all_groups().map(|g| g.id()).collect();
    for g in groups {
        if let Some(mut group) = db.group_mut(g) {
            group.times = fixed_times(t);
        }
    }
    let entries: Vec<EntryId> = db.iter_all_entries().map(|e| e.id()).collect();
    for e in entries {
        stamp(db, e, t);
    }
}

/// Pin one entry's timestamps, as a KeePass client does when it saves an edit.
fn stamp(db: &mut Database, e: EntryId, t: &str) {
    if let Some(mut entry) = db.entry_mut(e) {
        let created = entry.times.creation;
        entry.times = fixed_times(t);
        // An edit never changes when the entry was created.
        if created.is_some() {
            entry.times.creation = created;
        }
    }
}

fn save(db: &Database, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    db.save(&mut f, key())
        .with_context(|| format!("save {}", path.display()))?;
    Ok(())
}

/// Write `<name>/before.kdbx` and `<name>/after.kdbx`, where `after` is a
/// clone of `before` with `edit` applied.
fn pair(
    name: &str,
    before: Database,
    edit: impl FnOnce(&mut Database) -> Result<()>,
) -> Result<()> {
    let dir = Path::new(FIXTURES_ROOT).join(name);
    let mut after = before.clone();
    edit(&mut after).with_context(|| format!("build {name}/after"))?;
    save(&before, &dir.join("before.kdbx"))?;
    save(&after, &dir.join("after.kdbx"))?;
    println!("  {name}/");
    Ok(())
}

fn main() -> Result<()> {
    println!("Generating fixture pairs into {FIXTURES_ROOT}/ (password: {MASTER})");

    // No semantic difference: an empty vault and an identical clone.
    pair(
        "empty",
        {
            let mut db = Database::new_with_root_id(ROOT);
            db.root_mut().name = "Root".into();
            freeze_all_times(&mut db, CREATED);
            db
        },
        |_| Ok(()),
    )?;

    // A new entry appears in Work.
    pair("add_entry", base()?, |db| {
        let mut work = db.group_mut(WORK).context("Work group")?;
        let mut gh = work.add_entry_with_id(GITHUB)?;
        gh.set_unprotected(fields::TITLE, "GitHub");
        gh.set_unprotected(fields::USERNAME, "octocat");
        gh.set_protected(fields::PASSWORD, "gh-password");
        stamp(db, GITHUB, EDITED);
        Ok(())
    })?;

    // Bank's protected password changes: a masked Modified field.
    pair("password_change", base()?, |db| {
        db.entry_mut(BANK)
            .context("Bank")?
            .set_protected(fields::PASSWORD, "new-password");
        stamp(db, BANK, EDITED);
        Ok(())
    })?;

    // Email is deleted.
    pair("remove_entry", base()?, |db| {
        db.entry_mut(EMAIL).context("Email")?.remove();
        Ok(())
    })?;

    // VPN moves from Work to Personal, content unchanged.
    pair("move_entry", base()?, |db| {
        db.entry_mut(VPN).context("VPN")?.move_to(PERSONAL)?;
        Ok(())
    })?;

    // The Work group is renamed; its entries do not move.
    pair("rename_group", base()?, |db| {
        db.group_mut(WORK).context("Work group")?.name = "Office".into();
        Ok(())
    })?;

    // Bank gains a tag.
    pair("tag_diff", base()?, |db| {
        db.entry_mut(BANK)
            .context("Bank")?
            .tags
            .push("finance".into());
        stamp(db, BANK, EDITED);
        Ok(())
    })?;

    // Bank carries an attachment whose content changes, and gains a second one.
    pair(
        "attachment_change",
        {
            let mut db = base()?;
            db.entry_mut(BANK)
                .context("Bank")?
                .add_attachment("recovery.txt", Value::unprotected(b"codes-v1".to_vec()));
            db
        },
        |db| {
            let mut bank = db.entry_mut(BANK).context("Bank")?;
            bank.remove_attachment_by_name("recovery.txt");
            bank.add_attachment("recovery.txt", Value::unprotected(b"codes-v2".to_vec()));
            bank.add_attachment("statement.pdf", Value::unprotected(b"%PDF-1.7".to_vec()));
            stamp(db, BANK, EDITED);
            Ok(())
        },
    )?;

    // Email's protected custom `otp` field (a TOTP seed) is rotated.
    pair("custom_field", base()?, |db| {
        db.entry_mut(EMAIL)
            .context("Email")?
            .set_protected("otp", "otpauth://totp/Email?secret=KRSXG5CTMVRXEZLU");
        stamp(db, EMAIL, EDITED);
        Ok(())
    })?;

    // Bank's URL is edited with history tracking: the prior state is pushed
    // into the entry's history, as a KeePass client does on every edit.
    pair("history_grew", base()?, |db| {
        db.entry_mut(BANK)
            .context("Bank")?
            .edit_tracking(|e| e.set_unprotected(fields::URL, "https://bank.example/login"));
        stamp(db, BANK, EDITED);
        Ok(())
    })?;

    // Opened and re-saved without edits: only access time and usage count move.
    pair("noisy_resave", base()?, |db| {
        let ids: Vec<EntryId> = db.iter_all_entries().map(|e| e.id()).collect();
        for e in ids {
            let mut entry = db.entry_mut(e).context("entry")?;
            entry.times.last_access = Some(at(EDITED));
            entry.times.usage_count = Some(entry.times.usage_count.unwrap_or(0) + 1);
        }
        Ok(())
    })?;

    println!("Done.");
    Ok(())
}
