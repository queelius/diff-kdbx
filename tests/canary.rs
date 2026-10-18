//! No fixture secret reaches any output. For every fixture pair, the
//! secrets are read from the vaults themselves (every field value that
//! `kdbx_core::visibility::is_secret` calls a secret, in entries and their
//! history, plus every attachment's content), with noise and the recycle bin
//! shown:
//!
//! - a vault's dump contains none of that vault's secrets, and
//! - the text diff and the JSON contain no secret of either side, except a
//!   value that one side holds as visible metadata (a field whose protection
//!   was turned off is shown on that side by design).

mod common;

use std::collections::BTreeSet;

use diff_kdbx::kdbx_core::capture::keepass_0_15::capture;
use diff_kdbx::kdbx_core::model::{Entry, Sealing, Value};
use diff_kdbx::kdbx_core::visibility::is_secret;
use diff_kdbx::{
    DiffOptions, DumpOptions, JsonOptions, Noise, RecycleBin, TextOptions, compute, dump,
    render_json, render_text,
};

fn open_db(relative: &str) -> keepass::Database {
    let mut file = std::fs::File::open(common::fixtures().join(relative)).unwrap();
    keepass::Database::open(
        &mut file,
        keepass::DatabaseKey::new().with_password(common::PW),
    )
    .unwrap()
}

/// A vault's secrets and its visible values, from a revealed capture and
/// the raw attachments. Very short strings would match by accident (fixture
/// secrets are long), so only strings of 6 or more bytes count.
fn secrets(db: &keepass::Database) -> (BTreeSet<String>, BTreeSet<String>) {
    let key = common::test_key();
    let snap = capture(db, &Sealing::Reveal(&key));
    let (mut out, mut visible) = (BTreeSet::new(), BTreeSet::new());
    let mut add_fields = |e: &Entry| {
        for (name, field) in &e.fields {
            if let Value::Plain(s) = &field.value {
                if is_secret(name, field.protected) {
                    out.insert(s.clone());
                } else {
                    visible.insert(s.clone());
                }
            }
        }
    };
    for e in snap.entries() {
        add_fields(e);
        e.history.iter().for_each(&mut add_fields);
    }
    for e in db.iter_all_entries() {
        for (_, att) in e.attachments_named() {
            out.insert(String::from_utf8_lossy(att.data.get()).into_owned());
        }
    }
    out.retain(|s| s.len() >= 6);
    (out, visible)
}

#[test]
fn no_fixture_secret_appears_in_any_output() {
    let mut checked = 0;
    for name in common::pairs() {
        let (a, b) = (
            open_db(&format!("{name}/before.kdbx")),
            open_db(&format!("{name}/after.kdbx")),
        );
        let ((secret_a, visible_a), (secret_b, visible_b)) = (secrets(&a), secrets(&b));
        let key = common::test_key();
        let seal = Sealing::Fingerprint(&key);
        let (sa, sb) = (capture(&a, &seal), capture(&b, &seal));
        let diff = DiffOptions::new(Noise::Show, RecycleBin::Include);
        let shown = DumpOptions::new(Noise::Show, RecycleBin::Include);
        let cs = compute(&sa, &sb, &diff);
        let mut check = |secrets: &BTreeSet<String>, out: &str| {
            for secret in secrets {
                assert!(
                    !out.contains(secret.as_str()),
                    "{name}: {secret:?} leaked:\n{out}"
                );
                checked += 1;
            }
        };
        check(
            &secret_a.difference(&visible_a).cloned().collect(),
            &dump(&sa, &shown),
        );
        check(
            &secret_b.difference(&visible_b).cloned().collect(),
            &dump(&sb, &shown),
        );
        let visible: BTreeSet<String> = visible_a.union(&visible_b).cloned().collect();
        let hidden: BTreeSet<String> = secret_a
            .union(&secret_b)
            .filter(|s| !visible.contains(*s))
            .cloned()
            .collect();
        check(&hidden, &render_text(&cs, &TextOptions::default()));
        check(&hidden, &render_json(&cs, &JsonOptions::default()));
    }
    assert!(checked >= 200, "only {checked} checks");
}
