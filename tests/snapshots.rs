//! Pinned text, JSON and dump output for every committed fixture pair.
//!
//! The JSON snapshots pin the `format_version: 1` contract: a change to one
//! is a change to the documented shape and must be deliberate.

mod common;

use diff_kdbx::{DiffOptions, DumpOptions, JsonOptions, compute, dump, render_json, render_text};

#[test]
fn every_fixture_pair_renders_as_pinned() {
    let pairs = common::pairs();
    assert!(pairs.len() >= 11, "{pairs:?}");
    for name in pairs {
        let before = common::open(&format!("{name}/before.kdbx"));
        let after = common::open(&format!("{name}/after.kdbx"));
        let cs = compute(&before, &after, &DiffOptions::default());
        insta::assert_snapshot!(format!("{name}__text"), render_text(&cs));
        insta::assert_snapshot!(
            format!("{name}__json"),
            render_json(&cs, &JsonOptions::default())
        );
        insta::assert_snapshot!(
            format!("{name}__dump"),
            dump(&after, &DumpOptions::default())
        );
    }
}

#[test]
fn legacy_kdbx40_dump_is_pinned() {
    let snap = common::open("legacy_kdbx40/vault.kdbx");
    insta::assert_snapshot!(dump(&snap, &DumpOptions::default()));
}
