//! Pinned text, JSON and dump output for every committed fixture pair.
//!
//! The JSON snapshots pin the `format_version: 1` contract: a change to one
//! is a change to the documented shape and must be deliberate.

mod common;

use diff_kdbx::{
    DiffOptions, DumpOptions, JsonOptions, TextOptions, compute, dump, render_json, render_text,
};

#[test]
fn every_fixture_pair_renders_as_pinned() {
    let pairs = common::pairs();
    assert!(pairs.len() >= 11, "{pairs:?}");
    for name in pairs {
        let before = common::open(&format!("{name}/before.kdbx"));
        let after = common::open(&format!("{name}/after.kdbx"));
        let cs = compute(&before, &after, &DiffOptions::default());
        insta::assert_snapshot!(
            format!("{name}__text"),
            render_text(&cs, &TextOptions::default())
        );
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

/// The equivalent of `git diff --check` over every rendering of every
/// fixture: no line ends in whitespace and none carries a carriage return.
#[test]
fn no_output_line_ends_in_whitespace() {
    use diff_kdbx::{Noise, RecycleBin};
    let diff = DiffOptions::new(Noise::Show, RecycleBin::Include);
    let shown = DumpOptions::new(Noise::Show, RecycleBin::Include);
    for name in common::pairs() {
        let before = common::open(&format!("{name}/before.kdbx"));
        let after = common::open(&format!("{name}/after.kdbx"));
        let cs = compute(&before, &after, &diff);
        for out in [
            render_text(&cs, &TextOptions::default()),
            render_json(&cs, &JsonOptions::default()),
            dump(&before, &shown),
            dump(&after, &shown),
        ] {
            for line in out.lines() {
                assert!(
                    line == line.trim_end() && !line.contains('\r'),
                    "{name}: trailing whitespace in {line:?}"
                );
            }
        }
    }
}
