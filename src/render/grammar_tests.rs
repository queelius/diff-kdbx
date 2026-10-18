//! The label and value grammar of the dump and the text diff, read back.
//!
//! Closed-set names (standard fields, typed keys) are bare; every
//! vault-controlled string printed next to renderer syntax (a custom field
//! name, the user part of a bracketed key, a plain single-line value, a node
//! path) is one `kdbx_core::text::quote` token. These tests scan rendered
//! lines back into label and value tokens and check that each probe string
//! comes back exactly, so no label or value can imitate another property, a
//! history item, a continuation line, `<sealed:...>`, a protection marker or
//! ` -> `.

use kdbx_core::model::{Field, Group};
use kdbx_core::text::unquote;

use crate::change_set::{Change, ChangeSet, NodeChange, NodeStatus, PropertyChange};
use crate::options::{DumpOptions, Noise, RecycleBin};
use crate::properties::{FieldName, Property, Shown};
use crate::render::text::{TextOptions, render_text};
use crate::test_support::*;
use crate::{DiffOptions, compute, dump};

/// A rendered line split at renderer syntax: the sign (diff only), the label
/// and the value tokens (two for a `~` change).
#[derive(Debug, PartialEq)]
struct Scanned {
    sign: Option<char>,
    label: String,
    values: Vec<String>,
}

/// Split `rest` at the first occurrence of `sep` outside quoted tokens and
/// brackets.
fn split_top(rest: &str, sep: &str) -> Option<(String, String)> {
    let (mut quoted, mut escaped, mut depth) = (false, false, 0usize);
    for (i, c) in rest.char_indices() {
        if quoted {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => quoted = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 && rest[i..].starts_with(sep) => {
                return Some((rest[..i].to_owned(), rest[i + sep.len()..].to_owned()));
            }
            _ => {}
        }
    }
    None
}

fn scan(line: &str, indent: &str) -> Scanned {
    let mut rest = line.strip_prefix(indent).expect("indented property line");
    let mut sign = None;
    for s in ['+', '-', '~'] {
        if let Some(r) = rest.strip_prefix(&format!("{s} ")) {
            sign = Some(s);
            rest = r;
        }
    }
    let Some((label, value)) = split_top(rest, ": ") else {
        return Scanned {
            sign,
            label: rest.trim_end_matches(':').to_owned(),
            values: vec![],
        };
    };
    let values = match split_top(&value, " -> ") {
        Some((a, b)) => vec![a, b],
        None => vec![value],
    };
    Scanned {
        sign,
        label,
        values,
    }
}

/// The text inside the first quoted token of `s` (after `prefix`).
fn first_token(s: &str, prefix: &str) -> String {
    let body = s
        .strip_prefix(prefix)
        .unwrap_or_else(|| panic!("{s:?} lacks {prefix:?}"));
    let end = (1..=body.len())
        .find(|&i| unquote(&body[..i]).is_ok())
        .unwrap_or_else(|| panic!("no quoted token in {body:?}"));
    unquote(&body[..end]).unwrap()
}

const PROBE_FIELDS: [&str; 4] = [
    "  | forged notes line",
    "History[2026-01-01T00:00:00Z].Password",
    "Password",
    "UserName: \"x\" -> \"y\"",
];
const PROBE_VALUES: [&str; 4] = ["<sealed:2668135c>", "a -> b", "x (protected)", "\"quoted\""];

fn probe_snapshot() -> kdbx_core::model::Snapshot {
    let mut bank = titled(0x11, "Bank (moved from \"/Work/x\")")
        .with_field("URL", Field::plain(PROBE_VALUES[0]))
        .with_field("UserName", Field::plain(PROBE_VALUES[1]))
        .with_field("Notes", Field::plain("first\n  UserName: \"forged\""));
    for (i, name) in PROBE_FIELDS.iter().enumerate().skip(1) {
        bank.fields
            .insert((*name).into(), Field::plain(PROBE_VALUES[i % 4]));
    }
    bank.fields
        .insert(PROBE_FIELDS[0].into(), Field::plain(PROBE_VALUES[2]));
    bank.tags.insert("a]b".into());
    bank.tags.insert("c\"] Tag[\"d".into());
    snapshot(Group::new(id(1), "Root").with_entry(bank))
}

#[test]
fn custom_field_labels_are_quoted_and_read_back() {
    let out = dump(&probe_snapshot(), &DumpOptions::default());
    let lines: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("    "))
        .collect();
    for name in PROBE_FIELDS.iter().filter(|n| **n != "Password") {
        let found: Vec<Scanned> = lines
            .iter()
            .map(|l| scan(l, "  "))
            .filter(|s| s.label.starts_with('"') && unquote(&s.label).as_deref() == Ok(*name))
            .collect();
        assert_eq!(
            found.len(),
            1,
            "custom field {name:?} not read back:\n{out}"
        );
    }
    // The standard Password is bare; a custom field named like a history
    // item is a quoted token, never a History label.
    assert!(lines.iter().all(|l| !l.starts_with("  History[")), "{out}");
    // No property line can pass for a continuation line.
    for l in out.lines().filter(|l| l.starts_with("    ")) {
        assert!(l.starts_with("    | "), "{l:?}");
    }
    assert!(
        out.contains("\n  Notes:\n    | first\n    |   UserName: \"forged\"\n"),
        "{out}"
    );
}

#[test]
fn plain_values_are_quoted_tokens() {
    let out = dump(&probe_snapshot(), &DumpOptions::default());
    let url = out.lines().find(|l| l.starts_with("  URL: ")).unwrap();
    let s = scan(url, "  ");
    assert_eq!(s.values.len(), 1, "{url}");
    assert_eq!(unquote(&s.values[0]).unwrap(), "<sealed:2668135c>");
    let user = out.lines().find(|l| l.starts_with("  UserName: ")).unwrap();
    let s = scan(user, "  ");
    assert_eq!(
        s.values.len(),
        1,
        "a value's ' -> ' is inside its token: {user}"
    );
    assert_eq!(unquote(&s.values[0]).unwrap(), "a -> b");
    // A real sealed value is bare renderer syntax.
    let sealed = dump(&base(), &DumpOptions::default());
    assert!(sealed.contains("\n  Password: <sealed:"), "{sealed}");
}

#[test]
fn bracketed_keys_quote_their_user_part() {
    let out = dump(&probe_snapshot(), &DumpOptions::default());
    let tags: Vec<String> = out
        .lines()
        .filter(|l| l.starts_with("  Tag["))
        .map(|l| first_token(l, "  Tag["))
        .collect();
    assert_eq!(tags, ["a]b", "c\"] Tag[\"d"], "{out}");
    for l in out.lines().filter(|l| l.starts_with("  Tag[")) {
        let s = scan(l, "  ");
        assert!(s.values.is_empty() && s.label.ends_with(']'), "{l}");
    }
}

#[test]
fn paths_are_quoted_tokens() {
    let snap = probe_snapshot();
    let out = dump(&snap, &DumpOptions::default());
    let header = out.lines().find(|l| l.starts_with("ENTRY ")).unwrap();
    let path = first_token(header, "ENTRY ");
    let parsed = kdbx_core::path::VaultPath::parse(&path).unwrap();
    assert_eq!(
        parsed.resolve_entry(&snap).unwrap().title(),
        Some("Bank (moved from \"/Work/x\")")
    );
    // In the diff, a title imitating a move stays inside the path token.
    let mut b = snap.clone();
    b.root.entries[0]
        .fields
        .insert("URL".into(), Field::plain("u"));
    let text = render_text(
        &compute(&snap, &b, &DiffOptions::default()),
        &TextOptions::default(),
    );
    let record = text.lines().find(|l| l.starts_with("~ ENTRY ")).unwrap();
    assert_eq!(first_token(record, "~ ENTRY "), path);
    assert!(!record.ends_with(')'), "no move is reported: {record}");
}

#[test]
fn diff_lines_read_back_with_both_sides() {
    let change = |name: &str, before: &str, after: &str| {
        PropertyChange::new(
            Property::Field(FieldName::new(name)),
            Some(Shown::field(
                false,
                kdbx_core::model::Value::Plain(before.into()),
            )),
            Some(Shown::field(
                false,
                kdbx_core::model::Value::Plain(after.into()),
            )),
        )
    };
    let cs = ChangeSet::new(
        vec![Change::Entry(NodeChange::new(
            id(1),
            None,
            NodeStatus::modified(
                None,
                vec![
                    change("URL", "a -> b", "<sealed:2668135c>"),
                    change(PROBE_FIELDS[1], "x (protected)", "\"q\" -> \"r\""),
                ],
            ),
        ))],
        vec![],
        0,
    );
    let out = render_text(&cs, &TextOptions::default());
    let lines: Vec<Scanned> = out
        .lines()
        .filter(|l| l.starts_with("  ~ "))
        .map(|l| scan(l, "  "))
        .collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert_eq!(lines[0].label, "URL");
    let unq = |v: &str| unquote(v).unwrap();
    assert_eq!(
        (unq(&lines[0].values[0]), unq(&lines[0].values[1])),
        ("a -> b".into(), "<sealed:2668135c>".into())
    );
    assert_eq!(unq(&lines[1].label), PROBE_FIELDS[1]);
    assert_eq!(
        (unq(&lines[1].values[0]), unq(&lines[1].values[1])),
        ("x (protected)".into(), "\"q\" -> \"r\"".into())
    );
}

#[test]
fn every_maximal_label_is_distinct_and_scans_whole() {
    let mut snap = maximal_snapshot();
    snap.root = snap.root.with_entry(maximal_entry(id(0x12), 0, true));
    let strict = DumpOptions::new(Noise::Show, RecycleBin::Exclude);
    let out = dump(&snap, &strict);
    let mut labels = std::collections::BTreeSet::new();
    let mut block = String::new();
    for line in out.lines() {
        if !line.starts_with(' ') {
            block = line.to_owned();
        } else if !line.starts_with("    | ") {
            let s = scan(line, "  ");
            assert!(s.values.len() <= 1, "{line}");
            assert!(
                labels.insert((block.clone(), s.label.clone())),
                "duplicate {line}"
            );
        }
    }
    assert!(labels.len() > 100);
}
