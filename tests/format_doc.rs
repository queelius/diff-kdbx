//! docs/FORMAT.md's examples are real output: every line of a block marked
//! `<!-- checked: text -->` or `<!-- checked: dump -->` must be a line of the
//! format_tour pair's text diff or of its after side's dump.

mod common;

use diff_kdbx::{DiffOptions, DumpOptions, TextOptions, compute, dump, render_text};

/// The fenced blocks following each `<!-- checked: <kind> -->` marker.
fn checked_blocks(doc: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut lines = doc.lines();
    while let Some(line) = lines.next() {
        let Some(kind) = line
            .strip_prefix("<!-- checked: ")
            .and_then(|r| r.strip_suffix(" -->"))
        else {
            continue;
        };
        assert_eq!(lines.next(), Some("```text"), "a fence follows the marker");
        let body: Vec<String> = lines
            .by_ref()
            .take_while(|l| *l != "```")
            .map(str::to_owned)
            .collect();
        out.push((kind.to_owned(), body));
    }
    out
}

#[test]
fn every_documented_example_line_is_real_output() {
    let doc =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/FORMAT.md")).unwrap();
    let before = common::open("format_tour/before.kdbx");
    let after = common::open("format_tour/after.kdbx");
    let text = render_text(
        &compute(&before, &after, &DiffOptions::default()),
        &TextOptions::default(),
    );
    let dumped = dump(&after, &DumpOptions::default());
    let blocks = checked_blocks(&doc);
    assert_eq!(blocks.len(), 2, "one dump and one text example");
    for (kind, body) in blocks {
        let actual = match kind.as_str() {
            "text" => &text,
            "dump" => &dumped,
            other => panic!("unknown example kind {other}"),
        };
        assert!(body.len() > 10);
        for line in body {
            assert!(
                actual.lines().any(|l| l == line),
                "documented {kind} line {line:?} is not in the output:\n{actual}"
            );
        }
    }
}
