//! The tree-shaped human-readable rendering of a change set.

use std::fmt::Write as _;

use kdbx_core::path::VaultPath;
use kdbx_core::text::continuation_lines;
use uuid::Uuid;

use super::{CONTINUATION, ValueText, kdf_name, path_token};
use crate::change_set::{
    Change, ChangeSet, DiffWarning, KdfWeakening, NodeChange, NodeStatus, PropertyChange, Summary,
};

/// Options for [`render_text`]. None yet; the parameter exists so options
/// can be added without breaking callers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TextOptions {}

/// Render a change set as text: a summary line, one `warning:` line per
/// warning, then one block per changed node (`+`, `-` or `~`, the kind, the
/// path) with one line per property change. Prints `(no changes)` when there
/// are none.
///
/// Every name and value is rendered through `kdbx_core::text` (inline
/// escapes, or `| ` continuation lines for multi-line values), so no vault
/// content can forge a structural line.
pub fn render_text(cs: &ChangeSet, _opts: &TextOptions) -> String {
    let mut out = String::new();
    summary(&cs.summary, &mut out);
    for w in &cs.warnings {
        let _ = writeln!(out, "warning: {}", warning(w));
    }
    if cs.changes.is_empty() {
        out.push_str("(no changes)\n");
    }
    for change in &cs.changes {
        match change {
            Change::Database { changes } => {
                out.push_str("DATABASE\n");
                properties(changes, &mut out);
            }
            Change::Group(node) => record("GROUP", node, &mut out),
            Change::Entry(node) => record("ENTRY", node, &mut out),
        }
    }
    out
}

fn summary(s: &Summary, out: &mut String) {
    let _ = writeln!(
        out,
        "summary: entries +{}/-{}/~{} ({} moved), groups +{}/-{}/~{} ({} moved), \
         properties {}, database {}, suppressed {}",
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
    );
}

fn warning(w: &DiffWarning) -> String {
    match w {
        DiffWarning::VersionMismatch { before, after } => {
            format!("KDBX version differs: {before} -> {after}")
        }
        DiffWarning::KdfWeakened { weakening } => {
            let how = match weakening {
                KdfWeakening::NoLongerMemoryHard { before, after } => format!(
                    "{} replaced by {}, which is not memory-hard",
                    kdf_name(*before),
                    kdf_name(*after)
                ),
                KdfWeakening::Unrecognized { before } => {
                    format!("{} replaced by an unrecognized KDF", kdf_name(*before))
                }
                KdfWeakening::MemoryLowered { before, after } => {
                    format!("memory lowered from {before} to {after} bytes")
                }
                KdfWeakening::IterationsLowered { before, after } => {
                    format!("iterations lowered from {before} to {after}")
                }
                KdfWeakening::RoundsLowered { before, after } => {
                    format!("rounds lowered from {before} to {after}")
                }
            };
            format!("KDF weakened: {how}")
        }
    }
}

/// A node's address in the diff: its path, or its UUID when it has none.
fn address(path: Option<&VaultPath>, uuid: Uuid) -> String {
    match path {
        Some(p) => path_token(p),
        None => format!("(no path) [uuid:{uuid}]"),
    }
}

fn record(keyword: &str, node: &NodeChange, out: &mut String) {
    let at = address(node.path.as_ref(), node.uuid);
    match &node.status {
        NodeStatus::Added => {
            let _ = writeln!(out, "+ {keyword} {at}");
        }
        NodeStatus::Removed => {
            let _ = writeln!(out, "- {keyword} {at}");
        }
        NodeStatus::Modified {
            moved_from,
            changes,
        } => {
            let _ = write!(out, "~ {keyword} {at}");
            if let Some(from) = moved_from {
                let _ = write!(out, " (moved from {})", path_token(from));
            }
            out.push('\n');
            properties(changes, out);
        }
    }
}

fn properties(changes: &[PropertyChange], out: &mut String) {
    for c in changes {
        let label = c.property.to_string();
        match (&c.before, &c.after) {
            (None, Some(v)) => ValueText::of(&c.property, v).write(out, "  ", "+ ", &label),
            (Some(v), None) => ValueText::of(&c.property, v).write(out, "  ", "- ", &label),
            (Some(a), Some(b)) => modified(
                &label,
                ValueText::of(&c.property, a),
                ValueText::of(&c.property, b),
                out,
            ),
            (None, None) => {}
        }
    }
}

/// A modified property: `~ label: before -> after` on one line, or, when
/// either side is multi-line text, a `~ label:` line followed by the before
/// lines (`-`) and the after lines (`+`).
fn modified(label: &str, before: ValueText<'_>, after: ValueText<'_>, out: &mut String) {
    if before.block.is_none() && after.block.is_none() {
        let _ = writeln!(out, "  ~ {label}: {} -> {}", before.inline, after.inline);
        return;
    }
    let _ = writeln!(out, "  ~ {label}:");
    for (sign, side) in [("-", before), ("+", after)] {
        let lead = format!("      {sign} ");
        if !side.inline.is_empty() {
            let _ = writeln!(out, "{lead}{}", side.inline);
        }
        if let Some(text) = side.block {
            let prefix = format!("{lead}{CONTINUATION}");
            for line in continuation_lines(text, &prefix) {
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use kdbx_core::model::{FormatVersion, Value};

    use super::*;
    use crate::properties::{FieldName, KdfKind, Property, Shown};

    fn path(s: &str) -> Option<VaultPath> {
        Some(VaultPath::parse(s).unwrap())
    }

    fn field(name: &str) -> Property {
        Property::Field(FieldName::new(name))
    }

    fn plain(s: &str) -> Option<Shown> {
        Some(Shown::Field {
            protected: false,
            value: Value::Plain(s.into()),
        })
    }

    fn sealed(n: u8) -> Option<Shown> {
        Some(Shown::Field {
            protected: true,
            value: Value::Sealed(kdbx_core::fingerprint::Fingerprint::from_bytes([n; 32])),
        })
    }

    fn entry(n: u128, p: &str, status: NodeStatus) -> Change {
        Change::Entry(NodeChange::new(Uuid::from_u128(n), path(p), status))
    }

    #[test]
    fn empty_change_set() {
        assert_eq!(
            render_text(&ChangeSet::new(vec![], vec![], 6), &TextOptions::default()),
            "summary: entries +0/-0/~0 (0 moved), groups +0/-0/~0 (0 moved), \
             properties 0, database 0, suppressed 6\n(no changes)\n"
        );
    }

    #[test]
    fn full_rendering_is_pinned() {
        let cs = ChangeSet::new(
            vec![
                Change::Database {
                    changes: vec![PropertyChange::new(
                        Property::Meta(crate::MetaKey::DatabaseName),
                        Some(Shown::Text("Old".into())),
                        Some(Shown::Text("New".into())),
                    )],
                },
                Change::Group(NodeChange::new(
                    Uuid::from_u128(3),
                    path("/Office/"),
                    NodeStatus::Modified {
                        moved_from: None,
                        changes: vec![PropertyChange::new(
                            Property::Name,
                            Some(Shown::Text("Work".into())),
                            Some(Shown::Text("Office".into())),
                        )],
                    },
                )),
                entry(0x14, "/Office/GitHub", NodeStatus::Added),
                entry(0x12, "/Personal/Email", NodeStatus::Removed),
                entry(
                    0x13,
                    "/Personal/VPN",
                    NodeStatus::Modified {
                        moved_from: path("/Office/VPN"),
                        changes: vec![
                            PropertyChange::new(field("Password"), sealed(0x12), sealed(0x34)),
                            PropertyChange::new(field("Notes"), plain("a\nb"), plain("a\nc")),
                            PropertyChange::new(
                                Property::Tag("vpn".into()),
                                None,
                                Some(Shown::Present),
                            ),
                            PropertyChange::new(field("otp"), sealed(0x56), None),
                        ],
                    },
                ),
                Change::Entry(NodeChange::new(
                    Uuid::from_u128(0x15),
                    None,
                    NodeStatus::Added,
                )),
            ],
            vec![
                DiffWarning::VersionMismatch {
                    before: FormatVersion::KDBX_4_0,
                    after: FormatVersion::KDBX_4_1,
                },
                DiffWarning::KdfWeakened {
                    weakening: KdfWeakening::NoLongerMemoryHard {
                        before: KdfKind::Argon2d,
                        after: KdfKind::AesKdf,
                    },
                },
            ],
            0,
        );
        assert_eq!(
            render_text(&cs, &TextOptions::default()),
            r#"summary: entries +2/-1/~1 (1 moved), groups +0/-0/~1 (0 moved), properties 5, database 1, suppressed 0
warning: KDBX version differs: 4.0 -> 4.1
warning: KDF weakened: Argon2d replaced by AES-KDF, which is not memory-hard
DATABASE
  ~ DatabaseName: "Old" -> "New"
~ GROUP "/Office/"
  ~ Name: "Work" -> "Office"
+ ENTRY "/Office/GitHub"
- ENTRY "/Personal/Email"
~ ENTRY "/Personal/VPN" (moved from "/Office/VPN")
  ~ Password: <sealed:12121212> -> <sealed:34343434>
  ~ Notes:
      - | a
      - | b
      + | a
      + | c
  + Tag["vpn"]
  - "otp": <sealed:56565656>
+ ENTRY (no path) [uuid:00000000-0000-0000-0000-000000000015]
"#
        );
    }

    #[test]
    fn protection_toggles_are_visible() {
        let unprotected = Some(Shown::Field {
            protected: false,
            value: Value::Sealed(kdbx_core::fingerprint::Fingerprint::from_bytes([0x12; 32])),
        });
        let cs = ChangeSet::new(
            vec![entry(
                1,
                "/x",
                NodeStatus::Modified {
                    moved_from: None,
                    changes: vec![
                        PropertyChange::new(field("Password"), sealed(0x12), unprotected),
                        PropertyChange::new(
                            field("Title"),
                            plain("Bank"),
                            Some(Shown::Field {
                                protected: true,
                                value: Value::Plain("Bank".into()),
                            }),
                        ),
                    ],
                },
            )],
            vec![],
            0,
        );
        let out = render_text(&cs, &TextOptions::default());
        assert!(
            out.contains("  ~ Password: <sealed:12121212> -> <sealed:12121212> (unprotected)\n"),
            "{out}"
        );
        assert!(
            out.contains("  ~ Title: \"Bank\" -> \"Bank\" (protected)\n"),
            "{out}"
        );
    }

    #[test]
    fn kdf_warnings_render() {
        let w = |weakening| warning(&DiffWarning::KdfWeakened { weakening });
        assert_eq!(
            w(KdfWeakening::MemoryLowered {
                before: 2,
                after: 1
            }),
            "KDF weakened: memory lowered from 2 to 1 bytes"
        );
        assert_eq!(
            w(KdfWeakening::Unrecognized {
                before: KdfKind::Argon2id
            }),
            "KDF weakened: Argon2id replaced by an unrecognized KDF"
        );
        assert_eq!(
            w(KdfWeakening::IterationsLowered {
                before: 3,
                after: 2
            }),
            "KDF weakened: iterations lowered from 3 to 2"
        );
        assert_eq!(
            w(KdfWeakening::RoundsLowered {
                before: 9,
                after: 8
            }),
            "KDF weakened: rounds lowered from 9 to 8"
        );
    }
}
