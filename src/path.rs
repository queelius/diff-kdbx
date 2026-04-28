//! Path: a hierarchical location of a group or entry.
//!
//! Display form: slash-separated segments where `/` and control chars in
//! names are backslash-escaped (`\/`, `\n`, `\t`, `\\`).
//! Identity form: ordered list of ancestor UUIDs from root to this node (inclusive).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Path {
    /// Human-readable, escaped form.
    pub display: String,
    /// Ancestor chain UUIDs from root to this node (inclusive).
    pub uuids: Vec<Uuid>,
}

impl Path {
    /// Encode a name segment for display use.
    pub fn encode_segment(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '/' => out.push_str("\\/"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                ch if ch.is_control() => {
                    out.push_str(&format!("\\u{{{:04x}}}", ch as u32));
                }
                ch => out.push(ch),
            }
        }
        out
    }

    /// Build a Path by joining encoded name segments and UUIDs.
    pub fn from_segments(segments: &[&str], uuids: Vec<Uuid>) -> Self {
        let display = segments
            .iter()
            .map(|s| Self::encode_segment(s))
            .collect::<Vec<_>>()
            .join("/");
        let display = if display.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", display)
        };
        Self { display, uuids }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_plain_segment() {
        assert_eq!(Path::encode_segment("Banking"), "Banking");
    }

    #[test]
    fn encode_slash_in_segment() {
        assert_eq!(Path::encode_segment("Foo/Bar"), "Foo\\/Bar");
    }

    #[test]
    fn encode_backslash_in_segment() {
        assert_eq!(Path::encode_segment("Foo\\Bar"), "Foo\\\\Bar");
    }

    #[test]
    fn encode_newline_in_segment() {
        assert_eq!(Path::encode_segment("a\nb"), "a\\nb");
    }

    #[test]
    fn encode_control_char() {
        assert_eq!(Path::encode_segment("a\x07b"), "a\\u{0007}b");
    }

    #[test]
    fn from_segments_root() {
        let p = Path::from_segments(&[], vec![]);
        assert_eq!(p.display, "/");
        assert!(p.uuids.is_empty());
    }

    #[test]
    fn from_segments_nested() {
        let id1 = Uuid::nil();
        let id2 = Uuid::from_u128(1);
        let p = Path::from_segments(&["Banking", "Chase"], vec![id1, id2]);
        assert_eq!(p.display, "/Banking/Chase");
        assert_eq!(p.uuids, vec![id1, id2]);
    }

    #[test]
    fn from_segments_with_special_chars() {
        let p = Path::from_segments(&["A/B", "C"], vec![]);
        assert_eq!(p.display, "/A\\/B/C");
    }
}
