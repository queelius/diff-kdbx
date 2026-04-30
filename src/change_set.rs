//! ChangeSet and friends: structured representation of a diff between two
//! KDBX databases.

use crate::mask::HashPrefix;
use crate::path::Path;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Display form of a single field value, after masking policy is applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValueDisplay {
    /// Unprotected field: show the raw value.
    Plain { value: String },
    /// Protected field: show only an 8-char SHA-256 hash prefix.
    Masked { hash: HashPrefix },
}

impl ValueDisplay {
    /// Construct a ValueDisplay according to the protected-flag and show-secrets policy.
    pub fn from_value(value: &str, protected: bool, show_secrets: bool) -> Self {
        if protected && !show_secrets {
            Self::Masked {
                hash: HashPrefix::of(value),
            }
        } else {
            Self::Plain {
                value: value.to_string(),
            }
        }
    }
}

/// A change to a single value: from one display to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueChange {
    pub from: ValueDisplay,
    pub to: ValueDisplay,
}

/// A single field-level change inside a modified entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldChange {
    /// A field that did not exist in `a` and exists in `b`.
    Added { name: String, value: ValueDisplay },
    /// A field that existed in `a` and does not exist in `b`.
    Removed { name: String, value: ValueDisplay },
    /// A field that exists in both with different content.
    Modified { name: String, change: ValueChange },
    /// A tag added to the entry.
    TagAdded { tag: String },
    /// A tag removed from the entry.
    TagRemoved { tag: String },
    /// Attachment with a given name was added.
    AttachmentAdded { name: String, hash: HashPrefix },
    /// Attachment was removed.
    AttachmentRemoved { name: String, hash: HashPrefix },
    /// Attachment with the same name has different content.
    AttachmentModified {
        name: String,
        from_hash: HashPrefix,
        to_hash: HashPrefix,
    },
    /// Per-entry history grew (entry was modified, previous state pushed).
    HistoryGrew { added: usize },
    /// Per-entry history shrank or non-prefix-extended (suspicious).
    HistoryRewritten { from_len: usize, to_len: usize },
}

/// Database-level metadata change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DatabaseChange {
    NameChanged {
        from: String,
        to: String,
    },
    ColorChanged {
        from: Option<String>,
        to: Option<String>,
    },
    RecycleBinChanged {
        from: Option<Uuid>,
        to: Option<Uuid>,
    },
    CustomDataModified {
        key: String,
        change: ValueChange,
    },
    CustomDataAdded {
        key: String,
        value: ValueDisplay,
    },
    CustomDataRemoved {
        key: String,
        value: ValueDisplay,
    },
}

/// Group-level change kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GroupChangeKind {
    Added,
    Removed,
    Moved { to: Path },
    Renamed { from: String, to: String },
    PropertiesChanged { fields: Vec<FieldChange> },
}

/// Entry-level change kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryChangeKind {
    Added,
    Removed,
    Moved { to: Path },
    Modified { fields: Vec<FieldChange> },
}

/// One change at any level of the KDBX hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum Change {
    Database(DatabaseChange),
    Group {
        uuid: Uuid,
        path: Path,
        kind: GroupChangeKind,
    },
    Entry {
        uuid: Uuid,
        path: Path,
        kind: EntryChangeKind,
    },
}

/// Counts of various change types. Rendered at the top of text output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub groups_added: usize,
    pub groups_removed: usize,
    pub groups_modified: usize,
    pub entries_added: usize,
    pub entries_removed: usize,
    pub entries_modified: usize,
    pub fields_changed: usize,
    pub attachments_changed: usize,
    pub history_changes: usize,
    pub metadata_changed: usize,
    /// Count of changes hidden by suppression policy.
    pub suppressed: usize,
}

/// Non-fatal observation surfaced from `compute`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiffWarning {
    /// The two databases use different KDBX versions.
    VersionMismatch { a: String, b: String },
    /// Hash collision in 8-char prefix detected (should be vanishingly rare).
    HashCollision {
        plaintext_a_hash_full: String,
        plaintext_b_hash_full: String,
    },
}

/// The top-level diff result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    pub changes: Vec<Change>,
    pub summary: Summary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<DiffWarning>,
}

impl ChangeSet {
    /// True iff there are no changes (warnings don't count).
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn value_display_plain_for_unprotected() {
        let d = ValueDisplay::from_value("foo", false, false);
        match d {
            ValueDisplay::Plain { value } => assert_eq!(value, "foo"),
            _ => panic!("expected Plain"),
        }
    }

    #[test]
    fn value_display_masked_for_protected() {
        let d = ValueDisplay::from_value("hunter2", true, false);
        match d {
            ValueDisplay::Masked { hash } => {
                assert_eq!(hash.0.len(), HashPrefix::LEN);
            }
            _ => panic!("expected Masked"),
        }
    }

    #[test]
    fn show_secrets_overrides_masking() {
        let d = ValueDisplay::from_value("hunter2", true, true);
        match d {
            ValueDisplay::Plain { value } => assert_eq!(value, "hunter2"),
            _ => panic!("expected Plain when show_secrets=true"),
        }
    }

    #[test]
    fn field_change_added_serializes() {
        let fc = FieldChange::Added {
            name: "Title".into(),
            value: ValueDisplay::Plain {
                value: "Chase".into(),
            },
        };
        let json = serde_json::to_string(&fc).unwrap();
        assert!(json.contains("\"kind\":\"added\""));
        assert!(json.contains("\"name\":\"Title\""));
    }

    #[test]
    fn field_change_modified_with_masked_value() {
        let fc = FieldChange::Modified {
            name: "Password".into(),
            change: ValueChange {
                from: ValueDisplay::Masked {
                    hash: HashPrefix::of("a"),
                },
                to: ValueDisplay::Masked {
                    hash: HashPrefix::of("b"),
                },
            },
        };
        let json = serde_json::to_string(&fc).unwrap();
        assert!(json.contains("\"kind\":\"modified\""));
        assert!(json.contains("\"masked\""));
    }

    #[test]
    fn empty_change_set_is_empty() {
        let cs = ChangeSet::default();
        assert!(cs.is_empty());
    }

    #[test]
    fn change_set_with_changes_is_not_empty() {
        let cs = ChangeSet {
            changes: vec![Change::Database(DatabaseChange::NameChanged {
                from: "old".into(),
                to: "new".into(),
            })],
            ..Default::default()
        };
        assert!(!cs.is_empty());
    }

    #[test]
    fn change_set_serializes_with_warnings_omitted_when_empty() {
        let cs = ChangeSet::default();
        let json = serde_json::to_string(&cs).unwrap();
        assert!(!json.contains("warnings"));
    }
}
