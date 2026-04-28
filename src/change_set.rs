//! ChangeSet and friends: structured representation of a diff between two
//! KDBX databases.

use crate::mask::HashPrefix;
use serde::{Deserialize, Serialize};

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
            Self::Masked { hash: HashPrefix::of(value) }
        } else {
            Self::Plain { value: value.to_string() }
        }
    }
}

/// A change to a single value: from one display to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueChange {
    pub from: ValueDisplay,
    pub to: ValueDisplay,
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
}
