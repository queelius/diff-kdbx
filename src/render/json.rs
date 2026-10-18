//! The machine-readable rendering of a change set: a versioned JSON contract.

use kdbx_core::fingerprint::DeriveParams;
use uuid::Uuid;

use super::wire::Document;
use crate::change_set::ChangeSet;

/// The version of the JSON shape [`render_json`] emits. A change that breaks
/// a consumer of the shape bumps it.
pub const JSON_FORMAT_VERSION: u32 = 1;

/// Options for [`render_json`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct JsonOptions {
    /// How the fingerprint key was derived, recorded so a holder of the
    /// vault can reproduce every fingerprint in the output. `None` (emitted
    /// as `null`) when the key was not derived from the vault (a random
    /// per-session key, for example).
    pub fingerprint_key: Option<FingerprintKeyInfo>,
}

/// The inputs, other than the vault's key material, of the
/// `FingerprintKey::derive` call that produced a change set's fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FingerprintKeyInfo {
    /// The Argon2id parameters.
    pub params: DeriveParams,
    /// The salt: the root group UUID of the vault whose key material was
    /// used.
    pub salt: Uuid,
}

impl JsonOptions {
    /// Options recording how the fingerprint key was derived.
    pub fn with_fingerprint_key(info: FingerprintKeyInfo) -> Self {
        JsonOptions {
            fingerprint_key: Some(info),
        }
    }
}

impl FingerprintKeyInfo {
    /// The derivation inputs.
    pub fn new(params: DeriveParams, salt: Uuid) -> Self {
        FingerprintKeyInfo { params, salt }
    }
}

/// Render a change set as pretty-printed JSON:
///
/// ```json
/// {"format_version": 1, "fingerprint_key": null | {"params": {...}, "salt": "<uuid>"},
///  "changes": [...], "summary": {...}, "warnings": [...]}
/// ```
///
/// Fingerprints appear in full (64 hex characters). The shape is pinned by
/// snapshot tests and versioned by [`JSON_FORMAT_VERSION`].
pub fn render_json(cs: &ChangeSet, opts: &JsonOptions) -> String {
    let doc = Document::new(cs, opts.fingerprint_key.as_ref());
    let mut out = serde_json::to_string_pretty(&doc)
        .unwrap_or_else(|e| unreachable!("the wire document always serializes: {e}"));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use serde_json::{Value as Json, json};

    use super::*;

    #[test]
    fn document_shape() {
        let out = render_json(&ChangeSet::new(vec![], vec![], 3), &JsonOptions::default());
        let v: Json = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v,
            json!({
                "format_version": 1,
                "fingerprint_key": null,
                "changes": [],
                "summary": {
                    "entries_added": 0, "entries_removed": 0, "entries_modified": 0,
                    "entries_moved": 0, "groups_added": 0, "groups_removed": 0,
                    "groups_modified": 0, "groups_moved": 0, "node_properties": 0,
                    "database_properties": 0, "suppressed": 3
                },
                "warnings": []
            })
        );
        assert!(out.ends_with("}\n"));
    }

    #[test]
    fn fingerprint_key_is_recorded() {
        let opts = JsonOptions::with_fingerprint_key(FingerprintKeyInfo::new(
            DeriveParams::FLOOR,
            Uuid::from_u128(1),
        ));
        let v: Json = serde_json::from_str(&render_json(&ChangeSet::default(), &opts)).unwrap();
        assert_eq!(
            v["fingerprint_key"],
            json!({
                "params": {"memory_kib": 65536, "iterations": 3, "lanes": 1},
                "salt": "00000000-0000-0000-0000-000000000001"
            })
        );
    }
}
