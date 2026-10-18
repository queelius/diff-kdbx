//! Secret masking: produce stable hash prefixes for protected fields.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// 8-character lowercase-hex prefix of SHA-256(plaintext).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashPrefix(pub String);

impl HashPrefix {
    pub const LEN: usize = 8;

    /// Compute hash prefix over UTF-8 NFC-normalized plaintext.
    ///
    /// Inputs in NFC and NFD that represent the same logical text hash
    /// identically. Without this step, a vault round-tripped through
    /// an editor that NFD-normalizes would produce false-positive
    /// Modified events on otherwise-unchanged Unicode strings.
    pub fn of(plaintext: &str) -> Self {
        let normalized: String = plaintext.nfc().collect();
        Self::of_bytes(normalized.as_bytes())
    }

    /// Compute hash prefix over arbitrary binary content.
    /// For pure-ASCII strings, `of_bytes(s.as_bytes())` equals `of(s)`.
    /// For non-ASCII text, prefer `of()` to get NFC normalization.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let hex = format!("{:x}", digest);
        Self(hex[..Self::LEN].to_string())
    }
}

impl std::fmt::Display for HashPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn known_vector_empty() {
        // SHA-256("") = e3b0c442 98fc1c14 ...
        let h = HashPrefix::of("");
        assert_eq!(h.0, "e3b0c442");
    }

    #[test]
    fn known_vector_hello() {
        // SHA-256("hello") = 2cf24dba 5fb0a30e ...
        let h = HashPrefix::of("hello");
        assert_eq!(h.0, "2cf24dba");
    }

    #[test]
    fn length_is_8() {
        let h = HashPrefix::of("any value here");
        assert_eq!(h.0.len(), HashPrefix::LEN);
    }

    #[test]
    fn deterministic() {
        let a = HashPrefix::of("password");
        let b = HashPrefix::of("password");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        let a = HashPrefix::of("password");
        let b = HashPrefix::of("Password");
        assert_ne!(a, b);
    }

    #[test]
    fn display_matches_inner() {
        let h = HashPrefix::of("hello");
        assert_eq!(format!("{}", h), "2cf24dba");
    }

    #[test]
    fn hash_prefix_of_bytes_matches_text_for_ascii() {
        let h_text = HashPrefix::of("hello");
        let h_bytes = HashPrefix::of_bytes(b"hello");
        assert_eq!(h_text, h_bytes);
    }

    #[test]
    fn nfc_and_nfd_hash_identically() {
        // U+00E9 (precomposed e-acute) vs U+0065 U+0301 (e + combining acute).
        // Same logical character, different byte sequences. NFC normalization
        // collapses them to the same hash.
        let nfc = HashPrefix::of("\u{00E9}");
        let nfd = HashPrefix::of("\u{0065}\u{0301}");
        assert_eq!(nfc, nfd);
    }
}
