//! Secret masking: produce stable hash prefixes for protected fields.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 8-character lowercase-hex prefix of SHA-256(plaintext).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashPrefix(pub String);

impl HashPrefix {
    pub const LEN: usize = 8;

    /// Compute hash prefix over the UTF-8 NFC-normalized plaintext.
    /// Plaintext is treated as already-NFC; callers normalize if they care.
    pub fn of(plaintext: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(plaintext.as_bytes());
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
}
