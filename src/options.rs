//! Options for diff and dump operations.

use serde::{Deserialize, Serialize};

/// Options for `compute`. Default suppresses noisy timestamps and masks secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffOptions {
    /// If true, do not suppress noisy fields (LastAccessTime, UsageCount, etc.).
    pub strict: bool,
    /// If true, ChangeSet contains plaintext for protected fields. Default false.
    pub show_secrets: bool,
    /// If true, include the recycle bin group and its descendants in the diff.
    /// Default false: the recycle bin is hidden from output.
    pub include_recycle_bin: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self { strict: false, show_secrets: false, include_recycle_bin: false }
    }
}

/// Options for `dump`. Default suppresses noisy timestamps and masks secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpOptions {
    pub strict: bool,
    pub show_secrets: bool,
    /// If true, include the recycle bin group and its descendants in the dump.
    /// Default false: the recycle bin is hidden from output.
    pub include_recycle_bin: bool,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self { strict: false, show_secrets: false, include_recycle_bin: false }
    }
}

/// Options for renderers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderOptions {
    /// Use ANSI color when rendering text. Default false.
    pub color: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self { color: false }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn diff_options_default() {
        let o = DiffOptions::default();
        assert!(!o.strict);
        assert!(!o.show_secrets);
        assert!(!o.include_recycle_bin);
    }

    #[test]
    fn dump_options_default() {
        let o = DumpOptions::default();
        assert!(!o.strict);
        assert!(!o.show_secrets);
        assert!(!o.include_recycle_bin);
    }

    #[test]
    fn render_options_default_no_color() {
        assert!(!RenderOptions::default().color);
    }
}
