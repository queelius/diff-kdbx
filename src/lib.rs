//! diff-kdbx: semantic diff for KeePass KDBX files.
//!
//! See the README and the design spec at
//! `docs/superpowers/specs/2026-04-27-diff-kdbx-design.md` for the full design.

pub mod change_set;
pub mod compute;
pub mod dump;
pub mod mask;
pub mod options;
pub mod path;
