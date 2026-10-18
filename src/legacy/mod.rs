//! The keepass-typed engine of the unpublished 0.2 candidate.
//!
//! Transitional: kept compiling under the `cli` feature only while the
//! snapshot-based modules replace it task by task. Removed when the CLI is
//! ported to the new API.

pub mod change_set;
pub mod compute;
pub mod dump;
pub mod mask;
pub mod options;
pub mod path;
pub mod render;
