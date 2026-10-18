//! diff-kdbx: semantic diff for KeePass KDBX files.
//!
//! The library is a pure function of two [`kdbx_core`] snapshots: it names no
//! keepass type, performs no I/O, and builds for `wasm32-unknown-unknown`.
//! The `cli` feature adds the `diff-kdbx` binary, which opens files with
//! keepass 0.15 and captures them through `kdbx-core`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The vault model and shared rules this crate's API is expressed in.
pub use kdbx_core;

mod change_set;
mod compute;
mod dump;
mod nodes;
mod options;
mod properties;
mod render;
#[cfg(test)]
mod test_support;

pub use change_set::{
    Change, ChangeSet, DiffWarning, KdfWeakening, NodeChange, NodeStatus, PropertyChange, Summary,
};

pub use compute::compute;
pub use dump::dump;
pub use options::{DiffOptions, DumpOptions, Noise, RecycleBin};
pub use properties::{
    AutoTypeKey, ColorRole, FieldName, GroupFlag, HeaderKey, HistoryKey, KdfKind, MetaKey,
    Property, Shown, TimeField,
};

#[cfg(feature = "cli")]
#[doc(hidden)]
#[allow(missing_docs)]
pub mod legacy;
