//! diff-kdbx: semantic diff for KeePass KDBX files.
//!
//! The library is a pure function of two [`kdbx_core`] snapshots: it names no
//! keepass type, performs no I/O, and builds for `wasm32-unknown-unknown`.
//! The `cli` feature adds the `diff-kdbx` binary (a standalone diff and a git
//! textconv driver), which opens files with keepass 0.15 and captures them
//! through `kdbx-core`.
//!
//! - [`compute`] compares two snapshots into a [`ChangeSet`]: one record per
//!   changed node (matched by UUID, a move is a field of the record), each
//!   listing the [`Property`] values that differ.
//! - [`dump`] renders one snapshot as stable, line-safe text for git's
//!   textconv. It prints exactly the properties `compute` diffs.
//! - [`render_text`] and [`render_json`] render a change set; the JSON shape
//!   is a contract versioned by [`JSON_FORMAT_VERSION`].
//!
//! Secrets never reach this crate in plaintext unless the caller asked: a
//! snapshot captured with `Sealing::Fingerprint` holds keyed fingerprints in
//! place of every secret (see [`kdbx_core::model::Sealing`]), and diff and
//! dump show those fingerprints (`<sealed:xxxxxxxx>`).
//!
//! ```
//! use diff_kdbx::kdbx_core::model::{Entry, Field, FormatVersion, Group, Meta, Snapshot};
//! use diff_kdbx::{DiffOptions, compute, render_text};
//! use uuid::Uuid;
//!
//! let vault = |url: &str| {
//!     let bank = Entry::new(Uuid::from_u128(2))
//!         .with_field("Title", Field::plain("Bank"))
//!         .with_field("URL", Field::plain(url));
//!     let root = Group::new(Uuid::from_u128(1), "Root").with_entry(bank);
//!     Snapshot::new(FormatVersion::KDBX_4_1, Meta::default(), root)
//! };
//! let cs = compute(&vault("https://a.example"), &vault("https://b.example"), &DiffOptions::default());
//! assert_eq!(cs.summary.entries_modified, 1);
//! assert!(render_text(&cs, &Default::default())
//!     .contains("~ ENTRY \"/Bank\"\n  ~ URL: \"https://a.example\" -> \"https://b.example\"\n"));
//! ```
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
pub use render::json::{FingerprintKeyInfo, JSON_FORMAT_VERSION, JsonOptions, render_json};
pub use render::text::{TextOptions, render_text};
