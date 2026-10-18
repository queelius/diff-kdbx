//! diff-kdbx: semantic diff for KeePass KDBX files.
//!
//! The library is a pure function of two [`kdbx_core`] snapshots: it names no
//! keepass type, performs no I/O, and builds for `wasm32-unknown-unknown`.
//! The `cli` feature adds the `diff-kdbx` binary, which opens files with
//! keepass 0.15 and captures them through `kdbx-core`.
#![forbid(unsafe_code)]

/// The vault model and shared rules this crate's API is expressed in.
pub use kdbx_core;

#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod legacy;
