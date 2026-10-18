//! Options for [`compute`](crate::compute) and [`dump`](crate::dump).
//!
//! Both take the same two choices with the same meaning, so `--strict` and
//! `--include-recycle-bin` behave identically in diff and dump mode. Whether
//! secrets are revealed is not an option here: it is decided when the
//! snapshot is captured (`kdbx_core::model::Sealing`).

/// Whether noise (see [`Property::is_noise`](crate::Property::is_noise)) is
/// shown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Noise {
    /// Leave noise out (count it in [`Summary::suppressed`](crate::Summary)).
    #[default]
    Suppress,
    /// Show everything (`--strict`).
    Show,
}

/// Whether the recycle bin group and its subtree are shown.
///
/// The recycle bin is the group named by `<Meta><RecycleBinUUID>`. A
/// recycle-bin UUID that names the root group is ignored: excluding the root
/// would hide the whole vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum RecycleBin {
    /// Leave the recycle bin out.
    #[default]
    Exclude,
    /// Show it (`--include-recycle-bin`).
    Include,
}

/// Options for [`compute`](crate::compute).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DiffOptions {
    /// Whether noise is shown.
    pub noise: Noise,
    /// Whether the recycle bin is shown.
    pub recycle_bin: RecycleBin,
}

/// Options for [`dump`](crate::dump).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DumpOptions {
    /// Whether noise is shown.
    pub noise: Noise,
    /// Whether the recycle bin is shown.
    pub recycle_bin: RecycleBin,
}

impl DiffOptions {
    /// Options with both choices given.
    pub fn new(noise: Noise, recycle_bin: RecycleBin) -> Self {
        DiffOptions { noise, recycle_bin }
    }
}

impl DumpOptions {
    /// Options with both choices given.
    pub fn new(noise: Noise, recycle_bin: RecycleBin) -> Self {
        DumpOptions { noise, recycle_bin }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_suppress_noise_and_exclude_the_recycle_bin() {
        assert_eq!(
            DiffOptions::default(),
            DiffOptions::new(Noise::Suppress, RecycleBin::Exclude)
        );
        assert_eq!(
            DumpOptions::default(),
            DumpOptions::new(Noise::Suppress, RecycleBin::Exclude)
        );
    }
}
