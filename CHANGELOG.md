# Changelog

All notable changes to diff-kdbx. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump may break the
library API).

The 0.1 and 0.2 lines differ in the `keepass` crate they build against, and
`keepass` types appear in diff-kdbx's public API (`compute(&Database, ...)`). A
caller must use the same `keepass` version as the diff-kdbx line it picks:
0.1.x for `keepass` 0.12, 0.2.x for `keepass` 0.15.

## [0.2.0] - unreleased

### Changed
- Builds against `keepass` 0.15.3 (was 0.12). Reads KDBX 4.1 as well as 4.0.
- Minimum supported Rust version is 1.89 (required by `keepass` 0.15).
- `compute::field_diff_entry` takes `&EntryRef` for both entries and no longer
  takes the two databases (an `EntryRef` carries its database's attachment pool).
- Attachments are enumerated with `EntryRef::attachments_named()`, replacing a
  JSON round-trip workaround; `keepass`'s `serialization` feature is no longer
  required.
- Warnings render as text (`warning: KDBX version differs: KDBX4.0 -> KDBX4.1`)
  instead of Rust debug output.

### Added
- Entry timestamps are diffed: `FieldChange::TimeChanged { field, from, to }`
  with a `TimeField` enum covering the seven KDBX `<Times>` values. Default mode
  suppresses access time, usage count, last-modification time, and
  location-changed; `--strict` shows them. Creation and expiry changes are always
  reported (ExpiryTime only when the entry actually expires).
- Fixtures for every kind of change, with fixed UUIDs and timestamps so their
  content is reproducible: `remove_entry`, `move_entry`, `rename_group`,
  `tag_diff`, `attachment_change`, `custom_field`, `history_grew`,
  `noisy_resave`, plus a frozen KDBX 4.0 file for read and cross-version
  coverage. The two previously ignored integration tests now run.

### Fixed
- `--strict` had nothing to show: noise suppression matched field names, but
  `keepass` keeps timestamps in `entry.times`, so they were never diffed.
- A custom field whose name matched a timestamp (for example `UsageCount`) was
  silently suppressed as noise. Noise is now a property of `TimeField`, never of
  a field name.
- `password_change` and similar fixtures previously diffed as an entry removed
  plus an entry added (independently generated UUIDs), so the masked
  field-level `Modified` path was not exercised end to end.

### Removed
- `compute::NOISY_TIMESTAMP_FIELDS` (superseded by `TimeField::is_noise`).

## [0.1.0] - unreleased

First release line, on `keepass` 0.12. Library, CLI, and git textconv driver.

### Fixed (since the initial v0.1 work)
- Field edits were dropped for moved or renamed entries; moves are now
  classified by immediate parent UUID, group renames are reported as `Renamed`,
  and moving a group no longer reports every descendant as moved.
- The textconv dump omitted custom fields and attachment identity, so editing a
  custom field (including a protected `otp` TOTP seed) produced no git diff.
- Dump ordering was nondeterministic for siblings with the same name; ties now
  break by UUID.
- `--show-secrets` now warns on a non-TTY stdout in textconv and dump modes too.

[0.2.0]: https://github.com/queelius/diff-kdbx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/queelius/diff-kdbx/releases/tag/v0.1.0
