# Changelog

All notable changes to diff-kdbx. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump may break the
library API or the JSON `format_version`).

## [0.1.0] - unreleased

The first published release. diff-kdbx was rebuilt on
[`kdbx-core`](https://github.com/queelius/kdbx-core): the library is a pure
function of two keepass-free snapshots, so it no longer ties its callers to a
keepass version.

Two earlier release candidates, a local `0.1.0` (on keepass 0.12) and `0.2.0`
(on keepass 0.15), with a `release/0.1` maintenance branch, exposed keepass
types in their API. They were never pushed as releases or published, and this
line replaces them.

### Library
- `compute(&Snapshot, &Snapshot, &DiffOptions) -> ChangeSet`,
  `dump(&Snapshot, &DumpOptions) -> String`, `render_text(&ChangeSet)` and
  `render_json(&ChangeSet, &JsonOptions)`, all re-exported at the crate root
  along with `kdbx_core` itself. Engine internals are private and every public
  type that may grow is `#[non_exhaustive]`.
- One property map per node (database, group, entry) is the single source of
  both the diff and the dump, so they can no longer disagree. Everything the
  model holds is reported: fields with their protection flags, tags,
  attachments, every history item's properties, the seven times, icons,
  colors, URL override, quality check, auto-type, custom data, group notes,
  tags and flags, `<Meta>` settings, the outer header (KDF and parameters,
  ciphers, compression), and deleted-object tombstones.
- One record per changed node: a move is `moved_from` on the record, so a
  moved-and-edited entry or a moved-and-renamed group is one record and
  counts once. Every `Summary` counter is computed from the records.
- History items are keyed by modification time, so trimming at the history
  cap and editing at the cap are precise additions and removals.
- Secrets arrive sealed (keyed fingerprints from kdbx-core); the diff shows
  `<sealed:xxxxxxxx>` and marks protection where it is not implied, so turning
  protection off is visible even when the value is unchanged. The Title is
  never sealed: it is the entry's address.
- Typed warnings: `VersionMismatch` and `KdfWeakened` (Argon2 memory or
  passes lowered, Argon2 replaced by AES-KDF, AES-KDF rounds lowered, a
  recognized KDF replaced by an unrecognized one).
- Noise is a typed classification (`Property::is_noise`), applied at compute
  time with a count, and `--strict` means the same in diff and dump.
- The recycle-bin rule ignores a recycle-bin UUID that names the root group.
- Paths use the ecosystem grammar (no root-group name, `\/` escapes, `:N`
  ordinals for same-named siblings), and every rendered name and value goes
  through `kdbx_core::text`, so no vault content can forge an output line.
- The JSON document is a versioned contract: `format_version: 1`, with the
  fingerprint key's derivation parameters and salt recorded.

### CLI
- Opens files with keepass 0.15 (KDBX 3.1, 4.0, 4.1) and captures them with
  fingerprint sealing; `--show-secrets` captures plaintext instead.
- Fingerprint keys are derived with Argon2id from the vault's key material,
  never cheaper than the vault's own KDF: per file for `--textconv` and
  `--dump`, once from side A for a two-file diff, with the costlier of both
  files' parameters (`DeriveParams::stronger`, whole cost memory x passes).
- Key-file-only vaults work: a key file alone is the key when no password
  source exists, an empty interactive password with `--key-file` means none,
  and `--no-password` says so explicitly.
- New: `diff-kdbx fingerprint --field NAME --entry PATH-OR-UUID VAULT` prints
  a field's full keyed fingerprint, to verify recorded fingerprints.
- Removed: `--color` (it did nothing). Exit codes are unchanged (0 no changes,
  1 changes, 2 error).
- The fixture generator is an example (`cargo run --example gen_fixtures`),
  so `cargo install` no longer installs it.

[0.1.0]: https://github.com/queelius/diff-kdbx/releases/tag/v0.1.0
