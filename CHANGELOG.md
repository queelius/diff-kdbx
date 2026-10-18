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
  `dump(&Snapshot, &DumpOptions) -> String`,
  `render_text(&ChangeSet, &TextOptions)` and
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
  ordinals for same-named siblings).
- One reversible text grammar for the diff and the dump: closed-set names are
  bare, and every vault-controlled string beside renderer syntax (custom
  field names, tags and other keys, plain values, paths) is one quoted token,
  so no vault content can forge a line, a label, a sealed value or a ` -> `.
- History items are compared by modification time: an item whose time
  exists on one side only is an addition or a removal, so trimming at the
  history cap and pushing a new item are one removal and one addition. Items
  sharing a time pair by equal content first (reporting nothing, so a
  reordering is no change), then by position; a leftover is an addition or a
  removal. Labels number an item among those sharing its time in its own
  snapshot (`History[<time>#2]`), so they match that snapshot's dump.
- The JSON document is a versioned contract defined by diff-kdbx itself
  (`format_version: 1`, flat leaves, no other crate's serde output), with the
  fingerprint key's derivation parameters and salt recorded. `render_json` is
  the only JSON entry point; public types do not implement `Serialize`.
- Every enum variant with named fields is `#[non_exhaustive]` with a
  constructor.
- `docs/FORMAT.md` documents the dump and text diff grammar, checked against
  real output by a test.

### CLI
- Opens files with keepass 0.15 (KDBX 3.1, 4.0, 4.1) and captures them with
  fingerprint sealing; `--show-secrets` captures plaintext instead.
  `--show-secrets` is refused together with `--textconv`: git may store
  textconv output (its textconv cache notes travel with mirror pushes and
  bundles). Caching textconv output is documented as opt-in for that reason.
- Fingerprint keys are derived with Argon2id from the vault's key material,
  never cheaper than the vault's own KDF: per file for `--textconv` and
  `--dump`, once from side A for a two-file diff, with the costlier of both
  files' parameters (`DeriveParams::stronger`, whole cost memory x passes).
- Key-file-only vaults work: a key file alone is the key when no password
  source exists, an empty interactive password with `--key-file` means none,
  and `--no-password` says so explicitly.
- New: `diff-kdbx fingerprint --field NAME --entry PATH-OR-UUID VAULT` prints
  a field's full keyed fingerprint, to verify recorded fingerprints;
  `--params` and `--salt` reproduce keys recorded elsewhere (a two-file
  diff's JSON, mcp-kdbx audit logs).
- `--separate-keys` refuses a shared `--key-file`; an empty
  `KDBX_DIFF_PASSWORD` with a key file means no password; a panic exits 2.
- Removed: `--color` (it did nothing). Exit codes are unchanged (0 no changes,
  1 changes, 2 error).
- The fixture generator is an example (`cargo run --example gen_fixtures`),
  so `cargo install` no longer installs it.

[0.1.0]: https://github.com/queelius/diff-kdbx/releases/tag/v0.1.0
