# diff-kdbx: Semantic diff for KDBX files

**Project:** diff-kdbx (first member of the *-kdbx ecosystem)
**Date:** 2026-04-27
**Author:** Alexander Towell
**Status:** Design (pending implementation plan)

## Goal

A Rust library and CLI tool that produces semantic diffs between two KDBX
files. The primary deployment is as a git custom diff driver, so `git diff`
produces meaningful output on version-controlled vault files. The library is
reusable by other members of the *-kdbx ecosystem.

## The *-kdbx ecosystem

diff-kdbx is one of six committed members:

| Role   | Member         | Status                                    |
|--------|----------------|-------------------------------------------|
| Anchor | web-kdbx       | next after diff-kdbx                      |
| Bridge | mcp-kdbx       | committed                                 |
| Bridge | arkiv-kdbx     | pinned (revisit later)                    |
| Bridge | longecho-kdbx  | pinned (revisit later)                    |
| Tool   | diff-kdbx      | committed (this spec)                     |
| Tool   | hugo-kdbx      | committed (depends on web-kdbx)           |

The ecosystem brings KDBX into a static-first, browser-native, AI-agent-aware
personal data stack. KDBX is the only widely-adopted, multi-implementation,
cryptographically-sound, structured-record format that fills the "structured,
secret, mutable working data" slot in this stack. The ecosystem treats it
accordingly: as a durable substrate worth investing in, not a niche file
format.

## Motivation

Five problems converge here.

**Binary diff is useless.** `.kdbx` files are encrypted binary blobs.
`git diff` on a vault shows nothing meaningful, breaking the version-control
workflow for users who track vaults in git.

**No maintained semantic-diff tool exists.** KeePassXC's built-in merge has
no preview-only mode. Other implementations don't expose diff at all. The
gap is real and persistent.

**Cross-implementation testing needs a rigorous diff.** Writing a vault with
KeePassXC, reading with keepass-rs, writing back, and comparing to the
original is exactly how to catch subtle interop bugs. diff-kdbx with
`--strict` is the tool for that workflow.

**Interactive "what changed?" inspection.** A daily driver who keeps backups
wants to compare snapshots without opening two KeePassXC windows side by
side.

**Library reuse multiplies value.** The same diff engine powers web-kdbx
(browser-side change tracking via WASM), mcp-kdbx (AI agents reporting vault
diffs), and potentially hugo-kdbx. Built once well, used four times.

The 30-year durability test, applied: KDBX has multiple FOSS implementations
and NIST/IETF crypto primitives. A static HTML+JS+WASM bundle runs in any
browser indefinitely. A Rust library that compiles cleanly to native and
WASM today still compiles decades later. diff-kdbx targets durable
substrates exclusively.

## Use cases (priority-ordered)

1. **Git diff driver (primary).** Register diff-kdbx as a textconv driver
   for `*.kdbx`, so `git diff`, `git log -p`, and `git show` produce
   meaningful output on version-controlled vaults. Defaults: nonzero exit
   on any change, masked secrets, suppressed timestamp noise.

2. **Daily driver (natural side effect).** `diff-kdbx old.kdbx new.kdbx`
   for interactive inspection. Same defaults as git mode.

3. **Dev tool (`--strict` mode).** `diff-kdbx --strict --show-secrets a.kdbx
   b.kdbx` for cross-implementation testing and keepass-rs bug hunting.
   Reports every difference; reveals plaintext.

## Non-goals

- **Merge.** Conflict resolution, three-way merge, CRDT considerations:
  separate project (merge-kdbx, deferred).
- **Real-time sync.** Out of scope.
- **Key escrow / password recovery.** Out of scope.
- **Custom format.** diff-kdbx operates on standard KDBX; we do not invent
  formats.
- **Format conversion.** No KDB to KDBX upgrade path. diff-kdbx is read-only
  with respect to the file format.
- **Editor.** No interactive editing of vaults; diff is read-only.

## Architecture

A library plus a thin CLI binary, with a clean separation of concerns:

```
+----------------------------------------------------------+
|  Binary: diff-kdbx                                       |
|   - clap-based CLI parsing                               |
|   - Mode dispatch:                                       |
|       standalone:  diff-kdbx a.kdbx b.kdbx               |
|       textconv:    diff-kdbx --textconv file.kdbx        |
|       dump:        diff-kdbx --dump file.kdbx            |
|   - Key resolution (env vars, key files, TTY prompt)     |
|   - File I/O                                             |
|   - Stdout/stderr/exit-code policy                       |
+---------------+------------------------------------------+
                |
                v (passes parsed keepass::Database structs)
+----------------------------------------------------------+
|  Library: diff_kdbx (no I/O, WASM-compatible)            |
|                                                          |
|   db ----> ChangeSet::compute(&a, &b, opts) -> ChangeSet |
|                                                       |  |
|                                                       v  |
|                              render::text / render::json |
|                                                          |
|   db ----> dump::format(&v, opts)        -> String       |
+--------------------------+-------------------------------+
                           |
                           v depends on
                     keepass-rs (keepass crate)
```

Three observations.

**Two operations, one library.** `compute` produces a structural diff
(UUID-based identity, "moved" detection, granular field changes). `dump`
produces a stable line-oriented text representation of one vault. They
share the underlying entity walk and the masking/suppression policy, but
they are distinct outputs. `compute` powers standalone mode; `dump` powers
textconv (where git's own line-differ runs over the dumped text). Both
live in the library so web-kdbx can reuse either.

**Library is I/O-free.** The library accepts already-parsed
`keepass::Database` values and returns strings or change-set values. It has
no filesystem, no stdin, no stdout. This makes it WASM-compatible by
construction (no surprises when web-kdbx consumes it) and makes tests
trivial: fixtures are in-memory `keepass::Database` builders, not temp
files.

**Suppression is computed, not rendered.** Noise suppression
(LastAccessTime, UsageCount, etc.) is a parameter to `ChangeSet::compute`,
not to renderers. The change-set value is "what users care about given
these options." `--strict` flips one flag in the options. Renderers are
dumb consumers.

## Components

Single crate `diff-kdbx`. The `cli` feature gates the binary, mirroring
the `utilities` feature pattern in keepass-rs.

```
diff-kdbx/
|-- Cargo.toml          # [features] cli = [clap, rpassword, atty, anyhow]
|-- src/
|   |-- lib.rs          # public API surface
|   |-- change_set.rs   # ChangeSet, Change, FieldChange, ValueChange,
|   |                   # Summary, Path, DiffWarning
|   |-- compute.rs      # compute(a, b, opts) -> ChangeSet
|   |-- dump.rs         # dump(db, opts) -> String  (textconv + --dump)
|   |-- mask.rs         # SecretMask, hash_prefix (8-char SHA-256)
|   |-- options.rs      # DiffOptions, DumpOptions, RenderOptions
|   |-- render/
|   |   |-- text.rs     # tree-shaped human output
|   |   |-- json.rs     # serde-derived machine output
|   |-- bin/
|       |-- diff-kdbx.rs   # CLI (gated on feature = "cli")
```

### Public types (sketched; exact signatures land in the plan)

- **`ChangeSet`**. Top-level value. A vector of `Change` plus a `Summary`
  of counts and an optional `Vec<DiffWarning>` for non-fatal observations
  (such as cross-version diffs).
- **`Change`**. Enum with three top-level variants:
  - `Database(DatabaseChange)`. Name, color, recycle-bin id, custom data.
  - `Group { uuid, path, kind }`. Added, Removed, Moved, Renamed,
    PropertiesChanged.
  - `Entry { uuid, path, kind }`. Added, Removed, Moved,
    Modified { fields }.
- **`FieldChange`**. Added, Removed, Modified, TagAdded, TagRemoved,
  AttachmentAdded, AttachmentRemoved, AttachmentModified, HistoryGrew,
  HistoryRewritten.
- **`ValueDisplay`**. `Plain(String)` for unprotected fields;
  `Masked { hash: HashPrefix }` for protected fields. Renderers consume
  this. Secret policy is enforced when the ChangeSet is built, not when
  it is rendered.
- **`Path`**. Display string plus `Vec<Uuid>` ancestor chain. Display for
  humans; UUIDs for stable identity.

### Key resolution (in CLI binary)

Two contexts: standalone (interactive prompt OK) and textconv (must be
non-interactive). Resolution order, first success wins:

1. `--key-file <path>` flag (or `--key-file-a` / `--key-file-b` with
   `--separate-keys`).
2. `KDBX_DIFF_PASSWORD` env var (or `KDBX_DIFF_PASSWORD_A` /
   `KDBX_DIFF_PASSWORD_B`).
3. TTY prompt via rpassword (standalone only; textconv fails closed with
   a clear error).

`--separate-keys` opts into divergent credentials for the two inputs
(cross-vault diff, dev tooling). Default is "same key for both," matching
the common case of two snapshots of the same vault.

Security note for the README: env vars leak via shell history,
`/proc/$$/environ`, and parent process inheritance. v0.1 documents this
honestly. Future versions may add a `KDBX_DIFF_KEY_HELPER` interface
(helper command outputs password on stdout) for keyring/password-manager
integration. Not in v0.1 scope.

### CLI invocation, end-to-end

| Mode                                   | Inputs        | Library calls                              | Output                          |
|----------------------------------------|---------------|--------------------------------------------|---------------------------------|
| `diff-kdbx a.kdbx b.kdbx`              | 2 paths, key  | parse 2x; compute(a, b, opts); render      | text or JSON to stdout          |
| `diff-kdbx --textconv f.kdbx`          | 1 path, key   | parse 1x; dump(db, opts)                   | stable text dump to stdout      |
| `diff-kdbx --dump f.kdbx`              | 1 path, key   | parse 1x; dump(db, opts)                   | same dump (manual inspection)   |

## Data flow

### Standalone diff flow

```
diff-kdbx a.kdbx b.kdbx
   |
   |-> resolve key(s)              (CLI key module)
   |-> parse a, b                  (keepass::Database::open x2)
   |
   |-> compute(&a, &b, opts):
   |     |
   |     |-> metadata_diff           (DB name, color, recycle bin,
   |     |                            custom data)
   |     |
   |     |-> tree_walk(a), tree_walk(b)
   |     |     each builds HashMap<Uuid, (Path, Node)>
   |     |
   |     |-> symmetric difference on UUID sets:
   |     |     in a only             -> Removed
   |     |     in b only             -> Added
   |     |     in both, diff path    -> Moved
   |     |     in both, same path,
   |     |       diff content        -> Modified
   |     |
   |     |-> per matched entry: field_diff
   |     |     standard fields (5), custom fields, tags,
   |     |     attachments, history (length cmp; rewrite detection
   |     |     only in --strict), timestamps (suppress noisy ones
   |     |     unless --strict)
   |     |
   |     |-> apply suppression policy
   |     |-> return ChangeSet, sorted deterministically by path
   |
   |-> render::text or render::json
   |
   |-> stdout <- output
       exit code: 0 if change_set empty, 1 otherwise
```

### Textconv dump flow

```
diff-kdbx --textconv vault.kdbx
   |
   |-> resolve key                  (NON-INTERACTIVE only;
   |                                 fail closed if absent)
   |-> parse vault
   |
   |-> dump(&db, opts):
         emit DATABASE header
         tree_walk sorted by path
         for each node, emit a multi-line block:
            ENTRY /Banking/Chase [uuid:abc123]
              title: Chase
              username: alice@example.com
              password: <hash:a1b2c3d4>
              url: https://www.chase.com
              tags: banking, primary
              attachments: 0
              history: 5 entries
              modified: 2026-04-15T10:30:00Z

       stdout <- dump string
       (git's line-differ runs over the dumped output of both sides)
```

### Cross-cutting properties

**Identity by UUID, display by path.** Every KDBX group and entry has a
stable UUID. The diff matches by UUID. "Moved" means same UUID, different
path. This prevents false-positive add/remove pairs after group
reorganization. Path is for human display only; never load-bearing for
matching.

**Determinism.** Both `compute` and `dump` produce byte-identical output
for identical inputs. Sort is by path lexicographic, with UUID as
tiebreaker. Hash prefixes are computed over a canonical UTF-8 NFC
encoding of the plaintext. Path encoding handles `/` and control chars
in names via backslash escapes (detail for the plan).

**Suppression at compute time, not at render time.** Default
`DiffOptions` suppresses a fixed noise set: `LastAccessTime`,
`UsageCount`, and modification/access timestamps on entries whose
content didn't otherwise change. `--strict` empties the suppression
set. The change-set value is canonical for a given options bundle:
two renderers (text, JSON) of the same change set are
guaranteed-consistent by construction.

**Masking at compute time, not at render time.** Protected fields (per
the KDBX `Protected="True"` attribute) become
`ValueDisplay::Masked { hash }` while the change set is built.
Plaintext never enters the change-set value unless `--show-secrets`.
Renderers cannot accidentally un-mask.

**Exit code policy.** 0 if and only if the change_set is empty after
suppression. Nonzero otherwise. In `--strict`, suppression is off, so
opening-and-saving an unchanged file (which still touches
LastAccessTime) reports nonzero, exactly what dev/strict mode wants.

## Error handling

### Exit codes (mirror `/usr/bin/diff`)

| Code | Meaning                                         |
|------|-------------------------------------------------|
| 0    | No changes after suppression                    |
| 1    | Changes detected                                |
| 2    | Error (filesystem, crypto, parse, usage)        |

### Error categories

| Category           | Examples                                         | Where caught            | User-facing behavior                                                                |
|--------------------|--------------------------------------------------|-------------------------|-------------------------------------------------------------------------------------|
| Parse / format     | Invalid KDBX magic, truncated, malformed XML     | CLI (via keepass-rs)    | Exit 2; stderr `error: failed to parse <path>: <reason>`                            |
| Decryption         | Wrong password, wrong key file                   | CLI                     | Exit 2; suggest `--separate-keys` if B failed after A succeeded                     |
| Cross-version diff | A is KDBX 3.1, B is KDBX 4.0                     | Library `compute`       | Non-fatal. Emit `Warning` in ChangeSet; renderer prints it above the output         |
| Cross-vault diff   | Master-key mismatch with `--separate-keys` unset | CLI                     | Exit 2; stderr suggests `--separate-keys`                                           |
| I/O                | Permission denied, file not found                | CLI                     | Exit 2; stderr with full path                                                       |
| Broken pipe        | `diff-kdbx a b \| head`                          | CLI                     | Treat as user-cancellation; exit 0 if change set was emitting successfully          |
| Usage              | Bad flags, missing required args                 | clap                    | Exit 2; clap's standard message                                                     |
| Security           | `--show-secrets` with non-TTY stdout             | CLI                     | Stderr warning, continue (explicit user intent)                                     |

### Library API: mostly infallible

The library operates on already-parsed `keepass::Database` values, so
`compute()` and `dump()` return values, not `Result`s. The one
accommodation: `ChangeSet` carries an optional
`warnings: Vec<DiffWarning>` field for non-fatal observations such as
`KdbxVersionMismatch { a: "3.1", b: "4.0" }`. Renderers prepend warnings
above the diff output.

This keeps the API clean for web-kdbx reuse: a library that returned
`Result<ChangeSet, _>` from its primary entry point would force every JS
consumer to write error-handling for cases that can't actually arise
post-parse.

### Textconv mode error discipline

Textconv is invoked by git, which displays whatever lands on stdout as
the file's "text representation" before computing line-diff. If we emit
partial output and then fail, git produces a corrupted diff. Two rules:

1. **All-or-nothing stdout.** Buffer the dump in memory; write to stdout
   only after `dump()` completes successfully. On any error before that
   point, write nothing to stdout.
2. **Errors go to stderr; exit nonzero.** Git surfaces stderr in some
   workflows and ignores it in others; that is acceptable. Empty stdout
   plus nonzero exit is the canonical "this file couldn't be textconv'd"
   signal.

### CLI implementation

`anyhow` for the binary. `.with_context()` at each error site so the
error chain shows the operation that failed
(`while opening "/path/to/vault.kdbx" -> KDBX parse error -> ...`).
Single-line errors by default. Full chain only when `RUST_BACKTRACE=1`.
No panics in normal paths: every `?` on a `Result` carries context.

## Testing

### Six test layers

| Layer              | Tool                          | Coverage                                                                                         |
|--------------------|-------------------------------|--------------------------------------------------------------------------------------------------|
| Unit (library)     | `#[test]` + `insta`           | Each module: compute, dump, mask, render, options. In-memory `keepass::Database` builders.       |
| Snapshot (library) | `insta::assert_snapshot!`     | Stable text and JSON output for curated ChangeSets. Same convention as keepass-rs and prql.      |
| Property (library) | `proptest`                    | Invariants over generated databases (see below).                                                 |
| Determinism        | std test, multi-run           | Run `compute` and `dump` N times, hash outputs, assert all hashes identical.                     |
| Integration (CLI)  | `assert_cmd` + `predicates`   | End-to-end invocations with real .kdbx fixtures.                                                 |
| Cross-impl         | `#[ignore]` tests + scripts   | KeePassXC roundtrip. Run on demand, not in CI initially.                                         |

### Property invariants

- `compute(a, a)` is empty.
- `compute(a, b)` and `compute(b, a)` produce inverse change sets at the
  level of summary counts.
- `dump(a)` is deterministic over input ordering shuffles.

### Fixtures

`tests/fixtures/` holds canonical .kdbx files committed to the repo. A
helper binary `tests/gen_fixtures.rs` regenerates them deterministically
(fixed UUIDs, fixed timestamps, fixed master password
`test-password-do-not-use`). Regen is manual: `cargo run --bin
gen_fixtures` when fixtures change. Output is byte-stable so commits to
fixtures show meaningful diffs.

Fixture set (each produced as `before.kdbx` + `after.kdbx` pairs):

- `empty/`. Both empty.
- `add_entry/`. One entry added.
- `remove_entry/`. One entry removed.
- `move_entry/`. Entry moved between groups.
- `password_change/`. One password modified (tests masking).
- `tag_diff/`. Tags added and removed.
- `attachment_change/`. Attachment swapped.
- `history_grew/`. Entry edited, history pushed.
- `cross_version/`. KDBX 3.1 vs KDBX 4.0.
- `noisy_resave/`. Opened-and-saved with no semantic changes (default
  suppresses, strict reports).

### Determinism as an explicit test

Two assertions worth elevating:

1. `compute(a, b)` is deterministic. Run 100 times in a single test
   process; hash each ChangeSet's text rendering; assert all 100 hashes
   identical.
2. `dump(db)` is deterministic and byte-stable across processes. Same as
   above, plus dump twice in separate test processes (subprocess via
   `Command`); assert byte-identical. Catches process-startup
   nondeterminism.

These are not redundant with property tests; they directly target the
textconv contract (textconv must be deterministic or git's diff display
breaks).

### CI

- `cargo test --all-features` (library plus CLI).
- `cargo build --target wasm32-unknown-unknown --no-default-features`
  (library WASM-compatibility check, mirroring keepass-rs).
- `cargo clippy --all-targets --all-features -- -D warnings`.
- `cargo fmt --check`.
- `cargo deny check` (license / advisory hygiene).

Coverage is monitored (`cargo-llvm-cov`), not gated. Library target
greater than or equal to 85%; CLI target greater than or equal to 70%;
missing lines flagged in PR comment.

## Out of scope (deferred to later versions)

- Fuzz testing of the dump function. Belongs upstream in keepass-rs.
- Performance benchmarks via `criterion`. Revisit in v0.2 with real KDBX
  size data.
- WASM browser testing via `wasm-bindgen-test`. Revisit when web-kdbx
  consumes the library.
- KDBX-1 (.kdb) format quirks beyond what keepass-rs handles natively.
- Output formats other than tree-text and JSON.
- External diff driver as an alternative to textconv
  (`diff.<name>.command` git config). v0.1 documents textconv as the
  primary integration path; external is a future addition.
- Helper-command-based key resolution (`KDBX_DIFF_KEY_HELPER` for
  keyring/password-manager integration). v0.1 documents env-var
  tradeoffs honestly; helper integration arrives in a later version.

## Decisions made during the brainstorm

- **Language:** Rust. Depends on keepass-rs as the only KDBX
  implementation in the Rust ecosystem.
- **Primary use case:** Git diff driver (B). Daily driver (A) and dev
  tool (C) fall out as side effects.
- **Scope:** Maximal. Every KDBX entity (groups, entries, fields, custom
  fields, tags, attachments, history, database metadata) is covered.
  Default noise suppression for known-noisy timestamps; `--strict`
  disables suppression.
- **Output formats:** Tree-shaped text (default) plus JSON via
  `--format=json`. Both ship in v0.1.
- **Secret masking:** Format-respecting (respects KDBX
  `Protected="True"` attribute) plus 8-character SHA-256 hash prefix on
  changed protected fields. `--show-secrets` reveals plaintext with a
  stderr warning if stdout is non-TTY.
- **Code structure:** Single crate `diff-kdbx`. Library is the default
  build; the binary is gated on the `cli` feature, mirroring
  keepass-rs's `utilities` feature pattern.
- **Git integration:** textconv driver as the primary documented
  integration path. The CLI's standalone mode just works when invoked
  directly.

## Open questions for the implementation plan

These are not load-bearing for the design; they belong in the plan:

- Exact CLI flag names, short aliases, and clap command structure.
- Specific list of timestamps in the default suppression set.
  `LastAccessTime` and `UsageCount` are confirmed; modification
  timestamps on otherwise-unchanged entries also suppressed; full list
  to enumerate.
- Path-encoding rules for group/entry names containing `/`, control
  characters, or non-NFC Unicode.
- Whether to bundle git config snippets in the README, in a separate
  `examples/` directory, or as an installation helper subcommand.
- Test fixture authoring strategy: hand-crafted vs. programmatically
  generated `.kdbx` files for `tests/fixtures/`.
