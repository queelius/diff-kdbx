# CLAUDE.md

Orientation for working in `diff-kdbx`, a member of the `*-kdbx` ecosystem
(see `~/github/kdbx/CLAUDE.md` and `~/github/kdbx/DESIGN.md`).

## What this is

A Rust library and CLI for semantic diffs of KeePass `.kdbx` files. Primary
deployment is as a `git diff` textconv driver; standalone use also works. The
library is built on `kdbx-core` (`../kdbx-core`, path dependency until both
are published): it is a pure function of two `kdbx_core::model::Snapshot`s and
names no keepass type. The CLI (feature `cli`) opens files with keepass 0.15
and captures them through `kdbx-core/keepass-0_15`.

## Authoritative docs

- `../kdbx-core/docs/superpowers/specs/2026-10-18-kdbx-core-design.md`,
  section 4 (diff-kdbx) and section 9 (decisions): the design.
- `docs/superpowers/plans/2026-10-18-diff-kdbx-snapshot-0.1.md`: the 0.1 plan
  and its Decisions section (formats, rules, trade-offs made while
  implementing).
- `docs/superpowers/specs/2026-04-27-diff-kdbx-design.md`: original motivation,
  textconv discipline, exit codes, git-driver workflow.
- `docs/testing.md` and `tests/fixtures/MANIFEST.md`: test layers, fixtures.

## Architecture

```
src/
├── lib.rs          # crate docs; re-exports the whole public API and kdbx_core
├── properties.rs   # Property (typed keys), Shown (values), and the per-node
│                   # property maps: the single source of diff and dump
├── nodes.rs        # covered nodes of a snapshot (recycle-bin rule, PathIndex
│                   # paths, parents) and the canonical path order
├── compute.rs      # compute(): UUID match + merge-join of property maps,
│                   # noise suppression, ordering, warnings (KDF weakening)
├── change_set.rs   # ChangeSet, Change, NodeChange, NodeStatus, PropertyChange,
│                   # Summary (computed from records), DiffWarning
├── dump.rs         # dump(): the textconv text, from the same property maps
├── options.rs      # DiffOptions, DumpOptions, Noise, RecycleBin
├── render/mod.rs   # value text forms shared by dump and text renderer
├── render/text.rs  # render_text()
├── render/json.rs  # render_json(), JsonOptions, FingerprintKeyInfo
├── render/wire.rs  # the JSON wire format (private types, every leaf)
├── test_support.rs # snapshot builders for unit tests (cfg(test))
└── bin/diff-kdbx.rs  # CLI: key resolution, fingerprint key derivation,
                      # capture, modes, fingerprint subcommand
examples/gen_fixtures.rs  # regenerates tests/fixtures (keepass save_kdbx4)
```

## Invariants (do not break)

- The library never names a keepass type and does no I/O; it builds for
  `wasm32-unknown-unknown` with `--no-default-features`.
- Dump and diff read the same property maps. A new model field means one
  `Property` variant plus one line in `properties.rs`; the serde tripwire
  tests in `src/properties/tests.rs` fail until it is mapped.
- No re-derived rules: secrecy comes from the snapshot (`Value::Sealed` vs
  `Value::Plain`, decided by `kdbx_core::visibility::is_secret` at capture);
  paths from `kdbx_core::path::PathIndex`; escaping from `kdbx_core::text`.
- Noise is `Property::is_noise` (typed), never a name list. Names and JSON
  keys of key enums come from one `Display` match each.
- Output is deterministic (sorted maps, explicit ordering); the textconv
  stdout is all-or-nothing.
- Exit codes mirror `/usr/bin/diff`: 0 no changes, 1 changes, 2 error.
- Textconv output is storable (git's textconv cache is a notes ref that
  mirrors and bundles carry): `--textconv` never reveals secrets, and the
  docs keep `cachetextconv` opt-in.
- The JSON shape is versioned (`JSON_FORMAT_VERSION`) and defined only in
  `src/render/wire.rs`; public types do not implement `Serialize`. The insta
  snapshots in `tests/snapshots/` pin it. Changing a snapshot is changing the
  contract.

## Commands (the gates; run all before every commit)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features cli -- -D warnings
cargo test --features cli
cargo test --lib
cargo build --target wasm32-unknown-unknown --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

MSRV is 1.89 (keepass 0.15): `cargo +1.89.0 test --features cli`.
Regenerate fixtures with `cargo run --example gen_fixtures` (master password
`test-password-do-not-use`), then `INSTA_UPDATE=always cargo test --test
snapshots` and review every snapshot diff.

## Tests (as of 0.1.0): 142 with `--features cli`

| Suite | What | Count |
|---|---|---|
| `cargo test --lib` | unit: properties (incl. serde tripwires), change set, compute (incl. history pairing), dump, label and value grammar read-back, JSON wire leaves, options | 73 |
| binary unit tests | panic-to-exit-2 guard, `--params` parsing | 2 |
| `tests/snapshots.rs` | insta text, JSON and dump snapshots for every fixture pair (64 snapshots) | 2 |
| `tests/integration.rs` | CLI end to end over every fixture | 33 |
| `tests/cli.rs` | key resolution, `fingerprint` subcommand (`--params`, `--salt`), `--separate-keys`, two-file key parameters, JSON key provenance | 14 |
| `tests/canary.rs` | no vault secret in any text, JSON or dump output of any fixture pair | 1 |
| `tests/mirror.rs` | proptest: `compute(a, a)` empty, `compute(a, b)` mirrors `compute(b, a)` (trees, history, recycle bin, headers) | 2 |
| `tests/public_api.rs` | every public item, signature, field and variant pinned | 3 |
| `tests/determinism.rs` | byte-stable output across processes | 3 |
| `tests/git_driver.rs` | real git in tempdirs | 5 |
| `tests/remote_roundtrip.rs` | bare repo as remote, clone, pull | 3 |
| doc tests | crate example | 1 |

External dependencies for the full suite: `cargo` and `git`.

## Notes

- Every CLI invocation derives a fingerprint key with Argon2id: the vault's
  own Argon2 parameters when they cost (memory x passes) at least as much as
  the 64 MiB x 3 floor, else the floor (`DeriveParams`, kdbx-core). A
  two-file diff takes `DeriveParams::stronger` of both vaults. Fixtures use a
  cheap KDF, so tests derive at the floor.
- keepass 0.15 saves KDBX 4.1 only, so `tests/fixtures/legacy_kdbx40/` is
  frozen, not regenerated.
- keepass 0.15 keeps history items crate-private except `add_entry` and
  `get_entries`; the generator rebuilds `History` to trim at the cap.

## Out of scope (deferred)

- A KDBX 3.1 fixture (keepass cannot write KDBX 3).
- Helper-command key resolution (`KDBX_DIFF_KEY_HELPER`) for keyrings.
- Verifying side B of a two-file diff whose two vaults have different key
  material (`fingerprint` always derives from the opened vault's key).
- Benchmarks.
