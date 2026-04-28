# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`diff-kdbx` is a Rust library and CLI for semantic diffs of KeePass `.kdbx` files. Primary deployment is as a `git diff` textconv driver so version-controlled vault files produce meaningful diffs. Standalone use also works.

This is the first member of the **`*-kdbx` ecosystem**: a planned family of Rust tools and libraries for working with KDBX files in a static-first, browser-native, AI-agent-aware personal data stack. Other planned members:

- `web-kdbx` (anchor): browser-side WASM viewer/editor
- `mcp-kdbx` (bridge): MCP server exposing KDBX to AI agents
- `hugo-kdbx` (tool): Hugo theme embedding `web-kdbx`
- `arkiv-kdbx`, `longecho-kdbx` (bridges): pinned for later

## Architecture

Single Rust crate. Library is the default build (I/O-free, WASM-compatible). CLI binary is gated on the `cli` feature, mirroring `keepass-rs`'s `utilities` pattern.

```
src/
├── lib.rs          # public surface: re-exports modules
├── change_set.rs   # ChangeSet, Change, FieldChange, ValueDisplay, Summary
├── compute.rs      # compute(a, b, opts) -> ChangeSet  (the diff engine)
├── dump.rs         # dump(db, opts) -> String  (textconv mode)
├── render/text.rs  # tree-shaped human renderer
├── render/json.rs  # serde-based machine renderer
├── mask.rs         # 8-char SHA-256 hash prefix for protected fields
├── options.rs      # DiffOptions, DumpOptions, RenderOptions
├── path.rs         # backslash-escape encoded paths
└── bin/diff-kdbx.rs   # CLI (cli feature)
└── bin/gen_fixtures.rs  # fixture generator (cli feature)
```

## Authoritative docs

- `docs/superpowers/specs/2026-04-27-diff-kdbx-design.md`: full design rationale, motivation, non-goals, error policy.
- `docs/superpowers/plans/2026-04-27-diff-kdbx.md`: 29-task implementation plan with TDD steps.

Read the spec before making design-level changes. Read the plan before adding new modules so file-structure stays consistent.

## Build and test

```bash
cargo test --lib                    # 47 unit tests (foundation, compute, dump, render, mask, path)
cargo test --features cli           # + 8 integration + 3 determinism, total 58
cargo build --features cli          # CLI binary
cargo run --features cli --bin gen-fixtures   # regenerate test fixtures (deterministic master pw "test-password-do-not-use")
```

WASM build smoke check (lib only):

```bash
cargo build --target wasm32-unknown-unknown --no-default-features
```

## keepass-rs version and known API quirks

This crate depends on `keepass = "0.12"` with features `["serialization", "save_kdbx4"]`. The 0.12 API has several non-obvious shapes that bit us during implementation:

- `Database::root()` returns `GroupRef<'_>`; the crate uses flat hashmaps internally, not a recursive node tree.
- `entry.id().uuid()` to get a `Uuid`; UUIDs are wrapped in IDs.
- `entry.fields: pub HashMap<String, Value<String>>`; `Value::is_protected()` is the protected check.
- `entry.history` accessed via `History::get_entries()`, not direct field.
- **`Entry.attachments` is `pub(crate)`**: enumerating `(name, content)` requires the `serialization` feature and a JSON round-trip. See `compute.rs::collect_attachments`. Filed upstream as [keepass-rs#314](https://github.com/sseemayer/keepass-rs/issues/314); replace with the proper API once it lands.
- Entry/Group UUIDs are set internally with no public setter, so test fixtures inherently have varying UUIDs across regenerations.

## Conventions

- Library is I/O-free. The CLI binary owns file I/O, key resolution, and stdout/stderr/exit-code policy.
- `compute()` and `dump()` are deterministic by construction. Determinism is tested across separate processes (`tests/determinism.rs`).
- Suppression and masking are applied at compute time, not at render time. The change-set value is canonical for a given options bundle; renderers can't drift.
- Exit codes mirror `/usr/bin/diff`: `0` no changes, `1` changes detected, `2` error.
- Textconv mode buffers stdout (all-or-nothing) so git never sees partial dumps on error.

## Out of scope (deferred)

- 7 of 10 planned fixtures (`move_entry`, `tag_diff`, `attachment_change`, `history_grew`, `cross_version`, `noisy_resave`, `remove_entry`). 2 integration tests are `#[ignore]` awaiting these.
- Property tests via proptest (dep is in Cargo.toml; tests not yet written).
- Performance benchmarks via criterion.
- `wasm-bindgen-test` browser tests (revisit when `web-kdbx` consumes the library).
- Helper-command-based key resolution (`KDBX_DIFF_KEY_HELPER`) for keyring integration.
