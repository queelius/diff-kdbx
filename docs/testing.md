# Testing diff-kdbx

The test architecture: what each layer covers, how to run it, and how
fixtures are managed.

## Goals

1. **Travel with the repo.** A fresh clone (next to `kdbx-core`) plus
   `cargo test --features cli` runs the full suite. No external state, no
   network, no manual setup.
2. **Be honest about provenance.** Every fixture is documented in
   `tests/fixtures/MANIFEST.md` with origin, password, contents and
   regeneration.
3. **Cover real workflows.** Not just exit codes, but git itself, configured
   with the textconv driver, producing meaningful `git diff` / `log -p` /
   `show` / clone / pull output.
4. **Pin contracts.** The JSON shape, the dump format and the public API are
   pinned by tests, so changing one is a deliberate act.

## Layers

| Layer | Suite | What it catches |
|---|---|---|
| 1. Unit | `cargo test --lib` (68) | Logic of each module on hand-built snapshots: property mapping (with serde tripwires that fail when kdbx-core adds a model field nobody maps), change-set shapes, compute rules (moves, renames, protection toggles, history at the cap, noise, recycle bin, KDF weakening), dump and renderer formats and line safety |
| 2. Snapshots | `tests/snapshots.rs` | Text, JSON and dump output of every fixture pair, pinned with `insta` (the JSON contract lives here) |
| 3. CLI | `tests/integration.rs`, `tests/cli.rs` | Flag parsing, key resolution (password, key file, key-file only, separate keys), the `fingerprint` subcommand, exit codes, every fixture end to end |
| 4. Properties | `tests/mirror.rs` | proptest over generated snapshots: `compute(a, a)` is empty and `compute(a, b)` mirrors `compute(b, a)` |
| 5. API | `tests/public_api.rs` | Every public item, signature, field and enum variant, named from outside the crate |
| 6. Determinism | `tests/determinism.rs` | Byte-stable dump and diff output across processes |
| 7. Git driver | `tests/git_driver.rs` | Real `git diff` / `log -p` / `show` with the driver, fail-closed on a wrong password |
| 8. Remote roundtrip | `tests/remote_roundtrip.rs` | A bare repo as remote: push, clone, pull, per-clone driver setup |

## Running

| Command | Purpose |
|---|---|
| `cargo test --lib` | Fastest; no keepass, no I/O |
| `cargo test --features cli` | Everything |
| `cargo test --features cli --test git_driver` | One suite |
| `cargo test --features cli <pattern>` | Tests matching a name |
| `cargo test --features cli -- --nocapture` | See git output when debugging |

External dependencies: `cargo`, and `git` for the git-driver and roundtrip
suites. No `gh`, no network.

Every CLI invocation derives a fingerprint key with Argon2id at no less than
the vault's own KDF cost and the 64 MiB / 3 passes / 1 lane floor, so the
fixtures use a deliberately cheap KDF. The frozen `legacy_kdbx40/` vault uses
keepass-rs's default KDF and makes the tests that open it the slowest.

## Fixtures

All fixtures live under `tests/fixtures/`, documented in `MANIFEST.md`.
Synthetic ones regenerate with:

```bash
cargo run --example gen_fixtures
INSTA_UPDATE=always cargo test --test snapshots   # then review every diff
```

Content is reproducible (fixed UUIDs, every timestamp frozen); the encrypted
bytes change on every save. Unit tests and `tests/cli.rs` build their own
snapshots and vaults instead of using fixtures.

## Adding a test

- **Unit:** next to the module (`src/<module>/tests.rs` or a `mod tests`),
  building snapshots with `src/test_support.rs`. Use `crate::test_support::key()`
  for sealed values, so fingerprints are stable.
- **CLI:** `tests/integration.rs` for fixture pairs, `tests/cli.rs` for
  behavior that needs its own vault (`common::cheap_db`, `common::save`).
- **A new fixture pair** is picked up by `tests/snapshots.rs` automatically;
  add a `pair(...)` in `examples/gen_fixtures.rs`, a row in `MANIFEST.md`, and
  an integration test for the behavior it isolates.

## What we deliberately don't test

- **Real vaults.** Fixtures are throwaway material with a published password.
- **Real git hosting.** The remote roundtrip uses a local bare repository.
- **KeePassXC interop in CI.** It would need KeePassXC on the runner. As a
  manual smoke test: open a fixture in KeePassXC, edit, save, and diff
  against the original.
