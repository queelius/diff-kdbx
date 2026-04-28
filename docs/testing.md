# Testing diff-kdbx

This document describes the test architecture: what each layer covers, how
to run, and how fixtures are managed.

## Goals

The test apparatus is designed to:

1. **Travel with the repo.** Fresh `git clone` plus `cargo test --features cli`
   runs the full default suite. No external state, no network, no manual setup.
2. **Be honest about provenance.** Every fixture file is documented in
   `tests/fixtures/MANIFEST.md` with origin, password, contents, and
   regeneration procedure.
3. **Cover real workflows.** Not just "the binary returns the right exit code"
   but also "git itself, configured with our textconv driver, produces
   meaningful output for git diff / log / show / clone / push / pull."
4. **Run fast.** Default suite under 10 seconds. No skipped-by-default tests
   for things that should work.

## Test pyramid (five layers)

```
+----------------------------------------------------------+
|  Layer 5: Remote roundtrip                              |   ~3 tests
|    tempdir/origin.git (bare) + clone-a + clone-b         |
|    real git push/fetch/pull/clone, real textconv         |
|    no GitHub, no network, no auth                        |
+----------------------------------------------------------+
|  Layer 4: Local .git integration                        |   ~5 tests
|    tempdir + git init + textconv driver configured       |
|    real git diff / log -p / show against committed       |
|    fixtures                                              |
+----------------------------------------------------------+
|  Layer 3: Determinism                                   |   3 tests
|    multi-process byte-stability of dump/diff outputs     |
+----------------------------------------------------------+
|  Layer 2: CLI integration                               |   ~10 tests
|    assert_cmd against the binary, fixture-based          |
|    standalone diff, --textconv, --format=json,           |
|    --show-secrets, exit-code policy                      |
+----------------------------------------------------------+
|  Layer 1: Unit                                          |   ~50 tests
|    in-process tests for path, mask, options, change_set, |
|    compute, dump, render::text, render::json             |
|    no I/O                                                |
+----------------------------------------------------------+
```

Each layer adds exactly one new dimension of risk:

- Layer 1 catches per-module logic errors.
- Layer 2 catches integration errors (CLI flag parsing, file I/O, exit codes).
- Layer 3 catches nondeterminism that would break the textconv contract.
- Layer 4 catches integration errors with `git` itself: driver config syntax,
  whether stdin/stdout/stderr are wired correctly, whether `git diff` actually
  invokes the driver, whether the driver's exit code propagates appropriately.
- Layer 5 catches errors that only manifest after a clone: are .gitattributes
  carried correctly, does the driver need re-configuring per-clone (yes, it
  does), is the diff output stable across clones.

## Running

| Command | Layers | Purpose |
|---|---|---|
| `cargo test --lib` | 1 | Fastest; iterate on a single module |
| `cargo test --features cli` | 1, 2, 3, 4, 5 | Full default suite |
| `cargo test --features cli --test git_driver` | 4 only | Iterate on driver-config tests |
| `cargo test --features cli --test remote_roundtrip` | 5 only | Iterate on push/pull tests |
| `cargo test --features cli -- --nocapture` | all + log | See git stderr/stdout when debugging |

External dependencies:

- `cargo` (always required)
- `git` (required for layers 4 and 5; standard on developer machines and CI)

That's it. No `gh`, no `glab`, no network access, no test repos to provision.

## Fixture management

All KDBX fixtures live under `tests/fixtures/<name>/{before,after}.kdbx`. Each
is documented in `tests/fixtures/MANIFEST.md` with:

- **Origin**: synthetic via `gen-fixtures`, KeePassXC-Copy-As, or external.
- **Master password**: `test-password-do-not-use` for everything synthetic.
- **Contents**: what semantic state the file represents.
- **Regeneration**: how to recreate it.

Synthetic fixtures regenerate via:

```bash
cargo run --features cli --bin gen-fixtures
```

This produces deterministic content (modulo upstream `keepass-rs` limitations
around UUID setters; see MANIFEST.md). Re-running may change UUIDs but should
not change the semantic test surface.

KeePassXC-generated fixtures (currently none committed) require a manual
procedure documented per-fixture in MANIFEST.md.

## Adding a new test

**Layer 1 (unit):** add `#[test]` inside the relevant `mod test` block in
`src/<module>.rs`. Use in-memory `keepass::Database` builders; no I/O.

**Layer 2 (CLI integration):** add a `#[test]` to `tests/integration.rs`.
Use `assert_cmd::Command::cargo_bin("diff-kdbx")` and reference fixture paths
relative to the crate root.

**Layer 3 (determinism):** add a `#[test]` to `tests/determinism.rs`. Run the
binary twice in separate subprocesses; assert byte-equality.

**Layer 4 (git driver):** add a `#[test]` to `tests/git_driver.rs`. Use the
`setup_repo` helper for the standard tempdir + git init + driver config flow.
Use `git()` for assertions-on-success or `git_no_panic()` when you expect a
nonzero exit.

**Layer 5 (remote roundtrip):** add a `#[test]` to `tests/remote_roundtrip.rs`.
Use the `setup_world` helper which gives you `(tempdir, origin.git, clone-a)`.
Add a clone-b yourself when needed.

## Adding a new fixture

1. Generate the fixture (extend `gen-fixtures` for synthetic; document the
   manual procedure for KeePassXC-generated).
2. Add an entry to `tests/fixtures/MANIFEST.md` filling in all four
   provenance fields.
3. Reference the new fixture in tests that need it.
4. If a previously-`#[ignore]`d test depended on the fixture, remove the
   ignore attribute.

## What we deliberately don't test

- **Real-world KDBX files in CI.** Personal vaults stay personal. Test
  fixtures are throwaway material with a published password.
- **Real GitHub / GitLab / etc.** The textconv driver doesn't care about the
  remote. Layer 5 uses a local bare repo and exercises the same protocol.
  If you want manual end-to-end validation against a real provider, configure
  a test repo on that provider and follow the README's "Git integration"
  section. But it's not part of the automated suite.
- **Cross-implementation roundtrips with KeePassXC.** Future work; would
  require KeePassXC on the test runner. See "manual smoke tests" below.

## Manual smoke tests

Some validation requires real-world ingredients we don't ship in CI. These
are documented procedures, not automated tests:

- **Real-vault diff.** Run `diff-kdbx` against your own personal vault to
  confirm the dump format is sensible. See README's "Git integration" section.
- **KeePassXC roundtrip.** Open a synthetic fixture in KeePassXC, edit it,
  save, then diff against the original. Validates that our writer's output
  is interoperable with KeePassXC's reader (and vice versa). Requires
  KeePassXC installed.
- **Cross-platform.** Tests should pass on Linux, macOS, and Windows. CI
  currently runs Linux only; macOS and Windows are spot-checked manually.

When discoveries from manual smoke tests should become regression tests, add
a fixture and an automated test. That's how the apparatus grows.
