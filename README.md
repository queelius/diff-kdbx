# diff-kdbx

Semantic diff for KeePass KDBX files. Works as a `git diff` driver, a standalone CLI, and a reusable Rust library.

## Status

v0.1: library and CLI working. Fixture-driven test coverage. WASM build verified. Not yet on crates.io.

## Why

`git diff` on a `.kdbx` file shows nothing meaningful (the file is encrypted, binary). diff-kdbx parses both sides, computes a structural diff (UUID-based identity, "moved" detection, granular field changes), and emits a tree-shaped human-readable text or a structured JSON document. Default secret masking, default suppression of noisy timestamps that change on every read.

## Install

```bash
cargo install --path . --features cli
```

## Quick start

### Standalone

```bash
KDBX_DIFF_PASSWORD="..." diff-kdbx old.kdbx new.kdbx
```

Or with prompts:

```bash
diff-kdbx old.kdbx new.kdbx           # prompts for password
diff-kdbx --separate-keys old new     # prompts twice
diff-kdbx --format=json old new       # JSON output
diff-kdbx --strict old new            # disable suppression
diff-kdbx --show-secrets old new      # reveal plaintext (TTY only by default)
```

Exit codes: `0` no changes, `1` changes detected, `2` error (mirrors `/usr/bin/diff`).

### Git integration (textconv driver)

Once installed, configure git for `*.kdbx` files (per-user, in `~/.gitconfig`):

```gitconfig
[diff "kdbx"]
    textconv = diff-kdbx --textconv
    binary = true
    cachetextconv = true
```

Then per-repo (`.gitattributes`):

```
*.kdbx diff=kdbx
```

For non-interactive use (which is the textconv mode), pre-set the password:

```bash
export KDBX_DIFF_PASSWORD="..."
git diff path/to/vault.kdbx
git log -p path/to/vault.kdbx
```

See `examples/git-config.md` for additional setups (per-repo overrides, key files, separate passwords).

## Security

- **Masking by default.** Protected fields (per the KDBX `Protected="True"` attribute) are emitted as 8-character SHA-256 hash prefixes. `--show-secrets` reveals plaintext and warns to stderr if stdout is non-TTY.
- **Env var caveat.** `KDBX_DIFF_PASSWORD` may leak via shell history, `/proc/$$/environ`, parent-process inheritance, or CI logs. Treat it as you would any password env var. Future versions will add a helper-command interface for keyring/password-manager integration.
- **All-or-nothing stdout.** In `--textconv` mode, no partial output is emitted on error; git either gets a complete dump or an empty stdout plus exit code 2.

## Library

```rust
let a = keepass::Database::open(&mut fa, key.clone())?;
let b = keepass::Database::open(&mut fb, key)?;
let cs = diff_kdbx::compute::compute(&a, &b, &Default::default());
let text = diff_kdbx::render::text::render(&cs, &Default::default());
println!("{}", text);
```

The library is I/O-free and compiles to `wasm32-unknown-unknown`, so it is reusable from browser-side tooling (web-kdbx).

## Spec and design

Design documents live in `docs/superpowers/`:

- `specs/2026-04-27-diff-kdbx-design.md`: full design rationale.
- `plans/2026-04-27-diff-kdbx.md`: implementation plan.

## License

MIT.
