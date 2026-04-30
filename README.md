# diff-kdbx

**Semantic diff for KeePass KDBX files.** A Rust CLI, a `git` textconv driver,
and a reusable library. Use it to put your password vault under version
control and get meaningful diffs out of `git diff`, `git log -p`, and
`git show` instead of "Binary files differ."

```
summary: +1/-0/~1 entries, +0/-0/~0 groups, 2 fields, 0 suppressed
+ ENTRY /Banking/Citi
~ ENTRY /Banking/Chase
  ~ Password: <hash:a1b2c3d4> -> <hash:d4e5f6a7>
  ~ URL: https://chase.com -> https://www.chase.com
```

Default secret masking. Default suppression of noisy timestamps. Deterministic
output (textconv contract). Exit codes mirror `/usr/bin/diff` (0 no changes,
1 changes, 2 error).

## Status

v0.1. Library and CLI working. 71 active tests across five layers (unit,
integration, determinism, real-git driver, push/clone roundtrip). WASM build
verified. Not yet on crates.io. The `keepass = "0.12"` API has known gaps
that diff-kdbx works around; see [keepass-rs#314](https://github.com/sseemayer/keepass-rs/issues/314)
for the upstream tracking issue.

## Why

`git diff` on a `.kdbx` file shows "Binary files differ" because the file is
encrypted and binary. That breaks version control for vault files: you cannot
audit, review, revert, or browse history in any meaningful way.

diff-kdbx parses both sides, computes a structural diff (UUID-based identity,
"moved" detection, granular per-field changes), and emits either tree-shaped
text or structured JSON. Registered as a git textconv driver, it makes
`*.kdbx` files behave like normal text files in every git workflow. Pair this
with a private remote (any git remote, no GitHub-specific coupling) and your
vault is version-controlled, distributed, and recoverable.

## Hands-on getting started

The walkthrough takes 15 minutes. By the end you will have diff-kdbx
installed, the git driver configured, a real vault under git, and a
day-to-day workflow.

### 1. Prerequisites

| Tool | Why | Check |
|---|---|---|
| `rustup` and `cargo` (Rust 1.85+) | Build diff-kdbx from source | `cargo --version` |
| `git` (any modern version) | The whole point | `git --version` |
| KeePassXC (optional) | Create and edit `.kdbx` files for real-world testing | `keepassxc --version` |

If you don't have KeePassXC, you can use diff-kdbx's bundled synthetic
fixtures for the first few sections without ever touching real data. The
walkthrough flags where the paths diverge.

### 2. Install

```bash
git clone https://github.com/queelius/diff-kdbx.git
cd diff-kdbx
cargo install --path . --features cli
```

This compiles the release binary and places `diff-kdbx` in `~/.cargo/bin/`.
Make sure that directory is on your PATH:

```bash
echo $PATH | tr ':' '\n' | grep -q "$HOME/.cargo/bin" && echo OK || echo "Add ~/.cargo/bin to PATH"
```

Verify:

```bash
diff-kdbx --help
```

You should see usage with all flags. If you get "command not found,"
your `~/.cargo/bin` is not on PATH.

### 3. First diff (no real data needed)

The repo ships synthetic fixtures under `tests/fixtures/`. They use a
published throwaway password (`test-password-do-not-use`).

```bash
export KDBX_DIFF_PASSWORD='test-password-do-not-use'
diff-kdbx tests/fixtures/add_entry/before.kdbx tests/fixtures/add_entry/after.kdbx
```

Expected:

```
summary: +1/-0/~0 entries, +0/-0/~0 groups, 0 fields, 0 suppressed
+ ENTRY /Root/Chase
```

Exit code 1 (changes detected). Try variations:

```bash
# JSON output for machine consumption
diff-kdbx --format=json tests/fixtures/add_entry/before.kdbx tests/fixtures/add_entry/after.kdbx | head -40

# Textconv dump (what git will see when invoking the driver)
diff-kdbx --textconv tests/fixtures/add_entry/after.kdbx

# Reveal plaintext for protected fields (TTY only by default; warns if piped)
diff-kdbx --show-secrets --textconv tests/fixtures/add_entry/after.kdbx

# Disable noise suppression (--strict): every difference, including LastAccessTime
diff-kdbx --strict tests/fixtures/password_change/before.kdbx tests/fixtures/password_change/after.kdbx
```

If all of that worked, the binary is healthy. Now wire it into git.

### 4. Configure the git diff driver

One-time per-machine. Add to `~/.gitconfig`:

```bash
git config --global diff.kdbx.textconv 'diff-kdbx --textconv'
git config --global diff.kdbx.binary true
git config --global diff.kdbx.cachetextconv true
```

What each setting does:

- `textconv`: tells git "for this file type, run this command on each side
  before computing the diff." git diffs the converted text, not the raw
  binary blob.
- `binary = true`: marks the file type as binary so git does not try to
  show it as text in other contexts.
- `cachetextconv = true`: git caches the textconv output keyed by blob hash,
  so repeated `git log -p` calls do not re-decrypt every commit. Safe
  because diff-kdbx output is deterministic.

The driver definition lives in `~/.gitconfig`. The "use this driver for
`*.kdbx`" part is per-repo, set via `.gitattributes` (next).

### 5. Initialize a git repo for your vault

```bash
mkdir -p ~/test-vault
cd ~/test-vault
git init -b main
echo "*.kdbx diff=kdbx" > .gitattributes
git add .gitattributes
git commit -m "configure diff driver for kdbx files"
```

The `.gitattributes` line binds `*.kdbx` files to the `kdbx` diff driver
you configured globally in step 4.

### 6. Add your vault and make a change

If you have KeePassXC: create a fresh test database `~/test-vault/vault.kdbx`
(NOT your real vault), pick a disposable password like `hunter2`, add 2-3
fake entries.

If you don't: copy a synthetic fixture instead:

```bash
cp ~/path/to/diff-kdbx/tests/fixtures/add_entry/before.kdbx ~/test-vault/vault.kdbx
export KDBX_DIFF_PASSWORD='test-password-do-not-use'
```

Either way, commit it:

```bash
cd ~/test-vault
git add vault.kdbx
git commit -m "initial vault"
```

Now make a change. Either edit in KeePassXC and save, or with the synthetic
path swap in the "after" version:

```bash
cp ~/path/to/diff-kdbx/tests/fixtures/add_entry/after.kdbx vault.kdbx
```

Run `git diff` and watch the textconv driver kick in:

```bash
git diff vault.kdbx
```

You should see a structured diff showing the added entry, NOT "Binary files
differ." If you do see "Binary files differ," see Troubleshooting below.

Commit:

```bash
git add vault.kdbx
git commit -m "add Chase entry"
```

### 7. Browse history

These all work now:

```bash
git log -p vault.kdbx              # full audit trail of every textconv'd change
git show HEAD vault.kdbx           # latest commit's diff
git show HEAD~1 vault.kdbx         # previous commit's diff
git diff HEAD~1 HEAD -- vault.kdbx # any range
git log --oneline vault.kdbx       # quick browsable history
```

### 8. Recovery

Accidentally deleted an entry and committed it? Roll back:

```bash
git revert HEAD                    # creates a new commit that undoes HEAD
```

Want to inspect an old version without committing?

```bash
git checkout HEAD~3 -- vault.kdbx  # vault.kdbx now matches 3 commits ago
# Open in KeePassXC, copy what you need
git checkout HEAD -- vault.kdbx    # restore the current version
```

### 9. Sync to a remote (optional)

The diff driver is purely local. For sync across machines, push to any git
remote: GitHub (private), GitLab (private), Codeberg, Gitea, sourcehut, your
own server over SSH, anywhere. The remote sees only encrypted ciphertext.

```bash
cd ~/test-vault
git remote add origin <your-repo-url>
git push -u origin main
```

On a second machine, after a clone:

```bash
git clone <your-repo-url> vault-clone
cd vault-clone
# .gitattributes came along with the clone, but the global diff driver
# config did NOT (it lives in ~/.gitconfig, not in the repo).
# Set it up on this machine: redo step 4. Then:
export KDBX_DIFF_PASSWORD='...'
git log -p vault.kdbx              # textconv'd diffs over the cloned history
```

### 10. Day-to-day workflow

Once configured, the typical loop:

```bash
# Edit vault.kdbx in KeePassXC, save
cd ~/your-vault-repo
git diff vault.kdbx                # sanity-check what changed
git add vault.kdbx
git commit -m "rotate Chase password"
git push                           # if you have a remote
```

A monthly habit worth forming: scan
`git log -p vault.kdbx --since='1 month ago'` to review what changed. Catches
accidental damage and surfaces patterns ("rotated 8 passwords last month;
three of them more than once").

## Troubleshooting

### "Binary files differ" instead of a real diff

One of three things:

- **Driver not configured in this shell.** Check
  `git config --get diff.kdbx.textconv`. If empty, redo step 4.
- **`.gitattributes` missing or wrong.** From the repo root: `cat .gitattributes`.
  Should contain `*.kdbx diff=kdbx`.
- **`KDBX_DIFF_PASSWORD` not set.** The textconv command is non-interactive;
  without the env var it fails closed and git falls back to "Binary files differ."

### "Error: could not decrypt"

Wrong password. Test outside git:

```bash
diff-kdbx --textconv vault.kdbx
```

If that fails, the password is wrong. If it succeeds but `git diff` still
fails, the env var isn't propagating to git's child process: run `git diff`
in the same shell where you ran `export KDBX_DIFF_PASSWORD=...`.

### Driver hangs

Should never happen. If it does, ctrl-C and check whether something is
asking for input. The textconv mode never prompts. Force non-interactive
by ensuring `KDBX_DIFF_PASSWORD` is set.

### `git log -p` is slow on first run

Expected. Git invokes the textconv driver once per commit's blob, decrypts,
dumps. With `cachetextconv = true` (recommended), subsequent runs hit the
cache and are nearly instant.

## Security

- **The .kdbx is encrypted.** Pushing to a remote does not leak plaintext.
  An attacker who steals the repo gets the same ciphertext they would have
  gotten by stealing the file directly.
- **Passwords appear masked by default.** Diff and dump output show
  protected fields as 8-char SHA-256 hash prefixes. `--show-secrets`
  reveals plaintext and warns to stderr if stdout is non-TTY.
- **Env var caveat.** `KDBX_DIFF_PASSWORD` lives in your shell env. It can
  leak via shell history, `/proc/$$/environ`, parent process inheritance,
  CI logs. Treat it like any password env var. A future `KDBX_DIFF_KEY_HELPER`
  interface (v0.2) will let you fetch from a keyring or `pass` instead.
- **Git tracks history forever.** A password committed once and rotated
  out is still in `git log` accessible to anyone who clones the repo. This
  is the same risk as committing any sensitive value to git: the cure is
  `git filter-repo` or rebuilding history. Don't commit your master
  password to the repo.
- **Hash side channel.** If two entries share a password, their hash
  prefixes match. Diff output reveals password reuse. Useful for
  inadvertent audit, but also a side channel. Worth knowing.
- **Recycle bin currently visible in dumps.** See
  [issue #1](https://github.com/queelius/diff-kdbx/issues/1) for the
  enhancement to hide it by default.
- **All-or-nothing stdout.** In `--textconv` mode, no partial output is
  emitted on error; git either gets a complete dump or empty stdout plus
  nonzero exit.

## Library API

```rust
use std::fs::File;
let mut fa = File::open("a.kdbx")?;
let mut fb = File::open("b.kdbx")?;
let key = keepass::DatabaseKey::new().with_password("...");
let a = keepass::Database::open(&mut fa, key.clone())?;
let b = keepass::Database::open(&mut fb, key)?;

let cs = diff_kdbx::compute::compute(&a, &b, &Default::default());
let text = diff_kdbx::render::text::render(&cs, &Default::default());
println!("{}", text);

let json = diff_kdbx::render::json::render(&cs);
println!("{}", json);

// Or just dump one side (textconv-style, deterministic)
let dump = diff_kdbx::dump::dump(&a, &Default::default());
println!("{}", dump);
```

The library is I/O-free and compiles cleanly to `wasm32-unknown-unknown`,
so it is reusable from browser-side tooling. (Eventually `web-kdbx` will
consume it that way; see the `*-kdbx` ecosystem docs.)

## Where to go next

| You want to | Read |
|---|---|
| File a bug or request a feature | [Issues](https://github.com/queelius/diff-kdbx/issues) |
| Understand the design rationale | `docs/superpowers/specs/2026-04-27-diff-kdbx-design.md` |
| See the implementation plan | `docs/superpowers/plans/2026-04-27-diff-kdbx.md` |
| Add a new test or fixture | `docs/testing.md` and `tests/fixtures/MANIFEST.md` |
| See alternative git config recipes | `examples/git-config.md` |

## License

MIT.
