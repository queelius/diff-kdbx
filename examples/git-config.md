# Git integration recipes

## Per-user setup

Add to `~/.gitconfig`:

```gitconfig
[diff "kdbx"]
    textconv = diff-kdbx --textconv
    binary = true
    cachetextconv = true
```

## Per-repo override

In a repository-local `.git/config`, you can override defaults, for example to use a key file:

```gitconfig
[diff "kdbx"]
    textconv = diff-kdbx --textconv --key-file ~/keepass.key
```

## Per-repo `.gitattributes`

```
*.kdbx diff=kdbx
*.kdbx -text -merge
```

The `-text` and `-merge` lines tell git not to attempt automatic line-merging on KDBX files (always conflict on concurrent changes; resolve via diff-kdbx and an external merge tool).

## Password handling

`diff-kdbx --textconv` is non-interactive. Pre-set the password:

```bash
export KDBX_DIFF_PASSWORD="..."
git diff path/to/vault.kdbx
```

Or use a key file:

```gitconfig
[diff "kdbx"]
    textconv = diff-kdbx --textconv --key-file ~/keepass.key
```

For a vault with a key file and no password, the key file alone is the key in textconv mode (no password variable needed). `--no-password` states it explicitly and ignores a stray `KDBX_DIFF_PASSWORD`:

```gitconfig
[diff "kdbx"]
    textconv = diff-kdbx --textconv --no-password --key-file ~/keepass.key
```

If the database requires a password as well, the env var must be set in the same environment as `git`.

## Caching

`cachetextconv = true` lets git cache the text representation of a file by blob hash, so repeated `git log -p` calls don't re-decrypt every commit. This is safe because the textconv output is deterministic, and worth it: each dump unlocks the vault and derives a fingerprint key at the vault's own KDF cost.

## Caveats

- `git log -p` over a long history can be slow on the first pass; the cache amortizes subsequent runs.
- `git blame` does not use textconv directly. It will still show binary diffs.
- Key files referenced by absolute path travel poorly across machines. Use a relative path that exists in every checkout, or set the env var per-machine.
