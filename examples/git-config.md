# Git integration recipes

## Per-user setup

Add to `~/.gitconfig`:

```gitconfig
[diff "kdbx"]
    textconv = diff-kdbx --textconv
    binary = true
```

Caching is deliberately absent: see "Caching" below before turning it on.

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

`cachetextconv = true` lets git cache the text representation of a file by blob hash, so repeated `git log -p` calls don't re-decrypt every commit (each dump unlocks the vault and derives a fingerprint key at the vault's own KDF cost). The cache is correct, because the dump is deterministic, but it is **opt-in for a reason**:

git stores cached textconv output as ordinary blobs under
`refs/notes/textconv/kdbx`. Those notes are not pushed by a plain `git push`,
but a mirror push (`git push --mirror`), a mirror clone of that remote, and
`git bundle create ... --all` do carry them. The dump holds everything that is
not a secret in plaintext: titles, user names, URLs, Notes, tags, unprotected
custom fields, attachment names. A repository whose `.kdbx` blobs are safe to
publish therefore stops being safe once its textconv cache travels with it.

Enable it per repository only where that is acceptable:

```bash
git config diff.kdbx.cachetextconv true
```

and drop the cache before any mirror push or bundle:

```bash
git update-ref -d refs/notes/textconv/kdbx
```

`diff-kdbx` refuses `--show-secrets` together with `--textconv`, so a cache can never hold protected values.

## Caveats

- `git log -p` over a long history can be slow on the first pass; the cache amortizes subsequent runs.
- `git blame` does not use textconv directly. It will still show binary diffs.
- Key files referenced by absolute path travel poorly across machines. Use a relative path that exists in every checkout, or set the env var per-machine.
