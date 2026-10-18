# diff-kdbx

**Semantic diff for KeePass KDBX files.** A Rust library, a CLI, and a `git`
textconv driver. Put your password vault under version control and get
meaningful diffs out of `git diff`, `git log -p` and `git show` instead of
"Binary files differ."

```
$ diff-kdbx tests/fixtures/move_and_edit/before.kdbx tests/fixtures/move_and_edit/after.kdbx
summary: entries +0/-0/~1 (1 moved), groups +0/-0/~0 (0 moved), properties 1, database 0, suppressed 4
~ ENTRY /Personal/VPN (moved from /Work/VPN)
  ~ URL: https://vpn.example -> https://vpn2.example

$ diff-kdbx tests/fixtures/password_change/before.kdbx tests/fixtures/password_change/after.kdbx
summary: entries +0/-0/~1 (0 moved), groups +0/-0/~0 (0 moved), properties 1, database 0, suppressed 3
~ ENTRY /Personal/Bank
  ~ Password: <sealed:96ea7ab3> -> <sealed:8422c055>
```

Secrets are shown as keyed fingerprints, never in plaintext unless you ask.
Timestamp noise is suppressed by default. Output is deterministic (the
textconv contract). Exit codes mirror `/usr/bin/diff` (0 no changes, 1
changes, 2 error).

## Status

0.1.0, unreleased. diff-kdbx is built on
[`kdbx-core`](https://github.com/queelius/kdbx-core), the shared vault model
of the `*-kdbx` ecosystem: the library is a pure function of two
`kdbx_core::model::Snapshot`s and names no keepass type, so a keepass upgrade
never forces a new diff-kdbx release line. The CLI reads KDBX 3.1, 4.0 and
4.1 with keepass 0.15. See [CHANGELOG.md](CHANGELOG.md).

Until both crates are published, diff-kdbx depends on kdbx-core by path:
check the two repositories out side by side (`kdbx/diff-kdbx`,
`kdbx/kdbx-core`).

## Install

```bash
git clone https://github.com/queelius/kdbx-core.git
git clone https://github.com/queelius/diff-kdbx.git
cd diff-kdbx
cargo install --path . --features cli
```

Rust 1.89 or later (keepass 0.15 requires it).

## Quick start (no real data needed)

The repository ships synthetic fixtures with a published throwaway password.

```bash
export KDBX_DIFF_PASSWORD='test-password-do-not-use'
diff-kdbx tests/fixtures/move_and_edit/before.kdbx tests/fixtures/move_and_edit/after.kdbx
diff-kdbx --format=json tests/fixtures/password_change/before.kdbx tests/fixtures/password_change/after.kdbx
diff-kdbx --textconv tests/fixtures/password_change/after.kdbx     # what git sees
diff-kdbx --strict tests/fixtures/noisy_resave/before.kdbx tests/fixtures/noisy_resave/after.kdbx
```

## Git setup

Once per machine:

```bash
git config --global diff.kdbx.textconv 'diff-kdbx --textconv'
git config --global diff.kdbx.binary true
git config --global diff.kdbx.cachetextconv true
```

Once per repository:

```bash
echo '*.kdbx diff=kdbx' >> .gitattributes
git add .gitattributes && git commit -m 'diff kdbx files with diff-kdbx'
```

Then `git diff vault.kdbx`, `git log -p vault.kdbx` and `git show HEAD
vault.kdbx` show the textconv dumps' line diff. The driver never prompts: set
`KDBX_DIFF_PASSWORD` (and/or put `--key-file` in the textconv command) in the
shell that runs git. `cachetextconv` is safe because the dump is
deterministic, and it matters: each dump derives a fingerprint key with the
vault's own KDF cost (see below). More recipes: `examples/git-config.md`.

The driver definition lives in your git config, not in the repository, so a
fresh clone on another machine needs the `git config` step again.

## CLI

```
diff-kdbx [OPTIONS] <A> <B>            # diff two files (exit 0 / 1 / 2)
diff-kdbx [OPTIONS] --textconv <FILE>  # dump one file for git (never prompts)
diff-kdbx [OPTIONS] --dump <FILE>      # the same dump, for reading
diff-kdbx fingerprint --field <NAME> --entry <PATH-OR-UUID> [--key-file F] [--no-password] <VAULT>
```

| Option | Meaning |
|---|---|
| `--format text\|json` | Output of a two-file diff (default `text`) |
| `--strict` | Show noise too (timestamps that move on every save, UI state, settings timestamps); same meaning in diff and dump |
| `--include-recycle-bin` | Show the recycle bin group and its contents (hidden by default) |
| `--show-secrets` | Capture protected values in plaintext (warns on a non-TTY stdout) |
| `--key-file PATH` | Key file for both files |
| `--no-password` | The vault has no password (key file only) |
| `--separate-keys` | Different keys for A and B (`--key-file-a`, `--key-file-b`, `KDBX_DIFF_PASSWORD_A`, `KDBX_DIFF_PASSWORD_B`) |

**Key resolution** (first match wins): `--no-password` (requires
`--key-file`), then `KDBX_DIFF_PASSWORD`, then a TTY prompt (never in
`--textconv`; an empty answer with `--key-file` means no password), then the
key file alone.

## Output

**Text diff.** A summary line, `warning:` lines, then one record per changed
node: `+`/`-`/`~`, `GROUP` or `ENTRY`, and the node's vault path (the
ecosystem path grammar: no root-group name, `\/` escapes, `:2` for
same-named siblings ordered by UUID, trailing `/` for groups). A move is part
of the record (`(moved from /Work/VPN)`), so a moved-and-edited entry is one
record. Each changed property is one line: `+ label: value`, `- label:
value`, `~ label: before -> after`. Multi-line values (Notes) print as `| `
continuation lines, so they still diff line by line and can never forge a
structural line.

**Dump** (`--textconv`, `--dump`). A `DATABASE` block, then `GROUP <path>
[uuid:...]` and `ENTRY <path> [uuid:...]` blocks in tree order, each listing
every property in canonical order:

```
ENTRY /Personal/Bank [uuid:00000011-d1ff-4000-8000-000000000000]
  Title: Bank
  UserName: alice
  Password: <sealed:8422c055>
  URL: https://bank.example
  QualityCheck: true
  CreationTime: 2026-01-01T09:00:00Z
  Expires: false
```

The dump and the diff are built from the same per-node property map, so they
cannot disagree: everything the diff can report (fields and their protection
flags, tags, attachments, history items, times, icons, colors, auto-type,
custom data, group settings, `<Meta>` settings, the KDF and ciphers) is in
the dump.

**Values.** Sealed values show the first 8 hex characters of their
fingerprint (`<sealed:8422c055>`). A plain value whose protection flag is set
(a protected Title, or anything under `--show-secrets`) is marked
`(protected)`; a sealed value whose flag is off (a Password whose protection
was turned off) is marked `(unprotected)`, so turning protection off is a
visible change even when the value is not. Colors are `#RRGGBB`.

**Noise.** Default mode leaves out `LastAccessTime`, `UsageCount`,
`LastModificationTime`, `LocationChanged`, a node's previous parent, group
expansion, the generator stamp, last-selected and top-visible groups, the
`*Changed` settings timestamps, custom-data and custom-icon modification
times, and deleted-object tombstones, and counts what it left out.
`MasterKeyChanged` is never noise.

**Warnings.** `warning: KDBX version differs: 4.0 -> 4.1`, and `warning: KDF
weakened: ...` when the key derivation got cheaper to attack (Argon2 memory or
passes lowered, Argon2 replaced by AES-KDF, AES-KDF rounds lowered, or a
recognized KDF replaced by an unrecognized one).

## The JSON contract

`--format=json` (and `render_json` in the library) emits one document:

```json
{
  "format_version": 1,
  "fingerprint_key": {
    "params": {"memory_kib": 65536, "iterations": 3, "lanes": 1},
    "salt": "00000001-d1ff-4000-8000-000000000000"
  },
  "changes": [
    {
      "scope": "entry",
      "uuid": "00000011-d1ff-4000-8000-000000000000",
      "path": "/Personal/Bank",
      "status": "modified",
      "moved_from": null,
      "changes": [
        {
          "property": {"kind": "field", "key": "Password"},
          "before": {"type": "field", "value": {"protected": true, "value": {"sealed": "96ea7ab3...42ac"}}},
          "after": {"type": "field", "value": {"protected": true, "value": {"sealed": "8422c055...2e88"}}}
        }
      ]
    }
  ],
  "summary": {"entries_added": 0, "entries_removed": 0, "entries_modified": 1, "entries_moved": 0,
              "groups_added": 0, "groups_removed": 0, "groups_modified": 0, "groups_moved": 0,
              "node_properties": 1, "database_properties": 0, "suppressed": 3},
  "warnings": []
}
```

(Fingerprints are abbreviated here; the output has all 64 hex characters.)

- `changes[]` is ordered: the database record (`"scope": "database"`, with
  `changes`), then groups, then entries, each by path and then UUID. A node
  record has `uuid`, `path` (`null` for a node without a path, such as an
  entry with an empty title), and `status`: `added`, `removed`, or `modified`
  with `moved_from` and `changes`.
- A property is `{"kind", "key"}`: `field` (key: the field name), `tag`,
  `attachment`, `time` (key: the KDBX element name, such as `UsageCount`),
  `meta` (`DatabaseName`, `ProtectPassword`, ...), `header` (`Kdf`,
  `KdfMemory`, ...), `custom_data`, `history` (key: `{"item": {"modified",
  "index"}, "property": {...}}`), and the rest listed in the rustdoc of
  `Property`.
- A value is `{"type", "value"}`: `text`, `sealed` (64 hex), `field`
  (`{"protected", "value": {"plain": ...} | {"sealed": ...}}`), `bool`,
  `int`, `uint`, `time` (`YYYY-MM-DDTHH:MM:SSZ`), `uuid`, `color`
  (`#RRGGBB`), `icon`, `attachment`, `blob`, `present`, `format`, `kdf`,
  `outer_cipher`, `inner_cipher`, `compression`, `obfuscation`. A missing side
  of a change is `null`.
- `fingerprint_key` records how the fingerprint key was derived (Argon2id
  parameters and salt), so anyone holding the vault can reproduce every
  fingerprint; it is `null` when the key was not derived from a vault.
- Breaking any of this bumps `format_version`. Snapshot tests pin the shape
  for every fixture pair.

## Sealing and fingerprints

A secret never reaches the diff engine in plaintext unless you ask. The CLI
captures each file into a `kdbx-core` snapshot with **fingerprint sealing**:
every secret field value (protected, or the Password even when its flag is
off, but never the Title, which is the entry's address), every custom-data
value (KeePassXC keeps browser-integration keys there), and every
attachment's content is replaced by a **keyed fingerprint**,
HMAC-SHA256 under a per-vault key.

The key is derived with Argon2id from your password and key file, salted with
the vault's root group UUID. The parameters are the vault's own Argon2 memory,
passes and lanes when their cost (memory x passes) is at least that of a
floor of 64 MiB x 3 passes, and the floor otherwise (AES-KDF vaults always
get the floor). An unkeyed hash of a short secret is
a lookup table (a 4-digit PIN falls in 10,000 tries); a keyed fingerprint is
only as attackable as the vault itself. Consequences:

- Fingerprints are stable across runs (git textconv dumps each blob in a
  separate process), so an unchanged secret dumps identically.
- A two-file diff derives one key from file A's key material and root UUID,
  with the costlier of the two vaults' parameters (whole cost, not a
  per-component mix), so an unchanged secret compares equal even when the
  master password changed between the two; the master-key change itself is
  reported (`MasterKeyChanged`).
- In textconv output each blob uses its own key, so changing the master
  password changes every sealed value in that commit's `git diff`.
- Equal fingerprints within one vault reveal equal values (password reuse).
  That is useful for audits and a side channel worth knowing.
- Deriving the key costs about as much as unlocking the vault, once per file
  per run. Turn on `cachetextconv`.
- `--show-secrets` captures plaintext instead (attachments stay
  fingerprinted). It warns when stdout is not a terminal.

To check a recorded fingerprint (for example from an mcp-kdbx audit log),
print a field's full fingerprint with the vault's own key:

```bash
diff-kdbx fingerprint --field Password --entry /Personal/Bank vault.kdbx
diff-kdbx fingerprint --field otp --entry 00000012-d1ff-4000-8000-000000000000 vault.kdbx
```

Its first 8 characters match the `<sealed:...>` in that vault's dump.

## Library

```rust
use diff_kdbx::kdbx_core::capture::keepass_0_15::{capture, header};
use diff_kdbx::kdbx_core::fingerprint::{DeriveParams, FingerprintKey, KeyMaterial};
use diff_kdbx::kdbx_core::model::Sealing;
use diff_kdbx::{DiffOptions, JsonOptions, compute, dump, render_json, render_text};

// Open with keepass 0.15 (kdbx-core feature "keepass-0_15"), then:
let params = DeriveParams::for_header(Some(&header(&db_a)));
let material = KeyMaterial::new(Some(b"password".as_slice()), None);
let key = FingerprintKey::derive(&material, db_a.root().id().uuid(), &params)?;
let a = capture(&db_a, &Sealing::Fingerprint(&key));
let b = capture(&db_b, &Sealing::Fingerprint(&key));

let cs = compute(&a, &b, &DiffOptions::default());
print!("{}", render_text(&cs));
print!("{}", render_json(&cs, &JsonOptions::default()));
print!("{}", dump(&a, &Default::default()));
```

A process that only compares within itself (an editor's staged diff, say)
can seal with `FingerprintKey::from_bytes` and a random key, and skip the
KDF. The library performs no I/O, reads no clock, depends on no keepass
version, and builds for `wasm32-unknown-unknown`.

## How it differs from `keepass-diff`

[`keepass-diff`](https://crates.io/crates/keepass-diff) is an existing CLI
that compares two KDBX files. diff-kdbx exists for a different job, version
control of a vault:

- a git textconv mode with a deterministic, line-safe dump of every property;
- identity by UUID, so moves, renames and moved-and-edited entries are single
  records rather than a removal plus an addition;
- secrets as keyed fingerprints, so a diff can say "the password changed"
  without printing it or a crackable hash of it;
- typed noise suppression for the timestamps every save touches;
- a library API over a keepass-free snapshot and a versioned JSON contract
  for other tools (mcp-kdbx uses it for staged-change diffs).

## Security notes

- The `.kdbx` stays encrypted in git; a remote sees only ciphertext.
- `KDBX_DIFF_PASSWORD` lives in your environment and can leak through shell
  history, `/proc/<pid>/environ`, or child processes. Treat it like any
  password variable.
- Git keeps history: a secret committed once stays in every clone.
- In `--textconv` mode stdout is all-or-nothing: on any error git gets empty
  output and a nonzero exit, never a partial dump.
- Titles are never sealed (they are addresses). A vault that needs secret
  titles is out of scope.

## Troubleshooting

- **"Binary files differ"**: the driver is not configured in this shell
  (`git config --get diff.kdbx.textconv`), `.gitattributes` lacks `*.kdbx
  diff=kdbx`, or `KDBX_DIFF_PASSWORD` is not set (the driver fails closed).
- **"Error: unlocking ..."**: wrong password or key file. Test with
  `diff-kdbx --dump vault.kdbx`. For a vault without a password, pass
  `--key-file` (and `--no-password` to be explicit).
- **Slow `git log -p`**: every dump derives a fingerprint key at the vault's
  KDF cost. Enable `cachetextconv`.

## Where to go next

| You want to | Read |
|---|---|
| Report a bug | [Issues](https://github.com/queelius/diff-kdbx/issues) |
| Understand the design | `kdbx-core`'s `docs/superpowers/specs/2026-10-18-kdbx-core-design.md` (section 4) and this repo's `docs/superpowers/specs/2026-04-27-diff-kdbx-design.md` |
| Add a test or fixture | `docs/testing.md` and `tests/fixtures/MANIFEST.md` |
| See git config recipes | `examples/git-config.md` |

## License

MIT. See [LICENSE](LICENSE).
