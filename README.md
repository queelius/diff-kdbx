# diff-kdbx

**Semantic diff for KeePass KDBX files.** A Rust library, a CLI, and a `git`
textconv driver. Put your password vault under version control and get
meaningful diffs out of `git diff`, `git log -p` and `git show` instead of
"Binary files differ."

```
$ diff-kdbx tests/fixtures/move_and_edit/before.kdbx tests/fixtures/move_and_edit/after.kdbx
summary: entries +0/-0/~1 (1 moved), groups +0/-0/~0 (0 moved), properties 1, database 0, suppressed 4
~ ENTRY "/Personal/VPN" (moved from "/Work/VPN")
  ~ URL: "https://vpn.example" -> "https://vpn2.example"

$ diff-kdbx tests/fixtures/password_change/before.kdbx tests/fixtures/password_change/after.kdbx
summary: entries +0/-0/~1 (0 moved), groups +0/-0/~0 (0 moved), properties 1, database 0, suppressed 3
~ ENTRY "/Personal/Bank"
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
4.1 with keepass 0.15. See [CHANGELOG.md](https://github.com/queelius/diff-kdbx/blob/main/CHANGELOG.md).

## Install

```bash
cargo install diff-kdbx --features cli
```

Rust 1.89 or later (keepass 0.15 requires it). The library alone (no
keepass, no KDF, WASM-ready) is `diff-kdbx = "0.1"` in `Cargo.toml`.

From source, check out [kdbx-core](https://github.com/queelius/kdbx-core)
next to this repository (the development build depends on it by path,
`../kdbx-core`):

```bash
git clone https://github.com/queelius/kdbx-core.git
git clone https://github.com/queelius/diff-kdbx.git
cd diff-kdbx && cargo install --path . --features cli
```

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
```

Once per repository:

```bash
echo '*.kdbx diff=kdbx' >> .gitattributes
git add .gitattributes && git commit -m 'diff kdbx files with diff-kdbx'
```

Then `git diff vault.kdbx`, `git log -p vault.kdbx` and `git show HEAD
vault.kdbx` show the textconv dumps' line diff. The driver never prompts: set
`KDBX_DIFF_PASSWORD` (and/or put `--key-file` in the textconv command) in the
shell that runs git. More recipes: [examples/git-config.md](https://github.com/queelius/diff-kdbx/blob/main/examples/git-config.md).

### Caching textconv output (opt-in, read this first)

Each dump unlocks the vault and derives a fingerprint key at the vault's own
KDF cost, so `git log -p` over a long history is slow. git can cache textconv
output (`git config diff.kdbx.cachetextconv true`), and the dump is
deterministic, so the cache is correct. It is **not** private:

git stores cached textconv output as ordinary blobs under
`refs/notes/textconv/kdbx`. Those notes are not pushed by a plain `git push`,
but a mirror push (`git push --mirror`), a mirror clone of that remote, and
`git bundle create ... --all` do carry them. The dump holds everything that is
not a secret in plaintext: titles, user names, URLs, Notes, tags, unprotected
custom fields, attachment names. A repository whose `.kdbx` blobs are safe to
publish therefore stops being safe once its textconv cache travels with it.

Turn caching on only for repositories that never leave your machines in
mirror or bundle form, or remove the cache before mirroring
(`git update-ref -d refs/notes/textconv/kdbx`). `--show-secrets` is refused
together with `--textconv` for the same reason.

The driver definition lives in your git config, not in the repository, so a
fresh clone on another machine needs the `git config` step again.

## CLI

```
diff-kdbx [OPTIONS] <A> <B>            # diff two files (exit 0 / 1 / 2)
diff-kdbx [OPTIONS] --textconv <FILE>  # dump one file for git (never prompts)
diff-kdbx [OPTIONS] --dump <FILE>      # the same dump, for reading
diff-kdbx fingerprint --field <NAME> --entry <PATH-OR-UUID> [--params P] [--salt UUID] [--key-file F] [--no-password] <VAULT>
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
`--textconv`), then the key file alone. An empty password, from the variable
or the prompt, together with a key file means the vault has no password.
With `--separate-keys`, each side resolves on its own (`--key-file-a`,
`KDBX_DIFF_PASSWORD_A`, and so on); `--key-file` is refused there because it
would be ambiguous.

## Output

**Text diff.** A summary line, `warning:` lines, then one record per changed
node: `+`/`-`/`~`, `GROUP` or `ENTRY`, and the node's vault path as a quoted
token (the ecosystem path grammar inside: no root-group name, `\/` escapes,
`:2` for same-named siblings ordered by UUID, trailing `/` for groups). A move
is part of the record (`~ ENTRY "/Personal/VPN" (moved from "/Work/VPN")`), so
a moved-and-edited entry is one record. Each changed property is one line:
`+ label: value`, `- label: value`, `~ label: before -> after`. Multi-line
values (Notes) print as `|` continuation lines, so they can never forge a
structural line; a modified multi-line value prints both full sides (`- |`
lines, then `+ |` lines), not a line-by-line diff of them.

**Dump** (`--textconv`, `--dump`). A `DATABASE` block, then `GROUP <path>
[uuid:...]` and `ENTRY <path> [uuid:...]` blocks in tree order, each listing
every property in canonical order:

```
ENTRY "/Personal/Bank" [uuid:00000011-d1ff-4000-8000-000000000000]
  Title: "Bank"
  UserName: "alice"
  Password: <sealed:8422c055>
  URL: "https://bank.example"
  "otp": <sealed:af5c6854>
  Tag["finance"]
  QualityCheck: true
  CreationTime: 2026-01-01T09:00:00Z
  Expires: false
```

The dump and the diff are built from the same per-node property map, so they
cannot disagree: everything the diff can report (fields and their protection
flags, tags, attachments, history items, times, icons, colors, auto-type,
custom data, group settings, `<Meta>` settings, the KDF and ciphers) is in
the dump.

**Grammar.** Every line reads back unambiguously, which matters because
the dump is what git diffs. The complete production list for both formats
is [docs/FORMAT.md](https://github.com/queelius/diff-kdbx/blob/main/docs/FORMAT.md)
(also in the crate package); in short: Closed-set names are bare: the five standard
fields (`Title`, `UserName`, `Password`, `URL`, `Notes`), typed keys
(`CreationTime`, `ProtectPassword`, `Kdf`, ...), UUIDs, timestamps, numbers,
`true`/`false`, `<sealed:...>`. Every vault-controlled string printed next to
that syntax is one double-quoted token with backslash escapes (`\"`, `\\`,
`\n`, `\u{XXXX}`): a custom field's name (`"otp": ...`), the vault part of a
bracketed key (`Tag["a]b"]`, `Attachment["codes.txt"]`, `CustomData["k"]`,
`AutoType.Association["Bank*"]`), a plain single-line value (`URL: "b -> c"`)
and a node path (`ENTRY "/Personal/Bank"`). So a custom field named
`Tag[x]` or `History[...].Password`, a value `<sealed:2668135c>` or `a -> b`,
or a title imitating `(moved from ...)` can never pass for anything else.
Multi-line values (Notes) print as continuation lines (`    | line`), whose
content cannot be mistaken for a property line.

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
recognized KDF replaced by an unrecognized one). The warning compares each
parameter on its own, deliberately conservative: lowering the memory warns
even when more passes keep the total cost equal. Fingerprint key derivation,
by contrast, compares whole cost (memory x passes).

## The JSON contract

`--format=json` (and `render_json` in the library, the only way to get JSON:
the public types do not implement `Serialize`) emits one document whose
shape diff-kdbx defines itself, leaf by leaf:

```json
{
  "format_version": 1,
  "fingerprint_key": {
    "params": "argon2id$v=19$m=65536,t=3,p=1",
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
          "before": {"type": "field", "protected": true, "sealed": "96ea7ab3...42ac"},
          "after": {"type": "field", "protected": true, "sealed": "8422c055...2e88"}
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

- `changes[]` is ordered: the database record (`{"scope": "database",
  "changes": [...]}`), then groups, then entries, each by path and then UUID.
  A node record has `uuid`, `path` (`null` for a node without a path), and
  `status`: `added`, `removed`, or `modified` with `moved_from` and `changes`.
- A property is `{"kind", ...}`: `{"kind": "field", "key": "<name>"}` (the
  same for `tag`, `attachment`, `custom_data`, `custom_data_modified`,
  `public_custom_data`; `time`, `meta`, `header`, `color`, `auto_type`,
  `group_flag` with their KDBX names as `key`; `custom_icon`,
  `custom_icon_name`, `custom_icon_modified`, `deleted_object` with a UUID),
  `{"kind": "auto_type_association", "window", "occurrence"}`,
  `{"kind": "history", "modified": "<time>" | null, "index", "property": {...}}`,
  or a bare kind (`name`, `format`, `notes`, `override_url`, `quality_check`,
  `icon`, `previous_parent`). JSON counters are 0-based (`index`,
  `occurrence`); the text format's `#N` is 1-based (`#2` is index 1), like
  the path grammar's `:N`.
- A value is `{"type", ...}`:
  `{"type": "field", "protected": bool, "text": "..."}` or
  `{"type": "field", "protected": bool, "sealed": "<64 hex>"}`,
  `{"type": "text", "text": "..."}`, `{"type": "sealed", "sealed": "<64 hex>"}`,
  `{"type": "attachment", "size", "sealed", "protected"}`,
  `{"type": "blob", "size", "sealed"}`,
  `{"type": "icon", "standard": N}` or `{"type": "icon", "custom": "<uuid>"}`,
  `{"type": "present"}`, and `{"type": T, "value": V}` for `bool`, `int`,
  `uint`, `time` (`"YYYY-MM-DDTHH:MM:SSZ"`), `uuid`, `color` (`"#RRGGBB"`),
  `format` (`"4.1"`), `kdf` (`aes_kdf`, `argon2d`, `argon2id`), `outer_cipher`
  (`aes256`, `twofish`, `chacha20`), `inner_cipher` (`plain`, `salsa20`,
  `chacha20`), `compression` (`none`, `gzip`) and `obfuscation` (`none`,
  `use_clipboard`); an enum value a newer KDBX writer adds is
  `"unrecognized"`. A missing side of a change is `null`.
- Warnings: `{"kind": "version_mismatch", "before": "4.0", "after": "4.1"}`
  and `{"kind": "kdf_weakened", "aspect": "memory_lowered" |
  "iterations_lowered" | "rounds_lowered", "before": N, "after": N}`,
  `{"kind": "kdf_weakened", "aspect": "no_longer_memory_hard", "before":
  "<kdf>", "after": "<kdf>"}`, `{"kind": "kdf_weakened", "aspect":
  "unrecognized", "before": "<kdf>"}`.
- `fingerprint_key` records how the fingerprint key was derived: `params` in
  its recorded form `argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>` (exactly
  what `diff-kdbx fingerprint --params` accepts) and `salt` (a root-group
  UUID), so anyone holding the vault can reproduce every fingerprint; it is
  `null` when the key was not derived from a vault.
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
  per run (see "Caching textconv output" for the opt-in cache and its
  exposure).
- `--show-secrets` captures plaintext instead (attachments stay
  fingerprinted). It warns when stdout is not a terminal and is refused with
  `--textconv`.

In a two-file diff, **B's fingerprints are made with A's key** (A's key
material and root UUID). If A's password was rotated because it leaked, the
diff's fingerprints of B's secrets are only as safe as that leaked password
(and the KDF cost): treat that output like the old vault.

**Verifying a recorded fingerprint.** `diff-kdbx fingerprint` prints one
field's full fingerprint. It opens the vault with your key, captures it with
fingerprint sealing (so a secret's sealed value is printed as is; a plain
field is fingerprinted with the same key), and derives the key from **that
vault's key material**:

```bash
# As the vault's own --textconv / --dump shows it (its own params and root UUID):
diff-kdbx fingerprint --field Password --entry /Personal/Bank vault.kdbx
diff-kdbx fingerprint --field otp --entry 00000012-d1ff-4000-8000-000000000000 vault.kdbx
# As recorded elsewhere: params in DeriveParams' recorded form, salt a root UUID
diff-kdbx fingerprint --field Password --entry /Personal/Bank \
    --params 'argon2id$v=19$m=65536,t=3,p=1' --salt 00000001-d1ff-4000-8000-000000000000 b.kdbx
```

It can verify: the vault's own dump (first 8 characters match its
`<sealed:...>`); a two-file diff's fingerprints of either side, given the
JSON's `fingerprint_key.params` and `salt` and **side A's key material** (it
uses the key you open the given vault with, so B's values verify directly
only when A and B share a password and key file); and records that store
the derivation parameters, such as mcp-kdbx audit logs (salt: the vault's
root UUID unless recorded otherwise). It cannot verify attachments or
custom-data values (only fields), or anything sealed with a random
per-session key.

## Library

```rust
use diff_kdbx::kdbx_core::capture::keepass_0_15::{capture, header};
use diff_kdbx::kdbx_core::fingerprint::{DeriveParams, FingerprintKey, KeyMaterial};
use diff_kdbx::kdbx_core::model::Sealing;
use diff_kdbx::{
    DiffOptions, JsonOptions, TextOptions, compute, dump, render_json, render_text,
};

// Open with keepass 0.15 (kdbx-core feature "keepass-0_15"), then:
let params = DeriveParams::for_header(Some(&header(&db_a)));
let material = KeyMaterial::new(Some(b"password".as_slice()), None);
let key = FingerprintKey::derive(&material, db_a.root().id().uuid(), &params)?;
let a = capture(&db_a, &Sealing::Fingerprint(&key));
let b = capture(&db_b, &Sealing::Fingerprint(&key));

let cs = compute(&a, &b, &DiffOptions::default());
print!("{}", render_text(&cs, &TextOptions::default()));
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

- The `.kdbx` stays encrypted in git; a remote sees only ciphertext, unless
  textconv output travels with it (see "Caching textconv output").
- **Only secrets are sealed.** A dump or diff shows every other value in
  plaintext: titles, user names, URLs, tags, attachment names, unprotected
  custom fields and, notably, **Notes**, which many people treat as private.
  KeePass does not protect Notes by default. Mark a field protected (or keep
  sensitive notes in a protected custom field) if its content must not appear
  in diffs, terminals, logs or caches.
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
- **Slow `git log -p`**: every dump unlocks the vault and derives a
  fingerprint key at the vault's KDF cost. `cachetextconv` helps, with the
  exposure described under "Caching textconv output".

## Where to go next

| You want to | Read |
|---|---|
| Report a bug | [Issues](https://github.com/queelius/diff-kdbx/issues) |
| Understand the design | [kdbx-core design spec](https://github.com/queelius/kdbx-core/blob/main/docs/superpowers/specs/2026-10-18-kdbx-core-design.md) (section 4: diff-kdbx), the [diff-kdbx 0.1 plan and decisions](https://github.com/queelius/diff-kdbx/blob/main/docs/superpowers/plans/2026-10-18-diff-kdbx-snapshot-0.1.md), and the [original design](https://github.com/queelius/diff-kdbx/blob/main/docs/superpowers/specs/2026-04-27-diff-kdbx-design.md) |
| Add a test or fixture | [docs/testing.md](https://github.com/queelius/diff-kdbx/blob/main/docs/testing.md) and [tests/fixtures/MANIFEST.md](https://github.com/queelius/diff-kdbx/blob/main/tests/fixtures/MANIFEST.md) |
| See git config recipes | [examples/git-config.md](https://github.com/queelius/diff-kdbx/blob/main/examples/git-config.md) |

## License

MIT. See [LICENSE](https://github.com/queelius/diff-kdbx/blob/main/LICENSE).
