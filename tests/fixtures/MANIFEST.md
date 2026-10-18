# Test Fixtures Manifest

Each fixture pair under `tests/fixtures/<name>/` is a `before.kdbx` and an
`after.kdbx`. They are committed so a fresh `git clone` brings the full test
apparatus along. This manifest records, per fixture, its **origin**, **master
password**, **contents**, and **regeneration**.

## Common conventions

- **Master password (every fixture):** `test-password-do-not-use`. It is
  published; never put anything resembling real data in these files.
- **Generator:** `cargo run --features cli --bin gen-fixtures` rewrites every
  synthetic pair in one shot (`src/bin/gen_fixtures.rs`).
- **Reproducible content.** Every group and entry has a fixed UUID of the form
  `0000000n-d1ff-4000-8000-000000000000`, and every timestamp is fixed, so
  regenerating yields identical vault content and identical `--textconv` dumps.
  The encrypted bytes still change on each run, because KDBX draws fresh seeds
  and IVs on every save, so regenerating always shows up in `git status`.
- **Matched pairs.** Each `after` is a clone of `before` with one edit applied,
  so entries keep their UUIDs the way they do when a vault is edited in a
  KeePass client. Diffs therefore report the edit itself, not a remove plus add.
- **Format.** keepass 0.13+ can only write KDBX 4.1, so every synthetic fixture
  is KDBX 4.1. KDBX 4.0 read coverage comes from the frozen `legacy_kdbx40/`.

## The base vault

Most pairs start from the same vault (created `2026-01-01 09:00:00`):

```text
Root                      00000001
├── Personal              00000002
│   ├── Bank   (UserName alice, Password "old-password" [protected],
│   │           URL https://bank.example)                       00000011
│   └── Email  (UserName alice@example.com, Password [protected],
│               custom "otp" TOTP URI [protected])              00000012
└── Work                  00000003
    └── VPN    (UserName alice, Password [protected],
                URL https://vpn.example)                        00000013
```

(The number after each node is the leading 8 hex digits of its UUID, which is
also the `[uuid:...]` tag in the `--textconv` dump.) An edited entry gets every
timestamp moved to `2026-02-01 09:00:00`, except its creation time, as a client
does on save; default mode suppresses that noise.

## Synthetic fixtures (gen-fixtures)

| Fixture | `before` | Edit in `after` | Default-mode diff |
|---|---|---|---|
| `empty/` | Empty vault, root named Root | none | `(no changes)`, exit 0 |
| `add_entry/` | base | GitHub entry (octocat) added to Work | `+ ENTRY /Root/Work/GitHub` |
| `password_change/` | base | Bank password `old-password` -> `new-password` | `~ Password: <hash> -> <hash>` |
| `remove_entry/` | base | Email deleted | `- ENTRY /Root/Personal/Email` |
| `move_entry/` | base | VPN moved from Work to Personal | `~ ENTRY /Root/Work/VPN -> /Root/Personal/VPN` |
| `rename_group/` | base | Work renamed to Office | `~ GROUP /Root/Office (renamed: Work -> Office)`, no entry changes |
| `tag_diff/` | base | Bank tagged `finance` | `+ tag: finance` |
| `attachment_change/` | base, Bank has `recovery.txt` (`codes-v1`) | content becomes `codes-v2`; `statement.pdf` added | `~ attachment recovery.txt`, `+ attachment statement.pdf` |
| `custom_field/` | base | Email's protected `otp` seed rotated | `~ otp: <hash> -> <hash>` |
| `history_grew/` | base | Bank URL edited with history tracking | `~ URL: ...` and `H 1 history entries added` |
| `noisy_resave/` | base | every entry's access time and usage count bumped (an open-and-save with no edits) | `(no changes)`, exit 0, `6 suppressed`; `--strict` shows them, exit 1 |

Consumers: `tests/integration.rs` exercises every pair through the CLI.
`add_entry/` and `password_change/` also back `tests/determinism.rs`; the
git-driver and remote round-trip suites build their own vaults.

## Frozen fixtures (not regenerated)

### `legacy_kdbx40/vault.kdbx`

| | |
|---|---|
| Origin | The `add_entry/after.kdbx` written by gen-fixtures under keepass 0.12 (2026-04-28), frozen on 2026-10-18 when the crate moved to keepass 0.15, which cannot write KDBX 4.0 |
| Master password | `test-password-do-not-use` |
| Contents | KDBX 4.0. Unnamed root group with one entry: `Title=Test Entry`, `UserName=alice`, `Password=hunter2` (protected), `URL=https://example.com`. Random (unfixed) UUIDs. |
| Regen | None. Do not regenerate; it exists because the current generator cannot produce it. |

Consumers: `integration.rs::legacy_kdbx40_is_readable` (4.0 read coverage) and
`cross_version_diff_warns` (4.0 vs 4.1, the version-mismatch warning).

## Adding a fixture

Add a `pair(...)` call in `src/bin/gen_fixtures.rs` with fixed IDs (extend the
`id(n)` constants), regenerate, add an integration test, and add a row above.
Prefer a clone-plus-one-edit pair so the fixture isolates one behavior.

## Provenance categories

- **synthetic (gen-fixtures):** built with the keepass-rs API. Reproducible in
  content. The default for any new test.
- **frozen:** a file the current generator cannot produce (for example an older
  KDBX version). Never regenerated; document its origin here.
- **KeePassXC capture:** saved by a real KeePassXC build, for scenarios the
  keepass-rs API cannot express. Document the exact procedure per fixture.
- **external:** third-party files (test vectors, user-donated KDBX). Document
  attribution. Avoid unless necessary.
