# Test Fixtures Manifest

Each fixture pair under `tests/fixtures/<name>/` is a `before.kdbx` and an
`after.kdbx`. They are committed so a fresh `git clone` brings the full test
apparatus along. This manifest records, per fixture, its **origin**, **master
password**, **contents**, and **regeneration**.

## Common conventions

- **Master password (every fixture):** `test-password-do-not-use`. It is
  published; never put anything resembling real data in these files.
- **Generator:** `cargo run --example gen_fixtures` rewrites every
  synthetic pair in one shot (`examples/gen_fixtures.rs`).
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
- **Cheap KDF.** Every synthetic vault uses Argon2id with 1 MiB, 2 passes and
  1 lane, so opening it is fast and the CLI's fingerprint key derivation runs
  at its floor (64 MiB x 3 passes); a vault whose KDF costs more than the
  floor makes every derivation cost as much as its own. `kdf_downgrade/`
  varies the KDF on purpose.
- **Frozen times.** Every node's seven `<Times>` values are fixed, creation
  included (the 0.2 generator kept keepass's "now" creation time on entries,
  so their dumps were not reproducible).

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

(The number after each node is the leading 8 hex digits of its UUID; the
`--textconv` dump prints the full UUID as `[uuid:...]`.) An edited entry gets every
timestamp moved to `2026-02-01 09:00:00`, except its creation time, as a client
does on save; default mode suppresses that noise.

## Synthetic fixtures (gen-fixtures)

| Fixture | `before` | Edit in `after` | Default-mode diff |
|---|---|---|---|
| `empty/` | Empty vault, root named Root | none | `(no changes)`, exit 0 |
| `add_entry/` | base | GitHub entry (octocat) added to Work | `+ ENTRY /Work/GitHub` |
| `password_change/` | base | Bank password `old-password` -> `new-password` | `~ Password: <sealed:...> -> <sealed:...>` |
| `remove_entry/` | base | Email deleted | `- ENTRY /Personal/Email` |
| `move_entry/` | base | VPN moved from Work to Personal | `~ ENTRY /Personal/VPN (moved from /Work/VPN)` |
| `move_and_edit/` | base | VPN moved to Personal and its URL edited | one record: the move and `~ URL: ...` |
| `rename_group/` | base | Work renamed to Office | `~ GROUP /Office/` with `~ Name: Work -> Office`, no entry changes |
| `move_and_rename_group/` | base | Work moved under Personal and renamed Office | one record: `~ GROUP /Personal/Office/ (moved from /Work/)` with the Name change |
| `tag_diff/` | base | Bank tagged `finance` | `+ Tag[finance]` |
| `attachment_change/` | base, Bank has `recovery.txt` (`codes-v1`) | content becomes `codes-v2`; `statement.pdf` added | `~ Attachment[recovery.txt]`, `+ Attachment[statement.pdf]` |
| `custom_field/` | base | Email's protected `otp` seed rotated | `~ otp: <sealed:...> -> <sealed:...>` |
| `history_grew/` | base | Bank URL edited with history tracking | `~ URL: ...` and `+ History[2026-01-01T09:00:00Z].*` lines |
| `history_at_cap/` | base, history cap 3, three tracked URL edits (history items from 2026-01-01, -02, -03) | a fourth tracked edit, oldest item trimmed | `~ URL`, `- History[2026-01-01T09:00:00Z].*`, `+ History[2026-01-04T09:00:00Z].*` |
| `noisy_resave/` | base | every entry's access time and usage count bumped (an open-and-save with no edits) | `(no changes)`, exit 0, `suppressed 6`; `--strict` shows them, exit 1 |
| `protected_title/` | base | Bank's Title set protected (same value) | `~ Title: Bank -> Bank (protected)`; the path stays `/Personal/Bank` |
| `notes_injection/` | base | Bank's Notes set to lines imitating `+ ENTRY`, `~ GROUP`, `ENTRY ... [uuid:...]` | `+ Notes:` with `      \| ...` continuation lines; no forged structural line |
| `protection_toggle/` | base | Email's `otp` and Bank's Password set unprotected (same values) | `~ Password: <sealed:x> -> <sealed:x> (unprotected)`; `~ otp: <sealed:...> -> otpauth://...` |
| `override_url/` | base | Bank gains a URL override | `+ OverrideURL: cmd://firefox --private-window {URL}` |
| `trash_entry/` | base plus a Recycle Bin group (UUID `00000004`) set as the recycle bin | Email moved into the recycle bin | `- ENTRY /Personal/Email`; with `--include-recycle-bin`, `~ ENTRY /Recycle Bin/Email (moved from /Personal/Email)` |
| `recycle_bin_root/` | base with the recycle-bin UUID set to the root group | Bank's UserName alice -> bob | `~ UserName: alice -> bob` (the root is never hidden) |
| `kdf_downgrade/` | base with Argon2id 2 MiB, 4 passes | Argon2id 1 MiB, 2 passes | `~ KdfMemory`, `~ KdfIterations` and two `warning: KDF weakened:` lines |
| `format_tour/` | its own vault: Tour/Card (every property kind: a protected Password `pa"ss\wo` + newline + `rd-` + non-ASCII, a protected custom `PIN`, a custom field named `Tag[x]`, Notes with a blank line, a protected attachment, auto-type with two associations for one window, sealed custom data `KPXC_BROWSER`, three history items: two sharing 2026-01-02 09:00, one without a time), an untitled entry, Old/Moved | Notes edited, Password protection off, tags `work` -> `a]b`, attachment `backup.key` added, icon 0 -> 12, second association edited, custom data rotated, the second same-time history item rewritten and the untimed one dropped, untitled entry's UserName edited, Moved moved to Tour | every documented form (see `docs/FORMAT.md`, whose examples are this pair's output) |

### `keyfile_only/` (synthetic, single vault)

The base vault saved with **no password**: its key is the key file
`keyfile_only/vault.key` (published bytes, keepass hashes them). Consumers:
`integration.rs::keyfile_only_vault_opens_with_its_key_file` (textconv with
`--key-file` alone, and `--no-password`).

Consumers: `tests/snapshots.rs` pins the text, JSON and dump output of every
pair (it iterates this directory, so a new pair is covered automatically);
`tests/integration.rs` exercises every pair through the CLI. `add_entry/` and
`password_change/` also back `tests/determinism.rs`, the git-driver and
remote round-trip suites; `tests/cli.rs` builds its own vaults.

## Frozen fixtures (not regenerated)

### `legacy_kdbx40/vault.kdbx`

| | |
|---|---|
| Origin | The `add_entry/after.kdbx` written by gen-fixtures under keepass 0.12 (2026-04-28), frozen on 2026-10-18 when the crate moved to keepass 0.15, which cannot write KDBX 4.0 |
| Master password | `test-password-do-not-use` |
| Contents | KDBX 4.0. Unnamed root group with one entry: `Title=Test Entry`, `UserName=alice`, `Password=hunter2` (protected), `URL=https://example.com`. Random (unfixed) UUIDs. |
| Regen | None. Do not regenerate; it exists because the current generator cannot produce it. |

Its KDF is keepass-rs's default (Argon2d, 1 MiB, 50 passes, 4 lanes), which
costs less than the fingerprint-key floor, so its key derives at the floor.

Consumers: `integration.rs::legacy_kdbx40_is_readable` (4.0 read coverage),
`cross_version_diff_warns` (4.0 vs 4.1, the version-mismatch warning), and
`snapshots.rs::legacy_kdbx40_dump_is_pinned`.

## Adding a fixture

Add a `pair(...)` call in `examples/gen_fixtures.rs` with fixed IDs (extend the
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
