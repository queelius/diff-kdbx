# diff-kdbx text formats

The two line-oriented outputs of diff-kdbx: the **dump** (`--textconv`,
`--dump`, the library's `dump`), which git diffs, and the **text diff** (a
two-file diff, `render_text`). Both are built from the same per-node
property map and share every label and value form below. The JSON output has
its own contract (README, "The JSON contract").

The grammar is written in EBNF-style productions: `"x"` is literal text, `[ x ]`
is optional, `{ x }` repeats zero or more times, `NL` is a line feed. Every
output line is one printable line: no raw control characters, no trailing
whitespace, no carriage returns.

## Lexical forms

```ebnf
token     = '"' , { char | escape } , '"' ;
escape    = "\\" | '\"' | "\n" | "\t" | "\r" | "\u{" , hex , { hex } , "}" ;
```

A **token** is `kdbx_core::text::quote(s)`: the `kdbx_core::text::escape_inline`
escapes (`\\`, `\n`, `\t`, `\r`, and `\u{XXXX}`, uppercase hex with at least
four digits, for every other character of Unicode category Cc, Cf, Zl or Zp)
plus `\"` for a double quote. `kdbx_core::text::unquote` reverses it exactly.
Every vault-controlled string printed next to renderer syntax is a token: a
custom field name, the vault part of a bracketed key, a plain single-line
value, a node path.

```ebnf
path      = token ;   (* body: a vault path, see below *)
uuid      = hex8 , "-" , hex4 , "-" , hex4 , "-" , hex4 , "-" , hex12 ;   (* lowercase *)
time      = year , "-" , month , "-" , day , "T" , hh , ":" , mm , ":" , ss , "Z" ;
sealed    = "<sealed:" , hex8 , ">" ;   (* first 8 hex of the keyed fingerprint *)
n         = digit , { digit } ;
ordinal   = "#" , n ;                   (* 1-based, only for the 2nd and later *)
```

A **path** token's body is a vault path in the ecosystem grammar
(`kdbx_core::path::VaultPath::format`): rooted at `/`, the root group's own
name omitted, `\/` and `\:` escaping slash and colon inside a name, `:N`
(1-based, by UUID) picking among same-named siblings, a trailing `/` for a
group. Read it back with `unquote`, then `VaultPath::parse`.

## Labels

```ebnf
label     = standard  | token                                   (* custom field *)
          | typed-key | keyed | "History[" , ( time | "unknown" ) , [ ordinal ] , "]." , label ;
standard  = "Title" | "UserName" | "Password" | "URL" | "Notes" ;
keyed     = "Tag[" , token , "]" | "Attachment[" , token , "]"
          | "CustomData[" , token , "]" , [ ".Modified" ]
          | "PublicCustomData[" , token , "]"
          | "AutoType.Association[" , token , [ ordinal ] , "]"
          | "CustomIcon[" , uuid , "]" , [ ".Name" | ".Modified" ]
          | "DeletedObject[" , uuid , "]" ;
typed-key = "Name" | "Version" | "Notes" | "Icon" | "QualityCheck" | "OverrideURL"
          | "ForegroundColor" | "BackgroundColor" | "PreviousParentGroup"
          | "AutoType." , ( "Enabled" | "DefaultSequence" | "DataTransferObfuscation" )
          | time-key | group-flag | meta-key | header-key ;
time-key  = "CreationTime" | "LastModificationTime" | "LastAccessTime" | "ExpiryTime"
          | "Expires" | "UsageCount" | "LocationChanged" ;
group-flag = "IsExpanded" | "EnableAutoType" | "EnableSearching" | "DefaultAutoTypeSequence" ;
header-key = "Kdf" | "KdfRounds" | "KdfMemory" | "KdfIterations" | "KdfParallelism"
          | "KdfVersion" | "OuterCipher" | "InnerCipher" | "Compression" ;
meta-key  = (* the KDBX <Meta> element name: "DatabaseName", "RecycleBinUUID",
               "ProtectPassword", "MasterKeyChanged", ... *) ;
```

Closed-set names are bare; anything a vault supplies is a token, so a custom
field named `Tag[x]` prints as `"Tag[x]"` and can never pass for a tag. A
history item is `History[<time>]` (or `History[unknown]` without a
modification time) followed by `#N` when it is the N-th item sharing that time
in its own snapshot (document order, 1-based; the first has no ordinal). In a
diff, a removed item is numbered in the before snapshot and an added or
modified item in the after snapshot, so a label always names the same item as
that snapshot's dump. `AutoType.Association["w"#N]` is the N-th association
for window `w` (1-based, the first has no ordinal).

## Values

```ebnf
value     = text | sealed-value | attachment | blob | icon
          | n | "-" , n | "true" | "false" | time | uuid | color | version | name ;
text      = token , [ " (protected)" ] ;
sealed-value = sealed , [ " (unprotected)" ] ;
attachment = sealed , " (" , n , " bytes" , [ ", protected" ] , ")" ;
blob      = sealed , " (" , n , " bytes)" ;       (* a custom icon's image *)
icon      = "standard " , n | "custom " , uuid ;
color     = "#" , hex6 ;                            (* uppercase *)
version   = n , "." , n ;
name      = (* a closed-set name: "Argon2id", "AES-KDF", "AES-256", "ChaCha20",
               "Salsa20", "gzip", "none", "use-clipboard", "unrecognized", ... *) ;
```

A plain value is a token; ` (protected)` marks a plain value whose protection
flag is set (a protected Title, or anything captured with `--show-secrets`).
A sealed value shows the first 8 hex characters of its keyed fingerprint;
` (unprotected)` marks a sealed value whose flag is off (a Password whose
protection was turned off). Nothing else can produce `<sealed:`, a marker, or
` -> `, because every vault string sits inside a token.

**Multi-line values** (Notes by field trait, a group's Notes, the database
description) are not tokens. Their line is `label:` (plus ` (protected)` when
marked), followed by one continuation line per value line:

```ebnf
multiline = label , ":" , [ " (protected)" ] , NL , { cont } ;
cont      = indent , "|" , [ " " , escaped ] , NL ;   (* a blank value line is the bare "|" *)
```

where `escaped` is `kdbx_core::text::escape_inline` of the value line and
`indent` depends on the context (below). A line of only spaces is content and
keeps them.

## The dump

```ebnf
dump      = "DATABASE" , NL , { prop } , { block } ;
block     = ( "GROUP" | "ENTRY" ) , " " , address , NL , { prop } ;
address   = path , " [uuid:" , uuid , "]" | "(no path) [uuid:" , uuid , "]" ;
prop      = "  " , label , NL                              (* presence: tags, ... *)
          | "  " , label , ":" , " " , value , NL
          | "  " , multiline ;                             (* indent = "    " *)
```

Blocks come in tree order (a group directly before its contents, pathless
nodes last), properties in canonical order. A node has no path when it or an
ancestor has an empty name. Noise (access and modification times, usage
counts, UI state, `*Changed` settings timestamps, tombstones) appears only
with `--strict`.

<!-- checked: dump -->
```text
ENTRY "/Tour/Card" [uuid:00000021-d1ff-4000-8000-000000000000]
  Title: "Card"
  Password: <sealed:8d7ca101> (unprotected)
  URL: "https://card.example"
  Notes:
    | line one
    |
    | line 3
  "PIN": <sealed:7bd6a759>
  "Tag[x]": "a -> b"
  Tag["a]b"]
  Attachment["key.pem"]: <sealed:9fe344a1> (40 bytes, protected)
  Icon: standard 12
  AutoType.Association["Bank*"#2]: "{USERNAME}{ENTER}"
  CustomData["KPXC_BROWSER"]: <sealed:2e7eb066>
  History[2026-01-02T09:00:00Z].URL: "https://card.example/v2"
  History[2026-01-02T09:00:00Z#2].URL: "https://card.example/v1-rewritten"
```

## The text diff

```ebnf
diff      = summary , NL , { warning , NL } , ( "(no changes)" , NL | { record } ) ;
summary   = "summary: entries +" , n , "/-" , n , "/~" , n , " (" , n , " moved), groups +" ,
            n , "/-" , n , "/~" , n , " (" , n , " moved), properties " , n ,
            ", database " , n , ", suppressed " , n ;
warning   = "warning: KDBX version differs: " , version , " -> " , version
          | "warning: KDF weakened: " , weakening ;
weakening = "memory lowered from " , n , " to " , n , " bytes"
          | "iterations lowered from " , n , " to " , n
          | "rounds lowered from " , n , " to " , n
          | name , " replaced by " , name , ", which is not memory-hard"
          | name , " replaced by an unrecognized KDF" ;
record    = "DATABASE" , NL , { change }
          | ( "+" | "-" ) , " " , kind , " " , where , NL
          | "~ " , kind , " " , where , [ " (moved from " , path , ")" ] , NL , { change } ;
kind      = "GROUP" | "ENTRY" ;
where     = path | "(no path) [uuid:" , uuid , "]" ;
change    = "  " , ( "+" | "-" ) , " " , side
          | "  ~ " , label , ": " , value , " -> " , value , NL
          | "  ~ " , label , ":" , NL , { "      - " , part } , { "      + " , part } ;
side      = label , NL                                  (* a presence value *)
          | label , ":" , " " , value , NL
          | multiline ;                                 (* indent = "      " *)
part      = value , NL | cont ;                         (* indent = "" after the sign *)
```

A record's path is the node's path after the change (before it, for a
removal); a move adds its old path. A presence value (a tag, say) is either
there or not, so it only appears on `+` and `-` lines, as a bare label with no
other side. A modified multi-line value prints **both full sides** (its before
lines with `- |`, then its after lines with `+ |`), not a line-by-line diff;
blank lines are `- |` and `+ |` with nothing after the bar.

<!-- checked: text -->
```text
~ ENTRY "/Tour/Card"
  ~ Password: <sealed:8d7ca101> -> <sealed:8d7ca101> (unprotected)
  ~ Notes:
      - | line one
      - |
      - | line three
      + | line one
      + |
      + | line 3
  + Tag["a]b"]
  - Tag["work"]
  + Attachment["backup.key"]: <sealed:971cab75> (19 bytes, protected)
  ~ Icon: standard 0 -> standard 12
  ~ AutoType.Association["Bank*"#2]: "{USERNAME}" -> "{USERNAME}{ENTER}"
  ~ CustomData["KPXC_BROWSER"]: <sealed:d4135488> -> <sealed:2e7eb066>
  - History[unknown].URL: "https://card.example/untimed"
  ~ History[2026-01-02T09:00:00Z#2].URL: "https://card.example/v1" -> "https://card.example/v1-rewritten"
~ ENTRY "/Tour/Moved" (moved from "/Old/Moved")
~ ENTRY (no path) [uuid:00000022-d1ff-4000-8000-000000000000]
  ~ UserName: "nobody" -> "somebody"
```

The examples are excerpts of the `format_tour` fixture pair's output (sealed
with the test suite's fixed key); `tests/format_doc.rs` checks that every line
of every block marked `checked` is a line of the real output.
