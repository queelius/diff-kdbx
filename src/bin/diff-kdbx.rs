//! diff-kdbx: command-line interface.
//!
//! Opens files with keepass 0.15, captures them through kdbx-core (sealing
//! secrets as keyed fingerprints unless `--show-secrets`), and hands the
//! snapshots to the library. Exit codes mirror `/usr/bin/diff`: 0 no
//! changes, 1 changes, 2 error.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use diff_kdbx::kdbx_core::capture::keepass_0_15::{capture, header};
use diff_kdbx::kdbx_core::fingerprint::{DeriveParams, Domain, FingerprintKey, KeyMaterial};
use diff_kdbx::kdbx_core::model::{Sealing, Snapshot, Value};
use diff_kdbx::kdbx_core::path::VaultPath;
use diff_kdbx::{
    DiffOptions, DumpOptions, FingerprintKeyInfo, JsonOptions, Noise, RecycleBin, TextOptions,
    compute, dump, render_json, render_text,
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "diff-kdbx",
    version,
    about = "Semantic diff for KeePass KDBX files",
    long_about = "Semantic diff for KeePass KDBX files. Primarily a git textconv driver; \
                  also a standalone CLI. See README for git integration setup.",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// First KDBX file (older snapshot).
    #[arg(value_name = "A")]
    a: Option<PathBuf>,

    /// Second KDBX file (newer snapshot).
    #[arg(value_name = "B")]
    b: Option<PathBuf>,

    /// Run as git textconv driver: emit a stable text dump of one file.
    #[arg(long, value_name = "FILE", conflicts_with = "dump_path")]
    textconv: Option<PathBuf>,

    /// Emit a text dump of one file (manual inspection).
    #[arg(long = "dump", value_name = "FILE", conflicts_with = "textconv")]
    dump_path: Option<PathBuf>,

    #[command(flatten)]
    key: KeyArgs,

    /// Use separate keys for A and B (with --key-file-a / --key-file-b
    /// or KDBX_DIFF_PASSWORD_A / KDBX_DIFF_PASSWORD_B).
    #[arg(long)]
    separate_keys: bool,

    /// Key file for A only.
    #[arg(long, value_name = "PATH", requires = "separate_keys")]
    key_file_a: Option<PathBuf>,

    /// Key file for B only.
    #[arg(long, value_name = "PATH", requires = "separate_keys")]
    key_file_b: Option<PathBuf>,

    /// Output format of a two-file diff.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Show noise too: timestamps that move on every save, UI state, and
    /// settings timestamps. Same meaning in diff and dump mode.
    #[arg(long)]
    strict: bool,

    /// Show plaintext for protected fields. Off by default; refused with
    /// --textconv, whose output git may store.
    #[arg(long)]
    show_secrets: bool,

    /// Include the recycle bin group and its contents in diff/dump output.
    /// By default, the recycle bin is hidden to reduce noise.
    #[arg(long)]
    include_recycle_bin: bool,
}

/// How a vault is unlocked.
#[derive(Debug, Args)]
struct KeyArgs {
    /// Key file (used for both A and B unless --separate-keys).
    #[arg(long, value_name = "PATH")]
    key_file: Option<PathBuf>,

    /// The vault has no password (key file only). Without this flag, an
    /// empty interactive password together with --key-file means the same.
    #[arg(long)]
    no_password: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the keyed fingerprint of one entry field (in full), to verify a
    /// recorded fingerprint. The key is derived from this vault's key
    /// material; by default with its own parameters and root UUID, as
    /// --textconv and --dump do. --params and --salt reproduce a key
    /// recorded elsewhere (a two-file diff's JSON, an mcp-kdbx audit log).
    Fingerprint {
        /// The field name (for example Password, or a custom field).
        #[arg(long, value_name = "NAME")]
        field: String,
        /// The entry: a vault path (/Group/Title) or a UUID.
        #[arg(long, value_name = "PATH-OR-UUID")]
        entry: String,
        /// Derivation parameters, in their recorded form
        /// argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes> (default: the vault's own).
        #[arg(long, value_name = "PARAMS", value_parser = parse_params)]
        params: Option<DeriveParams>,
        /// Salt: the root group UUID of the vault whose key was recorded
        /// (default: this vault's root group UUID).
        #[arg(long, value_name = "UUID")]
        salt: Option<Uuid>,
        #[command(flatten)]
        key: KeyArgs,
        /// The vault.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Format {
    Text,
    Json,
}

/// The secret inputs that unlock one vault, wiped on drop.
struct Secret {
    password: Option<Zeroizing<String>>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
}

impl Secret {
    /// Resolve the key for one vault. Order: `--no-password` (key file
    /// only), then the environment variable, then a TTY prompt (only when
    /// `interactive`), then a key file alone. An empty password from the
    /// variable or the prompt together with a key file means no password.
    fn resolve(
        key_file: Option<&Path>,
        no_password: bool,
        env_var: &str,
        label: &str,
        interactive: bool,
    ) -> Result<Secret> {
        let keyfile = key_file
            .map(|p| {
                std::fs::read(p)
                    .map(Zeroizing::new)
                    .with_context(|| format!("reading key file {}", p.display()))
            })
            .transpose()?;
        let password = if no_password {
            if keyfile.is_none() {
                bail!("--no-password needs --key-file");
            }
            None
        } else if let Ok(p) = std::env::var(env_var) {
            // With a key file, an empty password means the vault has none
            // (the same rule as an empty interactive answer).
            if p.is_empty() && keyfile.is_some() {
                None
            } else {
                Some(Zeroizing::new(p))
            }
        } else if interactive && std::io::stdin().is_terminal() {
            let p = Zeroizing::new(
                rpassword::prompt_password(format!("Password for {label}: "))
                    .context("reading password from TTY")?,
            );
            // With a key file, an empty password means the vault has none.
            if p.is_empty() && keyfile.is_some() {
                None
            } else {
                Some(p)
            }
        } else if keyfile.is_some() {
            None
        } else {
            bail!(
                "no key source for {label}: set {env_var}, pass --key-file, or run interactively"
            );
        };
        Ok(Secret { password, keyfile })
    }

    fn database_key(&self) -> Result<keepass::DatabaseKey> {
        let mut key = keepass::DatabaseKey::new();
        if let Some(p) = &self.password {
            key = key.with_password(p);
        }
        if let Some(bytes) = &self.keyfile {
            key = key
                .with_keyfile(&mut bytes.as_slice())
                .context("reading key file")?;
        }
        Ok(key)
    }

    fn material(&self) -> KeyMaterial<'_> {
        KeyMaterial::new(
            self.password.as_ref().map(|p| p.as_bytes()),
            self.keyfile.as_ref().map(|k| k.as_slice()),
        )
    }
}

fn open(path: &Path, secret: &Secret) -> Result<keepass::Database> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    keepass::Database::open(&mut file, secret.database_key()?)
        .with_context(|| format!("unlocking {}", path.display()))
}

/// A stable fingerprint key: Argon2id over the key material, salted with a
/// vault's root group UUID, never cheaper than `params`.
fn derive_key(secret: &Secret, salt: Uuid, params: &DeriveParams) -> Result<FingerprintKey> {
    FingerprintKey::derive(&secret.material(), salt, params)
        .map_err(|e| anyhow!("deriving the fingerprint key: {e}"))
}

/// The derivation parameters for one vault: its own KDF, floored.
fn params_of(db: &keepass::Database) -> DeriveParams {
    DeriveParams::for_header(Some(&header(db)))
}

fn sealing(show_secrets: bool, key: &FingerprintKey) -> Sealing<'_> {
    if show_secrets {
        Sealing::Reveal(key)
    } else {
        Sealing::Fingerprint(key)
    }
}

fn main() -> std::process::ExitCode {
    // A panic is a bug, but it must still exit 2 (an error, as for diff),
    // never 101, and say so in one line instead of a backtrace dump.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("Error: internal error (please report it): {info}");
    }));
    // Returning ExitCode (rather than calling std::process::exit) lets the
    // runtime flush stdout before termination.
    std::process::ExitCode::from(guarded(run))
}

/// The exit code of `body`: its own on success, 2 on an error (printed to
/// stderr) or a panic (reported by the panic hook).
fn guarded(body: impl FnOnce() -> Result<u8> + std::panic::UnwindSafe) -> u8 {
    match std::panic::catch_unwind(body) {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            eprintln!("Error: {e:#}");
            2
        }
        Err(_) => 2,
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    if let Some(Command::Fingerprint {
        field,
        entry,
        params,
        salt,
        key,
        vault,
    }) = &cli.command
    {
        return run_fingerprint(field, entry, *params, *salt, key, vault);
    }
    if let Some(path) = &cli.textconv {
        if cli.show_secrets {
            bail!(
                "--show-secrets cannot be used with --textconv: git may store textconv \
                 output (diff.<driver>.cachetextconv keeps it under refs/notes/textconv/, \
                 which mirror pushes, mirror clones and bundles carry), so secrets would \
                 end up in the repository; use --dump to read them locally"
            );
        }
        // Never interactive: git runs the driver without a terminal.
        run_dump(&cli, path, false)
    } else if let Some(path) = &cli.dump_path {
        run_dump(&cli, path, true)
    } else if let (Some(a), Some(b)) = (&cli.a, &cli.b) {
        run_diff(&cli, a, b)
    } else {
        bail!("no operation: provide A and B, or --textconv FILE, or --dump FILE")
    }
}

/// Write all bytes to stdout and flush. A broken pipe means the consumer is
/// done reading (as for `grep` and `sort`).
fn write_stdout(bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Warn when --show-secrets would write plaintext to a non-TTY stdout (a
/// pipe, a file, or git's capture in textconv mode).
fn warn_show_secrets_non_tty(show_secrets: bool) {
    if show_secrets && !std::io::stdout().is_terminal() {
        eprintln!(
            "warning: --show-secrets with non-TTY stdout; secrets may be captured in logs/files"
        );
    }
}

fn noise(strict: bool) -> Noise {
    if strict { Noise::Show } else { Noise::Suppress }
}

fn recycle_bin(include: bool) -> RecycleBin {
    if include {
        RecycleBin::Include
    } else {
        RecycleBin::Exclude
    }
}

/// `--textconv` and `--dump`: one file, its own fingerprint key. The dump is
/// built in full before anything is written, so stdout is all-or-nothing.
fn run_dump(cli: &Cli, path: &Path, interactive: bool) -> Result<u8> {
    let secret = Secret::resolve(
        cli.key.key_file.as_deref(),
        cli.key.no_password,
        "KDBX_DIFF_PASSWORD",
        &path.display().to_string(),
        interactive,
    )?;
    let db = open(path, &secret)?;
    let key = derive_key(&secret, db.root().id().uuid(), &params_of(&db))?;
    let snap = capture(&db, &sealing(cli.show_secrets, &key));
    warn_show_secrets_non_tty(cli.show_secrets);
    let opts = DumpOptions::new(noise(cli.strict), recycle_bin(cli.include_recycle_bin));
    write_stdout(dump(&snap, &opts).as_bytes())?;
    Ok(0)
}

/// Two files: one fingerprint key for both, derived from A's key material
/// and salted with A's root UUID, so unchanged secrets compare equal even
/// when B's master key differs. Its parameters are the costlier of the two
/// vaults' (`DeriveParams::stronger`, comparing memory x passes as a whole),
/// so the key is never cheaper to attack than either vault and no costlier
/// than the stronger one.
fn run_diff(cli: &Cli, a_path: &Path, b_path: &Path) -> Result<u8> {
    if cli.separate_keys && cli.key.key_file.is_some() {
        bail!(
            "--key-file names one key file for both files; with --separate-keys use \
             --key-file-a and --key-file-b"
        );
    }
    let (secret_a, secret_b) = if cli.separate_keys {
        let a = Secret::resolve(
            cli.key_file_a.as_deref(),
            cli.key.no_password,
            "KDBX_DIFF_PASSWORD_A",
            &a_path.display().to_string(),
            true,
        )?;
        let b = Secret::resolve(
            cli.key_file_b.as_deref(),
            cli.key.no_password,
            "KDBX_DIFF_PASSWORD_B",
            &b_path.display().to_string(),
            true,
        )?;
        (a, Some(b))
    } else {
        let shared = Secret::resolve(
            cli.key.key_file.as_deref(),
            cli.key.no_password,
            "KDBX_DIFF_PASSWORD",
            "both files",
            true,
        )?;
        (shared, None)
    };
    let db_a = open(a_path, &secret_a)?;
    let db_b = open(b_path, secret_b.as_ref().unwrap_or(&secret_a)).with_context(|| {
        if cli.separate_keys {
            String::from("B did not open with its key")
        } else {
            String::from("B did not open with A's key; try --separate-keys")
        }
    })?;

    let params = params_of(&db_a).stronger(params_of(&db_b));
    let salt = db_a.root().id().uuid();
    let key = derive_key(&secret_a, salt, &params)?;
    let seal = sealing(cli.show_secrets, &key);
    let (before, after): (Snapshot, Snapshot) = (capture(&db_a, &seal), capture(&db_b, &seal));

    warn_show_secrets_non_tty(cli.show_secrets);
    let opts = DiffOptions::new(noise(cli.strict), recycle_bin(cli.include_recycle_bin));
    let cs = compute(&before, &after, &opts);
    let out = match cli.format {
        Format::Text => render_text(&cs, &TextOptions::default()),
        Format::Json => render_json(
            &cs,
            &JsonOptions::with_fingerprint_key(FingerprintKeyInfo::new(params, salt)),
        ),
    };
    write_stdout(out.as_bytes())?;
    Ok(if cs.is_empty() { 0 } else { 1 })
}

/// `fingerprint`: the full keyed fingerprint of one field. The vault is
/// captured with fingerprint sealing, so a secret field's sealed value is the
/// answer as is; a plain field is fingerprinted with the same key and domain.
fn run_fingerprint(
    field: &str,
    entry: &str,
    params: Option<DeriveParams>,
    salt: Option<Uuid>,
    key: &KeyArgs,
    vault: &Path,
) -> Result<u8> {
    let secret = Secret::resolve(
        key.key_file.as_deref(),
        key.no_password,
        "KDBX_DIFF_PASSWORD",
        &vault.display().to_string(),
        true,
    )?;
    let db = open(vault, &secret)?;
    let params = params.unwrap_or_else(|| params_of(&db));
    let salt = salt.unwrap_or_else(|| db.root().id().uuid());
    let fp_key = derive_key(&secret, salt, &params)?;
    let snap = capture(&db, &Sealing::Fingerprint(&fp_key));
    let found = match Uuid::parse_str(entry) {
        Ok(uuid) => snap
            .find_entry(uuid)
            .ok_or_else(|| anyhow!("no entry with UUID {uuid}"))?,
        Err(_) => VaultPath::parse(entry)
            .map_err(|e| anyhow!("invalid entry path {entry:?}: {e}"))?
            .resolve_entry(&snap)
            .map_err(|e| anyhow!("entry {entry:?}: {e}"))?,
    };
    let value = &found
        .field(field)
        .ok_or_else(|| anyhow!("entry {entry:?} has no field {field:?}"))?
        .value;
    let fp = match value {
        Value::Sealed(fp) => *fp,
        Value::Plain(plaintext) => fp_key.fingerprint(Domain::Field, plaintext.as_bytes()),
        _ => bail!("field {field:?} holds a value kind this version does not know"),
    };
    write_stdout(format!("{}\n", fp.to_hex()).as_bytes())?;
    Ok(0)
}

/// The recorded (`Display`) form of [`DeriveParams`]. kdbx-core prints it but
/// has no parser, so the grammar is read here: exactly
/// `argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>`, and nothing below the floor
/// (no fingerprint is ever derived with such parameters).
fn parse_params(s: &str) -> std::result::Result<DeriveParams, String> {
    const FORM: &str = "argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>";
    let malformed = || format!("expected {FORM}");
    let rest = s.strip_prefix("argon2id$v=19$").ok_or_else(malformed)?;
    let mut parts = rest.split(',');
    let mut component = |name: &str| -> std::result::Result<u32, String> {
        parts
            .next()
            .and_then(|p| p.strip_prefix(name))
            .and_then(|n| n.parse().ok())
            .ok_or_else(malformed)
    };
    let (m, t, p) = (component("m=")?, component("t=")?, component("p=")?);
    if parts.next().is_some() {
        return Err(malformed());
    }
    let params = DeriveParams::new(m, t, p);
    if (params.memory_kib(), params.iterations(), params.lanes()) != (m, t, p) {
        return Err(format!(
            "below the floor {}: no fingerprint is derived with these parameters",
            DeriveParams::FLOOR
        ));
    }
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_of_success_error_and_panic() {
        assert_eq!(guarded(|| Ok(1)), 1);
        assert_eq!(guarded(|| bail!("boom")), 2);
        assert_eq!(guarded(|| panic!("a bug")), 2);
    }

    #[test]
    fn params_round_trip_through_their_recorded_form() {
        for params in [DeriveParams::FLOOR, DeriveParams::new(32 * 1024, 8, 4)] {
            assert_eq!(parse_params(&params.to_string()), Ok(params));
        }
        assert!(parse_params("argon2id$v=19$m=65536,t=3,p=1,x=1").is_err());
    }
}
