//! diff-kdbx: command-line interface.

use clap::Parser;
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "diff-kdbx",
    version,
    about = "Semantic diff for KeePass KDBX files",
    long_about = "Semantic diff for KeePass KDBX files. Primarily a git textconv driver; \
                  also a standalone CLI. See README for git integration setup.",
)]
struct Cli {
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

    /// Key file (used for both A and B unless --separate-keys).
    #[arg(long, value_name = "PATH")]
    key_file: Option<PathBuf>,

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

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Disable noise suppression. Reports every difference, including
    /// LastAccessTime and other timestamps that change on every read.
    #[arg(long)]
    strict: bool,

    /// Show plaintext for protected fields. Off by default.
    #[arg(long)]
    show_secrets: bool,

    /// Use ANSI color in text output. Defaults to off.
    #[arg(long)]
    color: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Format {
    Text,
    Json,
}

mod key {
    use anyhow::{anyhow, Context, Result};
    use std::io::IsTerminal;
    use std::path::{Path, PathBuf};

    #[derive(Debug, Clone)]
    pub struct ResolvedKey {
        pub password: Option<String>,
        pub key_file: Option<PathBuf>,
    }

    /// Resolve a key for a given role (e.g., "A" or "B" or shared "").
    /// Order: explicit key file flag, then env var, then TTY prompt
    /// (only if `interactive_allowed`).
    pub fn resolve(
        key_file_explicit: Option<&Path>,
        env_var: &str,
        prompt_label: &str,
        interactive_allowed: bool,
    ) -> Result<ResolvedKey> {
        let key_file = key_file_explicit.map(|p| p.to_path_buf());
        if let Ok(p) = std::env::var(env_var) {
            return Ok(ResolvedKey { password: Some(p), key_file });
        }
        if interactive_allowed && std::io::stdin().is_terminal() {
            let p = rpassword::prompt_password(format!("Password for {}: ", prompt_label))
                .context("reading password from TTY")?;
            return Ok(ResolvedKey { password: Some(p), key_file });
        }
        // No password source. If a key file alone suffices, return that.
        if key_file.is_some() {
            return Ok(ResolvedKey { password: None, key_file });
        }
        Err(anyhow!(
            "no key source for {}: set {}, pass --key-file, or run interactively",
            prompt_label, env_var
        ))
    }

    /// Build a keepass DatabaseKey from the resolved parts.
    pub fn build_db_key(rk: &ResolvedKey) -> Result<keepass::DatabaseKey> {
        let mut k = keepass::DatabaseKey::new();
        if let Some(p) = &rk.password {
            k = k.with_password(p);
        }
        if let Some(path) = &rk.key_file {
            let data = std::fs::read(path).with_context(|| format!("reading key file {}", path.display()))?;
            k = k.with_keyfile(&mut std::io::Cursor::new(data))?;
        }
        Ok(k)
    }
}

fn main() {
    // Exit codes: 0 = no changes, 1 = changes found, 2 = error.
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(2);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.textconv.is_some() {
        run_textconv(cli)
    } else if cli.dump_path.is_some() {
        run_dump(cli)
    } else if cli.a.is_some() && cli.b.is_some() {
        run_standalone(cli)
    } else {
        anyhow::bail!("no operation: provide A and B, or --textconv FILE, or --dump FILE")
    }
}

fn run_textconv(cli: Cli) -> anyhow::Result<()> {
    let path = cli.textconv.as_ref().expect("textconv guard");
    let rk = key::resolve(
        cli.key_file.as_deref(),
        "KDBX_DIFF_PASSWORD",
        &format!("{}", path.display()),
        false, // never interactive in textconv
    )?;
    let db_key = key::build_db_key(&rk)?;
    let mut file = std::fs::File::open(path)?;
    let db = keepass::Database::open(&mut file, db_key)?;
    let opts = diff_kdbx::options::DumpOptions {
        strict: cli.strict,
        show_secrets: cli.show_secrets,
    };
    let s = diff_kdbx::dump::dump(&db, &opts);
    // Buffer-then-write so stdout stays all-or-nothing.
    use std::io::Write as _;
    std::io::stdout().lock().write_all(s.as_bytes())?;
    Ok(())
}

fn run_dump(cli: Cli) -> anyhow::Result<()> {
    let path = cli.dump_path.as_ref().expect("dump guard");
    let rk = key::resolve(
        cli.key_file.as_deref(),
        "KDBX_DIFF_PASSWORD",
        &format!("{}", path.display()),
        true,
    )?;
    let db_key = key::build_db_key(&rk)?;
    let mut file = std::fs::File::open(path)?;
    let db = keepass::Database::open(&mut file, db_key)?;
    let opts = diff_kdbx::options::DumpOptions {
        strict: cli.strict,
        show_secrets: cli.show_secrets,
    };
    let s = diff_kdbx::dump::dump(&db, &opts);
    print!("{}", s);
    Ok(())
}

fn run_standalone(cli: Cli) -> anyhow::Result<()> {
    let a_path = cli.a.as_ref().expect("standalone guard");
    let b_path = cli.b.as_ref().expect("standalone guard");

    let (rk_a, rk_b) = if cli.separate_keys {
        let rk_a = key::resolve(
            cli.key_file_a.as_deref(),
            "KDBX_DIFF_PASSWORD_A",
            &format!("{}", a_path.display()),
            true,
        )?;
        let rk_b = key::resolve(
            cli.key_file_b.as_deref(),
            "KDBX_DIFF_PASSWORD_B",
            &format!("{}", b_path.display()),
            true,
        )?;
        (rk_a, rk_b)
    } else {
        let rk = key::resolve(
            cli.key_file.as_deref(),
            "KDBX_DIFF_PASSWORD",
            "both files",
            true,
        )?;
        (rk.clone(), rk)
    };

    let mut fa = std::fs::File::open(a_path)?;
    let mut fb = std::fs::File::open(b_path)?;
    let db_a = keepass::Database::open(&mut fa, key::build_db_key(&rk_a)?)?;
    let db_b = keepass::Database::open(&mut fb, key::build_db_key(&rk_b)?)?;

    if cli.show_secrets && !std::io::stdout().is_terminal() {
        eprintln!("warning: --show-secrets with non-TTY stdout; secrets may be captured in logs/files");
    }

    let opts = diff_kdbx::options::DiffOptions {
        strict: cli.strict,
        show_secrets: cli.show_secrets,
    };
    let cs = diff_kdbx::compute::compute(&db_a, &db_b, &opts);

    let render_opts = diff_kdbx::options::RenderOptions { color: cli.color };
    let out = match cli.format {
        Format::Text => diff_kdbx::render::text::render(&cs, &render_opts),
        Format::Json => diff_kdbx::render::json::render(&cs),
    };
    print!("{}", out);

    if cs.is_empty() {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
