//! diff-kdbx: command-line interface.

use clap::Parser;
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

fn main() -> anyhow::Result<()> {
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

// Stubs filled in by Tasks 21-22.
fn run_textconv(_cli: Cli) -> anyhow::Result<()> { unimplemented!("Task 22") }
fn run_dump(_cli: Cli) -> anyhow::Result<()> { unimplemented!("Task 22") }
fn run_standalone(_cli: Cli) -> anyhow::Result<()> { unimplemented!("Task 22") }
