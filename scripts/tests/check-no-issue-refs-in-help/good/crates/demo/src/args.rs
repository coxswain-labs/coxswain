//! Argument parsing for the demo crate.
//!
//! Module headers like this one are NOT rendered into `--help`, so they keep
//! issue references freely — see #123 for the original design.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Log output format selector.
#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum LogFormat {
    /// Human-readable output for local development.
    Console,
    /// Structured JSON output for production environments.
    Json,
}

/// Demo binary.
#[derive(Parser, Debug)]
pub(crate) struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Start a long-running demo pod.
    Serve(ServeArgs),
}

/// Arguments for the `serve` subcommand.
#[derive(Args, Debug)]
pub(crate) struct ServeArgs {
    /// Port the admin server binds.
    ///
    /// Operator-facing usage text only: what it does, the format, the default.
    #[arg(long, env = "DEMO_ADMIN_PORT", default_value_t = 8082)]
    pub admin_port: u16,

    /// Namespaces to watch. Comma-separated; empty means cluster-wide.
    #[arg(long, env = "DEMO_WATCH_NAMESPACE")]
    pub watch_namespace: Option<String>,
}

/// A plain (non-clap) struct. Its docs never reach `--help`, so a reference
/// like #456 is fine here — the tracker is open when you read this.
pub(crate) struct Internal {
    /// Field docs on a non-clap struct are also out of scope: see #789.
    pub value: u16,
}

/// A regular function's docs never render into help either (#321).
pub(crate) fn helper() -> u16 {
    0
}
