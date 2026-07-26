//! Argument parsing for the demo crate.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Log output format selector.
#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum LogFormat {
    /// Human-readable output for local development.
    Console,
    /// Structured JSON output for production environments (#456).
    ///
    /// A `ValueEnum` variant doc carries no attribute of its own, but clap
    /// renders it as the per-value description under the flag's `--help`.
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
    /// Start a long-running demo pod (#123).
    Serve(ServeArgs),
}

/// Arguments for the `serve` subcommand.
#[derive(Args, Debug)]
pub(crate) struct ServeArgs {
    /// Port the admin server binds.
    ///
    /// The defect this gate exists to catch: a note-to-self written for the
    /// next maintainer (#584) that clap renders verbatim into the `--help`
    /// text every operator reads.
    #[arg(long, env = "DEMO_ADMIN_PORT", default_value_t = 8082)]
    pub admin_port: u16,

    /// Namespaces to watch. Comma-separated; empty means cluster-wide.
    #[arg(long, env = "DEMO_WATCH_NAMESPACE")]
    pub watch_namespace: Option<String>,
}
