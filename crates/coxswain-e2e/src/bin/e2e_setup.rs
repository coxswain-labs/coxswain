//! Nextest setup script: bootstraps the e2e cluster once before any test runs.
//!
//! `cargo nextest run --profile e2e` invokes this binary as the `e2e-setup`
//! script defined in `.config/nextest.toml`. It runs the full one-time cluster
//! bootstrap — Docker image build, CRD installation, cert-manager, and the
//! initial Helm release — then exports `COXSWAIN_E2E_BOOTSTRAPPED=1` to every
//! test process via nextest's env-file protocol.
//!
//! Nextest passes the script a writable file path in `$NEXTEST_ENV` and reads
//! back `KEY=value` lines from it after the script exits, injecting each into
//! every test process (see nextest's `parse_env_file`). Writing to stdout does
//! NOT work — stdout is captured for logging, not parsed for env vars.
//!
//! Subsequent calls to `coxswain_e2e::bootstrap()` inside test processes see
//! `COXSWAIN_E2E_BOOTSTRAPPED` and return immediately, avoiding the serial
//! bottleneck — and the Helm-lock races — that occur when each of nextest's
//! per-test processes tries to run the heavy setup in parallel.

use std::io::Write as _;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = coxswain_e2e::bootstrap_cluster().await {
        eprintln!("e2e-setup: bootstrap_cluster failed: {e:#}");
        std::process::exit(1);
    }

    // Export the short-circuit signal to every test process by appending it to
    // the env file nextest provides via $NEXTEST_ENV. Absent that variable the
    // binary was run standalone (not under nextest) — bootstrap still ran, so
    // there's simply nothing to export.
    if let Ok(env_path) = std::env::var("NEXTEST_ENV") {
        match std::fs::OpenOptions::new().append(true).open(&env_path) {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "COXSWAIN_E2E_BOOTSTRAPPED=1") {
                    eprintln!("e2e-setup: failed to write {env_path}: {e}");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("e2e-setup: failed to open NEXTEST_ENV file {env_path}: {e}");
                std::process::exit(1);
            }
        }
    }
}
