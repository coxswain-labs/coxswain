//! Coxswain binary runtime: CLI parsing, shared-state wiring, and Pingora runtime bootstrap.

mod args;
mod discovery;
mod roles;
mod services;
mod wiring;

use anyhow::Result;
use clap::Parser;

use crate::args::{Cli, Commands, ProxyScope, Role};
use crate::roles::controller::run_controller;
use crate::roles::proxy::{run_proxy_gateway, run_proxy_shared};
use crate::roles::relay::run_relay;

/// Executes the Coxswain proxy/controller role specified by the CLI arguments.
///
/// This is the primary entry point for the binary, responsible for CLI parsing,
/// shared state wiring, and bootstrapping the Pingora runtime or Kubernetes
/// controllers.
///
/// # Errors
/// Returns an error if CLI parsing fails, an invalid configuration is provided,
/// or the server fails to bind or run.
#[must_use = "the run() result is the process exit status; dropping it hides startup failures"]
pub fn run() -> Result<()> {
    // reqwest is compiled with `rustls-no-provider`; install ring explicitly so
    // the ext_authz sub-request client can be constructed (rustls 0.23 requires
    // a crypto provider before any TLS object is created).
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cli = Cli::parse();
    let Commands::Serve(serve) = cli.command;

    let role = serve.role.ok_or_else(|| {
        anyhow::anyhow!(
            "missing role: pick one of `controller`, `proxy --shared`, `proxy --dedicated`, `relay --shared`, or `relay --namespace <NS>`"
        )
    })?;

    match role {
        Role::Controller(controller_args) => run_controller(controller_args),
        Role::Proxy(proxy_args) => match proxy_args.scope() {
            ProxyScope::Shared => run_proxy_shared(proxy_args),
            ProxyScope::Dedicated { name, namespace } => {
                run_proxy_gateway(proxy_args, name, namespace)
            }
        },
        Role::Relay(relay_args) => run_relay(relay_args),
    }
}
