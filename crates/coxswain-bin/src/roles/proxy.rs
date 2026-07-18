//! The `proxy` pod role runners: shared pool + dedicated per-Gateway.
//!
//! Read-only data plane; no status writes, no leader election. Shared wiring lives
//! in [`crate::wiring`], [`crate::services`], and [`crate::discovery`].

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::Result;
use coxswain_core::health::HealthRegistry;
use coxswain_discovery::Scope;
use tokio::sync::watch;

use crate::args::ProxyRoleArgs;
use crate::discovery::{build_discovery_client, register_discovery_background_services};
use crate::wiring::{
    ManagementServerConfig, build_server, init_logger, wire_gateway_only_proxy_services,
    wire_management_servers, wire_proxy_services,
};

/// Wire and run the `proxy --shared` pod role: read-only data plane for
/// Ingress + non-dedicated Gateway traffic. No status writes, no leader
/// election.
pub(crate) fn run_proxy_shared(args: ProxyRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "proxy",
        scope = "shared",
        controller_name = %args.common.controller_name,
        "Starting"
    );

    let mut server = build_server(&args.proxy);

    let health = HealthRegistry::new();
    let proxy_handle = health.register("proxy", &["routing_table_loaded"]);

    // Bound-port telemetry (#531): acceptor → discovery client → controller.
    let (bound_ports_tx, bound_ports_rx) = watch::channel(BTreeSet::new());
    let (client, supervisor, bootstrap_runner) = build_discovery_client(
        &args.discovery,
        &args.common,
        proxy_handle,
        Scope::SharedPool,
        Some(bound_ports_rx),
    )?;
    let listener_status = client.listener_status();

    wire_proxy_services(
        &mut server,
        &args.common,
        &args.proxy,
        &client,
        &listener_status,
        Some(bound_ports_tx),
    )?;

    register_discovery_background_services(&mut server, supervisor, bootstrap_runner);

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        ManagementServerConfig { health, leader },
    );

    tracing::info!(
        proxy_bind_address = %args.proxy.proxy_bind_address,
        ingress_http_port = ?args.common.ingress_http_port,
        ingress_https_port = ?args.common.ingress_https_port,
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        proxy_shutdown_grace_period = ?args.proxy.proxy_shutdown_grace_period,
        proxy_shutdown_timeout = ?args.proxy.proxy_shutdown_timeout,
        proxy_listener_drain_timeout = ?args.proxy.proxy_listener_drain_timeout,
        "Listening"
    );
    server.run_forever();
}

/// Wire and run the `proxy --dedicated` pod role: read-only data plane scoped
/// to one named Gateway.
///
/// `gateway_name`/`gateway_namespace` are the `ProxyScope::Dedicated` payload the
/// caller already matched in [`run`] — passed in rather than re-derived via a
/// second `args.scope()` call, which would re-clone both strings and force a
/// dead `ProxyScope::Shared` arm that could only be reached by a caller bug.
pub(crate) fn run_proxy_gateway(
    args: ProxyRoleArgs,
    gateway_name: String,
    gateway_namespace: String,
) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "proxy",
        scope = "gateway",
        gateway = %format!("{gateway_namespace}/{gateway_name}"),
        controller_name = %args.common.controller_name,
        "Starting"
    );

    let mut server = build_server(&args.proxy);

    let health = HealthRegistry::new();
    let proxy_handle = health.register("proxy", &["routing_table_loaded"]);

    // This dedicated proxy subscribes with Scope::Gateway{name, namespace}; the
    // discovery server filters the snapshot to this Gateway's routing world via
    // the dedicated registry (#426), so it receives only its own routes.
    let scope = Scope::Gateway {
        name: gateway_name.clone(),
        namespace: gateway_namespace.clone(),
    };
    // Bound-port telemetry (#531): the dedicated Programmed gate consumes the
    // same NodeStatus reports as the shared one, scoped to this Gateway.
    let (bound_ports_tx, bound_ports_rx) = watch::channel(BTreeSet::new());
    let (client, supervisor, bootstrap_runner) = build_discovery_client(
        &args.discovery,
        &args.common,
        proxy_handle,
        scope,
        Some(bound_ports_rx),
    )?;
    let listener_status = client.listener_status();

    wire_gateway_only_proxy_services(
        &mut server,
        &args.common,
        &args.proxy,
        &client,
        &listener_status,
        Some(bound_ports_tx),
    )?;

    register_discovery_background_services(&mut server, supervisor, bootstrap_runner);

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        ManagementServerConfig { health, leader },
    );

    tracing::info!(
        proxy_bind_address = %args.proxy.proxy_bind_address,
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        proxy_shutdown_grace_period = ?args.proxy.proxy_shutdown_grace_period,
        proxy_shutdown_timeout = ?args.proxy.proxy_shutdown_timeout,
        proxy_listener_drain_timeout = ?args.proxy.proxy_listener_drain_timeout,
        "Listening"
    );
    server.run_forever();
}
