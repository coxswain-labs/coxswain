//! Coxswain binary entry point: CLI parsing, shared-state wiring, and Pingora runtime bootstrap.

mod args;
mod hot_reload;

use anyhow::{Context, Result};
use clap::Parser;
use coxswain_admin::AdminServer;
use coxswain_controller::{
    ControllerConfig, IngressPorts, LeaseSettings, Operator, OperatorConfig, SharedClusterSummary,
    SharedGatewayListenerHealth, StatusWriterConfig, spawn_status_writer,
};
use coxswain_core::health::HealthRegistry;
use coxswain_core::routing::{RouteTimeouts, SharedGatewayRoutingTable, SharedIngressRoutingTable};
use coxswain_health::HealthServer;
use coxswain_proxy::{
    DedicatedProxyReflector, DedicatedProxyReflectorConfig, GatewayProxy, IngressProxy,
    KubernetesSource, ListenerProtocol, ListenerSpec, ProxyAcceptor, ProxyReflector,
    ProxyReflectorConfig, RoutingEngine, RoutingSource, SniCertSelector, TrustedSources,
    UpstreamCaCache, spawn_dedicated_routing_table_builder, spawn_routing_table_builder,
};
use coxswain_reflector::ReconcilerHealth;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::services::background::background_service;
use pingora_core::services::listening::Service;
use pingora_proxy::{http_proxy, http_proxy_service_with_name};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::args::{
    Cli, Commands, CommonArgs, ControllerArgs, ControllerRoleArgs, DevRoleArgs, LogFormat,
    ProxyArgs, ProxyRoleArgs, ProxyScope, Role,
};

fn main() -> Result<()> {
    // When spawned as a restart child, wait for the parent process to exit so
    // it releases its bound sockets before we try to bind them ourselves.
    if std::env::var("COXSWAIN_RESTART_CHILD").is_ok()
        && let Ok(pid_str) = std::env::var("COXSWAIN_RESTART_PARENT_PID")
        && let Ok(pid) = pid_str.parse::<i32>()
    {
        wait_for_parent_exit(pid);
    }

    let cli = Cli::parse();
    let Commands::Serve(serve) = cli.command;

    // No implicit-dev fallback: every production deployment picks `controller`
    // or `proxy` explicitly; the hidden `dev` role exists for local development.
    // Bare `coxswain serve` (with no role subcommand) is rejected by clap
    // (via `arg_required_else_help` on the `serve` parser).
    let role = serve.role.ok_or_else(|| {
        anyhow::anyhow!(
            "missing role: pick one of `controller`, `proxy --shared`, `proxy --dedicated`, \
             or `dev` (hidden, for local development)"
        )
    })?;

    match role {
        Role::Dev(dev_args) => run_dev(dev_args),
        Role::Controller(controller_args) => run_controller(controller_args),
        Role::Proxy(proxy_args) => match proxy_args.scope() {
            ProxyScope::Shared => run_proxy_shared(proxy_args),
            ProxyScope::Gateway { .. } => run_proxy_gateway(proxy_args),
        },
    }
}

/// Wire and run the `controller` pod role: leader-elected status writer, no
/// data-plane services. Watches the cluster, computes per-resource health, and
/// patches `*/status` subresources via [`coxswain_controller::Controller`].
fn run_controller(args: ControllerRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "controller",
        controller_name = %args.common.controller_name,
        "Starting"
    );

    let controller_config = build_controller_config(&args.common, &args.controller)?;

    let mut server = build_minimal_server();
    let health = HealthRegistry::new();

    let status_writer = spawn_status_writer(
        StatusWriterConfig {
            controller: controller_config,
            watch_namespace: args.common.watch_namespace.clone(),
            controller_name: args.common.controller_name.clone(),
            ingress_default_backend: None,
            ingress_ports: IngressPorts::new(
                args.common.ingress_http_port,
                args.common.ingress_https_port,
            ),
        },
        health.clone(),
    )?;

    server.add_service(background_service("controller", status_writer.controller));
    server.add_service(background_service("reconciler", status_writer.reconciler));

    server.add_service(background_service(
        "operator",
        Operator::new(OperatorConfig {
            controller_name: args.common.controller_name.clone(),
            controller_image: resolve_controller_image(),
            leader: Arc::clone(&status_writer.leader),
        }),
    ));

    let health_addr = SocketAddr::new(args.common.management_bind_address, args.common.health_port);
    server.add_service({
        let mut svc = Service::new(
            "health".to_string(),
            HealthServer {
                registry: health.clone(),
            },
        );
        svc.add_tcp(&health_addr.to_string());
        svc
    });

    let admin_addr = SocketAddr::new(args.common.management_bind_address, args.common.admin_port);
    server.add_service(
        AdminServer::new(
            health,
            status_writer.leader,
            status_writer.outputs.ingress_routes,
            status_writer.outputs.gateway_routes,
        )
        .with_cluster_summary(status_writer.outputs.cluster_summary)
        .into_service(admin_addr),
    );

    tracing::info!(
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        "Listening"
    );
    server.run_forever();
}

/// Resolve the image string the provisioning operator embeds in rendered
/// dedicated-proxy Deployments when `CoxswainGatewayParameters.spec.image`
/// is unset. Priority: `COXSWAIN_IMAGE` env var (set by the Helm chart from
/// the controller's own image) → built-in `ghcr.io/coxswain-labs/coxswain:<version>`
/// fallback for local `serve dev` runs. The fallback isn't pulled when
/// running locally (Step 8 is log-only); it shows up only in the logged
/// YAML so operators can spot whether the chart's env wiring is healthy.
fn resolve_controller_image() -> String {
    std::env::var("COXSWAIN_IMAGE").unwrap_or_else(|_| {
        format!(
            "ghcr.io/coxswain-labs/coxswain:{}",
            env!("CARGO_PKG_VERSION")
        )
    })
}

/// Wire and run the `proxy --shared` pod role: read-only data plane for
/// Ingress + non-dedicated Gateway traffic. No status writes, no leader
/// election, no `Controller`. The proxy ServiceAccount has zero K8s write
/// verbs; this binary path holds the same property structurally — nothing
/// in the call graph touches [`coxswain_controller::Controller`].
fn run_proxy_shared(args: ProxyRoleArgs) -> Result<()> {
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
    let controller_handle = health.register(
        "controller",
        &[
            "httproute",
            "ingress",
            "ingress_class",
            "gateway",
            "gateway_class",
            "endpoint_slice",
            "reference_grant",
            "secret",
            "service",
            "backend_tls_policy",
            "config_map",
            "routing_table_built",
        ],
    );
    let proxy_handle = health.register("proxy", &["routing_table_loaded"]);

    let reflector = spawn_routing_table_builder(ProxyReflectorConfig {
        controller_name: args.common.controller_name.clone(),
        watch_namespace: args.common.watch_namespace.clone(),
        ingress_ports: IngressPorts::new(
            args.common.ingress_http_port,
            args.common.ingress_https_port,
        ),
        ingress_default_backend: args.proxy.ingress_default_backend.clone(),
        health: ReconcilerHealth::new(controller_handle, proxy_handle),
    });

    let ProxyReflector {
        source,
        reconciler,
        tls_health,
    } = reflector;

    server.add_service(background_service("reconciler", reconciler));

    wire_proxy_services(&mut server, &args.common, &args.proxy, &source, &tls_health)?;

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        health,
        leader,
        source.ingress_routes(),
        source.gateway_routes(),
        None,
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
        "Listening"
    );
    server.run_forever();
}

/// Wire and run the `proxy --gateway` pod role: read-only data plane scoped
/// to one named Gateway. Same RBAC profile as `proxy --shared` today
/// (cluster-wide reads, zero writes); Step 10 narrows the reads to only the
/// namespaces the target Gateway routes traffic into.
fn run_proxy_gateway(args: ProxyRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    let (
        gateway_name,
        gateway_namespace,
        allow_cluster_wide_route_read,
        allow_cluster_wide_namespace_read,
    ) = match args.scope() {
        ProxyScope::Gateway {
            name,
            namespace,
            allow_cluster_wide_route_read,
            allow_cluster_wide_namespace_read,
        } => (
            name,
            namespace,
            allow_cluster_wide_route_read,
            allow_cluster_wide_namespace_read,
        ),
        ProxyScope::Shared => {
            // Invariant: this arm is only entered when the caller already
            // confirmed `ProxyScope::Gateway` via the match in `main`.
            panic!("invariant: run_proxy_gateway must be invoked with ProxyScope::Gateway");
        }
    };

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "proxy",
        scope = "gateway",
        gateway = %format!("{gateway_namespace}/{gateway_name}"),
        controller_name = %args.common.controller_name,
        allow_cluster_wide_route_read,
        allow_cluster_wide_namespace_read,
        "Starting"
    );

    let mut server = build_server(&args.proxy);

    let health = HealthRegistry::new();
    // Same check set as the shared-proxy pod: DedicatedProxyReconciler flips
    // `ingress` and `ingress_class` to Ready immediately (it doesn't watch
    // those resources), so `/readyz` does not get stuck waiting on them.
    let controller_handle = health.register(
        "controller",
        &[
            "httproute",
            "ingress",
            "ingress_class",
            "gateway",
            "gateway_class",
            "endpoint_slice",
            "reference_grant",
            "secret",
            "service",
            "backend_tls_policy",
            "config_map",
            "routing_table_built",
        ],
    );
    let proxy_handle = health.register("proxy", &["routing_table_loaded"]);

    let reflector = spawn_dedicated_routing_table_builder(DedicatedProxyReflectorConfig {
        controller_name: args.common.controller_name.clone(),
        gateway_name: gateway_name.clone(),
        gateway_namespace: gateway_namespace.clone(),
        allow_cluster_wide_route_read,
        allow_cluster_wide_namespace_read,
        health: ReconcilerHealth::new(controller_handle, proxy_handle),
    });

    let DedicatedProxyReflector {
        source,
        reconciler,
        tls_health,
    } = reflector;

    server.add_service(background_service("reconciler", reconciler));

    wire_gateway_only_proxy_services(
        &mut server,
        &args.common,
        &args.proxy,
        &source,
        &tls_health,
        &gateway_name,
        &gateway_namespace,
        &args.common.controller_name,
    )?;

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        health,
        leader,
        source.ingress_routes(),
        source.gateway_routes(),
        None,
    );

    tracing::info!(
        proxy_bind_address = %args.proxy.proxy_bind_address,
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        proxy_shutdown_grace_period = ?args.proxy.proxy_shutdown_grace_period,
        proxy_shutdown_timeout = ?args.proxy.proxy_shutdown_timeout,
        "Listening"
    );
    server.run_forever();
}

/// Wire only the `GatewayProxy` Pingora service (no `IngressProxy`) for the
/// `serve proxy --gateway` pod. Ports are discovered from the target
/// Gateway's `spec.listeners` only — the shared-pool union discovery is
/// inappropriate here since this pod must not bind ports declared by other
/// Gateways.
#[allow(clippy::too_many_arguments)]
fn wire_gateway_only_proxy_services(
    server: &mut Server,
    common: &CommonArgs,
    proxy: &ProxyArgs,
    source: &KubernetesSource,
    tls_health: &SharedGatewayListenerHealth,
    gateway_name: &str,
    gateway_namespace: &str,
    controller_name: &str,
) -> Result<()> {
    let default_timeouts = RouteTimeouts {
        request: proxy.proxy_default_request_timeout,
        backend_request: proxy.proxy_default_backend_request_timeout,
    };
    let ca_cache = Arc::new(UpstreamCaCache::new());

    let gateway_listeners: Vec<ListenerSpec> = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build tokio runtime for startup Gateway port discovery")?;
        let discovered = rt.block_on(discover_dedicated_gateway_ports(
            controller_name,
            gateway_name,
            gateway_namespace,
            proxy.proxy_bind_address,
        ));
        discovered
            .into_iter()
            .filter(|spec| match std::net::TcpListener::bind(spec.addr) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(
                        addr = %spec.addr,
                        error = %e,
                        "Cannot bind Gateway-discovered port; skipping listener",
                    );
                    false
                }
            })
            .collect::<Vec<_>>()
    };

    if gateway_listeners.is_empty() {
        tracing::warn!(
            gateway = %format!("{gateway_namespace}/{gateway_name}"),
            "No bindable listener ports discovered for the target Gateway. No traffic will be served until its spec.listeners produce reachable ports."
        );
    } else {
        let ports: Vec<u16> = gateway_listeners.iter().map(|l| l.addr.port()).collect();
        tracing::info!(?ports, "Binding ports discovered from target Gateway");
    }

    let currently_bound: HashSet<u16> = gateway_listeners.iter().map(|l| l.addr.port()).collect();

    if proxy.proxy_accept_proxy_protocol {
        if proxy.proxy_trusted_sources.is_empty() {
            tracing::warn!(
                "--proxy-accept-proxy-protocol is set but --proxy-trusted-sources is empty; \
                 all connections will be rejected"
            );
        }
        let trusted = Arc::new(TrustedSources::new(proxy.proxy_trusted_sources.clone()));
        if !gateway_listeners.is_empty() {
            let p = Arc::new(pingora_proxy::http_proxy(
                &server.configuration,
                GatewayProxy::new(
                    Arc::new(RoutingEngine::new(source.gateway_routes())),
                    default_timeouts.clone(),
                    ca_cache.clone(),
                ),
            ));
            let selector = SniCertSelector::new(source.tls_store());
            let acceptor = ProxyAcceptor::new(p, gateway_listeners, trusted, selector)
                .context("build GatewayProxy acceptor")?;
            server.add_service(acceptor);
        }
    } else if !gateway_listeners.is_empty() {
        let mut svc = http_proxy_service_with_name(
            &server.configuration,
            GatewayProxy::new(
                Arc::new(RoutingEngine::new(source.gateway_routes())),
                default_timeouts.clone(),
                ca_cache.clone(),
            ),
            "gateway-proxy",
        );
        for spec in &gateway_listeners {
            match spec.protocol {
                ListenerProtocol::Http => {
                    svc.add_tcp(&spec.addr.to_string());
                }
                ListenerProtocol::Https => {
                    let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
                        Box::new(SniCertSelector::new(source.tls_store()));
                    let tls_settings = TlsSettings::with_callbacks(callbacks)
                        .context("build Gateway TLS settings")?;
                    svc.add_tls_with_settings(&spec.addr.to_string(), None, tls_settings);
                }
            }
        }
        server.add_service(svc);
    }

    // The dedicated pod has no ingress listeners; `currently_bound` ports are
    // all Gateway-listener ports and the empty `ingress_ports` set tells
    // HotReloader not to try to re-bind ingress entry points.
    server.add_service(background_service(
        "hot-reloader",
        hot_reload::HotReloader::new(tls_health.clone(), currently_bound, HashSet::new()),
    ));
    let _ = common;
    Ok(())
}

/// List the target Gateway's listener ports for the dedicated proxy.
///
/// Unlike [`discover_gateway_ports`] (which unions across every owned
/// Gateway for the shared pool), this looks up exactly one Gateway by name
/// and namespace. Soft-fails to an empty Vec on any API error.
async fn discover_dedicated_gateway_ports(
    controller_name: &str,
    gateway_name: &str,
    gateway_namespace: &str,
    bind_address: IpAddr,
) -> Vec<ListenerSpec> {
    use gateway_api::apis::standard::gatewayclasses::GatewayClass;
    use gateway_api::apis::standard::gateways::Gateway;
    use kube::{Api, Client};

    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Cannot connect to Kubernetes at startup; skipping dedicated Gateway port discovery"
            );
            return vec![];
        }
    };

    let gw_api: Api<Gateway> = Api::namespaced(client.clone(), gateway_namespace);
    let gw = match gw_api.get(gateway_name).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(
                gateway = %format!("{gateway_namespace}/{gateway_name}"),
                error = %e,
                "Target Gateway not found at startup; will pick up listener ports on next HotReloader cycle"
            );
            return vec![];
        }
    };

    let gc_api = Api::<GatewayClass>::all(client);
    let gc = match gc_api.get(&gw.spec.gateway_class_name).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                class = %gw.spec.gateway_class_name,
                error = %e,
                "Target Gateway's GatewayClass not found; skipping port discovery"
            );
            return vec![];
        }
    };
    if gc.spec.controller_name != controller_name {
        tracing::warn!(
            class = %gw.spec.gateway_class_name,
            class_controller = %gc.spec.controller_name,
            this_controller = controller_name,
            "Target Gateway's GatewayClass is not owned by this controller; skipping port discovery"
        );
        return vec![];
    }

    let mut result: Vec<ListenerSpec> = Vec::new();
    let mut seen: HashSet<u16> = HashSet::new();
    for listener in &gw.spec.listeners {
        let port = listener.port as u16;
        if !seen.insert(port) {
            continue;
        }
        match listener.protocol.as_str() {
            "HTTP" => result.push(ListenerSpec::http(SocketAddr::new(bind_address, port))),
            "HTTPS" | "TLS" => {
                result.push(ListenerSpec::https(SocketAddr::new(bind_address, port)))
            }
            other => tracing::debug!(
                protocol = other,
                port,
                "Skipping non-HTTP/HTTPS Gateway listener at startup"
            ),
        }
    }
    result
}

/// Wire and run the hidden `dev` pod role: single-process all-in-one for local
/// development. Wires both the status-writer and the routing-table-build
/// pipelines in the same Pingora server, accepting the cost of two
/// independent reflector pipelines running side-by-side (each watching the
/// same K8s resources). The cost is a local-dev convenience trade-off; the
/// production split is `controller` + `proxy --shared`.
fn run_dev(args: DevRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "dev",
        controller_name = %args.common.controller_name,
        "Starting"
    );

    let controller_config = build_controller_config(&args.common, &args.controller)?;
    let mut server = build_server(&args.proxy);

    let health = HealthRegistry::new();
    let status_writer = spawn_status_writer(
        StatusWriterConfig {
            controller: controller_config,
            watch_namespace: args.common.watch_namespace.clone(),
            controller_name: args.common.controller_name.clone(),
            ingress_default_backend: args.proxy.ingress_default_backend.clone(),
            ingress_ports: IngressPorts::new(
                args.common.ingress_http_port,
                args.common.ingress_https_port,
            ),
        },
        health.clone(),
    )?;

    // Dev mode shares the single SharedProxyReconciler from the status writer between
    // the controller-side status path and the proxy-side data plane: routes,
    // tls store, and tls_health all come from the same in-process publish.
    // This preserves today's behaviour and avoids paying for two K8s watch
    // sets in local dev.
    let source = KubernetesSource::new(
        status_writer.outputs.ingress_routes.clone(),
        status_writer.outputs.gateway_routes.clone(),
        status_writer.outputs.tls.clone(),
    );
    let tls_health = status_writer.outputs.tls_health.clone();

    server.add_service(background_service("controller", status_writer.controller));
    server.add_service(background_service("reconciler", status_writer.reconciler));

    server.add_service(background_service(
        "operator",
        Operator::new(OperatorConfig {
            controller_name: args.common.controller_name.clone(),
            controller_image: resolve_controller_image(),
            leader: Arc::clone(&status_writer.leader),
        }),
    ));

    wire_proxy_services(&mut server, &args.common, &args.proxy, &source, &tls_health)?;

    wire_management_servers(
        &mut server,
        &args.common,
        health,
        status_writer.leader,
        source.ingress_routes(),
        source.gateway_routes(),
        Some(status_writer.outputs.cluster_summary),
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
        "Listening"
    );
    server.run_forever();
}

/// Build a [`ControllerConfig`] from the parsed CLI args of any role that
/// runs the status writer (`controller`, `dev`).
fn build_controller_config(
    common: &CommonArgs,
    controller: &ControllerArgs,
) -> Result<ControllerConfig> {
    ControllerConfig::new(
        common.controller_name.clone(),
        common.pod_name.clone(),
        common.pod_namespace.clone(),
        LeaseSettings::new(
            controller.controller_lease_ttl,
            controller.controller_lease_renew_interval,
        ),
        common.watch_namespace.clone(),
        controller.status_address.clone(),
        IngressPorts::new(common.ingress_http_port, common.ingress_https_port),
    )
    .map_err(Into::into)
}

/// Construct the listener-spec set for the proxy role from CLI args plus
/// (in dev mode) Gateway listener discovery.
fn build_ingress_listeners(common: &CommonArgs, proxy: &ProxyArgs) -> Vec<ListenerSpec> {
    let mut ingress_listeners: Vec<ListenerSpec> = Vec::new();
    if let Some(port) = common.ingress_http_port {
        ingress_listeners.push(ListenerSpec::http(SocketAddr::new(
            proxy.proxy_bind_address,
            port,
        )));
    }
    if let Some(port) = common.ingress_https_port {
        ingress_listeners.push(ListenerSpec::https(SocketAddr::new(
            proxy.proxy_bind_address,
            port,
        )));
    }
    ingress_listeners
}

/// Register both the Ingress and Gateway Pingora services + hot reloader on
/// the supplied server. Shared between `run_proxy_shared` and `run_dev` so
/// the data-plane wiring matches one-to-one.
fn wire_proxy_services(
    server: &mut Server,
    common: &CommonArgs,
    proxy: &ProxyArgs,
    source: &KubernetesSource,
    tls_health: &SharedGatewayListenerHealth,
) -> Result<()> {
    let default_timeouts = RouteTimeouts {
        request: proxy.proxy_default_request_timeout,
        backend_request: proxy.proxy_default_backend_request_timeout,
    };
    let ca_cache = Arc::new(UpstreamCaCache::new());

    let ingress_listeners = build_ingress_listeners(common, proxy);
    let ingress_ports: HashSet<u16> = ingress_listeners.iter().map(|l| l.addr.port()).collect();

    // Discover Gateway listener ports from the cluster's current state.
    let gateway_listeners: Vec<ListenerSpec> = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build tokio runtime for startup Gateway port discovery")?;
        let discovered = rt.block_on(discover_gateway_ports(
            &common.controller_name,
            common.watch_namespace.as_deref(),
            proxy.proxy_bind_address,
            &ingress_ports,
        ));
        discovered
            .into_iter()
            .filter(|spec| match std::net::TcpListener::bind(spec.addr) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(
                        addr = %spec.addr,
                        error = %e,
                        "Cannot bind Gateway-discovered port; skipping listener",
                    );
                    false
                }
            })
            .collect::<Vec<_>>()
    };
    if !gateway_listeners.is_empty() {
        let ports: Vec<u16> = gateway_listeners.iter().map(|l| l.addr.port()).collect();
        tracing::info!(
            ?ports,
            "Adding Gateway listener ports discovered from existing Gateway specs"
        );
    }

    if ingress_listeners.is_empty() && gateway_listeners.is_empty() {
        tracing::warn!(
            "No proxy listener ports configured (--ingress-http-port / --ingress-https-port) \
             and no Gateway listeners found. No traffic will be served until ports are added."
        );
    }

    let currently_bound: HashSet<u16> = ingress_listeners
        .iter()
        .chain(gateway_listeners.iter())
        .map(|l| l.addr.port())
        .collect();

    if proxy.proxy_accept_proxy_protocol {
        if proxy.proxy_trusted_sources.is_empty() {
            tracing::warn!(
                "--proxy-accept-proxy-protocol is set but --proxy-trusted-sources is empty; \
                 all connections will be rejected"
            );
        }
        let trusted = Arc::new(TrustedSources::new(proxy.proxy_trusted_sources.clone()));
        if !ingress_listeners.is_empty() {
            let p = Arc::new(http_proxy(
                &server.configuration,
                IngressProxy::new(
                    Arc::new(RoutingEngine::new(source.ingress_routes())),
                    default_timeouts.clone(),
                    ca_cache.clone(),
                ),
            ));
            let selector = SniCertSelector::new(source.tls_store());
            let acceptor = ProxyAcceptor::new(p, ingress_listeners, trusted.clone(), selector)
                .context("build IngressProxy acceptor")?;
            server.add_service(acceptor);
        }
        if !gateway_listeners.is_empty() {
            let p = Arc::new(http_proxy(
                &server.configuration,
                GatewayProxy::new(
                    Arc::new(RoutingEngine::new(source.gateway_routes())),
                    default_timeouts.clone(),
                    ca_cache.clone(),
                ),
            ));
            let selector = SniCertSelector::new(source.tls_store());
            let acceptor = ProxyAcceptor::new(p, gateway_listeners, trusted, selector)
                .context("build GatewayProxy acceptor")?;
            server.add_service(acceptor);
        }
    } else {
        if !ingress_listeners.is_empty() {
            let mut svc = http_proxy_service_with_name(
                &server.configuration,
                IngressProxy::new(
                    Arc::new(RoutingEngine::new(source.ingress_routes())),
                    default_timeouts.clone(),
                    ca_cache.clone(),
                ),
                "ingress-proxy",
            );
            for spec in &ingress_listeners {
                match spec.protocol {
                    ListenerProtocol::Http => {
                        svc.add_tcp(&spec.addr.to_string());
                    }
                    ListenerProtocol::Https => {
                        let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
                            Box::new(SniCertSelector::new(source.tls_store()));
                        let tls_settings = TlsSettings::with_callbacks(callbacks)
                            .context("build Ingress TLS settings")?;
                        svc.add_tls_with_settings(&spec.addr.to_string(), None, tls_settings);
                    }
                }
            }
            server.add_service(svc);
        }
        if !gateway_listeners.is_empty() {
            let mut svc = http_proxy_service_with_name(
                &server.configuration,
                GatewayProxy::new(
                    Arc::new(RoutingEngine::new(source.gateway_routes())),
                    default_timeouts.clone(),
                    ca_cache.clone(),
                ),
                "gateway-proxy",
            );
            for spec in &gateway_listeners {
                match spec.protocol {
                    ListenerProtocol::Http => {
                        svc.add_tcp(&spec.addr.to_string());
                    }
                    ListenerProtocol::Https => {
                        let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
                            Box::new(SniCertSelector::new(source.tls_store()));
                        let tls_settings = TlsSettings::with_callbacks(callbacks)
                            .context("build Gateway TLS settings")?;
                        svc.add_tls_with_settings(&spec.addr.to_string(), None, tls_settings);
                    }
                }
            }
            server.add_service(svc);
        }
    }

    server.add_service(background_service(
        "hot-reloader",
        hot_reload::HotReloader::new(tls_health.clone(), currently_bound, ingress_ports),
    ));
    Ok(())
}

/// Register the health and admin HTTP servers on the supplied server.
///
/// When `cluster` is `Some`, the admin server also serves `GET /cluster` and
/// includes the three cluster-wide counters in `GET /status`. The shared-proxy
/// role passes `None` so its admin surface stays read-only-and-routing-only.
fn wire_management_servers(
    server: &mut Server,
    common: &CommonArgs,
    health: HealthRegistry,
    leader: Arc<AtomicBool>,
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    cluster: Option<SharedClusterSummary>,
) {
    let health_addr = SocketAddr::new(common.management_bind_address, common.health_port);
    server.add_service({
        let mut svc = Service::new(
            "health".to_string(),
            HealthServer {
                registry: health.clone(),
            },
        );
        svc.add_tcp(&health_addr.to_string());
        svc
    });

    let admin_addr = SocketAddr::new(common.management_bind_address, common.admin_port);
    let mut admin = AdminServer::new(health, leader, ingress_routes, gateway_routes);
    if let Some(cs) = cluster {
        admin = admin.with_cluster_summary(cs);
    }
    server.add_service(admin.into_service(admin_addr));
}

/// List all owned Gateway objects from the cluster and return listener specs for
/// ports that are not already in `already_bound`.
///
/// Soft-fails on any Kubernetes API error by logging a warning and returning an
/// empty list — coxswain will continue with the CLI-configured ports only and
/// pick up any new ports on the first HotReloader cycle.
async fn discover_gateway_ports(
    controller_name: &str,
    watch_namespace: Option<&str>,
    bind_address: IpAddr,
    already_bound: &HashSet<u16>,
) -> Vec<ListenerSpec> {
    use gateway_api::apis::standard::gatewayclasses::GatewayClass;
    use gateway_api::apis::standard::gateways::Gateway;
    use kube::api::ListParams;
    use kube::{Api, Client};

    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Cannot connect to Kubernetes at startup; skipping Gateway listener port discovery"
            );
            return vec![];
        }
    };

    let gc_api = Api::<GatewayClass>::all(client.clone());
    let gcs = match gc_api.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list GatewayClasses at startup");
            return vec![];
        }
    };

    let owned_classes: HashSet<String> = gcs
        .iter()
        .filter(|gc| gc.spec.controller_name == controller_name)
        .filter_map(|gc| gc.metadata.name.clone())
        .collect();

    if owned_classes.is_empty() {
        return vec![];
    }

    let gw_api: Api<Gateway> = match watch_namespace {
        Some(ns) => Api::namespaced(client, ns),
        None => Api::all(client),
    };
    let gateways = match gw_api.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list Gateways at startup");
            return vec![];
        }
    };

    let mut result: Vec<ListenerSpec> = Vec::new();
    let mut seen = already_bound.clone();

    for gw in gateways.iter() {
        if !owned_classes.contains(&gw.spec.gateway_class_name) {
            continue;
        }
        for listener in &gw.spec.listeners {
            let port = listener.port as u16;
            if !seen.insert(port) {
                continue;
            }
            match listener.protocol.as_str() {
                "HTTP" => result.push(ListenerSpec::http(SocketAddr::new(bind_address, port))),
                "HTTPS" | "TLS" => {
                    result.push(ListenerSpec::https(SocketAddr::new(bind_address, port)))
                }
                other => tracing::debug!(
                    protocol = other,
                    port,
                    "Skipping non-HTTP/HTTPS Gateway listener at startup"
                ),
            }
        }
    }

    result
}

/// Build a Pingora server with proxy-tuned defaults (threads + shutdown
/// timings). Used by `run_proxy_shared` and `run_dev`.
fn build_server(args: &ProxyArgs) -> Server {
    let conf = ServerConf {
        threads: args.proxy_threads,
        grace_period_seconds: Some(args.proxy_shutdown_grace_period.as_secs()),
        graceful_shutdown_timeout_seconds: Some(args.proxy_shutdown_timeout.as_secs()),
        ..Default::default()
    };

    let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), conf);
    server.bootstrap();
    server
}

/// Build a Pingora server with defaults sized for the controller role: no
/// proxy-thread tuning, no shutdown grace period required (no traffic to
/// drain). Used by `run_controller`.
fn build_minimal_server() -> Server {
    let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), ServerConf::default());
    server.bootstrap();
    server
}

/// Polls until the parent process has exited, up to 30 s.
///
/// Used by restart children to avoid binding ports before the parent has
/// released them. Runs synchronously before the async runtime starts.
///
/// The implementation uses `getppid()` rather than `kill(parent_pid, 0)`:
/// when the parent exits, the kernel reparents the child to PID 1 (`init` /
/// `launchd`) immediately, regardless of whether the parent's zombie has been
/// reaped. `kill(pid, 0)` returns success for an un-reaped zombie and can
/// stall the wait for the full deadline whenever the parent's grand-parent
/// (e.g. a test harness) doesn't actively `waitpid()` — observed in the
/// `coxswain-e2e` harness, where tokio holds the parent `Child` without
/// awaiting it.
fn wait_for_parent_exit(_parent_pid: i32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while nix::unistd::getppid().as_raw() != 1 {
        if std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn init_logger(format: LogFormat, log_filter: &str) -> Result<()> {
    let env_filter = EnvFilter::new(log_filter);

    match format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().flatten_event(true))
                .try_init()
                .context("failed to initialize JSON logger")?;
        }
        LogFormat::Console => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_ansi(true))
                .try_init()
                .context("failed to initialize console logger")?;
        }
    }

    Ok(())
}
