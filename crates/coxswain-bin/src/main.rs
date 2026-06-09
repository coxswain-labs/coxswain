//! Coxswain binary entry point: CLI parsing, shared-state wiring, and Pingora runtime bootstrap.

mod args;
mod hot_reload;

use anyhow::{Context, Result, bail};
use clap::Parser;
use coxswain_admin::AdminServer;
use coxswain_controller::{
    Controller, ControllerConfig, IngressPorts, LeaseSettings, Reconciler, ReconcilerHealth,
    ReconcilerOptions, ReconcilerOutputs, SharedGatewayListenerHealth,
};
use coxswain_core::health::HealthRegistry;
use coxswain_core::ownership::OwnedGateways;
use coxswain_core::routing::{RouteTimeouts, SharedGatewayRoutingTable, SharedIngressRoutingTable};
use coxswain_core::tls::SharedTlsStore;
use coxswain_health::HealthServer;
use coxswain_proxy::{
    GatewayProxy, IngressProxy, KubernetesSource, ListenerProtocol, ListenerSpec, ProxyAcceptor,
    RoutingEngine, RoutingSource, SniCertSelector, TrustedSources, UpstreamCaCache,
};
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

use crate::args::{Cli, Commands, DevRoleArgs, LogFormat, ProxyScope, Role};

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

    // Bare `coxswain serve` (no role) falls back to `dev` with a deprecation
    // warning. This keeps today's Helm chart and Dockerfile (CMD = ["serve"])
    // working through v0.2.0; Step 5 of the architecture plan removes this
    // fallback once the chart sets the role explicitly.
    let role_was_explicit = serve.role.is_some();
    let role = match serve.role {
        Some(r) => r,
        None => implicit_dev_role()?,
    };

    match role {
        Role::Dev(dev_args) => run_dev(dev_args, role_was_explicit),
        Role::Controller(_) => {
            bail!(
                "role 'controller' is not yet implemented (issue #202 scaffolding only; see Step 5)"
            )
        }
        Role::Proxy(proxy_args) => match proxy_args.scope() {
            ProxyScope::Shared => {
                bail!("role 'proxy --shared' is not yet implemented (see Step 5)")
            }
            ProxyScope::Gateway { .. } => {
                bail!("role 'proxy --gateway' is not yet implemented (see Step 7)")
            }
        },
    }
}

/// Constructs a [`Role::Dev`] populated with `coxswain serve dev` defaults
/// (including env-var overrides). Used when bare `coxswain serve` is invoked
/// without a role subcommand.
fn implicit_dev_role() -> Result<Role> {
    let cli = Cli::try_parse_from(["coxswain", "serve", "dev"])
        .context("constructing implicit-dev fallback")?;
    let Commands::Serve(serve) = cli.command;
    let Some(role @ Role::Dev(_)) = serve.role else {
        unreachable!("invariant: re-parsing ['serve', 'dev'] must yield Role::Dev")
    };
    Ok(role)
}

fn run_dev(args: DevRoleArgs, role_was_explicit: bool) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    if !role_was_explicit {
        tracing::warn!(
            "no role specified; defaulting to 'dev' (deprecated; production deployments must \
             pick `controller` or `proxy` explicitly — implicit default will be removed once the \
             Helm chart sets the role)"
        );
    }

    let controller_config = ControllerConfig::new(
        args.common.controller_name.clone(),
        args.common.pod_name.clone(),
        args.common.pod_namespace.clone(),
        LeaseSettings::new(
            args.controller.controller_lease_ttl,
            args.controller.controller_lease_renew_interval,
        ),
        args.controller.controller_watch_namespace.clone(),
        args.controller.status_address.clone(),
        IngressPorts::new(args.proxy.proxy_http_port, args.proxy.proxy_https_port),
    )?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        controller_name = %args.common.controller_name,
        "Starting"
    );

    let mut server = build_server(&args);

    let ingress_routes = SharedIngressRoutingTable::new();
    let gateway_routes = SharedGatewayRoutingTable::new();
    let tls_store = SharedTlsStore::new();
    let gateway_tls_health = SharedGatewayListenerHealth::new();
    let leader = Arc::new(AtomicBool::new(false));
    let owned_gateways = OwnedGateways::new();

    // Per-subsystem readiness model. Each Reconciler reflector flips its named
    // check on first `InitDone`; the first successful routing-table publish
    // flips `controller.routing_table_built` and `proxy.routing_table_loaded`.
    // `/readyz` is 200 iff every check across both subsystems is Ready/Degraded.
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

    // Clone before move into Controller so HotReloader can subscribe to the same health map.
    let hot_reload_health = gateway_tls_health.clone();

    let reconciler = Reconciler::new(
        ReconcilerOutputs::new(
            ingress_routes.clone(),
            gateway_routes.clone(),
            tls_store.clone(),
            gateway_tls_health.clone(),
        ),
        owned_gateways.clone(),
        ReconcilerHealth::new(controller_handle, proxy_handle),
        args.common.controller_name.clone(),
        {
            let mut opts = ReconcilerOptions::default();
            opts.watch_namespace = args.controller.controller_watch_namespace.clone();
            opts.ingress_default_backend = args.controller.ingress_default_backend.clone();
            opts.ingress_ports =
                IngressPorts::new(args.proxy.proxy_http_port, args.proxy.proxy_https_port);
            opts
        },
    );
    let route_health = reconciler.route_health();
    let policy_health = reconciler.policy_health();

    server.add_service(background_service(
        "controller",
        Controller::new(
            health.clone(),
            leader.clone(),
            owned_gateways,
            gateway_tls_health,
            route_health,
            policy_health,
            controller_config,
        ),
    ));

    server.add_service(background_service("reconciler", reconciler));

    let default_timeouts = RouteTimeouts {
        request: args.proxy.proxy_default_request_timeout,
        backend_request: args.proxy.proxy_default_backend_request_timeout,
    };

    // Ingress and Gateway proxies bind disjoint port sets. Ingress takes the
    // statically-configured `--proxy-http-port` / `--proxy-https-port`; Gateway
    // takes whatever Gateway `spec.listeners` declares, minus the Ingress set.
    let mut ingress_listeners: Vec<ListenerSpec> = Vec::new();
    if let Some(port) = args.proxy.proxy_http_port {
        ingress_listeners.push(ListenerSpec::http(SocketAddr::new(
            args.proxy.proxy_bind_address,
            port,
        )));
    }
    if let Some(port) = args.proxy.proxy_https_port {
        ingress_listeners.push(ListenerSpec::https(SocketAddr::new(
            args.proxy.proxy_bind_address,
            port,
        )));
    }
    let ingress_ports: HashSet<u16> = ingress_listeners.iter().map(|l| l.addr.port()).collect();

    // Discover Gateway listener ports from the cluster's current state so that, if
    // Gateways already exist when coxswain restarts, we bind their ports immediately
    // rather than waiting for the first reconcile + restart cycle. Ports already
    // reserved by Ingress flags are filtered out — those Gateway listeners are
    // surfaced as `Programmed=False, reason=PortUnavailable` by the controller.
    //
    // Gateway-discovered ports are also probe-bound up front: a port we cannot bind
    // (privileged port without capability, in use by another process) is dropped from
    // the discovery set with a warning, instead of taking the whole process down.
    // Unlike `--proxy-http-port` / `--proxy-https-port` (operator-explicit and strict),
    // Gateway listener ports come from user-deployed resources and should not be able
    // to crash the controller.
    let gateway_listeners: Vec<ListenerSpec> = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build tokio runtime for startup Gateway port discovery")?;
        let discovered = rt.block_on(discover_gateway_ports(
            &args.common.controller_name,
            args.controller.controller_watch_namespace.as_deref(),
            args.proxy.proxy_bind_address,
            &ingress_ports,
        ));
        let discovered = discovered
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
            .collect::<Vec<_>>();
        if !discovered.is_empty() {
            let ports: Vec<u16> = discovered.iter().map(|l| l.addr.port()).collect();
            tracing::info!(
                ?ports,
                "Adding Gateway listener ports discovered from existing Gateway specs"
            );
        }
        discovered
    };

    if ingress_listeners.is_empty() && gateway_listeners.is_empty() {
        tracing::warn!(
            "No proxy listener ports configured (--proxy-http-port / --proxy-https-port) \
             and no Gateway listeners found. No traffic will be served until ports are added."
        );
    }

    // Track every port we actually bind so HotReloader can detect additions.
    let currently_bound: HashSet<u16> = ingress_listeners
        .iter()
        .chain(gateway_listeners.iter())
        .map(|l| l.addr.port())
        .collect();

    // Single `KubernetesSource` exposes both shared handles; per-proxy engines
    // pull their typed snapshot via the trait getters.
    let source = KubernetesSource::new(
        ingress_routes.clone(),
        gateway_routes.clone(),
        tls_store.clone(),
    );
    let ca_cache = Arc::new(UpstreamCaCache::new());

    if args.proxy.proxy_accept_proxy_protocol {
        if args.proxy.proxy_trusted_sources.is_empty() {
            tracing::warn!(
                "--proxy-accept-proxy-protocol is set but --proxy-trusted-sources is empty; \
                 all connections will be rejected"
            );
        }
        let trusted = Arc::new(TrustedSources::new(
            args.proxy.proxy_trusted_sources.clone(),
        ));
        if !ingress_listeners.is_empty() {
            let proxy = Arc::new(http_proxy(
                &server.configuration,
                IngressProxy::new(
                    Arc::new(RoutingEngine::new(source.ingress_routes())),
                    default_timeouts.clone(),
                    ca_cache.clone(),
                ),
            ));
            let selector = SniCertSelector::new(source.tls_store());
            let acceptor = ProxyAcceptor::new(proxy, ingress_listeners, trusted.clone(), selector)
                .context("build IngressProxy acceptor")?;
            server.add_service(acceptor);
        }
        if !gateway_listeners.is_empty() {
            let proxy = Arc::new(http_proxy(
                &server.configuration,
                GatewayProxy::new(
                    Arc::new(RoutingEngine::new(source.gateway_routes())),
                    default_timeouts.clone(),
                    ca_cache.clone(),
                ),
            ));
            let selector = SniCertSelector::new(source.tls_store());
            let acceptor = ProxyAcceptor::new(proxy, gateway_listeners, trusted, selector)
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
        hot_reload::HotReloader::new(hot_reload_health, currently_bound, ingress_ports),
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
        AdminServer::new(health, leader, ingress_routes, gateway_routes).into_service(admin_addr),
    );

    tracing::info!(
        proxy_bind_address = %args.proxy.proxy_bind_address,
        proxy_http_port = ?args.proxy.proxy_http_port,
        proxy_https_port = ?args.proxy.proxy_https_port,
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        proxy_shutdown_grace_period = ?args.proxy.proxy_shutdown_grace_period,
        proxy_shutdown_timeout = ?args.proxy.proxy_shutdown_timeout,
        "Listening"
    );
    server.run_forever();
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

fn build_server(args: &DevRoleArgs) -> Server {
    let conf = ServerConf {
        threads: args.proxy.proxy_threads,
        grace_period_seconds: Some(args.proxy.proxy_shutdown_grace_period.as_secs()),
        graceful_shutdown_timeout_seconds: Some(args.proxy.proxy_shutdown_timeout.as_secs()),
        ..Default::default()
    };

    let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), conf);
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
