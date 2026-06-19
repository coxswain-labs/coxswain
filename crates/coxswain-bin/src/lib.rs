//! Coxswain binary runtime: CLI parsing, shared-state wiring, and Pingora runtime bootstrap.

mod args;

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use coxswain_admin::{AdminServer, EventSources, OperatorAggregator};
use coxswain_controller::{
    ControllerConfig, IngressPorts, LeaseSettings, Operator, OperatorConfig,
    SharedGatewayListenerHealth, StatusWriterConfig, spawn_status_writer,
};
use coxswain_core::health::HealthRegistry;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{RouteTimeouts, SharedGatewayRoutingTable, SharedIngressRoutingTable};
use coxswain_proxy::{
    DedicatedProxyReflector, DedicatedProxyReflectorConfig, GatewayProxy, IngressProxy,
    KubernetesSource, ListenerProtocol, ListenerSpec, ProxyAcceptor, ProxyReflector,
    ProxyReflectorConfig, RateLimiterRegistry, RoutingEngine, RoutingSource, SharedProxyConfig,
    SniCertSelector, TrustedSources, UpstreamCaCache, spawn_dedicated_routing_table_builder,
    spawn_routing_table_builder,
};
use coxswain_reflector::{GatewayListenerHealth, ListenerTlsOutcome, ReconcilerHealth};
use pingora_core::server::Server;
use pingora_core::server::ShutdownWatch;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::services::background::background_service;
use pingora_core::services::listening::Service;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::args::{
    AccessLogPathMode as BinAccessLogPathMode, Cli, Commands, CommonArgs, ControllerArgs,
    ControllerRoleArgs, DevRoleArgs, LogFormat, ProxyArgs, ProxyRoleArgs, ProxyScope, Role,
};
use coxswain_cache::ResponseCache;
use coxswain_proxy::AccessLogPathMode;

/// Executes the Coxswain proxy/controller role specified by the CLI arguments.
///
/// This is the primary entry point for the binary, responsible for CLI parsing,
/// shared state wiring, and bootstrapping the Pingora runtime or Kubernetes
/// controllers.
///
/// # Errors
/// Returns an error if CLI parsing fails, an invalid configuration is provided,
/// or the server fails to bind or run.
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

    // The operator publishes Gateway.status conditions for dedicated-mode
    // Gateways using the same per-listener TLS / route health channels the
    // shared-pool status writer subscribes to (#211). The bin layer is the
    // sole construction site for both — share the same instances so the
    // operator's reconcile-all retrigger fires off the exact channel the
    // reflector publishes into.
    let tls_health = status_writer.outputs.tls_health.clone();
    let route_health = status_writer.reconciler.route_health();

    // Capture the fleet handle before the reconciler is moved into its
    // background service — same pattern as `route_health` above.
    let fleet = status_writer.reconciler.fleet();

    // Event sources for the /api/v1/events SSE stream (#250). Capture the
    // rebuild generation receiver and clones of the fleet / cluster handles
    // before the originals are moved into the operator and aggregator below.
    let events = EventSources::new(
        route_health.subscribe(),
        fleet.clone(),
        status_writer.outputs.cluster_summary.clone(),
        args.common.pod_name.clone(),
    );

    server.add_service(background_service("controller", status_writer.controller));
    server.add_service(background_service("reconciler", status_writer.reconciler));

    server.add_service(background_service(
        "operator",
        Operator::new(OperatorConfig {
            controller_name: args.common.controller_name.clone(),
            controller_image: resolve_controller_image(),
            leader: Arc::clone(&status_writer.leader),
            tls_health,
            route_health,
            ingress_ports: IngressPorts::new(
                args.common.ingress_http_port,
                args.common.ingress_https_port,
            ),
            admin_port: args.common.admin_port,
        }),
    ));

    let aggregator = OperatorAggregator::new(fleet, status_writer.outputs.cluster_summary);

    let health_addr = SocketAddr::new(args.common.management_bind_address, args.common.health_port);
    server.add_service({
        let mut svc = Service::new(
            "health".to_string(),
            coxswain_health::HealthServer {
                registry: health.clone(),
            },
        );
        svc.add_tcp(&health_addr.to_string());
        svc
    });

    let admin_addr = SocketAddr::new(args.common.management_bind_address, args.common.admin_port);
    // The controller does NOT wire .with_routes() — its /api/v1/routes returns
    // 404. The aggregate routing surface is /api/v1/routing/* via the aggregator.
    server.add_service(
        AdminServer::new(health, status_writer.leader)
            .with_aggregator(aggregator)
            .with_events(events)
            .with_ui()
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
/// is unset.
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
/// election.
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
            "ingress_class_parameters",
            "gateway",
            "gateway_class",
            "endpoint_slice",
            "reference_grant",
            "secret",
            "auth_secret",
            "auth_tls_secret",
            "service",
            "backend_tls_policy",
            "config_map",
            "rate_limit",
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

    let cache = build_response_cache(&args.proxy);
    wire_proxy_services(
        &mut server,
        &args.common,
        &args.proxy,
        &source,
        &tls_health,
        cache,
    )?;

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        ManagementServerConfig {
            health,
            leader,
            ingress_routes: source.ingress_routes(),
            gateway_routes: source.gateway_routes(),
            aggregator: None,
            events: None,
            serve_ui: false,
            cache,
        },
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
fn run_proxy_gateway(args: ProxyRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    let (
        gateway_name,
        gateway_namespace,
        allow_cluster_wide_route_read,
        allow_cluster_wide_namespace_read,
        watch_namespaces,
    ) = match args.scope() {
        ProxyScope::Gateway {
            name,
            namespace,
            allow_cluster_wide_route_read,
            allow_cluster_wide_namespace_read,
            watch_namespaces,
        } => (
            name,
            namespace,
            allow_cluster_wide_route_read,
            allow_cluster_wide_namespace_read,
            watch_namespaces,
        ),
        ProxyScope::Shared => {
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
    let controller_handle = health.register(
        "controller",
        &[
            "httproute",
            "ingress",
            "ingress_class",
            "ingress_class_parameters",
            "gateway",
            "gateway_class",
            "endpoint_slice",
            "reference_grant",
            "secret",
            "service",
            "backend_tls_policy",
            "config_map",
            "rate_limit",
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
        watch_namespaces,
        health: ReconcilerHealth::new(controller_handle, proxy_handle),
    });

    let DedicatedProxyReflector {
        source,
        reconciler,
        tls_health,
    } = reflector;

    server.add_service(background_service("reconciler", reconciler));

    let cache = build_response_cache(&args.proxy);
    wire_gateway_only_proxy_services(
        &mut server,
        &args.common,
        &args.proxy,
        &source,
        &tls_health,
        cache,
    )?;

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        ManagementServerConfig {
            health,
            leader,
            ingress_routes: source.ingress_routes(),
            gateway_routes: source.gateway_routes(),
            aggregator: None,
            events: None,
            serve_ui: false,
            cache,
        },
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

/// Wire only the `GatewayProxy` dynamic acceptor for `serve proxy --dedicated`.
///
/// The listener set is driven by `tls_health` via a [`ListenerSpecsAdapter`]
/// background service — no startup port-discovery query is needed.  The
/// acceptor starts with an empty listener set and binds ports as the first
/// reconciler cycle completes.
fn wire_gateway_only_proxy_services(
    server: &mut Server,
    common: &CommonArgs,
    proxy: &ProxyArgs,
    source: &KubernetesSource,
    tls_health: &SharedGatewayListenerHealth,
    cache: Option<ResponseCache>,
) -> Result<()> {
    let default_timeouts = RouteTimeouts {
        request: proxy.proxy_default_request_timeout,
        backend_request: proxy.proxy_default_backend_request_timeout,
        connect: None,
        read: None,
        send: None,
    };
    let ca_cache = Arc::new(UpstreamCaCache::new());
    let rate_limiter = RateLimiterRegistry::new();
    // Single connection-pooling reqwest::Client shared across all requests for
    // ext_authz sub-requests.  rustls backend — no native-tls dep.
    let auth_client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .unwrap_or_else(|e| panic!("invariant: reqwest::Client construction must succeed: {e}"));
    let cfg = SharedProxyConfig::new(
        default_timeouts,
        ca_cache,
        proxy.access_log,
        access_log_path_mode(proxy),
        cache,
        rate_limiter.clone(),
        auth_client,
    );

    let gateway_proxy = Arc::new(pingora_proxy::http_proxy(
        &server.configuration,
        GatewayProxy::new(Arc::new(RoutingEngine::new(source.gateway_routes())), cfg),
    ));

    // Derive the initial listener set from the current health snapshot.
    // This may be empty if the reflector hasn't reconciled yet; the adapter
    // will push the first real set on its first tick.
    let initial_gw_specs = derive_gateway_specs(
        &tls_health.load(),
        proxy.proxy_bind_address,
        &HashSet::new(),
    );

    let (gw_tx, gw_rx) = watch::channel(initial_gw_specs.clone());

    if proxy.proxy_accept_proxy_protocol {
        if proxy.proxy_trusted_sources.is_empty() {
            tracing::warn!(
                "--proxy-accept-proxy-protocol is set but --proxy-trusted-sources is empty; \
                 all connections will be rejected"
            );
        }
        let trusted = Arc::new(TrustedSources::new(proxy.proxy_trusted_sources.clone()));
        let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
        server.add_service(
            ProxyAcceptor::new(
                gateway_proxy,
                initial_gw_specs,
                Some(gw_rx),
                Some(trusted),
                selector,
                proxy.proxy_listener_drain_timeout,
            )
            .context("build dedicated GatewayProxy acceptor (PROXY protocol)")?,
        );
    } else {
        let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
        server.add_service(
            ProxyAcceptor::new(
                gateway_proxy,
                initial_gw_specs,
                Some(gw_rx),
                None,
                selector,
                proxy.proxy_listener_drain_timeout,
            )
            .context("build dedicated GatewayProxy acceptor")?,
        );
    }

    server.add_service(background_service(
        "gateway-listener-specs",
        ListenerSpecsAdapter {
            tls_health: tls_health.clone(),
            bind_addr: proxy.proxy_bind_address,
            excluded_ports: HashSet::new(),
            tx: gw_tx,
        },
    ));

    server.add_service(background_service(
        "rate-limit-gc",
        RateLimiterGcService {
            registry: rate_limiter,
        },
    ));

    let _ = common;
    Ok(())
}

/// Convert the CLI `AccessLogPathMode` to the proxy-crate equivalent.
fn access_log_path_mode(proxy: &ProxyArgs) -> AccessLogPathMode {
    match proxy.access_log_path_mode {
        BinAccessLogPathMode::Full => AccessLogPathMode::Full,
        BinAccessLogPathMode::Pattern => AccessLogPathMode::Pattern,
        BinAccessLogPathMode::None => AccessLogPathMode::None,
    }
}

/// Build the process-wide response cache from `--cache-max-size`, or `None` when
/// caching is disabled (`0`). The returned handle is `Copy` and shared by every
/// proxy in the process so they hit one cache, not one per listener.
fn build_response_cache(proxy: &ProxyArgs) -> Option<ResponseCache> {
    (proxy.cache_max_size > 0).then(|| ResponseCache::with_max_bytes(proxy.cache_max_size))
}

/// Register both the Ingress and Gateway dynamic proxy acceptors on the
/// supplied server.  Shared between `run_proxy_shared` and `run_dev`.
///
/// - The **Ingress acceptor** binds a static set of ports from
///   `--ingress-http-port` / `--ingress-https-port` that never changes.
/// - The **Gateway acceptor** drives a dynamic port set derived from
///   `tls_health` via a [`ListenerSpecsAdapter`] background service; ports
///   are added or removed in-process with no restart.
fn wire_proxy_services(
    server: &mut Server,
    common: &CommonArgs,
    proxy: &ProxyArgs,
    source: &KubernetesSource,
    tls_health: &SharedGatewayListenerHealth,
    cache: Option<ResponseCache>,
) -> Result<()> {
    let default_timeouts = RouteTimeouts {
        request: proxy.proxy_default_request_timeout,
        backend_request: proxy.proxy_default_backend_request_timeout,
        connect: None,
        read: None,
        send: None,
    };
    let ca_cache = Arc::new(UpstreamCaCache::new());
    let rate_limiter = RateLimiterRegistry::new();
    // Single connection-pooling reqwest::Client shared across all requests for
    // ext_authz sub-requests.  rustls backend — no native-tls dep.
    let auth_client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .unwrap_or_else(|e| panic!("invariant: reqwest::Client construction must succeed: {e}"));
    // Shared startup-time config for both proxy types.  Clone is cheap:
    // Arc pointer bumps + Copy/Clone values.
    let mut shared_cfg = SharedProxyConfig::new(
        default_timeouts,
        ca_cache,
        proxy.access_log,
        access_log_path_mode(proxy),
        cache,
        rate_limiter.clone(),
        auth_client,
    );
    // Wire the live per-Ingress mTLS store from the reflector (#267).
    // The store is populated on the first reconcile cycle; reads before that
    // see an empty store (no mTLS enforced), which is correct — no Ingresses
    // have been observed yet.
    shared_cfg.client_certs = source.client_cert_store();

    let ingress_specs: HashSet<ListenerSpec> =
        build_ingress_listeners(common, proxy).into_iter().collect();
    let ingress_ports: HashSet<u16> = ingress_specs.iter().map(|s| s.addr.port()).collect();

    let initial_gw_specs =
        derive_gateway_specs(&tls_health.load(), proxy.proxy_bind_address, &ingress_ports);
    let (gw_tx, gw_rx) = watch::channel(initial_gw_specs.clone());

    if proxy.proxy_accept_proxy_protocol {
        if proxy.proxy_trusted_sources.is_empty() {
            tracing::warn!(
                "--proxy-accept-proxy-protocol is set but --proxy-trusted-sources is empty; \
                 all connections will be rejected"
            );
        }
        let trusted = Arc::new(TrustedSources::new(proxy.proxy_trusted_sources.clone()));

        if !ingress_specs.is_empty() {
            let p = Arc::new(pingora_proxy::http_proxy(
                &server.configuration,
                IngressProxy::new(
                    Arc::new(RoutingEngine::new(source.ingress_routes())),
                    shared_cfg.clone(),
                ),
            ));
            let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
            server.add_service(
                ProxyAcceptor::new(
                    p,
                    ingress_specs,
                    None, // static: ingress ports never change
                    Some(Arc::clone(&trusted)),
                    selector,
                    proxy.proxy_listener_drain_timeout,
                )
                .context("build IngressProxy acceptor (PROXY protocol)")?,
            );
        }

        let p = Arc::new(pingora_proxy::http_proxy(
            &server.configuration,
            GatewayProxy::new(
                Arc::new(RoutingEngine::new(source.gateway_routes())),
                shared_cfg.clone(),
            ),
        ));
        let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
        server.add_service(
            ProxyAcceptor::new(
                p,
                initial_gw_specs,
                Some(gw_rx),
                Some(trusted),
                selector,
                proxy.proxy_listener_drain_timeout,
            )
            .context("build GatewayProxy acceptor (PROXY protocol)")?,
        );
    } else {
        if !ingress_specs.is_empty() {
            let p = Arc::new(pingora_proxy::http_proxy(
                &server.configuration,
                IngressProxy::new(
                    Arc::new(RoutingEngine::new(source.ingress_routes())),
                    shared_cfg.clone(),
                ),
            ));
            let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
            server.add_service(
                ProxyAcceptor::new(
                    p,
                    ingress_specs,
                    None, // static: ingress ports never change
                    None,
                    selector,
                    proxy.proxy_listener_drain_timeout,
                )
                .context("build IngressProxy acceptor")?,
            );
        }

        let p = Arc::new(pingora_proxy::http_proxy(
            &server.configuration,
            GatewayProxy::new(
                Arc::new(RoutingEngine::new(source.gateway_routes())),
                shared_cfg,
            ),
        ));
        let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
        server.add_service(
            ProxyAcceptor::new(
                p,
                initial_gw_specs,
                Some(gw_rx),
                None,
                selector,
                proxy.proxy_listener_drain_timeout,
            )
            .context("build GatewayProxy acceptor")?,
        );
    }

    server.add_service(background_service(
        "gateway-listener-specs",
        ListenerSpecsAdapter {
            tls_health: tls_health.clone(),
            bind_addr: proxy.proxy_bind_address,
            excluded_ports: ingress_ports,
            tx: gw_tx,
        },
    ));

    server.add_service(background_service(
        "rate-limit-gc",
        RateLimiterGcService {
            registry: rate_limiter,
        },
    ));

    Ok(())
}

// ── Listener spec adapter ─────────────────────────────────────────────────────

/// Background service that watches [`SharedGatewayListenerHealth`] and
/// publishes the derived `HashSet<ListenerSpec>` to a watch channel consumed
/// by the [`ProxyAcceptor`].
///
/// The adapter fires immediately on startup (via `mark_changed`) so the
/// acceptor receives the first real spec set as soon as the reflector's
/// initial reconcile completes.
struct ListenerSpecsAdapter {
    tls_health: SharedGatewayListenerHealth,
    bind_addr: IpAddr,
    /// Ports already owned by a static acceptor (ingress ports in the shared-proxy
    /// case) that must be excluded from the gateway-derived set to avoid conflicts.
    excluded_ports: HashSet<u16>,
    tx: watch::Sender<HashSet<ListenerSpec>>,
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for ListenerSpecsAdapter {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut gen_rx = self.tls_health.subscribe();
        // Fire immediately so the acceptor gets the initial spec set as soon
        // as the reflector reconciles; do NOT fire before the first reconcile
        // (the health map is empty at that point).
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                Ok(()) = gen_rx.changed() => {
                    let specs = derive_gateway_specs(
                        &self.tls_health.load(),
                        self.bind_addr,
                        &self.excluded_ports,
                    );
                    if self.tx.send(specs).is_err() {
                        // Acceptor dropped — nothing more to do.
                        break;
                    }
                }
            }
        }
    }
}

// ── Rate-limiter GC service ───────────────────────────────────────────────────

/// Background service that periodically evicts idle per-client rate-limit buckets.
///
/// Calls [`RateLimiterRegistry::sweep`] every 60 seconds. The sweep invokes
/// `retain_recent` on every live governor `DashMapStateStore`, removing keys
/// whose GCRA state has fully recovered (bucket full; client has been quiet for
/// at least one full rate period). Routes with zero remaining keys are removed
/// from the registry entirely, bounding memory growth under high-cardinality
/// client spaces (many distinct IPs or many distinct header values).
struct RateLimiterGcService {
    registry: RateLimiterRegistry,
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for RateLimiterGcService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = interval.tick() => self.registry.sweep(),
            }
        }
    }
}

/// Derive a `HashSet<ListenerSpec>` from the current gateway listener health map.
///
/// Excludes ports already in `excluded_ports` (used to prevent the gateway
/// acceptor from binding ports already owned by the static ingress acceptor).
fn derive_gateway_specs(
    health: &std::collections::HashMap<ObjectKey, GatewayListenerHealth>,
    bind_addr: IpAddr,
    excluded_ports: &HashSet<u16>,
) -> HashSet<ListenerSpec> {
    let mut seen: HashSet<u16> = excluded_ports.clone();
    let mut specs = HashSet::new();
    for gw_health in health.values() {
        for info in gw_health.listeners.values() {
            let port = info.port;
            if !seen.insert(port) {
                continue;
            }
            let addr = SocketAddr::new(bind_addr, port);
            let protocol = match info.tls_outcome {
                ListenerTlsOutcome::NotApplicable => ListenerProtocol::Http,
                _ => ListenerProtocol::Https,
            };
            specs.insert(ListenerSpec { addr, protocol });
        }
    }
    specs
}

// ── Dev role ──────────────────────────────────────────────────────────────────

/// Wire and run the hidden `dev` pod role: single-process all-in-one for local
/// development.
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

    let source = KubernetesSource::new(
        status_writer.outputs.ingress_routes.clone(),
        status_writer.outputs.gateway_routes.clone(),
        status_writer.outputs.tls.clone(),
        status_writer.outputs.client_certs.clone(),
    );
    let tls_health = status_writer.outputs.tls_health.clone();
    // Operator's reconcile-all retrigger consumes both health channels — see
    // the `run_controller` arm for the shared rationale (#211).
    let route_health = status_writer.reconciler.route_health();
    // Capture fleet before the reconciler is moved into its background service.
    let fleet = status_writer.reconciler.fleet();

    // Event sources for /api/v1/events (#250); capture before the originals are
    // moved into the operator and aggregator below.
    let events = EventSources::new(
        route_health.subscribe(),
        fleet.clone(),
        status_writer.outputs.cluster_summary.clone(),
        args.common.pod_name.clone(),
    );

    server.add_service(background_service("controller", status_writer.controller));
    server.add_service(background_service("reconciler", status_writer.reconciler));

    server.add_service(background_service(
        "operator",
        Operator::new(OperatorConfig {
            controller_name: args.common.controller_name.clone(),
            controller_image: resolve_controller_image(),
            leader: Arc::clone(&status_writer.leader),
            tls_health: tls_health.clone(),
            route_health,
            ingress_ports: IngressPorts::new(
                args.common.ingress_http_port,
                args.common.ingress_https_port,
            ),
            admin_port: args.common.admin_port,
        }),
    ));

    let cache = build_response_cache(&args.proxy);
    wire_proxy_services(
        &mut server,
        &args.common,
        &args.proxy,
        &source,
        &tls_health,
        cache,
    )?;

    let dev_aggregator = OperatorAggregator::new(fleet, status_writer.outputs.cluster_summary);

    wire_management_servers(
        &mut server,
        &args.common,
        ManagementServerConfig {
            health,
            leader: status_writer.leader,
            ingress_routes: source.ingress_routes(),
            gateway_routes: source.gateway_routes(),
            aggregator: Some(dev_aggregator),
            events: Some(events),
            serve_ui: true,
            cache,
        },
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

// ── Shared helpers ────────────────────────────────────────────────────────────

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

/// Construct the static Ingress listener specs from CLI args.
fn build_ingress_listeners(common: &CommonArgs, proxy: &ProxyArgs) -> Vec<ListenerSpec> {
    let mut listeners: Vec<ListenerSpec> = Vec::new();
    if let Some(port) = common.ingress_http_port {
        listeners.push(ListenerSpec::http(SocketAddr::new(
            proxy.proxy_bind_address,
            port,
        )));
    }
    if let Some(port) = common.ingress_https_port {
        listeners.push(ListenerSpec::https(SocketAddr::new(
            proxy.proxy_bind_address,
            port,
        )));
    }
    listeners
}

/// Configuration bundle for [`wire_management_servers`].
///
/// Grouped to keep the function signature under the workspace
/// `>7-arg` threshold.
struct ManagementServerConfig {
    health: HealthRegistry,
    leader: Arc<AtomicBool>,
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    /// `Some` on the dev role (enables the aggregator REST surface on the
    /// single-process dev binary). Controller wires the aggregator inline.
    aggregator: Option<OperatorAggregator>,
    /// `Some` on the dev role (enables the `/api/v1/events` SSE stream).
    /// Controller wires events inline; proxy roles leave it `None`.
    events: Option<EventSources>,
    /// `true` on the dev role (serves the embedded operator UI at `GET /`).
    /// Controller wires `.with_ui()` inline; proxy roles leave this `false`.
    serve_ui: bool,
    /// Shared response cache for the `DELETE /cache/{host}/{path}` purge
    /// endpoint, or `None` when caching is disabled. Must be the *same* handle
    /// the data-plane proxies were built with so a purge hits the live cache.
    cache: Option<ResponseCache>,
}

fn wire_management_servers(
    server: &mut Server,
    common: &CommonArgs,
    config: ManagementServerConfig,
) {
    let health_addr = SocketAddr::new(common.management_bind_address, common.health_port);
    server.add_service({
        let mut svc = Service::new(
            "health".to_string(),
            coxswain_health::HealthServer {
                registry: config.health.clone(),
            },
        );
        svc.add_tcp(&health_addr.to_string());
        svc
    });

    let admin_addr = SocketAddr::new(common.management_bind_address, common.admin_port);
    let mut admin = AdminServer::new(config.health, config.leader)
        .with_routes(config.ingress_routes, config.gateway_routes)
        .with_cache(config.cache);
    if let Some(ag) = config.aggregator {
        admin = admin.with_aggregator(ag);
    }
    if let Some(ev) = config.events {
        admin = admin.with_events(ev);
    }
    if config.serve_ui {
        admin = admin.with_ui();
    }
    server.add_service(admin.into_service(admin_addr));
}

fn build_server(args: &ProxyArgs) -> Server {
    let conf = ServerConf {
        threads: args.proxy_threads,
        grace_period_seconds: Some(args.proxy_shutdown_grace_period.as_secs()),
        graceful_shutdown_timeout_seconds: Some(args.proxy_shutdown_timeout.as_secs()),
        upstream_keepalive_pool_size: args.proxy_upstream_keepalive_pool_size,
        ..Default::default()
    };

    let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), conf);
    server.bootstrap();
    server
}

fn build_minimal_server() -> Server {
    let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), ServerConf::default());
    server.bootstrap();
    server
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
