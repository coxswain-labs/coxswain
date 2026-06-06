mod hot_reload;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use coxswain_admin::AdminServer;
use coxswain_controller::tls::SharedGatewayListenerHealth;
use coxswain_controller::{
    Controller, ControllerConfig, IngressDefaultBackend, IngressPorts, Reconciler,
    ReconcilerOptions,
};
use coxswain_core::ownership::OwnedGateways;
use coxswain_core::routing::RouteTimeouts;
use coxswain_core::routing::SharedRoutingTable;
use coxswain_core::tls::SharedTlsStore;
use coxswain_health::HealthServer;
use coxswain_proxy::{
    ListenerProtocol, ListenerSpec, Proxy, ProxyAcceptor, RoutingEngine, SniCertSelector,
    TrustedSources,
};
use ipnet::IpNet;
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
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(ValueEnum, Clone, Debug, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Console,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "coxswain",
    version,
    about = "A Kubernetes Ingress & Gateway API Controller built on Pingora",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    /// Start the controller and proxy.
    Serve(ServeArgs),
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// GatewayClass `spec.controllerName` this instance claims.
    ///
    /// Must match exactly; resources belonging to other controllers are silently ignored.
    #[arg(
        long,
        env = "COXSWAIN_CONTROLLER_NAME",
        default_value = "coxswain-labs.dev/gateway-controller"
    )]
    pub controller_name: String,

    /// Kubernetes namespace to watch. Omit for cluster-wide scope.
    #[arg(long, env = "COXSWAIN_CONTROLLER_WATCH_NAMESPACE")]
    pub controller_watch_namespace: Option<String>,

    /// Name of this pod, used as the leader-election holder identity.
    ///
    /// Injected automatically by Kubernetes via the Downward API in production.
    #[arg(long, env = "POD_NAME", default_value = "coxswain-local")]
    pub pod_name: String,

    /// Namespace of this pod, used to scope the leader-election Lease resource.
    ///
    /// Injected automatically by Kubernetes via the Downward API in production.
    #[arg(long, env = "POD_NAMESPACE", default_value = "coxswain-system")]
    pub pod_namespace: String,

    /// Log output format: `json` (default) or `console`.
    ///
    /// Use `json` in production environments; `console` for local development.
    #[arg(long, env = "COXSWAIN_LOG_FORMAT", default_value = "json")]
    pub log_format: LogFormat,

    /// Log verbosity level: `trace`, `debug`, `info`, `warn`, or `error`.
    ///
    /// Supports the `RUST_LOG` directive syntax for per-crate overrides (e.g. `info,coxswain=debug`).
    #[arg(long = "log", env = "COXSWAIN_LOG", default_value = "info")]
    pub log_filter: String,

    /// Worker threads per proxy service.
    ///
    /// Threads are not shared across services. Set to the available CPU core count for maximum throughput.
    #[arg(long, env = "COXSWAIN_PROXY_THREADS", default_value_t = 2)]
    pub proxy_threads: usize,

    /// Drain window before the final shutdown step.
    ///
    /// After a shutdown signal, existing connections are given this long to complete
    /// before the final runtime-shutdown step begins.
    /// Accepts human-readable durations: `30s`, `1m`, `1m30s`. Set to `0s` to disable.
    /// Maps to Pingora's `grace_period_seconds`.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_SHUTDOWN_GRACE_PERIOD",
        default_value = "30s",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_shutdown_grace_period: Duration,

    /// Hard deadline for the final runtime-shutdown step after the grace period expires.
    ///
    /// Accepts human-readable durations: `5s`, `10s`. Set to `0s` to disable.
    /// Maps to Pingora's `graceful_shutdown_timeout_seconds`.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_SHUTDOWN_TIMEOUT",
        default_value = "5s",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_shutdown_timeout: Duration,

    /// How long a leader lease stays valid without renewal.
    ///
    /// Determines how quickly a standby replica can take over after the leader dies.
    /// Must be at least 3× `--controller-lease-renew-interval`.
    #[arg(
        long,
        env = "COXSWAIN_CONTROLLER_LEASE_TTL",
        default_value = "15s",
        value_parser = humantime::parse_duration,
    )]
    pub controller_lease_ttl: Duration,

    /// How often the active leader renews its lease.
    ///
    /// Must be at most 1/3 of `--controller-lease-ttl`.
    #[arg(
        long,
        env = "COXSWAIN_CONTROLLER_LEASE_RENEW_INTERVAL",
        default_value = "5s",
        value_parser = humantime::parse_duration,
    )]
    pub controller_lease_renew_interval: Duration,

    /// Port to listen on for the admin, metrics, and diagnostics endpoints.
    ///
    /// The bind address is controlled by `--proxy-bind-address`.
    #[arg(long, env = "COXSWAIN_ADMIN_PORT", default_value_t = 8082)]
    pub admin_port: u16,

    /// Port to listen on for liveness and readiness health endpoints.
    ///
    /// The bind address is controlled by `--proxy-bind-address`.
    #[arg(long, env = "COXSWAIN_HEALTH_PORT", default_value_t = 8081)]
    pub health_port: u16,

    /// IP address to bind all proxy listeners to.
    ///
    /// Shared by both HTTP and HTTPS listeners. Combine with `--proxy-http-port`
    /// and/or `--proxy-https-port` to form the full bind address for each listener.
    #[arg(long, env = "COXSWAIN_PROXY_BIND_ADDRESS", default_value = "0.0.0.0")]
    pub proxy_bind_address: IpAddr,

    /// Port to listen on for inbound HTTP traffic.
    ///
    /// When omitted, no default HTTP listener is bound; coxswain relies on
    /// Gateway `spec.listeners` to discover which ports to serve.
    #[arg(long, env = "COXSWAIN_PROXY_HTTP_PORT")]
    pub proxy_http_port: Option<u16>,

    /// Port to listen on for inbound HTTPS traffic.
    ///
    /// SNI selects the certificate from each Ingress's `spec.tls` block.
    /// Handshakes with no matching SNI fail cleanly.
    ///
    /// When omitted, no default HTTPS listener is bound; coxswain relies on
    /// Gateway `spec.listeners` to discover which ports to serve.
    #[arg(long, env = "COXSWAIN_PROXY_HTTPS_PORT")]
    pub proxy_https_port: Option<u16>,

    /// External address written to every owned `Ingress.status.loadBalancer.ingress[0]`
    /// and `Gateway.status.addresses[0]`.
    ///
    /// Accepts either a bare IP (`203.0.113.1`) or a DNS hostname
    /// (`coxswain.example.com`). IP values are written to `.ip`;
    /// hostname values are written to `.hostname`.
    ///
    /// Required for cert-manager HTTP-01 challenge resolution and
    /// external-dns DNS record creation. When omitted, status is
    /// not patched (backward-compatible default).
    #[arg(long, env = "COXSWAIN_STATUS_ADDRESS")]
    pub status_address: Option<String>,

    /// Controller-wide default backend for Ingress traffic that does not match any rule.
    ///
    /// Format: `<namespace>/<service>:<port>` — e.g. `default/my-404-page:80`.
    ///
    /// When set, requests to hosts with no matching path (and requests to entirely
    /// unknown hosts) are forwarded to this service. A per-Ingress `spec.defaultBackend`
    /// always overrides this setting within that Ingress's rule hosts.
    ///
    /// The backing service is re-resolved on every routing-table rebuild; the default
    /// disappears automatically if its endpoints become unavailable and reappears when
    /// they recover.
    #[arg(long, env = "COXSWAIN_INGRESS_DEFAULT_BACKEND")]
    pub ingress_default_backend: Option<IngressDefaultBackend>,

    /// Enable HAProxy PROXY protocol v1/v2 on the proxy listeners.
    ///
    /// When set, every accepted connection MUST carry a valid PROXY header.
    /// Connections from sources not listed in `--proxy-trusted-sources` are
    /// dropped immediately. Connections that omit or malform the header are
    /// also dropped (strict mode).
    ///
    /// The real client address is propagated upstream via the RFC 7239
    /// `Forwarded` header.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_ACCEPT_PROXY_PROTOCOL",
        default_value_t = false
    )]
    pub proxy_accept_proxy_protocol: bool,

    /// Comma-separated list of CIDR ranges that are permitted to send PROXY headers.
    ///
    /// Only meaningful when `--proxy-accept-proxy-protocol` is set. Connections
    /// from addresses outside this list are rejected at the TCP level.
    ///
    /// Example: `10.0.0.0/8,172.16.0.0/12,127.0.0.1/32`
    #[arg(long, env = "COXSWAIN_PROXY_TRUSTED_SOURCES", value_delimiter = ',')]
    pub proxy_trusted_sources: Vec<IpNet>,

    /// Global default for the total request timeout (client → proxy → upstream → client).
    ///
    /// Applied to routes that do not set `HTTPRouteRule.timeouts.request`. A route-level
    /// setting always overrides this value.
    /// Accepts human-readable durations: `30s`, `1m`, `1m30s`. Omit to disable.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_DEFAULT_REQUEST_TIMEOUT",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_default_request_timeout: Option<Duration>,

    /// Global default for the upstream-only (backend) request timeout.
    ///
    /// Applied to routes that do not set `HTTPRouteRule.timeouts.backendRequest`. A
    /// route-level setting always overrides this value.
    /// Accepts human-readable durations: `10s`, `500ms`. Omit to disable.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_DEFAULT_BACKEND_REQUEST_TIMEOUT",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_default_backend_request_timeout: Option<Duration>,
}

fn main() -> Result<()> {
    // When spawned as a restart child, wait for the parent process to exit and
    // release its bound sockets before we try to bind them ourselves.
    if std::env::var("COXSWAIN_RESTART_CHILD").is_ok() {
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let cli = Cli::parse();
    let Commands::Serve(args) = cli.command;

    // Initialise logging first so that any subsequent error is emitted in the
    // configured format (JSON in production, console in dev).
    init_logger(args.log_format, &args.log_filter)?;

    let controller_config = ControllerConfig::new(
        args.controller_name.clone(),
        args.pod_name.clone(),
        args.pod_namespace.clone(),
        args.controller_lease_ttl,
        args.controller_lease_renew_interval,
        args.controller_watch_namespace.clone(),
        args.status_address.clone(),
    )?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        controller_name = %args.controller_name,
        "Starting"
    );

    let mut server = build_server(&args);

    let routing_table = SharedRoutingTable::new();
    let tls_store = SharedTlsStore::new();
    let gateway_tls_health = SharedGatewayListenerHealth::new();
    let synced = Arc::new(AtomicBool::new(false));
    let leader = Arc::new(AtomicBool::new(false));
    let owned_gateways = OwnedGateways::new();

    // Clone before move into Controller so HotReloader can subscribe to the same health map.
    let hot_reload_health = gateway_tls_health.clone();

    let reconciler = Reconciler::new(
        routing_table.clone(),
        tls_store.clone(),
        gateway_tls_health.clone(),
        owned_gateways.clone(),
        args.controller_name.clone(),
        ReconcilerOptions {
            watch_namespace: args.controller_watch_namespace.clone(),
            ingress_default_backend: args.ingress_default_backend,
            ingress_ports: IngressPorts::new(args.proxy_http_port, args.proxy_https_port),
        },
    );
    let route_health = reconciler.route_health();

    server.add_service(background_service(
        "controller",
        Controller::new(
            synced.clone(),
            leader.clone(),
            owned_gateways,
            gateway_tls_health,
            route_health,
            controller_config,
        ),
    ));

    server.add_service(background_service("reconciler", reconciler));

    let default_timeouts = RouteTimeouts {
        request: args.proxy_default_request_timeout,
        backend_request: args.proxy_default_backend_request_timeout,
    };

    // Build the list of (addr, protocol) pairs from the configured port flags.
    let mut listeners: Vec<ListenerSpec> = Vec::new();
    if let Some(port) = args.proxy_http_port {
        listeners.push(ListenerSpec::http(SocketAddr::new(
            args.proxy_bind_address,
            port,
        )));
    }
    if let Some(port) = args.proxy_https_port {
        listeners.push(ListenerSpec::https(SocketAddr::new(
            args.proxy_bind_address,
            port,
        )));
    }

    // CLI-configured ports are always included in the "desired" set used by HotReloader.
    let cli_ports: HashSet<u16> = listeners.iter().map(|l| l.addr.port()).collect();

    // Discover additional Gateway listener ports from the cluster's current state so
    // that, if Gateways already exist when coxswain restarts, we bind their ports
    // immediately rather than waiting for the first reconcile + restart cycle.
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build tokio runtime for startup Gateway port discovery")?;
        let extra = rt.block_on(discover_gateway_ports(
            &args.controller_name,
            args.controller_watch_namespace.as_deref(),
            args.proxy_bind_address,
            &cli_ports,
        ));
        if !extra.is_empty() {
            let ports: Vec<u16> = extra.iter().map(|l| l.addr.port()).collect();
            tracing::info!(
                ?ports,
                "Adding listener ports discovered from existing Gateway specs"
            );
        }
        listeners.extend(extra);
    }

    if listeners.is_empty() {
        tracing::warn!(
            "No proxy listener ports configured (--proxy-http-port / --proxy-https-port) \
             and no Gateway listeners found. No traffic will be served until ports are added."
        );
    }

    // Track the full set of ports we actually bind, so HotReloader can detect additions.
    let currently_bound: HashSet<u16> = listeners.iter().map(|l| l.addr.port()).collect();

    if args.proxy_accept_proxy_protocol {
        if args.proxy_trusted_sources.is_empty() {
            tracing::warn!(
                "--proxy-accept-proxy-protocol is set but --proxy-trusted-sources is empty; \
                 all connections will be rejected"
            );
        }
        let engine = Arc::new(RoutingEngine::new(routing_table.clone()));
        let proxy = Arc::new(http_proxy(
            &server.configuration,
            Proxy {
                engine,
                default_timeouts: default_timeouts.clone(),
            },
        ));
        let trusted = Arc::new(TrustedSources::new(args.proxy_trusted_sources.clone()));
        let sni_selector = SniCertSelector::new(tls_store);
        let acceptor = ProxyAcceptor::new(proxy, listeners, trusted, sni_selector)
            .context("build ProxyAcceptor")?;
        server.add_service(acceptor);
    } else {
        let engine = Arc::new(RoutingEngine::new(routing_table.clone()));
        let mut svc = http_proxy_service_with_name(
            &server.configuration,
            Proxy {
                engine,
                default_timeouts,
            },
            "proxy",
        );
        for spec in &listeners {
            match spec.protocol {
                ListenerProtocol::Http => {
                    svc.add_tcp(&spec.addr.to_string());
                }
                ListenerProtocol::Https => {
                    let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
                        Box::new(SniCertSelector::new(tls_store.clone()));
                    let tls_settings =
                        TlsSettings::with_callbacks(callbacks).context("build TLS settings")?;
                    svc.add_tls_with_settings(&spec.addr.to_string(), None, tls_settings);
                }
            }
        }
        server.add_service(svc);
    }

    server.add_service(background_service(
        "hot-reloader",
        hot_reload::HotReloader::new(hot_reload_health, currently_bound, cli_ports),
    ));

    let health_addr = SocketAddr::new(args.proxy_bind_address, args.health_port);
    server.add_service({
        let mut svc = Service::new(
            "health".to_string(),
            HealthServer {
                synced: synced.clone(),
            },
        );
        svc.add_tcp(&health_addr.to_string());
        svc
    });

    let admin_addr = SocketAddr::new(args.proxy_bind_address, args.admin_port);
    server.add_service(
        AdminServer {
            synced,
            leader,
            routes: routing_table,
        }
        .into_service(admin_addr),
    );

    tracing::info!(
        proxy_bind_address = %args.proxy_bind_address,
        proxy_http_port = ?args.proxy_http_port,
        proxy_https_port = ?args.proxy_https_port,
        health_port = args.health_port,
        admin_port = args.admin_port,
        proxy_shutdown_grace_period = ?args.proxy_shutdown_grace_period,
        proxy_shutdown_timeout = ?args.proxy_shutdown_timeout,
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

fn build_server(args: &ServeArgs) -> Server {
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
