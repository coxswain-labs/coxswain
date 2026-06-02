use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use coxswain_admin::AdminServer;
use coxswain_controller::tls::SharedGatewayListenerHealth;
use coxswain_controller::{Controller, ControllerConfig, IngressDefaultBackend, Reconciler};
use coxswain_core::ownership::OwnedGateways;
use coxswain_core::routing::RouteTimeouts;
use coxswain_core::routing::SharedRoutingTable;
use coxswain_core::tls::SharedTlsStore;
use coxswain_health::HealthServer;
use coxswain_proxy::{Proxy, ProxyAcceptor, RoutingEngine, SniCertSelector, TrustedSources};
use ipnet::IpNet;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::services::background::background_service;
use pingora_core::services::listening::Service;
use pingora_proxy::{http_proxy, http_proxy_service_with_name};
use std::net::SocketAddr;
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

    /// Socket address to listen on for the admin, metrics, and diagnostics endpoints.
    #[arg(long, env = "COXSWAIN_ADMIN_ADDR", default_value = "0.0.0.0:8082")]
    pub admin_addr: SocketAddr,

    /// Socket address to listen on for liveness and readiness health endpoints.
    #[arg(long, env = "COXSWAIN_HEALTH_ADDR", default_value = "0.0.0.0:8081")]
    pub health_addr: SocketAddr,

    /// Socket address to listen on for inbound HTTP traffic.
    #[arg(long, env = "COXSWAIN_PROXY_ADDR", default_value = "0.0.0.0:8080")]
    pub proxy_addr: SocketAddr,

    /// Socket address to listen on for inbound HTTPS traffic.
    ///
    /// SNI selects the certificate from each Ingress's `spec.tls` block.
    /// The listener is always bound; handshakes with no matching SNI fail cleanly.
    #[arg(long, env = "COXSWAIN_PROXY_TLS_ADDR", default_value = "0.0.0.0:8443")]
    pub proxy_tls_addr: SocketAddr,

    /// External address written to every owned `Ingress.status.loadBalancer.ingress[0]`.
    ///
    /// Accepts either a bare IP (`203.0.113.1`) or a DNS hostname
    /// (`coxswain.example.com`). IP values are written to `.ip`;
    /// hostname values are written to `.hostname`.
    ///
    /// Required for cert-manager HTTP-01 challenge resolution and
    /// external-dns DNS record creation. When omitted, Ingress status
    /// is not patched (backward-compatible default).
    #[arg(long, env = "COXSWAIN_INGRESS_STATUS_ADDRESS")]
    pub ingress_status_address: Option<String>,

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
    let cli = Cli::parse();
    let Commands::Serve(args) = cli.command;

    let controller_config = ControllerConfig::new(
        args.controller_name.clone(),
        args.pod_name.clone(),
        args.pod_namespace.clone(),
        args.controller_lease_ttl,
        args.controller_lease_renew_interval,
        args.controller_watch_namespace.clone(),
        args.ingress_status_address.clone(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    init_logger(args.log_format, &args.log_filter)?;

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

    server.add_service(background_service(
        "controller",
        Controller::new(
            synced.clone(),
            leader.clone(),
            owned_gateways.clone(),
            gateway_tls_health.clone(),
            controller_config,
        ),
    ));

    server.add_service(background_service(
        "reconciler",
        Reconciler::new(
            routing_table.clone(),
            tls_store.clone(),
            gateway_tls_health,
            owned_gateways,
            args.controller_name.clone(),
            args.controller_watch_namespace.clone(),
            args.ingress_default_backend,
        ),
    ));

    let default_timeouts = RouteTimeouts {
        request: args.proxy_default_request_timeout,
        backend_request: args.proxy_default_backend_request_timeout,
    };

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
        let acceptor = ProxyAcceptor::new(
            proxy,
            args.proxy_addr,
            args.proxy_tls_addr,
            trusted,
            sni_selector,
        )
        .expect("build ProxyAcceptor");
        server.add_service(acceptor);
    } else {
        server.add_service({
            let engine = Arc::new(RoutingEngine::new(routing_table.clone()));
            let mut svc = http_proxy_service_with_name(
                &server.configuration,
                Proxy {
                    engine,
                    default_timeouts,
                },
                "proxy",
            );
            svc.add_tcp(&args.proxy_addr.to_string());
            let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
                Box::new(SniCertSelector::new(tls_store));
            let tls_settings =
                TlsSettings::with_callbacks(callbacks).expect("TlsSettings::with_callbacks");
            svc.add_tls_with_settings(&args.proxy_tls_addr.to_string(), None, tls_settings);
            svc
        });
    }

    server.add_service({
        let mut svc = Service::new(
            "health".to_string(),
            HealthServer {
                synced: synced.clone(),
            },
        );
        svc.add_tcp(&args.health_addr.to_string());
        svc
    });

    server.add_service(
        AdminServer {
            synced,
            leader,
            routes: routing_table,
        }
        .into_service(args.admin_addr),
    );

    tracing::info!(
        proxy_addr = %args.proxy_addr,
        proxy_tls_addr = %args.proxy_tls_addr,
        health_addr = %args.health_addr,
        admin_addr = %args.admin_addr,
        proxy_shutdown_grace_period = ?args.proxy_shutdown_grace_period,
        proxy_shutdown_timeout = ?args.proxy_shutdown_timeout,
        "Listening"
    );
    server.run_forever();
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
