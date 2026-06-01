use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use coxswain_admin::AdminServer;
use coxswain_controller::{Controller, ControllerConfig, Reconciler};
use coxswain_core::ownership::OwnedGateways;
use coxswain_core::routing::SharedRoutingTable;
use coxswain_health::HealthServer;
use coxswain_proxy::{Proxy, RoutingEngine};
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::services::background::background_service;
use pingora_core::services::listening::Service;
use pingora_proxy::http_proxy_service_with_name;
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
    let engine = build_routing_engine(routing_table.clone());
    let synced = build_flag();
    let leader = build_flag();
    let owned_gateways = OwnedGateways::new();

    register_controller(
        &mut server,
        synced.clone(),
        leader.clone(),
        owned_gateways.clone(),
        controller_config,
    );
    register_reconciler(
        &mut server,
        routing_table.clone(),
        owned_gateways,
        args.controller_name.clone(),
        args.controller_watch_namespace.clone(),
    );
    register_proxy(&mut server, engine, args.proxy_addr);
    register_health(&mut server, synced.clone(), args.health_addr);
    register_admin(&mut server, routing_table, synced, leader, args.admin_addr);

    tracing::info!(
        proxy_addr = %args.proxy_addr,
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

fn build_routing_engine(table: SharedRoutingTable) -> Arc<RoutingEngine> {
    Arc::new(RoutingEngine::new(table))
}

fn build_flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

fn register_controller(
    server: &mut Server,
    synced: Arc<AtomicBool>,
    leader: Arc<AtomicBool>,
    owned_gateways: OwnedGateways,
    config: ControllerConfig,
) {
    server.add_service(background_service(
        "controller",
        Controller::new(synced, leader, owned_gateways, config),
    ));
}

fn register_health(server: &mut Server, synced: Arc<AtomicBool>, addr: SocketAddr) {
    let mut svc = Service::new("health".to_string(), HealthServer { synced });
    svc.add_tcp(&addr.to_string());
    server.add_service(svc);
}

fn register_admin(
    server: &mut Server,
    routes: SharedRoutingTable,
    synced: Arc<AtomicBool>,
    leader: Arc<AtomicBool>,
    addr: SocketAddr,
) {
    server.add_service(
        AdminServer {
            synced,
            leader,
            routes,
        }
        .into_service(addr),
    );
}

fn register_reconciler(
    server: &mut Server,
    routes: SharedRoutingTable,
    owned_gateways: OwnedGateways,
    controller_name: String,
    watch_namespace: Option<String>,
) {
    server.add_service(background_service(
        "reconciler",
        Reconciler::new(routes, owned_gateways, controller_name, watch_namespace),
    ));
}

fn register_proxy(server: &mut Server, engine: Arc<RoutingEngine>, addr: SocketAddr) {
    let proxy_logic = Proxy { engine };
    let mut proxy_service =
        http_proxy_service_with_name(&server.configuration, proxy_logic, "proxy");
    proxy_service.add_tcp(&addr.to_string());
    server.add_service(proxy_service);
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
