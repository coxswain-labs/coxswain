use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use coxswain_controller::controller::Controller;
use coxswain_controller::reconciler::ReconcilerService;
use coxswain_core::routing::SharedRoutingTable;
use coxswain_proxy::engine::RoutingEngine;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::services::background::background_service;
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
    about = "A Kubernetes Ingress & Gateway API Controller built on Pingora"
)]
pub struct Config {
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
    #[arg(long, env = "COXSWAIN_WATCH_NAMESPACE")]
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
    #[arg(long, env = "COXSWAIN_LOG", default_value = "info")]
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

    /// Socket address to listen on for the admin, metrics, and diagnostics endpoints.
    #[arg(long, env = "COXSWAIN_ADMIN_ADDR", default_value = "0.0.0.0:8082")]
    pub admin_addr: SocketAddr,

    /// Socket address to listen on for liveness and readiness health endpoints.
    #[arg(long, env = "COXSWAIN_HEALTH_ADDR", default_value = "0.0.0.0:8081")]
    pub health_addr: SocketAddr,

    /// Socket address to listen on for inbound HTTP traffic.
    #[arg(long, env = "COXSWAIN_PROXY_ADDR", default_value = "0.0.0.0:8080")]
    pub proxy_addr: SocketAddr,
}

fn main() -> Result<()> {
    let args = Config::parse();

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

    register_controller(
        &mut server,
        synced.clone(),
        leader.clone(),
        args.controller_name.clone(),
        args.pod_name.clone(),
        args.pod_namespace.clone(),
    );
    register_reconciler(&mut server, routing_table.clone());
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

fn build_server(args: &Config) -> Server {
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
    controller_name: String,
    pod_name: String,
    pod_namespace: String,
) {
    let controller = background_service(
        "controller",
        Controller::new(synced, leader, controller_name, pod_name, pod_namespace),
    );
    server.add_service(controller);
}

fn register_health(server: &mut Server, synced: Arc<AtomicBool>, addr: SocketAddr) {
    use coxswain_proxy::health::HealthService;
    use pingora_core::services::listening::Service;
    let mut svc = Service::new("health".to_string(), HealthService { synced });
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
        coxswain_admin::AdminService {
            synced,
            leader,
            routes,
        }
        .into_service(addr),
    );
}

fn register_reconciler(server: &mut Server, routes: SharedRoutingTable) {
    server.add_service(background_service(
        "reconciler",
        ReconcilerService::new(routes),
    ));
}

fn register_proxy(server: &mut Server, engine: Arc<RoutingEngine>, addr: SocketAddr) {
    let proxy_logic = coxswain_proxy::engine::CoxswainProxy { engine };
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
