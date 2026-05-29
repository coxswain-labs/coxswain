use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::{Parser, ValueEnum};
use coxswain_controller::watcher::Controller;
use coxswain_core::routing::RoutingTable;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::services::background::background_service;
use pingora_proxy::http_proxy_service_with_name;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
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

    /// Port to listen on for inbound HTTP traffic.
    #[arg(long, env = "COXSWAIN_PROXY_HTTP_PORT", default_value_t = 8080)]
    pub proxy_http_port: u16,

    // /// Port to listen on for inbound HTTPS traffic.
    // #[arg(long, env = "COXSWAIN_PROXY_HTTPS_PORT", default_value_t = 8443)]
    // pub proxy_https_port: u16,
    /// Worker threads per proxy service.
    ///
    /// Threads are not shared across services. Set to the available CPU core count for maximum throughput.
    #[arg(long, env = "COXSWAIN_PROXY_THREADS", default_value_t = 2)]
    pub proxy_threads: usize,

    /// Seconds to drain in-flight requests before closing connections on shutdown.
    ///
    /// Set to 0 to disable graceful drain. Maps to Pingora's `grace_period_seconds`.
    #[arg(long, env = "COXSWAIN_PROXY_SHUTDOWN_TIMEOUT", default_value_t = 30)]
    pub proxy_shutdown_timeout: u64,

    /// Port to listen on for liveness and readiness health endpoints.
    #[arg(long, env = "COXSWAIN_HEALTH_PORT", default_value_t = 8081)]
    pub health_port: u16,

    /// Port to listen on for the admin, metrics, and diagnostics endpoints.
    #[arg(long, env = "COXSWAIN_ADMIN_PORT", default_value_t = 8082)]
    pub admin_port: u16,
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
    let routes = build_routing_table();
    let synced = build_flag();
    let leader = build_flag();
    register_controller(
        &mut server,
        routes.clone(),
        synced.clone(),
        leader.clone(),
        args.controller_name.clone(),
        args.pod_name.clone(),
        args.pod_namespace.clone(),
    );
    register_proxy(&mut server, routes.clone(), args.proxy_http_port);
    register_health(&mut server, routes.clone(), synced.clone(), args.health_port);
    register_admin(&mut server, routes, synced, leader, args.admin_port);

    tracing::info!(
        proxy_port = args.proxy_http_port,
        health_port = args.health_port,
        admin_port = args.admin_port,
        "Listening"
    );
    server.run_forever();
}

fn build_server(args: &Config) -> Server {
    let conf = ServerConf {
        threads: args.proxy_threads,
        grace_period_seconds: Some(args.proxy_shutdown_timeout),
        ..Default::default()
    };

    let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), conf);
    server.bootstrap();
    server
}

fn build_routing_table() -> Arc<ArcSwap<RoutingTable>> {
    Arc::new(ArcSwap::from_pointee(RoutingTable::new()))
}

fn build_flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

fn register_controller(
    server: &mut Server,
    routes: Arc<ArcSwap<RoutingTable>>,
    synced: Arc<AtomicBool>,
    leader: Arc<AtomicBool>,
    controller_name: String,
    pod_name: String,
    pod_namespace: String,
) {
    let controller = background_service(
        "controller",
        Controller::new(routes, synced, leader, controller_name, pod_name, pod_namespace),
    );
    server.add_service(controller);
}

fn register_health(
    server: &mut Server,
    routes: Arc<ArcSwap<RoutingTable>>,
    synced: Arc<AtomicBool>,
    port: u16,
) {
    use coxswain_proxy::health::HealthService;
    use pingora_core::services::listening::Service;
    let mut svc = Service::new("health".to_string(), HealthService { synced, routes });
    svc.add_tcp(&format!("0.0.0.0:{port}"));
    server.add_service(svc);
}

fn register_admin(
    server: &mut Server,
    routes: Arc<ArcSwap<RoutingTable>>,
    synced: Arc<AtomicBool>,
    leader: Arc<AtomicBool>,
    port: u16,
) {
    server.add_service(coxswain_admin::AdminService { synced, leader, routes }.into_service(port));
}

fn register_proxy(server: &mut Server, routes: Arc<ArcSwap<RoutingTable>>, port: u16) {
    let proxy_logic = coxswain_proxy::engine::CoxswainProxy { routes };
    let mut proxy_service =
        http_proxy_service_with_name(&server.configuration, proxy_logic, "proxy");
    proxy_service.add_tcp(&format!("0.0.0.0:{port}"));
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
