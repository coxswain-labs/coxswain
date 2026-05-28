use std::path::PathBuf;
use std::sync::Arc;
use arc_swap::ArcSwap;
use clap::Parser;
use pingora_core::server::Server;
use pingora_core::services::background::background_service;
use pingora_proxy::http_proxy_service;
use coxswain_controller::watcher::Controller;

#[derive(Parser, Debug)]
#[command(name = "coxswain", version, about = "Coxswain K8s Ingress Gateway")]
struct CliArgs {
    /// Path to the custom Coxswain/Pingora configuration YAML
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Specific namespace to watch (omitting watches all namespaces)
    #[arg(short, long, env = "WATCH_NAMESPACE")]
    namespace: Option<String>,

    /// Custom target port to bind HTTP traffic to
    #[arg(short, long, default_value_t = 80)]
    port: u16,
}

fn main() {
    println!("Bootstrapping Coxswain Ingress Engine (Strict Namespacing Mode)...");

    // 1. Instantiating the shared lock-free memory container using strict pathing
    let shared_routing_table = Arc::new(ArcSwap::from_pointee(
        coxswain_core::routing::RoutingTable::new()
    ));

    // 2. Initialize the master process manager framework for Pingora
    let mut server = Server::new(None).expect("Failed to initialize Pingora");
    server.bootstrap();

    // Register the control plane
    let controller = Controller::new(
        shared_routing_table.clone()
    );
    let controller = background_service(
        "Coxswain K8s Controller",
        controller
    );
    server.add_service(controller);

    // 4. Register the data plane via explicit module resolution
    let proxy_logic = coxswain_proxy::engine::CoxswainProxy {
        routes: shared_routing_table.clone(),
    };
    let mut proxy_service = http_proxy_service(&server.configuration, proxy_logic);
    proxy_service.add_tcp("0.0.0.0:80");
    server.add_service(proxy_service);

    // 5. Run the server loop
    println!("Coxswain runtime online. Intercepting infrastructure traffic.");
    server.run_forever();
}
