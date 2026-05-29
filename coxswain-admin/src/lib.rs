use arc_swap::ArcSwap;
use async_trait::async_trait;
use coxswain_core::routing::RoutingTable;
use http::Response;
use pingora_core::apps::http_app::{HttpServer, ServeHttp};
use pingora_core::modules::http::compression::ResponseCompressionBuilder;
use pingora_core::protocols::http::ServerSession;
use pingora_core::services::listening::Service;
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct AdminService {
    pub synced: Arc<AtomicBool>,
    pub routes: Arc<ArcSwap<RoutingTable>>,
}

impl AdminService {
    pub fn into_service(self, port: u16) -> Service<HttpServer<Self>> {
        let mut http_server = HttpServer::new_app(self);
        http_server.add_module(ResponseCompressionBuilder::enable(7));
        let mut svc = Service::new("admin".to_string(), http_server);
        svc.add_tcp(&format!("0.0.0.0:{port}"));
        svc
    }
}

#[async_trait]
impl ServeHttp for AdminService {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        match session.req_header().uri.path() {
            "/metrics" => metrics_response(),
            "/routes" => routes_response(&self.routes),
            "/status" => status_response(&self.synced, &self.routes),
            _ => Response::builder()
                .status(404)
                .body(Vec::new())
                .unwrap(),
        }
    }
}

fn metrics_response() -> Response<Vec<u8>> {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        tracing::warn!(error = %e, "Failed to encode Prometheus metrics");
        return Response::builder()
            .status(500)
            .body(Vec::new())
            .unwrap();
    }
    Response::builder()
        .status(200)
        .header("content-type", encoder.format_type())
        .body(buffer)
        .unwrap()
}

fn routes_response(routes: &Arc<ArcSwap<RoutingTable>>) -> Response<Vec<u8>> {
    let table = routes.load();
    let hosts: Vec<&str> = table.hosts.keys().map(String::as_str).collect();
    let body = serde_json::json!({ "hosts": hosts }).to_string();
    json_response(body)
}

fn status_response(synced: &Arc<AtomicBool>, routes: &Arc<ArcSwap<RoutingTable>>) -> Response<Vec<u8>> {
    let table = routes.load();
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "synced": synced.load(Ordering::Acquire),
        "host_count": table.hosts.len(),
    })
    .to_string();
    json_response(body)
}

fn json_response(body: String) -> Response<Vec<u8>> {
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(format!("{body}\n").into_bytes())
        .unwrap()
}
