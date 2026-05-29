use async_trait::async_trait;
use coxswain_core::routing::SharedRoutingTable;
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
    pub leader: Arc<AtomicBool>,
    pub routes: SharedRoutingTable,
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
            "/status" => status_response(&self.synced, &self.leader, &self.routes),
            _ => Response::builder()
                .status(404)
                .body(Vec::new())
                .expect("infallible: static response headers are valid"),
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
            .expect("infallible: static response headers are valid");
    }
    Response::builder()
        .status(200)
        .header("content-type", encoder.format_type())
        .body(buffer)
        .expect("infallible: static response headers are valid")
}

fn routes_response(routes: &SharedRoutingTable) -> Response<Vec<u8>> {
    let table = routes.load();
    let hosts: Vec<serde_json::Value> = table
        .host_routes()
        .into_iter()
        .map(|(host, router)| {
            let routes: Vec<serde_json::Value> = router
                .routes()
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "type": r.kind.as_str(),
                        "path": r.path,
                        "upstream": r.upstream.name,
                        "endpoints": r.upstream.endpoints().iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    })
                })
                .collect();
            serde_json::json!({ "host": host, "routes": routes })
        })
        .collect();
    let conflicts: Vec<serde_json::Value> = table
        .conflicts()
        .iter()
        .map(|c| {
            serde_json::json!({
                "host": c.host,
                "type": c.kind.as_str(),
                "path": c.path,
                "rejected_upstream": c.rejected_upstream,
            })
        })
        .collect();
    let body = serde_json::json!({ "hosts": hosts, "conflicts": conflicts }).to_string();
    json_response(body)
}

fn status_response(
    synced: &Arc<AtomicBool>,
    leader: &Arc<AtomicBool>,
    routes: &SharedRoutingTable,
) -> Response<Vec<u8>> {
    let table = routes.load();
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "synced": synced.load(Ordering::Acquire),
        "leader": leader.load(Ordering::Acquire),
        "host_count": table.host_count(),
    })
    .to_string();
    json_response(body)
}

fn json_response(mut body: String) -> Response<Vec<u8>> {
    body.push('\n');
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(body.into_bytes())
        .expect("infallible: static response headers are valid")
}
