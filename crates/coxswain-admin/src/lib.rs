//! Admin HTTP endpoints for Coxswain: `/metrics` (Prometheus), `/routes`, and `/status`.

use async_trait::async_trait;
use coxswain_core::health::{HealthRegistry, SubsystemSnapshot};
use coxswain_core::routing::SharedRoutingTable;
use http::{HeaderValue, Response, StatusCode, header};
use pingora_core::apps::http_app::{HttpServer, ServeHttp};
use pingora_core::modules::http::compression::ResponseCompressionBuilder;
use pingora_core::protocols::http::ServerSession;
use pingora_core::services::listening::Service;
use prometheus::{Encoder, TextEncoder};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Pingora HTTP app serving `/metrics`, `/routes`, and `/status`.
pub struct AdminServer {
    /// Shared health registry surfaced under `/status.subsystems`.
    pub health: HealthRegistry,
    /// Flipped to `true` while this replica holds the leader-election lease.
    pub leader: Arc<AtomicBool>,
    /// Live routing table snapshot used by `/routes`.
    pub routes: SharedRoutingTable,
}

impl AdminServer {
    /// Wraps `self` in a Pingora [`Service`] bound to `addr`.
    #[must_use]
    pub fn into_service(self, addr: SocketAddr) -> Service<HttpServer<Self>> {
        let mut http_server = HttpServer::new_app(self);
        http_server.add_module(ResponseCompressionBuilder::enable(7));
        let mut svc = Service::new("admin".to_string(), http_server);
        svc.add_tcp(&addr.to_string());
        svc
    }
}

#[async_trait]
impl ServeHttp for AdminServer {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        match session.req_header().uri.path() {
            "/metrics" => metrics_response(),
            "/routes" => routes_response(&self.routes),
            "/status" => status_response(&self.health, &self.leader, &self.routes),
            _ => {
                let mut r = Response::new(Vec::new());
                *r.status_mut() = StatusCode::NOT_FOUND;
                r
            }
        }
    }
}

fn metrics_response() -> Response<Vec<u8>> {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        tracing::warn!(error = %e, "Failed to encode Prometheus metrics");
        let mut r = Response::new(Vec::new());
        *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return r;
    }
    let content_type = HeaderValue::from_str(encoder.format_type())
        .unwrap_or_else(|_| HeaderValue::from_static("text/plain"));
    let mut r = Response::new(buffer);
    *r.status_mut() = StatusCode::OK;
    r.headers_mut().insert(header::CONTENT_TYPE, content_type);
    r
}

fn routes_response(routes: &SharedRoutingTable) -> Response<Vec<u8>> {
    let table = routes.load();
    let hosts: Vec<serde_json::Value> = table
        .host_routes()
        .into_iter()
        .map(|(port, host, router)| {
            let routes: Vec<serde_json::Value> = router
                .routes()
                .iter()
                .filter(|r| !r.backend_group.name().is_empty())
                .map(|r| {
                    serde_json::json!({
                        "type": r.kind.as_str(),
                        "path": r.path,
                        "backend_group": r.backend_group.name(),
                        "endpoints": r.backend_group.endpoints().iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    })
                })
                .collect();
            serde_json::json!({ "port": port, "host": host, "routes": routes })
        })
        .collect();
    let conflicts: Vec<serde_json::Value> = table
        .conflicts()
        .iter()
        .map(|c| {
            serde_json::json!({
                "port": c.port,
                "host": c.host,
                "type": c.kind.as_str(),
                "path": c.path,
                "rejected_group": c.rejected_group,
            })
        })
        .collect();
    let body = serde_json::json!({ "hosts": hosts, "conflicts": conflicts }).to_string();
    json_response(body)
}

/// Typed `/status` response. `synced` is retained as a derived top-level alias
/// of `health.is_ready()` so external consumers that pre-date the per-subsystem
/// model keep working; new tooling should read `subsystems`.
#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    synced: bool,
    leader: bool,
    host_count: usize,
    subsystems: BTreeMap<Arc<str>, SubsystemSnapshot>,
}

fn status_response(
    health: &HealthRegistry,
    leader: &Arc<AtomicBool>,
    routes: &SharedRoutingTable,
) -> Response<Vec<u8>> {
    let table = routes.load();
    let snapshot = health.snapshot();
    let resp = StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        synced: health.is_ready(),
        leader: leader.load(Ordering::Acquire),
        host_count: table.host_count(),
        subsystems: snapshot.subsystems,
    };
    match serde_json::to_string(&resp) {
        Ok(body) => json_response(body),
        Err(e) => {
            tracing::error!(error = %e, "Failed to encode /status response");
            let mut r = Response::new(Vec::new());
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            r
        }
    }
}

fn json_response(mut body: String) -> Response<Vec<u8>> {
    body.push('\n');
    let mut r = Response::new(body.into_bytes());
    *r.status_mut() = StatusCode::OK;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}
