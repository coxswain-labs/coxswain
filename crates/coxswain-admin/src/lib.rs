//! Admin HTTP endpoints for Coxswain: `/metrics` (Prometheus), `/routes`,
//! `/status`, and (controller-only) `/cluster`.

use async_trait::async_trait;
use coxswain_core::cluster::{ClusterSummary, ControllerSummary, SharedClusterSummary};
use coxswain_core::health::{HealthRegistry, SubsystemSnapshot};
use coxswain_core::routing::{RoutingTable, SharedGatewayRoutingTable, SharedIngressRoutingTable};
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

/// Pingora HTTP app serving `/metrics`, `/routes`, `/status`, and — when
/// constructed with [`Self::with_cluster_summary`] — `/cluster`.
///
/// The `cluster` handle is the opt-in switch: only the controller and `dev`
/// pod roles wire it through; `proxy --shared` and `proxy --gateway` leave
/// it `None`, so `GET /cluster` on a proxy pod returns 404. This makes the
/// proxy / controller surface difference structural rather than convention.
#[non_exhaustive]
pub struct AdminServer {
    /// Shared health registry surfaced under `/status.subsystems`.
    pub health: HealthRegistry,
    /// Flipped to `true` while this replica holds the leader-election lease.
    pub leader: Arc<AtomicBool>,
    /// Live Ingress routing table snapshot used by `/routes` and `/status`.
    pub ingress_routes: SharedIngressRoutingTable,
    /// Live Gateway-API routing table snapshot used by `/routes` and `/status`.
    pub gateway_routes: SharedGatewayRoutingTable,
    /// Optional aggregate cluster summary. `None` on proxy roles (returns 404
    /// from `/cluster` and omits the new `/status` counters); `Some` on the
    /// controller and `dev` roles.
    pub cluster: Option<SharedClusterSummary>,
}

impl AdminServer {
    /// Construct an `AdminServer` from its runtime collaborators.
    #[must_use]
    pub fn new(
        health: HealthRegistry,
        leader: Arc<AtomicBool>,
        ingress_routes: SharedIngressRoutingTable,
        gateway_routes: SharedGatewayRoutingTable,
    ) -> Self {
        Self {
            health,
            leader,
            ingress_routes,
            gateway_routes,
            cluster: None,
        }
    }

    /// Attach a cluster-summary snapshot, enabling `GET /cluster` and the three
    /// extra counters in `GET /status`.
    ///
    /// Called only from the `controller` and `dev` pod roles. Proxy roles
    /// omit this so the read-only-proxy invariant extends to "the proxy admin
    /// surface never returns cluster aggregates" structurally.
    #[must_use]
    pub fn with_cluster_summary(mut self, cluster: SharedClusterSummary) -> Self {
        self.cluster = Some(cluster);
        self
    }

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
            "/routes" => routes_response(&self.ingress_routes, &self.gateway_routes),
            "/status" => status_response(
                &self.health,
                &self.leader,
                &self.ingress_routes,
                &self.gateway_routes,
                self.cluster.as_ref(),
            ),
            "/cluster" => cluster_response(self.cluster.as_ref(), &self.leader),
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

/// Build the per-spec block of the `/routes` payload from a typed table.
///
/// Generic over `Kind` so the same body serialises both the Ingress and the
/// Gateway-API tables; the type parameter prevents the caller from passing the
/// wrong table to the wrong block label.
fn routes_block<K>(table: &RoutingTable<K>) -> serde_json::Value {
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
    serde_json::json!({ "hosts": hosts, "conflicts": conflicts })
}

fn routes_response(
    ingress: &SharedIngressRoutingTable,
    gateway: &SharedGatewayRoutingTable,
) -> Response<Vec<u8>> {
    let body = serde_json::json!({
        "ingress": routes_block(ingress.load().as_ref()),
        "gateway": routes_block(gateway.load().as_ref()),
    })
    .to_string();
    json_response(body)
}

/// Typed `/status` response. `synced` is retained as a derived top-level alias
/// of `health.is_ready()` so external consumers that pre-date the per-subsystem
/// model keep working; new tooling should read `subsystems`.
///
/// The `gateway_count` / `dedicated_count` / `ingress_count` fields are present
/// only on roles that publish a [`SharedClusterSummary`] (controller, dev) and
/// skipped via `Option::is_none` otherwise. The flat shape matches the existing
/// `host_count` precedent.
#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    synced: bool,
    leader: bool,
    host_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dedicated_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress_count: Option<usize>,
    subsystems: BTreeMap<Arc<str>, SubsystemSnapshot>,
}

fn status_response(
    health: &HealthRegistry,
    leader: &Arc<AtomicBool>,
    ingress: &SharedIngressRoutingTable,
    gateway: &SharedGatewayRoutingTable,
    cluster: Option<&SharedClusterSummary>,
) -> Response<Vec<u8>> {
    let host_count = ingress.load().host_count() + gateway.load().host_count();
    let snapshot = health.snapshot();
    let (gateway_count, dedicated_count, ingress_count) = cluster
        .map(|c| {
            let s = c.load();
            let dedicated = s
                .gateways
                .iter()
                .filter(|g| matches!(g.proxy.pool, coxswain_core::cluster::ProxyPool::Dedicated))
                .count();
            (
                Some(s.gateways.len()),
                Some(dedicated),
                Some(s.ingresses.len()),
            )
        })
        .unwrap_or((None, None, None));
    let resp = StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        synced: health.is_ready(),
        leader: leader.load(Ordering::Acquire),
        host_count,
        gateway_count,
        dedicated_count,
        ingress_count,
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

/// Borrowed view of a [`ClusterSummary`] whose `controller.leader` is sourced
/// from the live [`AtomicBool`] instead of the snapshot.
///
/// The reflector publishes a fresh `ClusterSummary` per debounce window (~500 ms);
/// leader-election transitions are seconds-scale, so reading the leader flag at
/// response time keeps the surface honest without introducing a clone of the
/// summary's gateway/ingress lists on every request.
#[derive(Serialize)]
struct ClusterResponse<'a> {
    gateways: &'a [coxswain_core::cluster::GatewaySummary],
    ingresses: &'a [coxswain_core::cluster::IngressSummary],
    controller: ControllerSummary,
}

fn cluster_response(
    cluster: Option<&SharedClusterSummary>,
    leader: &Arc<AtomicBool>,
) -> Response<Vec<u8>> {
    let Some(handle) = cluster else {
        let mut r = Response::new(Vec::new());
        *r.status_mut() = StatusCode::NOT_FOUND;
        return r;
    };
    let snapshot: Arc<ClusterSummary> = handle.load();
    let resp = ClusterResponse {
        gateways: &snapshot.gateways,
        ingresses: &snapshot.ingresses,
        controller: ControllerSummary::new(leader.load(Ordering::Acquire)),
    };
    match serde_json::to_string(&resp) {
        Ok(body) => json_response(body),
        Err(e) => {
            tracing::error!(error = %e, "Failed to encode /cluster response");
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

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::cluster::{
        ClusterSummary, ControllerSummary, GatewaySummary, IngressSummary, ProxyAssignment,
    };

    fn leader_flag(value: bool) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(value))
    }

    #[test]
    fn cluster_response_returns_404_without_summary() {
        let leader = leader_flag(false);
        let resp = cluster_response(None, &leader);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn cluster_response_returns_empty_json_when_summary_is_empty() {
        let cs: SharedClusterSummary = SharedClusterSummary::default();
        let leader = leader_flag(true);
        let resp = cluster_response(Some(&cs), &leader);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .map(|h| h.as_bytes()),
            Some(&b"application/json"[..])
        );
        let body = std::str::from_utf8(resp.body()).expect("utf8 body");
        let v: serde_json::Value = serde_json::from_str(body.trim()).expect("json");
        assert_eq!(
            v,
            serde_json::json!({
                "gateways": [],
                "ingresses": [],
                "controller": { "leader": true }
            })
        );
    }

    #[test]
    fn cluster_response_reflects_live_leader_flag_not_snapshot_value() {
        let cs: SharedClusterSummary = SharedClusterSummary::default();
        // Snapshot says leader=false; live flag says true. Response should follow the live flag.
        cs.store(Arc::new(ClusterSummary::new(
            vec![],
            vec![],
            ControllerSummary::new(false),
        )));
        let leader = leader_flag(true);
        let resp = cluster_response(Some(&cs), &leader);
        let body = std::str::from_utf8(resp.body()).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(body.trim()).expect("json");
        assert_eq!(v["controller"]["leader"], serde_json::Value::Bool(true));
    }

    #[test]
    fn cluster_response_serialises_populated_summary() {
        let cs: SharedClusterSummary = SharedClusterSummary::default();
        cs.store(Arc::new(ClusterSummary::new(
            vec![
                GatewaySummary::new("public-gw", "tenant-a")
                    .with_proxy(ProxyAssignment::dedicated())
                    .with_route_count(12),
            ],
            vec![IngressSummary::new("foo", "default").with_route_count(2)],
            ControllerSummary::new(false),
        )));
        let leader = leader_flag(false);
        let resp = cluster_response(Some(&cs), &leader);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = std::str::from_utf8(resp.body()).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(body.trim()).expect("json");
        assert_eq!(v["gateways"][0]["proxy"]["pool"], "dedicated");
        assert_eq!(v["gateways"][0]["route_count"], 12);
        assert_eq!(v["ingresses"][0]["route_count"], 2);
    }

    #[test]
    fn status_response_omits_cluster_counters_when_summary_is_absent() {
        let registry = HealthRegistry::new();
        let ingress = SharedIngressRoutingTable::new();
        let gateway = SharedGatewayRoutingTable::new();
        let leader = leader_flag(false);
        let resp = status_response(&registry, &leader, &ingress, &gateway, None);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = std::str::from_utf8(resp.body()).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(body.trim()).expect("json");
        assert!(v.get("gateway_count").is_none());
        assert!(v.get("dedicated_count").is_none());
        assert!(v.get("ingress_count").is_none());
    }

    #[test]
    fn status_response_includes_cluster_counters_when_summary_is_present() {
        let registry = HealthRegistry::new();
        let ingress = SharedIngressRoutingTable::new();
        let gateway = SharedGatewayRoutingTable::new();
        let leader = leader_flag(false);
        let cs: SharedClusterSummary = SharedClusterSummary::default();
        cs.store(Arc::new(ClusterSummary::new(
            vec![
                GatewaySummary::new("a", "default").with_proxy(ProxyAssignment::shared()),
                GatewaySummary::new("b", "default").with_proxy(ProxyAssignment::dedicated()),
                GatewaySummary::new("c", "default").with_proxy(ProxyAssignment::dedicated()),
            ],
            vec![
                IngressSummary::new("i1", "default"),
                IngressSummary::new("i2", "default"),
            ],
            ControllerSummary::new(false),
        )));
        let resp = status_response(&registry, &leader, &ingress, &gateway, Some(&cs));
        let body = std::str::from_utf8(resp.body()).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(body.trim()).expect("json");
        assert_eq!(v["gateway_count"], 3);
        assert_eq!(v["dedicated_count"], 2);
        assert_eq!(v["ingress_count"], 2);
    }

    #[test]
    fn admin_server_without_cluster_summary_serves_404_on_cluster_path() {
        // This is the proxy-role contract: no cluster summary wired → /cluster returns 404.
        let admin = AdminServer::new(
            HealthRegistry::new(),
            leader_flag(false),
            SharedIngressRoutingTable::new(),
            SharedGatewayRoutingTable::new(),
        );
        assert!(admin.cluster.is_none());
    }

    #[test]
    fn admin_server_with_cluster_summary_enables_cluster_endpoint() {
        let admin = AdminServer::new(
            HealthRegistry::new(),
            leader_flag(false),
            SharedIngressRoutingTable::new(),
            SharedGatewayRoutingTable::new(),
        )
        .with_cluster_summary(SharedClusterSummary::default());
        assert!(admin.cluster.is_some());
    }
}
