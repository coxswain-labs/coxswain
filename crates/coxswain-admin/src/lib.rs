//! Admin HTTP endpoints for Coxswain: `/metrics`, `/routes`,
//! `/api/v1/health`, `/api/v1/cluster`, and (controller-only)
//! the `/api/v1/{proxies,controllers,gateways,ingresses,routes/*}` aggregator
//! surface.

mod aggregator;
mod gw_types;

pub use aggregator::OperatorAggregator;

use aggregator::json_response;
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

// ── AdminServer ───────────────────────────────────────────────────────────────

/// Pingora HTTP app serving the Coxswain admin surface.
///
/// The available endpoints vary by pod role:
///
/// | Endpoint | All roles | Controller/dev only |
/// |---|---|---|
/// | `/metrics` | ✓ | |
/// | `/api/v1/health` | ✓ | |
/// | `/routes` | proxy + dev only | |
/// | `/api/v1/cluster` | | ✓ |
/// | `/api/v1/{proxies,controllers,gateways,ingresses,routes/*}` | | ✓ |
///
/// Each capability is gated by an `Option` field; missing capabilities return
/// 404 structurally rather than by convention.
#[non_exhaustive]
pub struct AdminServer {
    /// Shared health registry surfaced under `/api/v1/health`.
    pub health: HealthRegistry,
    /// Flipped to `true` while this replica holds the leader-election lease.
    pub leader: Arc<AtomicBool>,
    /// Routing tables for the `/routes` endpoint. `None` on the controller role
    /// (its `/routes` returns 404); `Some` on proxy and dev roles.
    pub routes: Option<(SharedIngressRoutingTable, SharedGatewayRoutingTable)>,
    /// Optional aggregate cluster summary. `None` on proxy roles (returns 404
    /// from `/api/v1/cluster`); `Some` on the controller and `dev` roles.
    pub cluster: Option<SharedClusterSummary>,
    /// Optional aggregator for the controller's `/api/v1/*` fan-out endpoints.
    /// `None` on proxy roles (those endpoints return 404).
    pub aggregator: Option<OperatorAggregator>,
}

impl AdminServer {
    /// Construct an `AdminServer` with the minimum required collaborators.
    ///
    /// Call `.with_routes()`, `.with_cluster_summary()`, and/or
    /// `.with_aggregator()` to enable optional capabilities.
    #[must_use]
    pub fn new(health: HealthRegistry, leader: Arc<AtomicBool>) -> Self {
        Self {
            health,
            leader,
            routes: None,
            cluster: None,
            aggregator: None,
        }
    }

    /// Enable `GET /routes` by supplying the proxy's local routing tables.
    ///
    /// Called only from proxy and dev pod roles. The controller omits this so
    /// its `/routes` returns 404 — the controller's routing view is the
    /// aggregate `/api/v1/routes/*` surface instead.
    #[must_use]
    pub fn with_routes(
        mut self,
        ingress: SharedIngressRoutingTable,
        gateway: SharedGatewayRoutingTable,
    ) -> Self {
        self.routes = Some((ingress, gateway));
        self
    }

    /// Enable `GET /api/v1/cluster` by supplying the cluster-summary snapshot.
    ///
    /// Called only from the `controller` and `dev` pod roles. Proxy roles
    /// omit this so the read-only-proxy invariant extends to "the proxy admin
    /// surface never returns cluster aggregates" structurally.
    #[must_use]
    pub fn with_cluster_summary(mut self, cluster: SharedClusterSummary) -> Self {
        self.cluster = Some(cluster);
        self
    }

    /// Enable the `/api/v1/{proxies,controllers,gateways,ingresses,routes/*}`
    /// aggregator endpoints.
    ///
    /// Called only from the `controller` and `dev` pod roles. Proxy roles
    /// leave the aggregator `None`, so these endpoints return 404 structurally.
    #[must_use]
    pub fn with_aggregator(mut self, aggregator: OperatorAggregator) -> Self {
        self.aggregator = Some(aggregator);
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

// ── Request routing ───────────────────────────────────────────────────────────

#[async_trait]
impl ServeHttp for AdminServer {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = session.req_header().uri.path();

        // Fast path: exact matches.
        match path {
            "/metrics" => return metrics_response(),
            "/routes" => return self.routes_response(),
            "/api/v1/health" => return health_response(&self.health),
            "/api/v1/cluster" => return cluster_response(self.cluster.as_ref(), &self.leader),
            _ => {}
        }

        // Aggregator endpoints — all under /api/v1/.
        // Return 404 when no aggregator is wired (proxy pod roles).
        let Some(agg) = self.aggregator.as_ref() else {
            if path.starts_with("/api/v1/") {
                return aggregator::not_found();
            }
            return aggregator::not_found();
        };

        // Split path into non-empty segments after the /api/v1/ prefix.
        let rest = path.strip_prefix("/api/v1/").unwrap_or(path);
        let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();

        match segs.as_slice() {
            // ── proxies ──────────────────────────────────────────────────────
            ["proxies"] => agg.list_proxies().await,
            ["proxies", name] => agg.get_proxy(name).await,
            ["proxies", name, "routes"] => agg.get_proxy_routes(name).await,
            ["proxies", name, "health"] => agg.get_proxy_health(name).await,

            // ── controllers ──────────────────────────────────────────────────
            ["controllers"] => agg.list_controllers().await,
            ["controllers", name] => agg.get_controller(name).await,
            ["controllers", name, "health"] => agg.get_controller_health(name).await,

            // ── gateways ─────────────────────────────────────────────────────
            ["gateways"] => agg.list_gateways(),
            ["gateways", namespace, name] => agg.get_gateway(namespace, name).await,

            // ── ingresses ────────────────────────────────────────────────────
            ["ingresses"] => agg.list_ingresses(),
            ["ingresses", namespace, name] => agg.get_ingress(namespace, name).await,

            // ── routes ───────────────────────────────────────────────────────
            ["routes", "httproute", namespace, name] => agg.get_httproute(namespace, name).await,
            ["routes", "ingress", namespace, name] => agg.get_ingress_route(namespace, name).await,

            _ => aggregator::not_found(),
        }
    }
}

// ── /metrics ──────────────────────────────────────────────────────────────────

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

// ── /routes ───────────────────────────────────────────────────────────────────

impl AdminServer {
    /// Build the `/routes` response from the local routing tables.
    ///
    /// Returns 404 when no routing tables are wired (controller pod role).
    fn routes_response(&self) -> Response<Vec<u8>> {
        let Some((ingress, gateway)) = self.routes.as_ref() else {
            let mut r = Response::new(Vec::new());
            *r.status_mut() = StatusCode::NOT_FOUND;
            return r;
        };
        let body = serde_json::json!({
            "ingress": routes_block(ingress.load().as_ref()),
            "gateway": routes_block(gateway.load().as_ref()),
        })
        .to_string();
        json_response(body)
    }
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

// ── /api/v1/health ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    version: &'static str,
    subsystems: BTreeMap<Arc<str>, SubsystemSnapshot>,
}

fn health_response(health: &HealthRegistry) -> Response<Vec<u8>> {
    let snapshot = health.snapshot();
    let resp = HealthResponse {
        version: env!("CARGO_PKG_VERSION"),
        subsystems: snapshot.subsystems,
    };
    match serde_json::to_string(&resp) {
        Ok(body) => json_response(body),
        Err(e) => {
            tracing::error!(error = %e, "Failed to encode /api/v1/health response");
            let mut r = Response::new(Vec::new());
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            r
        }
    }
}

// ── /api/v1/cluster ───────────────────────────────────────────────────────────

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
            tracing::error!(error = %e, "Failed to encode /api/v1/cluster response");
            let mut r = Response::new(Vec::new());
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            r
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
    fn health_response_returns_version_and_subsystems() {
        let registry = HealthRegistry::new();
        let resp = health_response(&registry);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .map(|h| h.as_bytes()),
            Some(&b"application/json"[..])
        );
        let body = std::str::from_utf8(resp.body()).expect("utf8 body");
        let v: serde_json::Value = serde_json::from_str(body.trim()).expect("json");
        assert!(v.get("version").is_some(), "response must carry `version`");
        assert!(
            v.get("subsystems").is_some(),
            "response must carry `subsystems`"
        );
        assert!(v.get("synced").is_none(), "dropped field `synced`");
        assert!(v.get("leader").is_none(), "dropped field `leader`");
        assert!(v.get("host_count").is_none(), "dropped field `host_count`");
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
    fn admin_server_without_routes_returns_404_on_routes_path() {
        let admin = AdminServer::new(HealthRegistry::new(), leader_flag(false));
        assert!(admin.routes.is_none());
    }

    #[test]
    fn admin_server_with_routes_enables_routes_endpoint() {
        let admin = AdminServer::new(HealthRegistry::new(), leader_flag(false)).with_routes(
            SharedIngressRoutingTable::new(),
            SharedGatewayRoutingTable::new(),
        );
        assert!(admin.routes.is_some());
    }

    #[test]
    fn admin_server_without_cluster_summary_serves_404_on_cluster_path() {
        let admin = AdminServer::new(HealthRegistry::new(), leader_flag(false));
        assert!(admin.cluster.is_none());
    }

    #[test]
    fn admin_server_with_cluster_summary_enables_cluster_endpoint() {
        let admin = AdminServer::new(HealthRegistry::new(), leader_flag(false))
            .with_cluster_summary(SharedClusterSummary::default());
        assert!(admin.cluster.is_some());
    }
}
