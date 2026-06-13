//! Admin HTTP endpoints for Coxswain: `/metrics`, `/routes`,
//! `/api/v1/health`, `/api/v1/cluster`, and (controller-only)
//! the `/api/v1/{proxies,controllers,gateways,ingresses,routes/*,problems}`
//! aggregator surface, plus the embedded operator UI served at `GET /`.

mod aggregator;
mod events;
mod gw_types;

pub use aggregator::OperatorAggregator;
pub use events::EventSources;

use aggregator::json_response;
use async_trait::async_trait;
use coxswain_core::cluster::{ClusterSummary, ControllerSummary, SharedClusterSummary};
use coxswain_core::health::{HealthRegistry, SubsystemSnapshot};
use coxswain_core::routing::{RoutingTable, SharedGatewayRoutingTable, SharedIngressRoutingTable};
use http::{HeaderValue, Response, StatusCode, header};
use pingora_core::apps::{HttpPersistentSettings, HttpServerApp, ReusedHttpStream};
use pingora_core::modules::http::HttpModules;
use pingora_core::modules::http::compression::ResponseCompressionBuilder;
use pingora_core::protocols::http::{HttpTask, ServerSession};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::listening::Service;
use pingora_http::ResponseHeader;
use prometheus::{Encoder, TextEncoder};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// ── AdminServer ───────────────────────────────────────────────────────────────

/// Embedded operator UI HTML, built from `ui/` by `npm run build`.
///
/// The build step must run before `cargo build`; CI and `Dockerfile` ensure
/// this ordering. `include_str!` resolves at compile time relative to this
/// source file — the path escapes to the workspace root via `../../`.
const UI_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ui/dist/index.html"
));

/// Pingora HTTP app serving the Coxswain admin surface.
///
/// The available endpoints vary by pod role:
///
/// | Endpoint | All roles | Controller/dev only |
/// |---|---|---|
/// | `GET /` (operator UI) | | ✓ |
/// | `/metrics` | ✓ | |
/// | `/api/v1/health` | ✓ | |
/// | `/routes` | proxy + dev only | |
/// | `/api/v1/cluster` | | ✓ |
/// | `/api/v1/{proxies,controllers,gateways,ingresses,routes/*}` | | ✓ |
/// | `/api/v1/problems` | | ✓ |
/// | `/api/v1/events` (SSE) | | ✓ |
///
/// Each capability is gated by an `Option` or `bool` field; missing
/// capabilities return 404 structurally rather than by convention.
///
/// Unlike the rest of the admin surface, `/api/v1/events` is a long-lived
/// Server-Sent Events stream, which Pingora's buffered
/// [`ServeHttp`](pingora_core::apps::http_app::ServeHttp) trait cannot drive.
/// `AdminServer` therefore implements the lower-level
/// [`HttpServerApp`] directly: it streams the events path and reproduces the
/// buffered request/response pipeline (including the response-compression
/// module) for every other endpoint.
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
    /// Optional live event sources for the `/api/v1/events` SSE stream. `None`
    /// on proxy roles (the endpoint returns 404 there).
    pub events: Option<EventSources>,
    /// Whether to serve the embedded operator UI at `GET /`. Enabled only on
    /// the controller and dev roles — proxy roles leave this `false` so `GET /`
    /// returns 404 structurally, the same gate as the aggregator surface.
    serve_ui: bool,
    /// HTTP module pipeline (response compression) applied to every buffered
    /// endpoint. The SSE stream deliberately bypasses it — compression buffers,
    /// which would defeat streaming.
    modules: HttpModules,
}

impl AdminServer {
    /// Construct an `AdminServer` with the minimum required collaborators.
    ///
    /// Call `.with_routes()`, `.with_cluster_summary()`, and/or
    /// `.with_aggregator()` to enable optional capabilities.
    #[must_use]
    pub fn new(health: HealthRegistry, leader: Arc<AtomicBool>) -> Self {
        let mut modules = HttpModules::new();
        modules.add_module(ResponseCompressionBuilder::enable(7));
        Self {
            health,
            leader,
            routes: None,
            cluster: None,
            aggregator: None,
            events: None,
            serve_ui: false,
            modules,
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

    /// Enable the `GET /api/v1/events` Server-Sent Events stream.
    ///
    /// Called only from the `controller` and `dev` pod roles. Proxy roles leave
    /// the event sources `None`, so the endpoint returns 404 structurally — the
    /// same gate as the aggregator surface.
    #[must_use]
    pub fn with_events(mut self, events: EventSources) -> Self {
        self.events = Some(events);
        self
    }

    /// Enable `GET /` to serve the embedded operator UI.
    ///
    /// Called only from the `controller` and `dev` pod roles — the same gate
    /// as the aggregator surface. Proxy roles omit this call so `GET /`
    /// returns 404 structurally.
    #[must_use]
    pub fn with_ui(mut self) -> Self {
        self.serve_ui = true;
        self
    }

    /// Wraps `self` in a Pingora [`Service`] bound to `addr`.
    ///
    /// `AdminServer` is its own [`HttpServerApp`] (it streams `/api/v1/events`),
    /// so it is registered directly rather than via Pingora's buffered
    /// `HttpServer` wrapper; the response-compression module lives on the
    /// `modules` field instead.
    #[must_use]
    pub fn into_service(self, addr: SocketAddr) -> Service<Self> {
        let mut svc = Service::new("admin".to_string(), self);
        svc.add_tcp(&addr.to_string());
        svc
    }
}

// ── HttpServerApp: streaming dispatch + buffered pipeline ──────────────────────

#[async_trait]
impl HttpServerApp for AdminServer {
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        match session.read_request().await {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => {
                tracing::error!(error = %e, "admin: failed to read request header");
                return None;
            }
        }

        // SSE stream: hand off to the events driver, which writes a chunked body
        // until the client disconnects or the server shuts down. Only the
        // controller/dev roles wire `events`; proxy roles fall through to the
        // buffered pipeline, where `/api/v1/events` resolves to a 404.
        if session.req_header().uri.path() == "/api/v1/events"
            && let Some(sources) = self.events.as_ref()
        {
            events::run_until_shutdown(sources, &self.leader, &mut session, shutdown).await;
            // The stream is torn down; never reuse the connection.
            return None;
        }

        if *shutdown.borrow() {
            session.set_keepalive(None);
        } else {
            session.set_keepalive(Some(60));
        }

        // Buffered pipeline — mirrors Pingora's `HttpServer::process_new_http`
        // so the response-compression module still runs on these endpoints.
        let mut module_ctx = self.modules.build_ctx();
        let req = session.req_header_mut();
        module_ctx.request_header_filter(req).await.ok()?;

        let response = self.build_response(&mut session).await;
        let (parts, body) = response.into_parts();
        let mut resp_header: ResponseHeader = parts.into();
        module_ctx
            .response_header_filter(&mut resp_header, body.is_empty())
            .await
            .ok()?;

        let header_task = HttpTask::Header(Box::new(resp_header), body.is_empty());
        if let Err(e) = session.response_duplex_vec(vec![header_task]).await {
            tracing::error!(error = %e, "admin: failed to write response header");
        }

        let mut body = Some(body.into());
        module_ctx.response_body_filter(&mut body, true).ok()?;
        let body_task = HttpTask::Body(body, true);
        if let Err(e) = session.response_duplex_vec(vec![body_task]).await {
            tracing::error!(error = %e, "admin: failed to write response body");
        }

        let persistent_settings = HttpPersistentSettings::for_session(&session);
        match session.finish().await {
            Ok(c) => c.map(|s| ReusedHttpStream::new(s, Some(persistent_settings))),
            Err(e) => {
                tracing::error!(error = %e, "admin: failed to finish request");
                None
            }
        }
    }
}

// ── Request routing ───────────────────────────────────────────────────────────

impl AdminServer {
    /// Build a fully-buffered response for a non-streaming admin endpoint.
    ///
    /// The exhaustive path match is the single source of truth for which
    /// endpoints exist per pod role; unwired capabilities resolve to 404.
    async fn build_response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = session.req_header().uri.path();

        // Fast path: exact matches.
        match path {
            "/" => return self.ui_response(),
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

            // ── problems ─────────────────────────────────────────────────────
            ["problems"] => agg.list_problems().await,

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

// ── GET / (operator UI) ───────────────────────────────────────────────────────

impl AdminServer {
    /// Serve the embedded operator UI HTML, or 404 when the UI is not enabled.
    ///
    /// The HTML is a single self-contained file (produced by
    /// `vite-plugin-singlefile`): all JavaScript and CSS are inlined; no
    /// external network requests at runtime. This satisfies air-gapped
    /// deployments reached via `kubectl port-forward`.
    fn ui_response(&self) -> Response<Vec<u8>> {
        if self.serve_ui {
            aggregator::html_response(UI_HTML)
        } else {
            aggregator::not_found()
        }
    }
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

    #[test]
    fn ui_disabled_by_default() {
        let admin = AdminServer::new(HealthRegistry::new(), leader_flag(false));
        assert!(!admin.serve_ui);
    }

    #[test]
    fn ui_enabled_after_with_ui() {
        let admin = AdminServer::new(HealthRegistry::new(), leader_flag(false)).with_ui();
        assert!(admin.serve_ui);
    }

    #[test]
    fn ui_response_returns_404_when_serve_ui_false() {
        let admin = AdminServer::new(HealthRegistry::new(), leader_flag(false));
        let resp = admin.ui_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn ui_response_returns_200_html_when_serve_ui_true() {
        let admin = AdminServer::new(HealthRegistry::new(), leader_flag(false)).with_ui();
        let resp = admin.ui_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .map(|h| h.as_bytes()),
            Some(&b"text/html; charset=utf-8"[..])
        );
        // The body should be non-empty and contain the Vite-generated HTML.
        assert!(!resp.body().is_empty());
    }
}
