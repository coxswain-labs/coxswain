//! Admin HTTP endpoints for Coxswain.
//!
//! Two axes (controller-only) plus a handful of cross-cutting endpoints
//! (issue #301):
//! - `/api/v1/fleet/{summary,controllers,proxies}` — all coxswain pods, with
//!   per-pod `/{name}`, `/{name}/health`, and (proxies) `/{name}/routes`.
//! - `/api/v1/routing/{summary,gateways,httproutes,ingresses}` — config
//!   resources, with detail at `/api/v1/routing/routes/{kind}/{ns}/{name}`.
//! - cross-cutting: `/api/v1/{health,problems,events,manifests/*,pods/*/logs}`.
//!
//! The routing list endpoints and `fleet/proxies/{name}/routes` accept the
//! shared filter/pagination envelope (see [`page`]). Role-local: the proxy's own
//! compiled table at `/api/v1/routes` (relayed by the controller through
//! `fleet/proxies/{name}/routes`), alongside `/metrics` and the embedded operator
//! UI at `GET /` — the two convention-bound endpoints that stay outside
//! `/api/v1/` (Prometheus scrape path and the web root).
//!
//! The full surface (paths + response schemas) is described in
//! `api/openapi.yaml` — an internal aid; keep it in sync with the dispatch
//! below and the [`aggregator`] handlers.

mod aggregator;
mod events;
mod gw_types;
mod logs;
mod page;
mod routes_dto;

pub use aggregator::OperatorAggregator;
pub use events::EventSources;

use aggregator::json_response;
use async_trait::async_trait;
use coxswain_core::health::{HealthRegistry, SubsystemSnapshot};
use coxswain_core::routing::{RoutingTable, SharedGatewayRoutingTable, SharedIngressRoutingTable};
use http::{HeaderValue, Response, StatusCode, header};
use page::ListParams;
use pingora_core::apps::{HttpPersistentSettings, HttpServerApp, ReusedHttpStream};
use pingora_core::modules::http::HttpModules;
use pingora_core::modules::http::compression::ResponseCompressionBuilder;
use pingora_core::protocols::http::{HttpTask, ServerSession};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::listening::Service;
use pingora_http::ResponseHeader;
use prometheus::{Encoder, TextEncoder};
use routes_dto::{ConflictRow, HostGroup, RouteBlock, RouteRow, RoutesResponse};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
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
/// | `/api/v1/routes` | proxy + dev only | |
/// | `/api/v1/fleet/{summary,controllers,proxies}` (+ sub-resources) | | ✓ |
/// | `/api/v1/routing/{summary,gateways,httproutes,ingresses}` | | ✓ |
/// | `/api/v1/routing/routes/{kind}/{ns}/{name}` | | ✓ |
/// | `/api/v1/{problems,manifests/*}` | | ✓ |
/// | `/api/v1/topology` | | ✓ |
/// | `/api/v1/events` (SSE) | | ✓ |
/// | `/api/v1/pods/{name}/logs` (chunked) | | ✓ |
///
/// The routing list endpoints and `fleet/proxies/{name}/routes` accept the
/// shared filter/pagination envelope (`host`/`path`/`limit`/`offset`/`status`,
/// default limit 200, max 1000; see [`page`]).
///
/// Each capability is gated by an `Option` or `bool` field; missing
/// capabilities return 404 structurally rather than by convention.
///
/// Unlike the rest of the admin surface, `/api/v1/events` and
/// `/api/v1/pods/{name}/logs` are long-lived streams (Server-Sent Events and a
/// chunked log relay), which Pingora's buffered
/// [`ServeHttp`](pingora_core::apps::http_app::ServeHttp) trait cannot drive.
/// `AdminServer` therefore implements the lower-level
/// [`HttpServerApp`] directly: it streams those two paths and reproduces the
/// buffered request/response pipeline (including the response-compression
/// module) for every other endpoint.
#[non_exhaustive]
pub struct AdminServer {
    /// Shared health registry surfaced under `/api/v1/health`.
    pub health: HealthRegistry,
    /// Flipped to `true` while this replica holds the leader-election lease.
    pub leader: Arc<AtomicBool>,
    /// Routing tables for the `/api/v1/routes` endpoint. `None` on the controller
    /// role (its `/api/v1/routes` returns 404); `Some` on proxy and dev roles.
    pub routes: Option<(SharedIngressRoutingTable, SharedGatewayRoutingTable)>,
    /// Optional aggregator for the controller's `/api/v1/*` fan-out endpoints.
    /// `None` on proxy roles (those endpoints return 404).
    pub aggregator: Option<OperatorAggregator>,
    /// Optional live event sources for the `/api/v1/events` SSE stream. `None`
    /// on proxy roles (the endpoint returns 404 there).
    pub events: Option<EventSources>,
    /// Whether to serve the embedded operator UI at `GET /`. Enabled only on
    /// the controller role — proxy roles leave this `false` so `GET /`
    /// returns 404 structurally, the same gate as the aggregator surface.
    serve_ui: bool,
    /// HTTP module pipeline (response compression) applied to every buffered
    /// endpoint. The SSE stream deliberately bypasses it — compression buffers,
    /// which would defeat streaming.
    modules: HttpModules,
    /// Active API surfaces included in every `/api/v1/health` response.
    api_surfaces: ApiSurfaces,
}

impl AdminServer {
    /// Construct an `AdminServer` with the minimum required collaborators.
    ///
    /// Call `.with_routes()` and/or `.with_aggregator()` to enable optional
    /// capabilities.
    #[must_use]
    pub fn new(health: HealthRegistry, leader: Arc<AtomicBool>) -> Self {
        let mut modules = HttpModules::new();
        modules.add_module(ResponseCompressionBuilder::enable(7));
        Self {
            health,
            leader,
            routes: None,
            aggregator: None,
            events: None,
            serve_ui: false,
            modules,
            api_surfaces: ApiSurfaces::default(),
        }
    }

    /// Override the active API surfaces reported in `/api/v1/health`.
    ///
    /// Call this when the role was started with `--disable-gateway-api` or
    /// `--disable-ingress`; the default is both surfaces enabled.
    #[must_use]
    pub fn with_api_surfaces(mut self, gateway_api: bool, ingress: bool) -> Self {
        self.api_surfaces = ApiSurfaces {
            gateway_api,
            ingress,
        };
        self
    }

    /// Enable `GET /api/v1/routes` by supplying the proxy's local routing tables.
    ///
    /// Called only from proxy and dev pod roles. The controller omits this so
    /// its `/api/v1/routes` returns 404 — the controller's routing view is the
    /// aggregate `/api/v1/routing/*` surface instead.
    #[must_use]
    pub fn with_routes(
        mut self,
        ingress: SharedIngressRoutingTable,
        gateway: SharedGatewayRoutingTable,
    ) -> Self {
        self.routes = Some((ingress, gateway));
        self
    }

    /// Enable the controller's `/api/v1/{fleet,routing}/*` aggregator endpoints.
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

        // Pod-log relay: another long-lived chunked stream that the buffered
        // pipeline can't drive. Only the controller/dev roles wire `aggregator`;
        // proxy roles fall through, where the path resolves to a 404. The pod
        // name is a single path segment, so this carries no `%2F`-decoding risk.
        if let Some(pod) = logs_pod_name(session.req_header().uri.path()).map(str::to_string)
            && let Some(agg) = self.aggregator.as_ref()
        {
            let query = session
                .req_header()
                .uri
                .query()
                .unwrap_or_default()
                .to_string();
            agg.stream_logs(&pod, &query, &mut session, shutdown).await;
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
        // Shared filter/pagination params for the list endpoints (and the
        // proxy-local `/api/v1/routes`). Cheap to parse unconditionally.
        let params = ListParams::parse(session.req_header().uri.query());

        // Fast path: exact matches.
        match path {
            "/" => return self.ui_response(),
            "/metrics" => return metrics_response(),
            "/api/v1/routes" => return self.routes_response(&params),
            "/api/v1/facets" => return self.facets_response(),
            "/api/v1/health" => {
                // The apiserver version is fetched + cached by the aggregator
                // (controller/dev roles only); proxy roles wire none, so the
                // field is simply omitted there.
                let version = match self.aggregator.as_ref() {
                    Some(agg) => agg.kubernetes_version().await,
                    None => None,
                };
                return health_response(
                    &self.health,
                    version,
                    self.leader.load(Ordering::Acquire),
                    self.api_surfaces,
                );
            }
            _ => {}
        }

        // Aggregator endpoints — all under /api/v1/.
        // Return 404 when no aggregator is wired (proxy pod roles).
        let Some(agg) = self.aggregator.as_ref() else {
            return aggregator::not_found();
        };

        // Split path into non-empty segments after the /api/v1/ prefix.
        let rest = path.strip_prefix("/api/v1/").unwrap_or(path);
        let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();

        match segs.as_slice() {
            // ── fleet (all coxswain pods) ─────────────────────────────────────
            ["fleet", "summary"] => agg.fleet_summary().await,
            ["fleet", "controllers"] => agg.list_controllers().await,
            ["fleet", "controllers", name] => agg.get_controller(name).await,
            ["fleet", "controllers", name, "health"] => agg.get_controller_health(name).await,
            ["fleet", "proxies"] => agg.list_proxies().await,
            ["fleet", "proxies", name] => agg.get_proxy(name).await,
            ["fleet", "proxies", name, "routes"] => agg.get_proxy_routes(name, &params).await,
            ["fleet", "proxies", name, "facets"] => agg.get_proxy_facets(name).await,
            ["fleet", "proxies", name, "health"] => agg.get_proxy_health(name).await,

            // ── routing (config resources) ────────────────────────────────────
            ["routing", "summary"] => agg.routing_summary(),
            ["routing", "gateways"] => agg.list_gateways(&params),
            ["routing", "gateways", namespace, name] => agg.get_gateway(namespace, name).await,
            ["routing", "httproutes"] => agg.list_httproutes(&params),
            ["routing", "ingresses"] => agg.list_ingresses(&params),
            ["routing", "ingresses", namespace, name] => agg.get_ingress(namespace, name).await,
            ["routing", "routes", kind, namespace, name] => {
                agg.get_route(kind, namespace, name).await
            }
            ["routing", "routes", kind, namespace, name, "check"] => {
                agg.check_route(kind, namespace, name).await
            }

            // ── cross-cutting ─────────────────────────────────────────────────
            ["manifests", kind, namespace, name] => agg.get_manifest(kind, namespace, name).await,
            ["problems"] => agg.list_problems().await,
            ["topology"] => agg.topology().await,
            // Internal-only: fetched by peer controller replicas to build the
            // merged topology view (#500 HA — each replica's registry only
            // holds the proxies that connected to IT). Harmless to call
            // directly; not surfaced in the UI.
            ["topology", "local"] => agg.topology_local().await,

            _ => aggregator::not_found(),
        }
    }
}

/// Extract the pod name from `/api/v1/pods/{name}/logs`, or `None` for any
/// other path.
///
/// The middle segment is a single DNS-1123 pod name (no embedded `/`), so a
/// three-way split is sufficient and unambiguous.
fn logs_pod_name(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/api/v1/")?;
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        ["pods", name, "logs"] => Some(name),
        _ => None,
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

// ── /api/v1/routes ──────────────────────────────────────────────────────────

impl AdminServer {
    /// Build the `/api/v1/routes` response from the local routing tables.
    ///
    /// Returns 404 when no routing tables are wired (controller pod role). When
    /// `params` carry a `host`/`path` filter or `limit`/`offset`, each spec block
    /// is filtered + windowed and gains `total`/`returned`/`offset` counts; with
    /// no params the legacy `{hosts, conflicts}` shape is reproduced (#286). The
    /// controller relays this whole body through `fleet/proxies/{name}/routes`.
    fn routes_response(&self, params: &ListParams) -> Response<Vec<u8>> {
        let Some((ingress, gateway)) = self.routes.as_ref() else {
            let mut r = Response::new(Vec::new());
            *r.status_mut() = StatusCode::NOT_FOUND;
            return r;
        };
        let body = serde_json::json!(RoutesResponse {
            ingress: routes_block(ingress.load().as_ref(), params),
            gateway: routes_block(gateway.load().as_ref(), params),
        })
        .to_string();
        json_response(body)
    }

    /// Build the `/api/v1/facets` response: the distinct hosts and route
    /// namespaces this proxy serves, so the operator UI can populate the route
    /// table's host/namespace filter dropdowns without fetching the whole table.
    /// Both lists are far smaller than the route set (many routes per host, and a
    /// bounded namespace count), so shipping them whole is cheap. Returns 404 when
    /// no routing tables are wired (controller role); the controller relays this
    /// through `fleet/proxies/{name}/facets`.
    fn facets_response(&self) -> Response<Vec<u8>> {
        let Some((ingress, gateway)) = self.routes.as_ref() else {
            let mut r = Response::new(Vec::new());
            *r.status_mut() = StatusCode::NOT_FOUND;
            return r;
        };
        let mut hosts: BTreeSet<String> = BTreeSet::new();
        let mut namespaces: BTreeSet<String> = BTreeSet::new();
        collect_facets(ingress.load().as_ref(), &mut hosts, &mut namespaces);
        collect_facets(gateway.load().as_ref(), &mut hosts, &mut namespaces);
        let body = serde_json::json!({
            "hosts": hosts.into_iter().collect::<Vec<_>>(),
            "namespaces": namespaces.into_iter().collect::<Vec<_>>(),
        })
        .to_string();
        json_response(body)
    }
}

/// Collect the distinct hosts and route namespaces from one typed table into the
/// shared sorted sets (`BTreeSet` keeps them de-duplicated and ordered for a
/// stable dropdown). Skips placeholder routes with no backend, matching the rows
/// the route table actually shows.
fn collect_facets<K>(
    table: &RoutingTable<K>,
    hosts: &mut BTreeSet<String>,
    namespaces: &mut BTreeSet<String>,
) {
    for (_port, host, router) in table.host_routes() {
        hosts.insert(host.clone());
        for r in router
            .routes()
            .iter()
            .filter(|r| !r.backend_group.name().is_empty())
        {
            if let Some((ns, _)) = r.route_id.split_once('/').filter(|(ns, _)| !ns.is_empty()) {
                namespaces.insert(ns.to_string());
            }
        }
    }
}

/// Build the per-spec block of the `/api/v1/routes` payload from a typed table.
///
/// Generic over `Kind` so the same body serialises both the Ingress and the
/// Gateway-API tables; the type parameter prevents the caller from passing the
/// wrong table to the wrong block label.
///
/// `params` filter the flattened route rows by `host` (exact), `path` (substring),
/// `namespace` (exact, the route's namespace) and `status=problem` (keep only
/// dead-backend rows — zero ready endpoints), then window them by `limit`/`offset`.
/// The same host/path/namespace predicates also narrow the conflict list (a
/// conflict belongs to a host/path and a rejected route's namespace), so a scoped
/// view shows only the conflicts in scope; `problems_only` leaves conflicts whole
/// (a conflict is itself a problem). When [`ListParams::is_empty`] the output is
/// structurally the legacy full dump; when any param is set the block also carries
/// `total`/`returned`/`offset` over the post-filter rows.
fn routes_block<K>(table: &RoutingTable<K>, params: &ListParams) -> RouteBlock {
    // Flatten to (port, host, RouteRow) so the offset/limit window applies across
    // the whole table, not per host-group. The exact `host` filter skips a whole
    // host-group; `path`/`namespace` filter per row.
    let mut matched: Vec<(u16, String, RouteRow)> = Vec::new();
    for (port, host, router) in table.host_routes() {
        if !params.host_matches(&host) {
            continue;
        }
        for r in router
            .routes()
            .iter()
            .filter(|r| !r.backend_group.name().is_empty())
        {
            if !params.path_matches(&r.path) {
                continue;
            }
            // `RouteRow::from_info` splits `route_id` into `namespace`/`name` so the
            // UI can deep-link a compiled row back to its source resource.
            let row = RouteRow::from_info(r);
            if !params.namespace_matches(&row.namespace) {
                continue;
            }
            // `status=problem`: a compiled route "with a problem" is one serving
            // zero ready endpoints (a dead backend) — the only per-row health the
            // compiled table can see.
            if params.problems_only && !row.endpoints.is_empty() {
                continue;
            }
            matched.push((port, host.clone(), row));
        }
    }

    let total = matched.len();
    let offset = params.offset.min(total);
    let limit = params.effective_limit();
    let windowed: Vec<(u16, String, RouteRow)> = if params.is_empty() {
        matched
    } else {
        matched.into_iter().skip(offset).take(limit).collect()
    };
    let returned = windowed.len();

    // Regroup the (possibly windowed) rows back into `(port, host)` host-groups.
    let mut hosts: Vec<HostGroup> = Vec::new();
    for (port, host, route) in windowed {
        match hosts.last_mut() {
            Some(last) if last.port == port && last.host == host => last.routes.push(route),
            _ => hosts.push(HostGroup {
                port,
                host,
                routes: vec![route],
            }),
        }
    }

    let conflicts: Vec<ConflictRow> = table
        .conflicts()
        .iter()
        .map(ConflictRow::from_conflict)
        // Narrow conflicts by the same host/path/namespace scope as the rows
        // (problems_only is intentionally ignored — a conflict is a problem).
        .filter(|c| {
            params.host_matches(&c.host)
                && params.path_matches(&c.path)
                && params.namespace_matches(&c.namespace)
        })
        .collect();

    if params.is_empty() {
        RouteBlock {
            hosts,
            conflicts,
            ..RouteBlock::default()
        }
    } else {
        RouteBlock {
            hosts,
            conflicts,
            total: Some(total),
            returned: Some(returned),
            offset: Some(offset),
        }
    }
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

/// Which API surfaces this pod role has enabled.
///
/// Serialised into every `/api/v1/health` response so the operator UI and
/// automated tooling can detect Ingress-only or Gateway-API-only deployments
/// without inspecting flags or Helm values.
#[derive(Clone, Copy, Serialize)]
#[non_exhaustive]
pub struct ApiSurfaces {
    /// `true` when the Gateway API surface (HTTPRoute, GatewayClass, etc.) is
    /// active on this pod. `false` when `--disable-gateway-api` was set.
    pub gateway_api: bool,
    /// `true` when the Ingress surface is active. `false` when
    /// `--disable-ingress` was set.
    pub ingress: bool,
}

impl Default for ApiSurfaces {
    fn default() -> Self {
        Self {
            gateway_api: true,
            ingress: true,
        }
    }
}

#[derive(Serialize)]
struct HealthResponse<'a> {
    version: &'static str,
    /// Kubernetes apiserver GitVersion (e.g. `v1.31.2`), supplied by the
    /// aggregator's cached `/version` lookup. Omitted when unavailable (proxy
    /// roles wire no aggregator, or the apiserver could not be reached) — the
    /// operator UI renders an em dash in that case.
    #[serde(skip_serializing_if = "Option::is_none")]
    kubernetes_version: Option<&'a str>,
    /// `true` while this pod holds the leader-election lease. Always `false` on
    /// proxy roles. The controller aggregator reads this off each peer's
    /// `/api/v1/health` to report per-pod leadership (it replaced the retired
    /// `/api/v1/cluster` leader probe).
    leader: bool,
    subsystems: BTreeMap<Arc<str>, SubsystemSnapshot>,
    /// Which API surfaces are enabled on this pod role.
    api_surfaces: ApiSurfaces,
}

fn health_response(
    health: &HealthRegistry,
    kubernetes_version: Option<&str>,
    leader: bool,
    api_surfaces: ApiSurfaces,
) -> Response<Vec<u8>> {
    let snapshot = health.snapshot();
    let resp = HealthResponse {
        version: env!("CARGO_PKG_VERSION"),
        kubernetes_version,
        leader,
        subsystems: snapshot.subsystems,
        api_surfaces,
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn leader_flag(value: bool) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(value))
    }

    #[test]
    fn health_response_carries_version_kubernetes_version_leader_and_subsystems() {
        let registry = HealthRegistry::new();
        let resp = health_response(&registry, Some("v1.31.2"), true, ApiSurfaces::default());
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
        assert_eq!(v["kubernetes_version"], "v1.31.2");
        assert_eq!(v["leader"], serde_json::Value::Bool(true));
        assert!(
            v.get("subsystems").is_some(),
            "response must carry `subsystems`"
        );
    }

    #[test]
    fn health_response_omits_kubernetes_version_when_unavailable() {
        let registry = HealthRegistry::new();
        let resp = health_response(&registry, None, false, ApiSurfaces::default());
        let body = std::str::from_utf8(resp.body()).expect("utf8 body");
        let v: serde_json::Value = serde_json::from_str(body.trim()).expect("json");
        assert!(
            v.get("kubernetes_version").is_none(),
            "field must be omitted when the apiserver version is unavailable"
        );
        assert_eq!(v["leader"], serde_json::Value::Bool(false));
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
    fn logs_pod_name_matches_pods_logs_path() {
        assert_eq!(
            logs_pod_name("/api/v1/pods/coxswain-abc/logs"),
            Some("coxswain-abc")
        );
    }

    #[test]
    fn logs_pod_name_rejects_other_paths() {
        assert_eq!(logs_pod_name("/api/v1/pods/coxswain-abc"), None);
        assert_eq!(logs_pod_name("/api/v1/pods"), None);
        assert_eq!(logs_pod_name("/api/v1/proxies/p/logs"), None);
        assert_eq!(logs_pod_name("/api/v1/events"), None);
        assert_eq!(logs_pod_name("/metrics"), None);
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
