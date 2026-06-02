use async_trait::async_trait;
use bytes::Bytes;
use coxswain_core::routing::{
    FilterAction, PathModifier, RequestContext, RouteOutcome, RouteTimeouts, SharedRoutingTable,
    Upstream,
};
use http::header;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{
    ConnectionClosed, ErrorSource, HTTPStatus, ReadError, ReadTimedout, Result, WriteError,
    WriteTimedout,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::filter::TrafficFilter;

/// Per-connection info seeded by the PROXY protocol accept loop.
#[derive(Clone)]
pub(crate) struct ConnectionInfo {
    pub real_addr: SocketAddr,
    pub proto: &'static str,
}

tokio::task_local! {
    /// Set by the PROXY protocol accept loop before calling process_new_http.
    /// Consumed by Proxy::new_ctx so that every request on the connection carries
    /// the real client address and protocol.
    pub(crate) static CONN_INFO: ConnectionInfo;
}

/// Routing result cached from `request_filter` for use in later hooks.
pub struct ResolvedRoute {
    pub upstream: Arc<Upstream>,
    pub filters: Arc<[FilterAction]>,
    pub timeouts: RouteTimeouts,
    pub original_host: String,
    pub original_path: String,
}

/// Per-request context carrying the real client address extracted from the PROXY header.
#[derive(Default)]
pub struct ProxyCtx {
    pub real_client_addr: Option<SocketAddr>,
    pub real_client_proto: Option<&'static str>,
    pub resolved: Option<ResolvedRoute>,
    /// Absolute deadline for the total request (from `timeouts.request`). 504 if exceeded.
    pub request_deadline: Option<Instant>,
    /// True when the effective read_timeout was derived from `timeouts.request` (not
    /// `timeouts.backendRequest`). Set in `upstream_peer`; consulted in `fail_to_proxy` to
    /// distinguish 504 (request budget) from 502 (backend budget) without relying on wall-clock
    /// comparisons that can race against OS timer granularity.
    pub request_timeout_is_controlling: bool,
}

/// Lock-free routing engine for the request hot path.
pub struct RoutingEngine {
    table: SharedRoutingTable,
}

impl RoutingEngine {
    pub fn new(table: SharedRoutingTable) -> Self {
        Self { table }
    }

    /// Like [`find`] but returns only the upstream, without host/path distinction.
    pub fn route(&self, host: &str, path: &str, ctx: &RequestContext<'_>) -> Option<Arc<Upstream>> {
        self.table.load().route(host, path, ctx)
    }

    /// Distinguishes "host not registered" from "path/predicate not matched".
    pub fn find(&self, host: &str, path: &str, ctx: &RequestContext<'_>) -> RouteOutcome {
        self.table.load().find(host, path, ctx)
    }
}

pub struct Proxy {
    pub engine: Arc<RoutingEngine>,
    /// Global fallback timeouts used when a matched route has no per-rule timeouts set.
    pub default_timeouts: RouteTimeouts,
}

/// Extract the bare hostname from a request (strips port suffix, prefers URI host over Host header).
fn extract_host<'a>(req: &'a RequestHeader, host_hdr: &'a mut String) -> &'a str {
    if let Some(h) = req.uri.host() {
        return h;
    }
    *host_hdr = req
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    host_hdr.split(':').next().unwrap_or("")
}

/// Request-context fields needed to build a redirect `Location` URL.
struct RedirectOrigin<'a> {
    scheme: &'a str,
    host: &'a str,
    path: &'a str,
    query: Option<&'a str>,
}

/// Build the `Location` URL for a `RequestRedirect` filter.
fn build_redirect_location(
    filter_scheme: Option<&str>,
    filter_hostname: Option<&str>,
    filter_port: Option<u16>,
    path_modifier: Option<&PathModifier>,
    origin: &RedirectOrigin<'_>,
) -> String {
    let eff_scheme = filter_scheme.unwrap_or(origin.scheme);
    let eff_host = filter_hostname.unwrap_or(origin.host);

    let new_path = match path_modifier {
        None => origin.path.to_string(),
        Some(PathModifier::ReplaceFullPath(p)) => p.clone(),
        Some(PathModifier::ReplacePrefixMatch {
            prefix,
            replacement,
        }) => {
            let prefix_trimmed = prefix.trim_end_matches('/');
            let suffix = &origin.path[prefix_trimmed.len().min(origin.path.len())..];
            let rep = replacement.trim_end_matches('/');
            if suffix.is_empty() || suffix == "/" {
                rep.to_string()
            } else {
                format!("{rep}{suffix}")
            }
        }
    };

    let path_and_query = match origin.query {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };

    // Omit default ports per Gateway API spec.
    let omit_port = filter_port.is_none()
        || (eff_scheme == "http" && filter_port == Some(80))
        || (eff_scheme == "https" && filter_port == Some(443));

    if omit_port {
        format!("{eff_scheme}://{eff_host}{path_and_query}")
    } else {
        format!(
            "{eff_scheme}://{}:{}{path_and_query}",
            eff_host,
            filter_port.unwrap()
        )
    }
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        CONN_INFO
            .try_with(|info| ProxyCtx {
                real_client_addr: Some(info.real_addr),
                real_client_proto: Some(info.proto),
                resolved: None,
                request_deadline: None,
                request_timeout_is_controlling: false,
            })
            .unwrap_or_default()
    }

    /// Perform routing early so `RequestRedirect` filters can short-circuit
    /// before an upstream connection is attempted.
    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyCtx) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let req = session.req_header();
        let mut host_buf = String::new();
        let host = extract_host(req, &mut host_buf).to_string();
        let path = req.uri.path().to_string();
        let query = req.uri.query().map(str::to_string);

        let route_ctx = RequestContext {
            method: &req.method,
            headers: &req.headers,
            query: query.as_deref(),
        };

        let (upstream, filters, route_timeouts) = match self.engine.find(&host, &path, &route_ctx) {
            RouteOutcome::Found(u, f, t) => (u, f, t),
            RouteOutcome::NoHost => {
                return Err(pingora_core::Error::explain(
                    HTTPStatus(503),
                    format!("no backend for host {host}"),
                ));
            }
            RouteOutcome::NoPath => {
                return Err(pingora_core::Error::explain(
                    HTTPStatus(404),
                    format!("no route for path {path} on host {host}"),
                ));
            }
        };

        // Merge per-route timeouts with global defaults (per-route wins).
        let timeouts = RouteTimeouts {
            request: route_timeouts.request.or(self.default_timeouts.request),
            backend_request: route_timeouts
                .backend_request
                .or(self.default_timeouts.backend_request),
        };

        // Record the request deadline so upstream_peer and fail_to_proxy can use it.
        ctx.request_deadline = timeouts.request.map(|d| Instant::now() + d);

        // Check for a RequestRedirect filter — if present, send the 3xx and short-circuit.
        for f in filters.iter() {
            if let FilterAction::RequestRedirect {
                scheme,
                hostname,
                port,
                status_code,
                path: path_mod,
            } = f
            {
                // Default scheme to "http"; TLS-terminated requests would need
                // scheme passed from the accept layer, which we don't thread through yet.
                let origin = RedirectOrigin {
                    scheme: "http",
                    host: &host,
                    path: &path,
                    query: query.as_deref(),
                };
                let location = build_redirect_location(
                    scheme.as_deref(),
                    hostname.as_deref(),
                    *port,
                    path_mod.as_ref(),
                    &origin,
                );
                let mut resp = ResponseHeader::build(*status_code, Some(2))?;
                resp.insert_header(header::LOCATION, location)?;
                session
                    .write_response_header(Box::new(resp), true)
                    .await
                    .unwrap_or_else(|e| tracing::error!("failed to write redirect response: {e}"));
                return Ok(true);
            }
        }

        ctx.resolved = Some(ResolvedRoute {
            upstream,
            filters,
            timeouts,
            original_host: host,
            original_path: path,
        });
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut ProxyCtx,
    ) -> Result<Box<HttpPeer>> {
        let resolved = ctx.resolved.as_ref().ok_or_else(|| {
            pingora_core::Error::explain(
                HTTPStatus(500),
                "routing not resolved before upstream_peer",
            )
        })?;

        // If a total request deadline has already passed, fail fast with 504.
        if let Some(deadline) = ctx.request_deadline
            && Instant::now() >= deadline
        {
            return Err(pingora_core::Error::explain(
                HTTPStatus(504),
                "request timeout exceeded before upstream connection",
            ));
        }

        let addr = resolved.upstream.next_endpoint().ok_or_else(|| {
            pingora_core::Error::explain(HTTPStatus(503), "upstream has no active endpoints")
        })?;

        // Use the (potentially rewritten) host from UrlRewrite hostname, or the original host.
        let sni_host = resolved.original_host.clone();

        let mut peer = HttpPeer::new(addr.to_string(), false, sni_host);

        // Apply per-route timeout settings.
        // backendRequest controls the upstream read (and connect) phase → 502 on expiry.
        // request controls the total budget; we use the remaining time as read_timeout so
        // that an expiry can be detected in fail_to_proxy and mapped to 504.
        let remaining_request = ctx
            .request_deadline
            .and_then(|d| d.checked_duration_since(Instant::now()));
        let backend_timeout = resolved.timeouts.backend_request;

        // Determine which timeout is the binding constraint and set the flag that
        // fail_to_proxy will use to pick 504 vs 502.  Doing this here (at peer-creation
        // time) avoids a racy Instant::now() >= deadline comparison in fail_to_proxy,
        // which can yield the wrong answer when the OS timer fires a few µs early.
        let read_timeout = match (backend_timeout, remaining_request) {
            (Some(bt), Some(rem)) => {
                // Whichever is smaller fires; record which one controls.
                ctx.request_timeout_is_controlling = rem <= bt;
                Some(bt.min(rem))
            }
            (Some(bt), None) => {
                ctx.request_timeout_is_controlling = false;
                Some(bt)
            }
            (None, Some(rem)) => {
                ctx.request_timeout_is_controlling = true;
                Some(rem)
            }
            (None, None) => None,
        };
        if let Some(t) = read_timeout {
            peer.options.read_timeout = Some(t);
        }
        if let Some(t) = backend_timeout {
            peer.options.connection_timeout = Some(t);
        }

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyCtx,
    ) -> Result<()> {
        let (filters, original_host, original_path) = ctx
            .resolved
            .as_ref()
            .map(|r| {
                (
                    r.filters.as_ref(),
                    r.original_host.as_str(),
                    r.original_path.as_str(),
                )
            })
            .unwrap_or((&[], "", ""));
        TrafficFilter::apply_request_filters(
            upstream_request,
            filters,
            original_host,
            original_path,
            ctx,
        )
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(resolved) = &ctx.resolved {
            TrafficFilter::apply_response_filters(upstream_response, &resolved.filters);
        }
        Ok(())
    }

    /// Send a plain-text error body instead of Pingora's default empty response.
    ///
    /// Mirrors the default code-selection logic but calls `respond_error_with_body`
    /// so clients see "503 Service Unavailable\n" rather than a zero-length body.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut ProxyCtx,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = match e.etype() {
            HTTPStatus(code) => *code,
            // A read/write timeout where the request budget was the binding constraint → 504.
            // We use the flag set in upstream_peer rather than a wall-clock comparison to
            // avoid races with OS timer granularity (timers can fire a few µs early).
            ReadTimedout | WriteTimedout if ctx.request_timeout_is_controlling => 504,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    ConnectionClosed | ReadError | WriteError => 0,
                    _ => 400,
                },
                _ => 500,
            },
        };
        if code > 0 {
            let reason = http::StatusCode::from_u16(code)
                .ok()
                .and_then(|s| s.canonical_reason())
                .unwrap_or("Unknown");
            session
                .respond_error_with_body(code, Bytes::from(format!("{code} {reason}\n")))
                .await
                .unwrap_or_else(|err| tracing::error!("failed to send error response: {err}"));
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::{RouteEntry, RoutingTableBuilder, SharedRoutingTable, Upstream};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn make_upstream(name: &str, addr: &str) -> Arc<Upstream> {
        Arc::new(Upstream::new(
            name.to_string(),
            vec![addr.parse::<SocketAddr>().unwrap()],
        ))
    }

    fn entry(us: Arc<Upstream>) -> Arc<RouteEntry> {
        Arc::new(RouteEntry::path_only(us, "default/svc".to_string(), None))
    }

    fn engine_with_table(shared: SharedRoutingTable) -> RoutingEngine {
        RoutingEngine::new(shared)
    }

    #[test]
    fn route_resolves_matched_host_and_path() {
        let upstream = make_upstream("default/backend", "10.0.0.1:8080");
        let mut builder = RoutingTableBuilder::new();
        builder
            .exact_host("example.com")
            .add_prefix_route("/", entry(upstream));
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        let result = engine.route("example.com", "/api/users", &ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "default/backend");
    }

    #[test]
    fn route_returns_none_for_unknown_host() {
        let upstream = make_upstream("default/backend", "10.0.0.1:8080");
        let mut builder = RoutingTableBuilder::new();
        builder
            .exact_host("example.com")
            .add_prefix_route("/", entry(upstream));
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        assert!(engine.route("other.com", "/", &ctx).is_none());
    }

    #[test]
    fn route_returns_none_on_empty_table() {
        let engine = engine_with_table(SharedRoutingTable::new());
        let ctx = RequestContext::default();
        assert!(engine.route("example.com", "/", &ctx).is_none());
    }

    #[test]
    fn upstream_with_no_endpoints_returns_none_from_next_endpoint() {
        let upstream = Arc::new(Upstream::new("default/empty".to_string(), vec![]));
        let mut builder = RoutingTableBuilder::new();
        builder
            .exact_host("example.com")
            .add_exact_route("/", entry(upstream));
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        let resolved = engine.route("example.com", "/", &ctx);
        assert!(resolved.is_some(), "route should resolve");
        assert!(
            resolved.unwrap().next_endpoint().is_none(),
            "empty upstream yields no endpoint"
        );
    }

    // ── build_redirect_location tests ─────────────────────────────────────────

    fn origin(
        scheme: &'static str,
        host: &'static str,
        path: &'static str,
        query: Option<&'static str>,
    ) -> RedirectOrigin<'static> {
        RedirectOrigin {
            scheme,
            host,
            path,
            query,
        }
    }

    #[test]
    fn redirect_location_no_overrides_returns_original() {
        let loc = build_redirect_location(
            None,
            None,
            None,
            None,
            &origin("http", "example.com", "/foo", None),
        );
        assert_eq!(loc, "http://example.com/foo");
    }

    #[test]
    fn redirect_location_scheme_override() {
        let loc = build_redirect_location(
            Some("https"),
            None,
            None,
            None,
            &origin("http", "example.com", "/foo", None),
        );
        assert_eq!(loc, "https://example.com/foo");
    }

    #[test]
    fn redirect_location_hostname_override() {
        let loc = build_redirect_location(
            None,
            Some("new.example.com"),
            None,
            None,
            &origin("http", "old.example.com", "/bar", None),
        );
        assert_eq!(loc, "http://new.example.com/bar");
    }

    #[test]
    fn redirect_location_preserves_query() {
        let loc = build_redirect_location(
            None,
            None,
            None,
            None,
            &origin("http", "example.com", "/x", Some("k=v")),
        );
        assert_eq!(loc, "http://example.com/x?k=v");
    }

    #[test]
    fn redirect_location_non_default_port_included() {
        let loc = build_redirect_location(
            None,
            None,
            Some(8080),
            None,
            &origin("http", "example.com", "/", None),
        );
        assert_eq!(loc, "http://example.com:8080/");
    }

    #[test]
    fn redirect_location_default_http_port_omitted() {
        let loc = build_redirect_location(
            Some("http"),
            None,
            Some(80),
            None,
            &origin("http", "example.com", "/", None),
        );
        assert_eq!(loc, "http://example.com/");
    }

    #[test]
    fn redirect_location_replace_full_path() {
        let pm = PathModifier::ReplaceFullPath("/new".to_string());
        let loc = build_redirect_location(
            None,
            None,
            None,
            Some(&pm),
            &origin("http", "example.com", "/old/path", None),
        );
        assert_eq!(loc, "http://example.com/new");
    }

    #[test]
    fn redirect_location_replace_prefix() {
        let pm = PathModifier::ReplacePrefixMatch {
            prefix: "/api".to_string(),
            replacement: "/v2".to_string(),
        };
        let loc = build_redirect_location(
            None,
            None,
            None,
            Some(&pm),
            &origin("http", "example.com", "/api/users", None),
        );
        assert_eq!(loc, "http://example.com/v2/users");
    }

    #[test]
    fn find_returns_filters_alongside_upstream() {
        use coxswain_core::routing::{FilterAction, HeaderMod, RouteOutcome};

        let upstream = make_upstream("default/backend", "10.0.0.1:8080");
        let filters = vec![FilterAction::RequestHeaderModifier(HeaderMod {
            set: vec![("x-env".to_string(), "test".to_string())],
            ..Default::default()
        })];
        let entry = Arc::new(RouteEntry::with_filters(
            upstream,
            Default::default(),
            filters,
            Default::default(),
            "default/svc".to_string(),
            None,
        ));
        let mut builder = RoutingTableBuilder::new();
        builder
            .exact_host("example.com")
            .add_prefix_route("/", entry);
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        match engine.find("example.com", "/test", &ctx) {
            RouteOutcome::Found(_, filters, _) => {
                assert_eq!(filters.len(), 1);
                assert!(matches!(
                    &filters[0],
                    FilterAction::RequestHeaderModifier(_)
                ));
            }
            _ => panic!("expected Found"),
        }
    }
}
