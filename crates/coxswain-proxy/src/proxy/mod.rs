use async_trait::async_trait;
use bytes::Bytes;
use coxswain_core::routing::{FilterAction, RequestContext, RouteOutcome, RouteTimeouts};
use http::header;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{
    ConnectTimedout, ConnectionClosed, ErrorSource, HTTPStatus, ReadError, ReadTimedout, Result,
    WriteError, WriteTimedout,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::sync::Arc;
use std::time::Instant;

use crate::filter::TrafficFilter;

mod ctx;
mod engine;
mod redirect;

pub(crate) use ctx::{CONN_INFO, ConnectionInfo};
pub use ctx::{ProxyCtx, ResolvedRoute};
pub use engine::RoutingEngine;

use redirect::{RedirectOrigin, build_redirect_location, extract_host};

pub struct Proxy {
    pub engine: Arc<RoutingEngine>,
    /// Global fallback timeouts used when a matched route has no per-rule timeouts set.
    pub default_timeouts: RouteTimeouts,
}

/// Merge per-route timeouts with global defaults; per-route wins when set.
fn merge_timeouts(route: &RouteTimeouts, default: &RouteTimeouts) -> RouteTimeouts {
    RouteTimeouts {
        request: route.request.or(default.request),
        backend_request: route.backend_request.or(default.backend_request),
    }
}

/// Resolves a pre-computed `RouteOutcome` into its components.
///
/// Returns `Some(...)` on success, or `None` when `RouteOutcome::Error` was
/// handled by writing an error response directly to `session`.
async fn resolve_outcome(
    session: &mut Session,
    host: &str,
    path: &str,
    outcome: RouteOutcome,
) -> Result<
    Option<(
        Arc<coxswain_core::routing::BackendGroup>,
        Arc<[FilterAction]>,
        RouteTimeouts,
    )>,
> {
    match outcome {
        RouteOutcome::Found(u, f, t) => Ok(Some((u, f, t))),
        RouteOutcome::Error(status) => {
            let resp = ResponseHeader::build(status, Some(0))?;
            session
                .write_response_header(Box::new(resp), true)
                .await
                .unwrap_or_else(|e| tracing::error!("failed to write error response: {e}"));
            Ok(None)
        }
        RouteOutcome::NoHost => Err(pingora_core::Error::explain(
            HTTPStatus(404),
            format!("no route for host {host}"),
        )),
        RouteOutcome::NoPath => Err(pingora_core::Error::explain(
            HTTPStatus(404),
            format!("no route for path {path} on host {host}"),
        )),
        _ => unreachable!("unhandled RouteOutcome variant"),
    }
}

/// If `filters` contains a `RequestRedirect`, build the `Location` header,
/// write the 3xx response, and return `true`. Returns `false` otherwise.
async fn try_redirect(
    session: &mut Session,
    filters: &[FilterAction],
    proto: &str,
    host: &str,
    incoming_port: u16,
    path: &str,
    query: Option<&str>,
) -> Result<bool> {
    for f in filters {
        if let FilterAction::RequestRedirect {
            scheme,
            hostname,
            port,
            status_code,
            path: path_mod,
        } = f
        {
            let origin = RedirectOrigin {
                scheme: proto,
                host,
                port: incoming_port,
                path,
                query,
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
    Ok(false)
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        CONN_INFO
            .try_with(|info| ProxyCtx {
                real_client_addr: Some(info.real_addr),
                real_client_proto: Some(info.proto),
                local_port: Some(info.local_addr.port()),
                resolved: None,
                request_deadline: None,
                request_timeout_is_controlling: false,
                backend_request_timeout_active: false,
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
        let host: Arc<str> = Arc::from(extract_host(req, &mut host_buf));
        let path: Arc<str> = Arc::from(req.uri.path());
        let query = req.uri.query().map(str::to_string);
        // PROXY-protocol path sets real_client_proto directly; standard Pingora TLS path
        // does not set CONN_INFO, so fall back to inspecting the session's TLS digest.
        let proto = ctx.real_client_proto.unwrap_or_else(|| {
            let is_tls = session
                .as_downstream()
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .is_some();
            if is_tls { "https" } else { "http" }
        });

        let port = ctx
            .local_port
            .or_else(|| {
                session
                    .as_downstream()
                    .server_addr()
                    .and_then(|a| a.as_inet())
                    .map(|a| a.port())
            })
            .unwrap_or(0);

        let outcome = {
            let route_ctx = RequestContext {
                method: &req.method,
                headers: &req.headers,
                query: query.as_deref(),
            };
            self.engine.find(port, &host, &path, &route_ctx)
        }; // route_ctx (and req borrow) drops here

        let Some((backend_group, filters, route_timeouts)) =
            resolve_outcome(session, &host, &path, outcome).await?
        else {
            return Ok(true);
        };

        let timeouts = merge_timeouts(&route_timeouts, &self.default_timeouts);
        ctx.request_deadline = timeouts.request.map(|d| Instant::now() + d);

        if try_redirect(
            session,
            &filters,
            proto,
            &host,
            port,
            &path,
            query.as_deref(),
        )
        .await?
        {
            return Ok(true);
        }

        ctx.resolved = Some(ResolvedRoute {
            backend_group,
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

        let addr = resolved.backend_group.next_endpoint().ok_or_else(|| {
            pingora_core::Error::explain(HTTPStatus(503), "no active endpoints for backend group")
        })?;

        let protocol = resolved.backend_group.protocol();
        // Allocate SNI string only for TLS connections; non-TLS ignores it.
        let sni_host = if protocol.is_tls() {
            resolved.original_host.to_string()
        } else {
            String::new()
        };
        // Pass SocketAddr directly — avoids the per-request addr.to_string() allocation.
        let mut peer = HttpPeer::new(addr, protocol.is_tls(), sni_host);
        if protocol.is_h2() {
            peer.options.set_http_version(2, 2);
        }
        // Pingora's HttpPeer hash includes http_version; pool isolation is automatic.
        // CA-based pool aliasing tracked separately: see #16.

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
            ctx.backend_request_timeout_active = true;
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
            .map(|r| (r.filters.as_ref(), &*r.original_host, &*r.original_path))
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
            // request/backendRequest read timeouts → 504 (Gateway API spec, GEP-1742).
            // Connect failure while backendRequest active → 502 (upstream unreachable).
            // Flags set in upstream_peer avoid races with OS timer granularity.
            ReadTimedout | WriteTimedout
                if ctx.request_timeout_is_controlling || ctx.backend_request_timeout_active =>
            {
                504
            }
            ConnectTimedout if ctx.backend_request_timeout_active => 502,
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
    use super::redirect::{RedirectOrigin, build_redirect_location};
    use super::*;
    use coxswain_core::routing::{
        BackendGroup, FilterAction, HeaderMod, PathModifier, RouteEntry, RouteOutcome,
        RoutingTableBuilder, SharedRoutingTable,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn make_group(name: &str, addr: &str) -> Arc<BackendGroup> {
        Arc::new(BackendGroup::new(
            name.to_string(),
            vec![addr.parse::<SocketAddr>().unwrap()],
        ))
    }

    fn entry(g: Arc<BackendGroup>) -> Arc<RouteEntry> {
        Arc::new(RouteEntry::path_only(g, "default/svc".to_string(), None))
    }

    fn engine_with_table(shared: SharedRoutingTable) -> RoutingEngine {
        RoutingEngine::new(shared)
    }

    const PORT: u16 = 80;

    #[test]
    fn route_resolves_matched_host_and_path() {
        let upstream = make_group("default/backend", "10.0.0.1:8080");
        let mut builder = RoutingTableBuilder::new();
        builder
            .for_port(PORT)
            .exact_host("example.com")
            .add_prefix_route("/", entry(upstream));
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        let result = engine.route(PORT, "example.com", "/api/users", &ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name(), "default/backend");
    }

    #[test]
    fn route_returns_none_for_unknown_host() {
        let upstream = make_group("default/backend", "10.0.0.1:8080");
        let mut builder = RoutingTableBuilder::new();
        builder
            .for_port(PORT)
            .exact_host("example.com")
            .add_prefix_route("/", entry(upstream));
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        assert!(engine.route(PORT, "other.com", "/", &ctx).is_none());
    }

    #[test]
    fn route_returns_none_on_empty_table() {
        let engine = engine_with_table(SharedRoutingTable::new());
        let ctx = RequestContext::default();
        assert!(engine.route(PORT, "example.com", "/", &ctx).is_none());
    }

    #[test]
    fn upstream_with_no_endpoints_returns_none_from_next_endpoint() {
        let upstream = Arc::new(BackendGroup::new("default/empty".to_string(), vec![]));
        let mut builder = RoutingTableBuilder::new();
        builder
            .for_port(PORT)
            .exact_host("example.com")
            .add_exact_route("/", entry(upstream));
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        let resolved = engine.route(PORT, "example.com", "/", &ctx);
        assert!(resolved.is_some(), "route should resolve");
        assert!(
            resolved.unwrap().next_endpoint().is_none(),
            "empty upstream yields no endpoint"
        );
    }

    fn origin(
        scheme: &'static str,
        host: &'static str,
        port: u16,
        path: &'static str,
        query: Option<&'static str>,
    ) -> RedirectOrigin<'static> {
        RedirectOrigin {
            scheme,
            host,
            port,
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
            &origin("http", "example.com", 80, "/foo", None),
        );
        assert_eq!(loc, "http://example.com/foo");
    }

    #[test]
    fn redirect_location_no_overrides_preserves_non_default_port() {
        let loc = build_redirect_location(
            None,
            None,
            None,
            None,
            &origin("http", "example.com", 8080, "/foo", None),
        );
        assert_eq!(loc, "http://example.com:8080/foo");
    }

    #[test]
    fn redirect_location_scheme_override() {
        let loc = build_redirect_location(
            Some("https"),
            None,
            None,
            None,
            &origin("http", "example.com", 80, "/foo", None),
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
            &origin("http", "old.example.com", 80, "/bar", None),
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
            &origin("http", "example.com", 80, "/x", Some("k=v")),
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
            &origin("http", "example.com", 80, "/", None),
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
            &origin("http", "example.com", 80, "/", None),
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
            &origin("http", "example.com", 80, "/old/path", None),
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
            &origin("http", "example.com", 80, "/api/users", None),
        );
        assert_eq!(loc, "http://example.com/v2/users");
    }

    #[test]
    fn find_returns_filters_alongside_upstream() {
        let upstream = make_group("default/backend", "10.0.0.1:8080");
        let filters = vec![FilterAction::RequestHeaderModifier(
            HeaderMod::parse(&[], &[("x-env", "test")], &[]).unwrap(),
        )];
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
            .for_port(PORT)
            .exact_host("example.com")
            .add_prefix_route("/", entry);
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        match engine.find(PORT, "example.com", "/test", &ctx) {
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
