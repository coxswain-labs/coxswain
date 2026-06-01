use async_trait::async_trait;
use bytes::Bytes;
use coxswain_core::routing::{RequestContext, RouteOutcome, SharedRoutingTable, Upstream};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{ConnectionClosed, ErrorSource, HTTPStatus, ReadError, Result, WriteError};
use pingora_http::RequestHeader;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::sync::Arc;

use crate::filter::TrafficFilter;

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
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let req_header = session.req_header();
        // HTTP/1.1 clients send origin-form requests (e.g. `GET /a HTTP/1.1`), so
        // uri.host() is always None — the hostname lives in the Host header instead.
        let host_hdr;
        let host = if let Some(h) = req_header.uri.host() {
            h
        } else {
            host_hdr = req_header
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            // Strip port suffix (e.g. "example.com:8080" → "example.com")
            host_hdr.split(':').next().unwrap_or("")
        };
        let path = req_header.uri.path();
        let ctx = RequestContext {
            method: &req_header.method,
            headers: &req_header.headers,
            query: req_header.uri.query(),
        };

        let upstream = match self.engine.find(host, path, &ctx) {
            RouteOutcome::Found(u) => u,
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

        let addr = upstream.next_endpoint().ok_or_else(|| {
            pingora_core::Error::explain(HTTPStatus(503), "upstream has no active endpoints")
        })?;

        Ok(Box::new(HttpPeer::new(
            addr.to_string(),
            false,
            host.to_string(),
        )))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        TrafficFilter::apply_request_filters(upstream_request)
    }

    /// Send a plain-text error body instead of Pingora's default empty response.
    ///
    /// Mirrors the default code-selection logic but calls `respond_error_with_body`
    /// so clients see "503 Service Unavailable\n" rather than a zero-length body.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        _ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = match e.etype() {
            HTTPStatus(code) => *code,
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
}
