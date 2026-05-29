use async_trait::async_trait;
use coxswain_core::routing::{SharedRoutingTable, Upstream};
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;

use crate::filter::TrafficFilter;

/// Wraps the active routing table for lock-free reads on the request hot path.
pub struct RoutingEngine {
    table: SharedRoutingTable,
}

impl RoutingEngine {
    pub fn new(table: SharedRoutingTable) -> Self {
        Self { table }
    }

    /// Resolves `host` and `path` to an upstream. Zero-allocation on the hot path.
    pub fn route(&self, host: &str, path: &str) -> Option<Arc<Upstream>> {
        self.table.load().route(host, path)
    }
}

pub struct Proxy {
    pub engine: Arc<RoutingEngine>,
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    /// Phase 1 of the Pingora request lifecycle: select the upstream peer.
    ///
    /// Consults the routing table for the request's `Host` header and URI path.
    /// Returns `ConnectNoRoute` if no route matches, or `InternalError` if the
    /// matched upstream has no active endpoints.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let req_header = session.req_header();
        let host = req_header.uri.host().unwrap_or("");
        let path = req_header.uri.path();

        let upstream = self.engine.route(host, path).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ConnectNoRoute,
                format!("no route for {}{}", host, path),
            )
        })?;

        let addr = upstream.next_endpoint().ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::InternalError,
                "upstream has no active endpoints",
            )
        })?;

        Ok(Box::new(HttpPeer::new(
            addr.to_string(),
            false,
            host.to_string(),
        )))
    }

    /// Phase 2 of the Pingora request lifecycle: mutate the upstream request headers.
    ///
    /// Delegates to [`TrafficFilter`] which stamps the `X-Proxy-Engine` header.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        TrafficFilter::apply_request_filters(upstream_request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::{RoutingTableBuilder, SharedRoutingTable, Upstream};
    use std::net::SocketAddr;

    fn make_upstream(name: &str, addr: &str) -> Arc<Upstream> {
        Arc::new(Upstream::new(
            name.to_string(),
            vec![addr.parse::<SocketAddr>().unwrap()],
        ))
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
            .add_prefix_route("/", upstream);
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let result = engine.route("example.com", "/api/users");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "default/backend");
    }

    #[test]
    fn route_returns_none_for_unknown_host() {
        let upstream = make_upstream("default/backend", "10.0.0.1:8080");
        let mut builder = RoutingTableBuilder::new();
        builder
            .exact_host("example.com")
            .add_prefix_route("/", upstream);
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        assert!(engine.route("other.com", "/").is_none());
    }

    #[test]
    fn route_returns_none_on_empty_table() {
        let engine = engine_with_table(SharedRoutingTable::new());
        assert!(engine.route("example.com", "/").is_none());
    }

    #[test]
    fn upstream_with_no_endpoints_returns_none_from_next_endpoint() {
        let upstream = Arc::new(Upstream::new("default/empty".to_string(), vec![]));
        let mut builder = RoutingTableBuilder::new();
        builder
            .exact_host("example.com")
            .add_exact_route("/", upstream);
        let shared = SharedRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let resolved = engine.route("example.com", "/");
        assert!(resolved.is_some(), "route should resolve");
        assert!(
            resolved.unwrap().next_endpoint().is_none(),
            "empty upstream yields no endpoint"
        );
    }
}
