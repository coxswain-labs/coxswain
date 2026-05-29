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

pub struct CoxswainProxy {
    pub engine: Arc<RoutingEngine>,
}

#[async_trait]
impl ProxyHttp for CoxswainProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

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

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        TrafficFilter::apply_request_filters(upstream_request)
    }
}
