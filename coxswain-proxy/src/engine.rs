use async_trait::async_trait;
use arc_swap::ArcSwap;
use std::sync::Arc;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};

use crate::filter::TrafficFilter;
use coxswain_core::routing::RoutingTable;

pub struct CoxswainProxy {
    pub routes: Arc<ArcSwap<RoutingTable>>,
}

#[async_trait]
impl ProxyHttp for CoxswainProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let req_header = session.req_header();
        let host = req_header.uri.host().unwrap_or("");
        let path = req_header.uri.path();

        let current_table = self.routes.load();
        let route_target = current_table.match_route(host, path)
            .ok_or_else(|| pingora_core::Error::explain(
                pingora_core::ConnectNoRoute,
                format!("Access Denied: No valid route mapped for {}{}", host, path)
            ))?;

        let target_pod = route_target.backends.first()
            .ok_or_else(|| pingora_core::Error::explain(
                pingora_core::InternalError,
                "Target backends contain no active pod IPs"
            ))?;

        let target_address = format!("{}:{}", target_pod.ip, target_pod.port);
        Ok(Box::new(HttpPeer::new(target_address, false, host.to_string())))
    }

    async fn upstream_request_filter(&self, _session: &mut Session, upstream_request: &mut RequestHeader, _ctx: &mut Self::CTX) -> Result<()> {
        TrafficFilter::apply_request_filters(upstream_request)
    }
}
