//! `GatewayProxy`: Pingora `ProxyHttp` implementation that serves traffic for
//! Gateway-API resources (`HTTPRoute`, `Gateway`).
//!
//! The proxy holds a typed [`RoutingEngine`][crate::routing::engine::RoutingEngine]
//! pinned to `Gateway`-flavored routing data and a CA-bundle parse cache. All
//! `ProxyHttp` hooks delegate to the shared bodies in
//! [`crate::hooks`]; the static `Kind` parameter on the engine
//! prevents a routing snapshot for one spec from being handed to the proxy
//! that serves the other.

use crate::config::ProxyServices;
use crate::ctx::ProxyCtx;
use crate::hooks;
use crate::retry;
use crate::routing::engine::RoutingEngine;
use async_trait::async_trait;
use bytes::Bytes;
use coxswain_core::routing::Gateway;
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::sync::Arc;

/// Typed routing engine pinned to Gateway-API-flavored data.
pub type GatewayEngine = RoutingEngine<Gateway>;

/// Pingora `ProxyHttp` implementation that routes Gateway-API traffic.
#[non_exhaustive]
pub struct GatewayProxy {
    /// Lock-free routing engine reading the Gateway snapshot.
    pub engine: Arc<GatewayEngine>,
    /// Startup-time collaborators shared between `IngressProxy` and `GatewayProxy`.
    ///
    /// The engine is kept separate because it is typed differently for each
    /// proxy; all other startup-time config lives here.
    pub cfg: ProxyServices,
}

impl GatewayProxy {
    /// Construct a `GatewayProxy` from its engine and shared runtime config.
    #[must_use]
    pub fn new(engine: Arc<GatewayEngine>, cfg: ProxyServices) -> Self {
        Self { engine, cfg }
    }
}

#[async_trait]
impl ProxyHttp for GatewayProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        hooks::new_ctx()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyCtx) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        hooks::request_filter(&self.engine, &self.cfg, session, ctx).await
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        hooks::request_body_filter(body.as_ref(), end_of_stream, ctx)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut ProxyCtx,
    ) -> Result<Box<HttpPeer>> {
        hooks::upstream_peer(&self.cfg, ctx).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyCtx,
    ) -> Result<()> {
        hooks::upstream_request_filter(session, upstream_request, ctx).await
    }

    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        _peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        _digest: Option<&pingora_core::protocols::Digest>,
        _ctx: &mut ProxyCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        hooks::connected_to_upstream(reused, _digest)
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        hooks::upstream_response_filter(session, upstream_response, ctx).await
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyCtx,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        hooks::response_body_filter(body, end_of_stream, ctx)?;
        Ok(None)
    }

    fn fail_to_connect(
        &self,
        session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut ProxyCtx,
        e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        retry::fail_to_connect(session, peer, ctx, e)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<pingora_core::Error>,
        ctx: &mut ProxyCtx,
        client_reused: bool,
    ) -> Box<pingora_core::Error> {
        retry::error_while_proxy(peer, session, e, ctx, client_reused)
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut ProxyCtx,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        retry::fail_to_proxy(session, e, ctx).await
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora_core::Error>,
        ctx: &mut ProxyCtx,
    ) where
        Self::CTX: Send + Sync,
    {
        hooks::logging(
            self.cfg.access_log_enabled,
            self.cfg.access_log_path_mode,
            &self.cfg.circuit_breakers,
            session,
            e,
            ctx,
        )
        .await;
    }
}
