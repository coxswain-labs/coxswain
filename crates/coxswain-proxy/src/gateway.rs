//! `GatewayProxy`: Pingora `ProxyHttp` implementation that serves traffic for
//! Gateway-API resources (`HTTPRoute`, `Gateway`).
//!
//! The proxy holds a typed [`RoutingEngine`][crate::common::engine::RoutingEngine]
//! pinned to `Gateway`-flavored routing data and a CA-bundle parse cache. All
//! `ProxyHttp` hooks delegate to the shared bodies in
//! [`crate::common::hooks`]; the static `Kind` parameter on the engine
//! prevents a routing snapshot for one spec from being handed to the proxy
//! that serves the other.

use crate::common::ctx::ProxyCtx;
use crate::common::engine::RoutingEngine;
use crate::common::hooks;
use crate::config::SharedProxyConfig;
use async_trait::async_trait;
use coxswain_core::routing::Gateway;
use pingora_cache::key::{CacheKey, HashBinary};
use pingora_cache::{CacheMeta, ForcedFreshness, HitHandler, RespCacheable};
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
    pub cfg: SharedProxyConfig,
}

impl GatewayProxy {
    /// Construct a `GatewayProxy` from its engine and shared runtime config.
    #[must_use]
    pub fn new(engine: Arc<GatewayEngine>, cfg: SharedProxyConfig) -> Self {
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

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut ProxyCtx) -> Result<()> {
        hooks::request_cache_filter(self.cfg.cache, session, ctx)
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut ProxyCtx) -> Result<CacheKey> {
        Ok(hooks::cache_key_callback(session, ctx))
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut ProxyCtx,
    ) -> Result<RespCacheable> {
        Ok(hooks::response_cache_filter(resp))
    }

    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        _ctx: &mut ProxyCtx,
        req: &RequestHeader,
    ) -> Option<HashBinary> {
        hooks::cache_vary_filter(meta, req)
    }

    async fn cache_hit_filter(
        &self,
        _session: &mut Session,
        _meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        _is_fresh: bool,
        ctx: &mut ProxyCtx,
    ) -> Result<Option<ForcedFreshness>>
    where
        Self::CTX: Send + Sync,
    {
        hooks::record_cache_hit(ctx);
        Ok(None)
    }

    fn cache_miss(&self, session: &mut Session, ctx: &mut ProxyCtx) {
        hooks::record_cache_miss(ctx);
        session.cache.cache_miss();
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
        hooks::request_body_filter(body.as_ref(), end_of_stream, &self.cfg, ctx)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut ProxyCtx,
    ) -> Result<Box<HttpPeer>> {
        hooks::upstream_peer(&self.cfg.ca_cache, &self.cfg.circuit_breakers, ctx).await
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
        hooks::connected_to_upstream(reused);
        Ok(())
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

    fn fail_to_connect(
        &self,
        session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut ProxyCtx,
        e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        hooks::fail_to_connect(session, peer, ctx, e)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<pingora_core::Error>,
        ctx: &mut ProxyCtx,
        client_reused: bool,
    ) -> Box<pingora_core::Error> {
        hooks::error_while_proxy(peer, session, e, ctx, client_reused)
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
        hooks::fail_to_proxy(session, e, ctx).await
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
