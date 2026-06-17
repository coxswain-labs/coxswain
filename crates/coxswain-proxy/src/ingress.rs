//! `IngressProxy`: Pingora `ProxyHttp` implementation that serves traffic for
//! Kubernetes `Ingress` resources.
//!
//! The proxy holds a typed [`RoutingEngine`][crate::common::engine::RoutingEngine]
//! pinned to `Ingress`-flavored routing data and a CA-bundle parse cache. All
//! `ProxyHttp` hooks delegate to the shared bodies in
//! [`crate::common::hooks`] — the only thing that varies between
//! `IngressProxy` and `GatewayProxy` today is the static `Kind` parameter on
//! the engine, which prevents a routing snapshot for one spec from being
//! handed to the proxy that serves the other.

use crate::common::ctx::ProxyCtx;
use crate::common::engine::RoutingEngine;
use crate::common::hooks;
use crate::config::AccessLogPathMode;
use crate::rate_limit::RateLimiterRegistry;
use crate::upstream_ca::UpstreamCaCache;
use async_trait::async_trait;
use coxswain_cache::ResponseCache;
use coxswain_core::routing::{Ingress, RouteTimeouts};
use pingora_cache::key::{CacheKey, HashBinary};
use pingora_cache::{CacheMeta, ForcedFreshness, HitHandler, RespCacheable};
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::sync::Arc;

/// Typed routing engine pinned to Ingress-flavored data.
pub type IngressEngine = RoutingEngine<Ingress>;

/// Pingora `ProxyHttp` implementation that routes Ingress traffic.
#[non_exhaustive]
pub struct IngressProxy {
    /// Lock-free routing engine reading the Ingress snapshot.
    pub engine: Arc<IngressEngine>,
    /// Global fallback timeouts applied when a matched route has no per-rule timeouts set.
    pub default_timeouts: RouteTimeouts,
    /// Parse cache for upstream CA bundles from `BackendTLSPolicy` attachments.
    pub ca_cache: Arc<UpstreamCaCache>,
    /// Whether to emit one access-log event per request.
    pub access_log_enabled: bool,
    /// Controls what the access log emits for the `path` field.
    pub access_log_path_mode: AccessLogPathMode,
    /// Shared response cache, or `None` when caching is disabled process-wide
    /// (`--cache-max-size=0`). Enabled per request only for routes carrying the
    /// `ingress.coxswain-labs.dev/cache-enabled` opt-in.
    pub cache: Option<ResponseCache>,
    /// Shared per-process rate-limiter registry. Holds one governor keyed limiter
    /// per route that has `ingress.coxswain-labs.dev/rate-limit-*` annotations or
    /// a `RateLimit` CRD `ExtensionRef` filter. Survives routing-table reconciles.
    pub rate_limiter: RateLimiterRegistry,
}

impl IngressProxy {
    /// Construct an `IngressProxy` from its runtime collaborators.
    #[must_use]
    pub fn new(
        engine: Arc<IngressEngine>,
        default_timeouts: RouteTimeouts,
        ca_cache: Arc<UpstreamCaCache>,
        access_log_enabled: bool,
        access_log_path_mode: AccessLogPathMode,
        cache: Option<ResponseCache>,
        rate_limiter: RateLimiterRegistry,
    ) -> Self {
        Self {
            engine,
            default_timeouts,
            ca_cache,
            access_log_enabled,
            access_log_path_mode,
            cache,
            rate_limiter,
        }
    }
}

#[async_trait]
impl ProxyHttp for IngressProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        hooks::new_ctx()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyCtx) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        hooks::request_filter(
            &self.engine,
            &self.default_timeouts,
            &self.rate_limiter,
            session,
            ctx,
        )
        .await
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut ProxyCtx) -> Result<()> {
        hooks::request_cache_filter(self.cache, session, ctx)
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
        _end_of_stream: bool,
        ctx: &mut ProxyCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        hooks::request_body_filter(body.as_ref(), ctx)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut ProxyCtx,
    ) -> Result<Box<HttpPeer>> {
        hooks::upstream_peer(&self.ca_cache, ctx).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyCtx,
    ) -> Result<()> {
        hooks::upstream_request_filter(session, upstream_request, ctx).await
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
            self.access_log_enabled,
            self.access_log_path_mode,
            session,
            e,
            ctx,
        )
        .await;
    }
}
