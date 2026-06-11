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
use crate::upstream_ca::UpstreamCaCache;
use async_trait::async_trait;
use coxswain_core::routing::{Ingress, RouteTimeouts};
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
    ) -> Self {
        Self {
            engine,
            default_timeouts,
            ca_cache,
            access_log_enabled,
            access_log_path_mode,
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
        hooks::request_filter(&self.engine, &self.default_timeouts, session, ctx).await
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
