//! Proxy-side runtime configuration types.
//!
//! These enums and structs are set once at startup from CLI flags (via
//! `coxswain-bin`) and stored on the proxy instances. They are intentionally
//! independent of the bin crate so the proxy crate remains self-contained.

use crate::edge::upstream_ca::UpstreamCaCache;
use crate::policy::circuit_breaker::CircuitBreakerRegistry;
use crate::policy::rate_limit::RateLimiterRegistry;
use coxswain_cache::ResponseCache;
use coxswain_core::routing::RouteTimeouts;
use coxswain_core::tls::{SharedClientCertStore, SharedListenerHostnames};
use std::sync::Arc;

/// Startup-time collaborators shared between both proxy types.
///
/// Passed to [`crate::IngressProxy::new`] and [`crate::GatewayProxy::new`] as a
/// single struct so the constructors stay within the 7-argument clippy budget
/// while the engine (which is typed differently per proxy) remains a separate
/// argument.  All fields are low-cost to clone: `Arc<T>` pointer bumps,
/// `Copy` values, or internally reference-counted types.
#[non_exhaustive]
#[derive(Clone)]
pub struct SharedProxyConfig {
    /// Global fallback timeouts applied when a matched route has no per-rule
    /// timeouts set.
    pub default_timeouts: RouteTimeouts,
    /// Parse cache for upstream CA bundles from `BackendTLSPolicy` attachments.
    pub ca_cache: Arc<UpstreamCaCache>,
    /// Whether to emit one access-log event per request.
    pub access_log_enabled: bool,
    /// Controls what the access log emits for the `path` field.
    pub access_log_path_mode: AccessLogPathMode,
    /// Shared response cache, or `None` when caching is disabled process-wide.
    pub cache: Option<ResponseCache>,
    /// Shared per-process rate-limiter registry.
    pub rate_limiter: RateLimiterRegistry,
    /// Shared HTTP client for ext_authz sub-requests (#24).
    pub auth_client: reqwest::Client,
    /// Per-Ingress client-certificate mTLS config store (#267).
    ///
    /// Looked up per-host in `request_filter` to enforce the mTLS handshake
    /// guard and optionally forward the verified cert as `X-SSL-Client-Cert`.
    /// Defaults to an empty store (no mTLS enforced) until the reflector's
    /// first reconcile cycle completes.
    pub client_certs: SharedClientCertStore,
    /// Per-port HTTPS Gateway-listener hostname snapshot for misdirected-request
    /// detection (GEP-3567, #96).
    ///
    /// Looked up in `request_filter` on every HTTPS request: when the request
    /// Host resolves to a different listener than the negotiated SNI, the proxy
    /// returns 421 Misdirected Request so the client opens a fresh connection
    /// on the correct listener. Defaults to an empty snapshot (check inactive)
    /// until the reflector's first Gateway reconcile completes.
    pub listener_hostnames: SharedListenerHostnames,
    /// Per-process per-endpoint circuit-breaker registry (#282).
    ///
    /// Keyed by `(metric_route_id, SocketAddr)`. Built once at startup; gated in
    /// `upstream_peer` (fail-fast 503 when Open) and recorded in `logging` (success
    /// or failure after each real upstream request). Gateway-API routes never carry
    /// a `CircuitBreakerConfig` so the registry is only touched for Ingress routes
    /// that configure `circuit-breaker-threshold`.
    pub circuit_breakers: CircuitBreakerRegistry,
    /// Tracker for fire-and-forget mirror tasks.
    pub mirror_tracker: tokio_util::task::TaskTracker,
}

impl SharedProxyConfig {
    /// Construct a `SharedProxyConfig` from its collaborators.
    #[must_use]
    pub fn new(
        default_timeouts: RouteTimeouts,
        ca_cache: Arc<UpstreamCaCache>,
        access_log_enabled: bool,
        access_log_path_mode: AccessLogPathMode,
        cache: Option<ResponseCache>,
        rate_limiter: RateLimiterRegistry,
        auth_client: reqwest::Client,
    ) -> Self {
        Self {
            default_timeouts,
            ca_cache,
            access_log_enabled,
            access_log_path_mode,
            cache,
            rate_limiter,
            auth_client,
            client_certs: SharedClientCertStore::new(),
            listener_hostnames: SharedListenerHostnames::new(),
            circuit_breakers: CircuitBreakerRegistry::new(),
            mirror_tracker: tokio_util::task::TaskTracker::new(),
        }
    }
}

/// Controls what the access log emits for the `path` field.
///
/// The architecturally correct home for PII scrubbing is the log-collection
/// pipeline. This enum exists for two narrower cases: operators whose pipeline
/// genuinely cannot filter, and the `Pattern` mode, which records the
/// *matched rule's path pattern* — information only the proxy holds cheaply
/// without duplicating route config downstream.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessLogPathMode {
    /// Emit the concrete request path as received (default).
    Full,
    /// Emit the matched rule's registered path pattern instead of the
    /// concrete request path (e.g. `/users/` instead of `/users/42/orders/7`).
    /// When no route matched, emits `"/"` as a stable placeholder.
    Pattern,
    /// Omit the `path` field from the access log entirely.
    None,
}
