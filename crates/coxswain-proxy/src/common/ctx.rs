//! Per-request and per-connection context types for the Pingora proxy.

use bytes::Bytes;
use coxswain_core::routing::{
    BackendGroup, CompressionConfig, FilterAction, RetryOn, RouteTimeouts,
};
use http::Method;
use pingora_core::protocols::http::compression::Encode;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Per-connection info seeded by the PROXY protocol accept loop.
#[derive(Clone)]
pub(crate) struct ConnectionInfo {
    pub real_addr: SocketAddr,
    /// Local address the server accepted this connection on.
    pub local_addr: SocketAddr,
    pub proto: &'static str,
}

tokio::task_local! {
    /// Set by the PROXY protocol accept loop before calling process_new_http.
    /// Consumed by Proxy::new_ctx so that every request on the connection carries
    /// the real client address and protocol.
    pub(crate) static CONN_INFO: ConnectionInfo;
}

/// Routing result cached from `request_filter` for use in later hooks.
///
/// `original_host`, `original_path`, `path_pattern`, and `metric_route_id`
/// are `Arc<str>` so that cloning them in subsequent hooks (e.g. for SNI,
/// redirect, access logging, or metric label emission) is a refcount bump,
/// not a heap allocation.
#[non_exhaustive]
pub struct ResolvedRoute {
    /// Chosen backend group for this request.
    pub backend_group: Arc<BackendGroup>,
    /// Filter actions to apply on request and response.
    pub filters: Arc<[FilterAction]>,
    /// Per-route timeout settings merged with global defaults.
    pub timeouts: RouteTimeouts,
    /// Original `Host` header value (before any rewrite).
    pub original_host: Arc<str>,
    /// Original request path (before any rewrite).
    pub original_path: Arc<str>,
    /// Registered path pattern of the matched rule (exact value, prefix, or regex).
    ///
    /// Shared from `RouteEntry::path_pattern` — one `Arc<str>` per rule, zero
    /// per-request allocation. Used by the access-log `pattern` mode to emit the
    /// rule pattern instead of the concrete request path.
    pub path_pattern: Arc<str>,
    /// Canonical metric/log identifier for the matched rule.
    ///
    /// Shared from `RouteEntry::metric_route_id` — emitted as the `route`
    /// Prometheus label and the `route_id` access-log field so a Grafana →
    /// log pivot has an exact join key.
    pub metric_route_id: Arc<str>,
    /// RFC 7234 response-cache opt-in for the matched route.
    ///
    /// Read in `request_cache_filter` to decide whether to enable Pingora's
    /// response cache for this request. `false` for every Gateway-API route and
    /// for Ingress routes without the `cache-enabled` annotation.
    pub cache_enabled: bool,
    /// Per-route response-compression configuration (`None` = no compression).
    ///
    /// Populated from `RouteMatch::compression`; `Some` only for Ingress routes
    /// that opt in via `compression-gzip`/`compression-brotli`. The proxy reads
    /// this in `upstream_response_filter` to decide whether to compress and
    /// constructs an encoder, stored in [`ProxyCtx::compression_encoder`].
    pub compression: Option<Arc<CompressionConfig>>,
}

/// Pending fire-and-forget mirror dispatch.
///
/// Populated by `request_filter` when the matched route carries a
/// [`coxswain_core::routing::FilterAction::Mirror`] filter.  Consumed by
/// `request_body_filter` on end-of-stream (with body) or dispatched immediately
/// in `request_filter` when no body buffering is configured.
pub(crate) struct MirrorDispatch {
    /// Pre-resolved mirror backend; a single endpoint is round-robin-selected at
    /// dispatch time via [`BackendGroup::next_endpoint_with_filters`].
    pub backend: Arc<BackendGroup>,
    /// HTTP method of the original request — forwarded verbatim to the mirror.
    pub method: Method,
    /// Original `Host` header value (forwarded as the mirror `Host`).
    pub host: Arc<str>,
    /// Path-and-query component, e.g. `/foo?bar=1` (forwarded verbatim).
    pub path_and_query: String,
    /// Forwardable request headers (hop-by-hop stripped, `Host` excluded).
    pub headers: Vec<(String, String)>,
}

/// Per-request context carrying the real client address extracted from the PROXY header.
#[non_exhaustive]
#[derive(Default)]
pub struct ProxyCtx {
    /// Real client IP from the PROXY protocol header (set only on the PROXY-protocol path).
    pub real_client_addr: Option<SocketAddr>,
    /// Protocol string (`"http"` or `"https"`) from the PROXY header.
    pub real_client_proto: Option<&'static str>,
    /// Local listener port for the connection; set from CONN_INFO on the PROXY-protocol path,
    /// or derived from the session's server address on the standard path.
    pub local_port: Option<u16>,
    /// Routing result set during `request_filter`; consumed by later hooks.
    pub resolved: Option<ResolvedRoute>,
    /// Absolute deadline for the total request (from `timeouts.request`). 504 if exceeded.
    pub request_deadline: Option<Instant>,
    /// True when the effective read_timeout was derived from `timeouts.request` (not
    /// `timeouts.backendRequest`). Set in `upstream_peer`; consulted in `fail_to_proxy` to
    /// distinguish 504 from upstream errors without relying on wall-clock comparisons that can
    /// race against OS timer granularity.
    pub request_timeout_is_controlling: bool,
    /// True when a `backendRequest` timeout was applied to this peer. Used in `fail_to_proxy` to
    /// map ConnectTimedout and ReadTimedout/WriteTimedout to 504 (Gateway API spec requires 504
    /// for both request and backendRequest timeout expiry).
    pub backend_request_timeout_active: bool,
    /// Per-backend `RequestHeaderModifier` filters from
    /// `HTTPRoute.spec.rules[].backendRefs[].filters`, attached to whichever backend
    /// won weighted selection in `upstream_peer`. Applied AFTER the rule-level
    /// filters in `upstream_request_filter`. `None` for the common case where no
    /// per-backend filters apply to this request.
    pub selected_backend_filters: Option<Arc<[FilterAction]>>,
    /// Timestamp captured at `request_filter` entry — used by the access log to compute
    /// `duration_ms`. `None` when `request_filter` was not reached (unusual error path).
    pub start: Option<Instant>,
    /// Upstream endpoint address chosen in `upstream_peer` — written to the access log.
    pub upstream_addr: Option<SocketAddr>,
    /// Number of upstream attempts already made for this request (excluding the initial).
    ///
    /// Incremented by `fail_to_connect` and `upstream_response_filter` before marking an
    /// error as retryable.  Compared against `RetryPolicy::max_retries` from the matched
    /// `BackendGroup` to enforce the per-route retry budget.
    pub retries_used: u32,
    /// The last retry condition that triggered a retry, for use in `error_while_proxy`.
    ///
    /// Set to the relevant [`RetryOn`] flag before marking an error retryable so that
    /// `error_while_proxy` can distinguish a 5xx-response retry (which must NOT be
    /// gated on `client_reused`) from a connection-error retry (which can check the
    /// retry buffer).
    pub last_retry_condition: Option<RetryOn>,
    /// Per-route request body size limit in bytes, from the matched route's
    /// `ingress.coxswain-labs.dev/max-body-size` annotation. `None` = unlimited.
    /// Set in `request_filter`; read by the up-front `Content-Length` check and the
    /// streaming `request_body_filter` cap.
    pub max_body_size: Option<u64>,
    /// Running count of request-body bytes seen so far in `request_body_filter`.
    /// Compared against [`Self::max_body_size`] to abort over-limit streaming/chunked
    /// uploads with 413 without buffering the whole body.
    pub body_bytes_seen: u64,
    /// Session-affinity endpoint resolved in `request_filter` from the request's
    /// cookie/header against the matched `BackendGroup`'s affinity index. When `Some`,
    /// `upstream_peer` pins to it instead of taking a round-robin tick. `None` (the
    /// common case, or a stale/absent pin) keeps weighted round-robin.
    pub affinity_pin: Option<SocketAddr>,
    /// True when cookie-mode affinity established a *fresh* pin this request (no valid
    /// cookie was presented), so `upstream_response_filter` must emit `Set-Cookie` for
    /// the chosen endpoint. Always `false` in header mode (the client supplies the key).
    pub affinity_set_cookie: bool,
    /// Headers from the ext_authz response to inject into the upstream request.
    ///
    /// Populated by [`crate::auth::enforce`] when the auth service returns 2xx and
    /// the route's `auth-response-headers` allow-list is non-empty.  Applied in
    /// `upstream_request_filter` after rule-level filters.  `None` (the common
    /// case) incurs no cost.
    ///
    /// Each element is `(lowercase-header-name, value)`.  The name is pre-lowercased
    /// at the auth-response parsing step so `upstream_request_filter` can use a
    /// case-insensitive comparison without per-request allocation.
    pub auth_response_headers: Option<Vec<(Box<str>, Box<str>)>>,
    /// Pending fire-and-forget mirror dispatch (#283).
    ///
    /// Set in `request_filter` when the route carries a `FilterAction::Mirror` filter
    /// and `max-body-size` is configured (body-mirroring mode).  `request_body_filter`
    /// accumulates body chunks in [`Self::mirror_body`] and `take`s this on
    /// end-of-stream to dispatch. When `max-body-size` is absent (header-only mode),
    /// this is never set — the dispatch fires immediately in `request_filter`.
    pub(crate) mirror: Option<MirrorDispatch>,
    /// Body chunks collected for fire-and-forget body mirroring.
    ///
    /// Only populated when [`Self::mirror`] is `Some` and the route has
    /// `max-body-size` set.  Each chunk is a [`Bytes`] refcount clone of the
    /// original request chunk — zero data copies.  Consumed (and cleared) by
    /// `request_body_filter` on end-of-stream.
    pub mirror_body: Vec<Bytes>,
    /// Live streaming compressor for the current response, set by
    /// `upstream_response_filter` when the route has compression enabled and
    /// the response qualifies. `None` for every Gateway-API route, for Ingress
    /// routes without compression annotations, and for responses that are
    /// already compressed or below the `min-size` threshold.
    ///
    /// Holds a fat pointer (data + vtable), so it is 16 bytes in its `Some`
    /// state and exactly one allocation is made when an encoder is created.
    /// The encoder is consumed by `response_body_filter`, chunk by chunk.
    pub compression_encoder: Option<Box<dyn Encode + Send + Sync>>,
    /// PEM-encoded verified client certificate to forward upstream (#267).
    ///
    /// Set in `request_filter` when the matched Ingress has
    /// `auth-tls-pass-certificate-to-upstream: "true"` AND the connection's
    /// `SslDigest` carries a verified [`crate::tls::ClientCertInfo`].
    /// Consumed (`.take()`d) in `upstream_request_filter` to inject the
    /// `X-SSL-Client-Cert` header (URL-encoded PEM).  `None` (the common case)
    /// incurs no cost.
    pub client_cert_pem: Option<String>,
    /// Effective client IP resolved in `request_filter` (#271).
    ///
    /// When the matched route carries a `ForwardedForConfig`, this is the first
    /// non-private IP extracted from the configured forwarded header (if the L4
    /// peer is within the trusted CIDRs, or unconditionally when no CIDRs are
    /// set); otherwise it is the PROXY-protocol addr (`real_client_addr`) or the
    /// L4 peer. Computed once per request and consumed by allow/deny-source-range,
    /// rate limiting, and access logging.  `None` when the peer address could not
    /// be determined.
    pub client_ip: Option<std::net::IpAddr>,
    /// Flat index into [`BackendGroup::lb_endpoints`] for the upstream selected
    /// this request by a stateful load-balancing algorithm (#275).
    ///
    /// `None` for `RoundRobin` and `Hash` (stateless; `track` is always `None`
    /// from `select_upstream`) and for every Gateway API route. When `Some`,
    /// `logging` calls [`BackendGroup::complete`] exactly once to decrement the
    /// active-connection count or update the EWMA latency. On a retriable failure,
    /// `upstream_peer` calls [`BackendGroup::release`] before re-selecting.
    pub lb_track: Option<u32>,
    /// Pre-computed FNV-1a hash key for `LoadBalance::Hash` selection (#276).
    ///
    /// Extracted once in `request_filter` from the attribute configured via
    /// `BackendGroup::hash_by()` and passed to `BackendGroup::select_upstream`.
    /// `None` for all other algorithms (zero overhead) or when the attribute is absent.
    pub hash_key: Option<u64>,
}

// Hot types — review with the team before bumping these numbers.
// ResolvedRoute: +16 bytes for path_pattern: Arc<str> (88→104).
// ResolvedRoute: +16 bytes for metric_route_id: Arc<str> (104→120).
// ResolvedRoute: +48 bytes because RouteTimeouts gained connect/read/send: Option<Duration> (120→168).
// ResolvedRoute: +8 (alignment) for cache_enabled: bool (#40) (168→176).
// ResolvedRoute: +8 for compression: Option<Arc<CompressionConfig>> (niche pointer) (#270) (176→184).
const _: () = assert!(std::mem::size_of::<ResolvedRoute>() == 184);
// ProxyCtx: +16 for start: Option<Instant>, +48 for upstream_addr: Option<SocketAddr>
// with alignment padding (176→240).
// ProxyCtx: +16 because Option<ResolvedRoute> inlines the struct (240→256).
// ProxyCtx: +48 because ResolvedRoute grew with RouteTimeouts (256→304).
// ProxyCtx: +24 for max_body_size: Option<u64> (16 — no niche) + body_bytes_seen: u64
// (8) — the max-body-size request-body limit and its running counter (312→336).
// ProxyCtx: +8 because the embedded ResolvedRoute grew for cache_enabled (#40) (336→344).
// ProxyCtx: +32 for the session-affinity pin — affinity_pin: Option<SocketAddr>
// (32, no niche) plus affinity_set_cookie: bool absorbed into existing alignment
// padding (#15) (344→376).
// ProxyCtx: +24 for auth_response_headers: Option<Vec<(Box<str>, Box<str>)>>
// (niche-opt on Vec's ptr; 24 bytes) (#24) (376→400).
// ProxyCtx: +120 for mirror: Option<MirrorDispatch> (96 — method 24, host 16,
// path_and_query 24, headers 24, backend 8; Option adds niche) + 24 for
// mirror_body: Vec<Bytes> (#283) (400→520).
// ProxyCtx: +8 because embedded ResolvedRoute grew for compression field (#270) (520→528).
// ProxyCtx: +16 for compression_encoder: Option<Box<dyn Encode + Send + Sync>>
// (fat pointer, niche-opted, 16 bytes) (#270) (528→544).
// ProxyCtx: +24 for client_cert_pem: Option<String> (niche-opt on String's ptr; 24 bytes) (#267) (544→568).
// ProxyCtx: +16 for client_ip: Option<IpAddr> (17 bytes packed into existing alignment gap by Rust layout; 568→584) (#271).
// ProxyCtx: +8 for lb_track: Option<u32> (discriminant + padding + u32 = 8 bytes; 584→592) (#275).
// ProxyCtx: +16 for hash_key: Option<u64> (discriminant padded to u64 align; 592→608) (#276).
const _: () = assert!(std::mem::size_of::<ProxyCtx>() == 608);
