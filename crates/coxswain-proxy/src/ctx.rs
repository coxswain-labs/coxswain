//! Per-request and per-connection context types for the Pingora proxy.

use crate::retry::RetryTrigger;
use bytes::Bytes;
use coxswain_core::routing::{
    BackendGroup, CircuitBreakerConfig, CompressionConfig, FilterAction, RouteTimeouts,
};
use http::Method;
use pingora_core::protocols::http::compression::Encode;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

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
    /// Per-class access-log enabled override for the matched route.
    ///
    /// Populated from `RouteMatch::access_log_enabled`. `Some(false)` suppresses
    /// the access-log line in the `logging` hook while leaving metrics unaffected.
    /// `None` or `Some(true)` means the proxy-wide `--access-log` flag governs.
    /// Only ever `Some(false)` for Ingress routes whose class has
    /// `CoxswainIngressClassParameters.spec.accessLog: false` (#279).
    pub access_log_enabled: Option<bool>,
    /// Per-route response-compression configuration (`None` = no compression).
    ///
    /// Populated from `RouteMatch::compression`; `Some` only for Ingress routes
    /// that opt in via `compression-gzip`/`compression-brotli`. The proxy reads
    /// this in `upstream_response_filter` to decide whether to compress and
    /// constructs an encoder, stored in [`ProxyCtx::compression_encoder`].
    pub compression: Option<Arc<CompressionConfig>>,
    /// Per-route circuit-breaker configuration (`None` = disabled).
    ///
    /// Populated from [`coxswain_core::routing::RouteEntry::circuit_breaker`]; `Some` only for Ingress
    /// routes configured with `circuit-breaker-threshold`. The proxy consumes
    /// this in `upstream_peer` to gate the request through the per-endpoint
    /// `policy::circuit_breaker::CircuitBreakerRegistry`, and in `logging` to
    /// record the outcome.
    pub circuit_breaker: Option<Arc<CircuitBreakerConfig>>,
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
    ///
    /// `Arc<str>` so the no-query mirror arm can reuse the captured request path
    /// without a copy (#397); matches the sibling [`Self::host`].
    pub path_and_query: Arc<str>,
    /// Forwardable request headers (hop-by-hop stripped, `Host` excluded).
    pub headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
    /// Canonical route identifier for the `route` Prometheus label on
    /// `coxswain_proxy_mirror_requests_total`.
    pub metric_route_id: Arc<str>,
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
    /// error as retryable.  Compared against `RetryPolicyConfig::attempts` from the matched
    /// `BackendGroup` to enforce the per-route retry budget.
    pub retries_used: u32,
    /// What triggered the last retry, for use in `error_while_proxy`.
    ///
    /// Set before marking an error retryable so that `error_while_proxy` can distinguish a
    /// response-code retry (`RetryTrigger::HttpCode`/`RetryTrigger::GrpcCode`, which must
    /// NOT be gated on `client_reused`) from a connection-error retry (which can check the
    /// retry buffer).
    pub last_retry_trigger: Option<RetryTrigger>,
    /// Per-route request body size limit in bytes, from the matched route's
    /// `ingress.coxswain-labs.dev/max-body-size` annotation. `None` = unlimited.
    /// Set in `request_filter`; read by the up-front `Content-Length` check and the
    /// streaming `request_body_filter` cap.
    pub max_body_size: Option<u64>,
    /// Running count of request-body bytes seen so far in `request_body_filter`.
    /// Compared against [`Self::max_body_size`] to abort over-limit streaming/chunked
    /// uploads with 413 without buffering the whole body.
    pub body_bytes_seen: u64,
    /// `true` when the downstream request is HTTP/2 (h2, h2c, or gRPC). Captured
    /// once at `request_filter` entry from the request version.
    ///
    /// Gates the mid-stream `max_body_size` cap in `request_body_filter`: on HTTP/2
    /// we must NOT reject from the body-filter hook because pingora's h2 proxy loop
    /// swallows the error and deadlocks the client (#509). h2 size limits are enforced
    /// only up-front via the `Content-Length` pre-check; correct mid-stream h2/gRPC
    /// enforcement awaits pingora request-body buffering (pingora #816/#780).
    pub is_h2: bool,
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
    /// Populated by `policy::auth::enforce` when the auth service returns 2xx and
    /// the route's `auth-response-headers` allow-list is non-empty.  Applied in
    /// `upstream_request_filter` after rule-level filters.  `None` (the common
    /// case) incurs no cost.
    ///
    /// Each element is `(lowercase-header-name, value)`.  The name is pre-lowercased
    /// at the auth-response parsing step so `upstream_request_filter` can use a
    /// case-insensitive comparison without per-request allocation.
    pub auth_response_headers: Option<Vec<(Box<str>, Box<str>)>>,
    /// Request header names to strip before forwarding upstream (#441).
    ///
    /// Populated by `policy::auth::enforce` with the bearer-token
    /// header name(s) when a `JwtAuth` check succeeds and its `forward` field
    /// is `false` (Envoy `JwtProvider.forward` default) — the raw token must
    /// not reach the upstream. Applied in `upstream_request_filter` before
    /// [`Self::auth_response_headers`] is applied, so a `claimToHeaders` entry
    /// can never be immediately stripped by a same-named removal. `None` (the
    /// common case: no JWT filter, or `forward: true`) incurs no cost.
    pub strip_upstream_headers: Option<Vec<Box<str>>>,
    /// Bounded mpsc senders feeding in-flight mirror tasks (#360).
    ///
    /// Populated in `request_filter` when the route carries one or more
    /// `FilterAction::Mirror` filters that survive the GEP-3171 sampling gate.
    /// One sender per surviving mirror backend; each receiver side is wrapped as
    /// a streaming `reqwest::Body` so the mirror task runs concurrently with
    /// primary body forwarding — no intermediate buffering.
    /// `request_body_filter` tees each arriving chunk to all senders via
    /// [`mpsc::Sender::try_send`] (drop on backpressure, never stall primary).
    /// Clearing this Vec on end-of-stream drops all senders, signalling EOF to
    /// each mirror's body stream.  Works regardless of whether `max-body-size`
    /// is set.
    pub(crate) mirror_txs: Vec<mpsc::Sender<Bytes>>,
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
    /// `SslDigest` carries a verified `edge::tls::ClientCertInfo`.
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
    /// `true` when `upstream_peer` returned 503 because the endpoint's circuit breaker
    /// was Open (fail-fast path, #282). When set, `logging` skips recording the outcome
    /// in the `policy::circuit_breaker::CircuitBreakerRegistry` — no upstream request
    /// was ever attempted, so there is no success/failure to record.
    pub circuit_breaker_rejected: bool,
    /// `Origin` request header value (GEP-1767 CORS, #41).
    ///
    /// Captured once in `request_filter` from the raw request header; stored as a
    /// heap-allocated string so the borrow of the request header is released before
    /// the session is mutated.  `None` when the request carries no `Origin` header
    /// (the common non-CORS case) — no allocation in that path.
    ///
    /// Consumed in `upstream_response_filter` to inject `Access-Control-Allow-Origin`
    /// and in `try_cors_preflight` for the preflight short-circuit.
    pub cors_origin: Option<Box<str>>,
}

// Hot types — review with the team before bumping these numbers.
// ResolvedRoute: +16 bytes for path_pattern: Arc<str> (88→104).
// ResolvedRoute: +16 bytes for metric_route_id: Arc<str> (104→120).
// ResolvedRoute: +48 bytes because RouteTimeouts gained connect/read/send: Option<Duration> (120→168).
// ResolvedRoute: +8 (alignment) for access_log_enabled: Option<bool> (#279) (168→176).
// ResolvedRoute: +8 for compression: Option<Arc<CompressionConfig>> (niche pointer) (#270) (176→184).
// ResolvedRoute: +8 for circuit_breaker: Option<Arc<CircuitBreakerConfig>> (niche pointer) (#282) (184→192).
const _: () = assert!(std::mem::size_of::<ResolvedRoute>() == 192);
// ProxyCtx: +16 for start: Option<Instant>, +48 for upstream_addr: Option<SocketAddr>
// with alignment padding (176→240).
// ProxyCtx: +16 because Option<ResolvedRoute> inlines the struct (240→256).
// ProxyCtx: +48 because ResolvedRoute grew with RouteTimeouts (256→304).
// ProxyCtx: +24 for max_body_size: Option<u64> (16 — no niche) + body_bytes_seen: u64
// (8) — the max-body-size request-body limit and its running counter (312→336).
// ProxyCtx: +8 because the embedded ResolvedRoute grew for access_log_enabled (#279) (336→344).
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
// ProxyCtx: -8 for MirrorDispatch.path_and_query String→Arc<str> (16 not 24; #397) (608→600).
// ProxyCtx: +8 because embedded ResolvedRoute grew for circuit_breaker field (#282) (600→608).
// ProxyCtx: +0 for circuit_breaker_rejected: bool absorbed into existing alignment padding (#282).
// ProxyCtx: +16 for cors_origin: Option<Box<str>> (fat pointer via niche; GEP-1767 CORS #41) (608→624).
// ProxyCtx: -64 mirrors: Vec<MirrorDispatch> (24B) replaces mirror: Option<MirrorDispatch> (88B);
//   Vec is smaller because Option<T> with a niche can't be smaller than T itself; the Vec
//   pointer/len/cap triple (24B) is much smaller than a full MirrorDispatch struct (88B)
//   (GEP-3171 multiple mirrors, #261) (624→560).
// ProxyCtx: -24 stream-concurrent mirroring (#360): mirrors: Vec<MirrorDispatch> (24B) +
//   mirror_body: Vec<Bytes> (24B) replaced by mirror_txs: Vec<mpsc::Sender<Bytes>> (24B);
//   the two staging fields collapse into one sender vec (560→536).
// ProxyCtx: +0 for is_h2: bool absorbed into existing alignment padding (#509).
// ProxyCtx: +24 for strip_upstream_headers: Option<Vec<Box<str>>> (niche-opt on
// Vec's ptr; 24 bytes) (#441) (536→560).
const _: () = assert!(std::mem::size_of::<ProxyCtx>() == 560);
