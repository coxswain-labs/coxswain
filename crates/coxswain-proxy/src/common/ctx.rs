//! Per-request and per-connection context types for the Pingora proxy.

use coxswain_core::routing::{BackendGroup, FilterAction, RouteTimeouts};
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
/// `original_host`, `original_path`, and `path_pattern` are `Arc<str>` so that
/// cloning them in subsequent hooks (e.g. for SNI, redirect, or access logging)
/// is a refcount bump, not a heap allocation.
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
}

/// Per-request context carrying the real client address extracted from the PROXY header.
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
}

// Hot types — review with the team before bumping these numbers.
// ResolvedRoute: +16 bytes for path_pattern: Arc<str> (88→104).
const _: () = assert!(std::mem::size_of::<ResolvedRoute>() == 104);
// ProxyCtx: +16 for start: Option<Instant>, +48 for upstream_addr: Option<SocketAddr>
// with alignment padding (176→240).
const _: () = assert!(std::mem::size_of::<ProxyCtx>() == 240);
