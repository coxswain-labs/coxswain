use crate::routing::predicate::MatchPredicates;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

/// How a path is modified by `URLRewrite` or `RequestRedirect`.
#[derive(Clone, Debug)]
pub enum PathModifier {
    ReplaceFullPath(String),
    /// Replace `prefix` with `replacement` in the matched request path.
    ReplacePrefixMatch {
        prefix: String,
        replacement: String,
    },
}

/// Header add/set/remove operations applied as a unit.
#[derive(Clone, Debug, Default)]
pub struct HeaderMod {
    /// Headers appended to any existing values.
    pub add: Vec<(String, String)>,
    /// Headers overwritten (set).
    pub set: Vec<(String, String)>,
    /// Header names removed entirely.
    pub remove: Vec<String>,
}

/// A filter action evaluated per-request on the proxy hot path.
#[derive(Clone, Debug)]
pub enum FilterAction {
    /// Modify request headers before forwarding upstream.
    RequestHeaderModifier(HeaderMod),
    /// Modify response headers before returning to the client.
    ResponseHeaderModifier(HeaderMod),
    /// Return a 3xx redirect without connecting to the upstream.
    RequestRedirect {
        scheme: Option<String>,
        hostname: Option<String>,
        port: Option<u16>,
        /// HTTP status code (default 302).
        status_code: u16,
        path: Option<PathModifier>,
    },
    /// Rewrite the upstream request host and/or path (client-visible URL is unchanged).
    UrlRewrite {
        hostname: Option<String>,
        path: Option<PathModifier>,
    },
}

/// Per-rule timeout configuration parsed from `HTTPRouteRule.timeouts`.
#[derive(Clone, Debug, Default)]
pub struct RouteTimeouts {
    /// Total request timeout (client → proxy → upstream → proxy → client). 504 on expiry.
    pub request: Option<Duration>,
    /// Upstream-only timeout (proxy → upstream response). 502 on expiry.
    pub backend_request: Option<Duration>,
}

/// A named group of pod endpoints with lock-free round-robin selection.
pub struct Upstream {
    /// Service identity in `"namespace/name"` form — used for logging only.
    pub name: String,
    endpoints: Vec<SocketAddr>,
    index: AtomicUsize,
}

impl Upstream {
    pub fn new(name: String, endpoints: Vec<SocketAddr>) -> Self {
        Self {
            name,
            endpoints,
            index: AtomicUsize::new(0),
        }
    }

    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }

    /// Returns the next endpoint using round-robin selection.
    ///
    /// Returns `None` if the upstream has no endpoints.
    pub fn next_endpoint(&self) -> Option<&SocketAddr> {
        if self.endpoints.is_empty() {
            return None;
        }
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.endpoints.len();
        self.endpoints.get(idx)
    }
}

/// How a path rule was registered — for introspection only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Exact,
    Prefix,
    Regex,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Exact => "exact",
            RouteKind::Prefix => "prefix",
            RouteKind::Regex => "regex",
        }
    }
}

/// Snapshot of a single path rule insertion, kept for inspection.
pub struct RouteInfo {
    pub path: String,
    pub kind: RouteKind,
    pub upstream: Arc<Upstream>,
}

/// A path rule that was silently dropped because an earlier rule already claimed the same slot.
pub struct RouteConflict {
    /// Host pattern where the conflict occurred (`"*"` for catch-all, `"*.example.com"` for wildcard).
    pub host: String,
    pub path: String,
    pub kind: RouteKind,
    /// `Upstream::name` of the rule that was rejected.
    pub rejected_upstream: String,
}

/// A single routing candidate: an upstream plus the predicates that must hold
/// for this candidate to be selected, along with metadata for precedence ordering.
pub struct RouteEntry {
    pub upstream: Arc<Upstream>,
    pub predicates: MatchPredicates,
    pub filters: Arc<[FilterAction]>,
    pub timeouts: RouteTimeouts,
    /// Parent resource identity `"{namespace}/{name}"` — used for precedence tiebreaking.
    pub route_id: String,
    /// Creation timestamp — older routes win ties after predicate-count comparison.
    /// `None` sorts last.
    pub created_at: Option<SystemTime>,
    /// When `Some`, the proxy returns this status code immediately without contacting upstream.
    /// Used for routes with invalid/missing/forbidden backend refs (Gateway API §4.3.4).
    pub error_status: Option<u16>,
}

impl RouteEntry {
    /// Constructs an entry with no predicates, no filters, and no timeouts.
    pub fn path_only(
        upstream: Arc<Upstream>,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            upstream,
            predicates: MatchPredicates::default(),
            filters: Arc::from([]),
            timeouts: RouteTimeouts::default(),
            route_id,
            created_at,
            error_status: None,
        }
    }

    /// Constructs an entry with predicates but no filters and no timeouts.
    pub fn new(
        upstream: Arc<Upstream>,
        predicates: MatchPredicates,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            upstream,
            predicates,
            filters: Arc::from([]),
            timeouts: RouteTimeouts::default(),
            route_id,
            created_at,
            error_status: None,
        }
    }

    /// Constructs an entry with predicates, filters, and per-rule timeouts.
    pub fn with_filters(
        upstream: Arc<Upstream>,
        predicates: MatchPredicates,
        filters: Vec<FilterAction>,
        timeouts: RouteTimeouts,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            upstream,
            predicates,
            filters: Arc::from(filters.into_boxed_slice()),
            timeouts,
            route_id,
            created_at,
            error_status: None,
        }
    }
}
