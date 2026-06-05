use crate::routing::predicate::MatchPredicates;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

/// One backend service's resolved pod endpoints with a round-robin counter.
struct BackendPool {
    addrs: Box<[SocketAddr]>,
    rr: AtomicUsize,
}

impl BackendPool {
    fn new(addrs: Vec<SocketAddr>) -> Self {
        Self {
            addrs: addrs.into_boxed_slice(),
            rr: AtomicUsize::new(0),
        }
    }

    fn next(&self) -> SocketAddr {
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.addrs.len();
        self.addrs[idx]
    }
}

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

impl PathModifier {
    /// Apply this modifier to `path` and return the resulting path string.
    ///
    /// For `ReplacePrefixMatch`, returns `path` unchanged if it does not start
    /// with the prefix (should not happen in practice since routing only selects
    /// routes whose prefix matched, but avoids a panic on edge cases).
    pub fn apply(&self, path: &str) -> String {
        match self {
            PathModifier::ReplaceFullPath(p) => p.clone(),
            PathModifier::ReplacePrefixMatch {
                prefix,
                replacement,
            } => {
                let prefix_trimmed = prefix.trim_end_matches('/');
                if path == prefix_trimmed || path.starts_with(prefix_trimmed) {
                    let suffix = &path[prefix_trimmed.len()..];
                    let rep = replacement.trim_end_matches('/');
                    match suffix {
                        "" | "/" => {
                            if rep.is_empty() {
                                "/".to_string()
                            } else {
                                rep.to_string()
                            }
                        }
                        s => format!("{rep}{s}"),
                    }
                } else {
                    path.to_string()
                }
            }
        }
    }
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

/// A named group of pod endpoints with two-level weighted round-robin selection.
///
/// Level 1 — backend selection: a GCD-reduced slot array maps request indices to
/// one of the backend pools proportional to their weights.
/// Level 2 — pod selection: within the chosen pool, a per-pool atomic counter
/// does fair round-robin across that backend's pods.
///
/// This gives exact per-backend traffic ratios regardless of pod count, and fair
/// pod distribution within each backend.
pub struct BackendGroup {
    /// Service identity — used for logging only.
    pub name: String,
    /// One entry per non-zero-weight backend ref.
    backends: Box<[BackendPool]>,
    /// Slot array: each entry is an index into `backends`.
    /// Length = Σ(weight_i after GCD reduction).
    slots: Box<[u16]>,
    /// Advances monotonically; taken mod `slots.len()` on each request.
    slot_counter: AtomicUsize,
    /// Flat snapshot of all pod addresses for the admin `/routes` endpoint.
    addrs_snapshot: Box<[SocketAddr]>,
}

impl BackendGroup {
    /// All endpoints with equal weight (weight-1 uniform round-robin).
    /// Used by Ingress reconciler and single-backend Gateway API rules.
    pub fn new(name: String, endpoints: Vec<SocketAddr>) -> Self {
        if endpoints.is_empty() {
            return Self::empty(name);
        }
        let addrs_snapshot = endpoints.clone().into_boxed_slice();
        let slots = vec![0u16].into_boxed_slice();
        let backends = Box::new([BackendPool::new(endpoints)]);
        Self {
            name,
            backends,
            slots,
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot,
        }
    }

    /// Weighted constructor for multi-backend Gateway API rules.
    ///
    /// `weighted` is `[(pod_addrs_for_backend, weight), ...]` — one entry per
    /// `backendRef`. Backends with `weight == 0` or empty address lists are
    /// dropped. Returns an empty `BackendGroup` when all weights resolve to zero.
    pub fn weighted(name: String, weighted: Vec<(Vec<SocketAddr>, u16)>) -> Self {
        let pools: Vec<(Vec<SocketAddr>, u16)> = weighted
            .into_iter()
            .filter(|(addrs, w)| *w > 0 && !addrs.is_empty())
            .collect();

        if pools.is_empty() {
            return Self::empty(name);
        }

        let weights: Vec<u16> = pools.iter().map(|(_, w)| *w).collect();
        let reduced = gcd_reduce(&weights);

        let mut slots: Vec<u16> = Vec::with_capacity(reduced.iter().map(|&w| w as usize).sum());
        for (idx, &w) in reduced.iter().enumerate() {
            for _ in 0..w {
                slots.push(idx as u16);
            }
        }

        let addrs_snapshot: Box<[SocketAddr]> = pools
            .iter()
            .flat_map(|(addrs, _)| addrs.iter().copied())
            .collect();

        let backends: Box<[BackendPool]> = pools
            .into_iter()
            .map(|(addrs, _)| BackendPool::new(addrs))
            .collect();

        Self {
            name,
            backends,
            slots: slots.into_boxed_slice(),
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot,
        }
    }

    fn empty(name: String) -> Self {
        Self {
            name,
            backends: Box::new([]),
            slots: Box::new([]),
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot: Box::new([]),
        }
    }

    /// Flat list of all pod addresses — used by the admin `/routes` endpoint.
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.addrs_snapshot
    }

    /// Returns the next endpoint using weighted round-robin.
    ///
    /// Returns `None` when there are no active endpoints.
    pub fn next_endpoint(&self) -> Option<SocketAddr> {
        if self.slots.is_empty() {
            return None;
        }
        let slot = self.slot_counter.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let pool = &self.backends[self.slots[slot] as usize];
        Some(pool.next())
    }
}

/// Reduce a slice of weights by their GCD so the slot array stays compact.
fn gcd_reduce(weights: &[u16]) -> Vec<u16> {
    let g = weights.iter().copied().fold(0u16, gcd);
    if g <= 1 {
        weights.to_vec()
    } else {
        weights.iter().map(|&w| w / g).collect()
    }
}

fn gcd(a: u16, b: u16) -> u16 {
    if b == 0 { a } else { gcd(b, a % b) }
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
    pub backend_group: Arc<BackendGroup>,
}

/// A path rule that was silently dropped because an earlier rule already claimed the same slot.
pub struct RouteConflict {
    /// Listener port on which the conflict occurred.
    pub port: u16,
    /// Host pattern where the conflict occurred (`"*"` for catch-all, `"*.example.com"` for wildcard).
    pub host: String,
    pub path: String,
    pub kind: RouteKind,
    /// `BackendGroup::name` of the rule that was rejected.
    pub rejected_group: String,
}

/// A single routing candidate: a backend group plus the predicates that must hold
/// for this candidate to be selected, along with metadata for precedence ordering.
pub struct RouteEntry {
    pub backend_group: Arc<BackendGroup>,
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
        backend_group: Arc<BackendGroup>,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            backend_group,
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
        backend_group: Arc<BackendGroup>,
        predicates: MatchPredicates,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            backend_group,
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
        backend_group: Arc<BackendGroup>,
        predicates: MatchPredicates,
        filters: Vec<FilterAction>,
        timeouts: RouteTimeouts,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            backend_group,
            predicates,
            filters: Arc::from(filters.into_boxed_slice()),
            timeouts,
            route_id,
            created_at,
            error_status: None,
        }
    }
}
