//! Route entry types: backend groups, filter actions, route timeouts, and path-rule metadata.

use crate::routing::predicate::MatchPredicates;
use http::{HeaderName, HeaderValue};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

/// CA certificate source for a [`BackendTLSPolicy`](https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1alpha3.BackendTLSPolicy) attachment.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum UpstreamCa {
    /// `wellKnownCACertificates: System` — use the OS trust store.
    System,
    /// `caCertificateRefs` — raw PEM bytes from the referenced ConfigMap.
    Bundle(Arc<[u8]>),
}

/// TLS configuration for upstream connections derived from a `BackendTLSPolicy` attachment.
///
/// When present on a [`BackendGroup`], the proxy overrides `appProtocol`-based TLS decisions
/// and uses these settings for every connection to that backend.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct UpstreamTls {
    /// Hostname used for SNI and certificate verification on the upstream connection.
    pub sni: Arc<str>,
    /// Certificate authority source for verifying the upstream cert.
    pub ca: UpstreamCa,
    /// Stable hash of `(sni, ca)` — folded into `HttpPeer.group_key` so distinct
    /// CA bundles never share a Pingora connection pool slot, and used as the cache
    /// key in the proxy-side parse cache.
    pub group_key: u64,
}

impl UpstreamTls {
    /// Construct an [`UpstreamTls`] from its components.
    pub fn new(sni: Arc<str>, ca: UpstreamCa, group_key: u64) -> Self {
        Self { sni, ca, group_key }
    }
}

/// Wire protocol spoken by a backend, derived from `Service.spec.ports[].appProtocol`
/// per [GEP-1911](https://gateway-api.sigs.k8s.io/geps/gep-1911/).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackendProtocol {
    /// Plain HTTP/1.1 — the default when `appProtocol` is absent or unrecognised.
    #[default]
    Http1,
    /// HTTP/2 cleartext (prior knowledge) — `kubernetes.io/h2c`.
    H2c,
    /// HTTP/1.1 with WebSocket upgrade — `kubernetes.io/ws`.
    WebSocket,
    /// HTTPS (TLS to upstream) — `https`.
    Https,
    /// WebSocket over TLS — `kubernetes.io/wss`.
    WebSocketTls,
}

impl BackendProtocol {
    /// Returns `true` for protocols that require TLS to the upstream.
    pub fn is_tls(self) -> bool {
        match self {
            Self::Https | Self::WebSocketTls => true,
            Self::Http1 | Self::H2c | Self::WebSocket => false,
        }
    }

    /// Returns `true` for protocols using HTTP/2 cleartext prior knowledge.
    pub fn is_h2(self) -> bool {
        match self {
            Self::H2c => true,
            Self::Http1 | Self::Https | Self::WebSocket | Self::WebSocketTls => false,
        }
    }
}

/// Parse a raw `appProtocol` string into a `BackendProtocol`.
///
/// Unknown or absent values map to `Http1` (the safe default).
#[must_use]
pub fn parse_app_protocol(raw: &str) -> BackendProtocol {
    match raw {
        "kubernetes.io/h2c" => BackendProtocol::H2c,
        "kubernetes.io/ws" => BackendProtocol::WebSocket,
        "kubernetes.io/wss" => BackendProtocol::WebSocketTls,
        "https" => BackendProtocol::Https,
        _ => BackendProtocol::Http1,
    }
}

/// One backend service's resolved pod endpoints with a round-robin counter.
struct BackendPool {
    addrs: Box<[SocketAddr]>,
    rr: AtomicUsize,
}

impl BackendPool {
    fn new(addrs: Vec<SocketAddr>) -> Self {
        assert!(
            !addrs.is_empty(),
            "BackendPool requires at least one address"
        );
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
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum PathModifier {
    /// Discard the entire original path and use this fixed value instead.
    ReplaceFullPath(String),
    /// Replace `prefix` with `replacement` in the matched request path.
    ReplacePrefixMatch {
        /// The path prefix to strip (as registered at route build time).
        prefix: String,
        /// The string to prepend in place of the stripped prefix.
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

/// Error produced when a header name or value is invalid at routing-table build time.
#[derive(Debug, thiserror::Error)]
pub enum HeaderModError {
    /// A header name string is not a valid HTTP token.
    #[error("invalid header name {name:?}: {source}")]
    InvalidName {
        /// The invalid header name string.
        name: String,
        /// The underlying parse error.
        #[source]
        source: http::header::InvalidHeaderName,
    },
    /// A header value string contains characters forbidden by RFC 7230.
    #[error("invalid header value for {name:?}: {source}")]
    InvalidValue {
        /// The header name the value was associated with.
        name: String,
        /// The underlying parse error.
        #[source]
        source: http::header::InvalidHeaderValue,
    },
}

/// Header add/set/remove operations applied as a unit.
///
/// Headers are pre-parsed at routing-table build time — no per-request
/// `HeaderName::from_bytes` / `HeaderValue::from_str` parsing on the hot path.
#[derive(Clone, Debug, Default)]
pub struct HeaderMod {
    /// Headers appended to any existing values.
    pub add: Vec<(HeaderName, HeaderValue)>,
    /// Headers overwritten (set).
    pub set: Vec<(HeaderName, HeaderValue)>,
    /// Header names removed entirely.
    pub remove: Vec<HeaderName>,
}

impl HeaderMod {
    /// Parse and validate raw string header pairs at build time.
    ///
    /// # Errors
    ///
    /// Returns `HeaderModError` if any name or value string is not a valid HTTP header.
    pub fn parse(
        add: &[(&str, &str)],
        set: &[(&str, &str)],
        remove: &[&str],
    ) -> Result<Self, HeaderModError> {
        let parse_pair = |name: &str,
                          value: &str|
         -> Result<(HeaderName, HeaderValue), HeaderModError> {
            let n = HeaderName::from_bytes(name.as_bytes()).map_err(|source| {
                HeaderModError::InvalidName {
                    name: name.to_string(),
                    source,
                }
            })?;
            let v =
                HeaderValue::from_str(value).map_err(|source| HeaderModError::InvalidValue {
                    name: name.to_string(),
                    source,
                })?;
            Ok((n, v))
        };
        let parse_name = |name: &str| -> Result<HeaderName, HeaderModError> {
            HeaderName::from_bytes(name.as_bytes()).map_err(|source| HeaderModError::InvalidName {
                name: name.to_string(),
                source,
            })
        };
        Ok(Self {
            add: add
                .iter()
                .map(|(n, v)| parse_pair(n, v))
                .collect::<Result<_, _>>()?,
            set: set
                .iter()
                .map(|(n, v)| parse_pair(n, v))
                .collect::<Result<_, _>>()?,
            remove: remove
                .iter()
                .map(|n| parse_name(n))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// A filter action evaluated per-request on the proxy hot path.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum FilterAction {
    /// Modify request headers before forwarding upstream.
    RequestHeaderModifier(HeaderMod),
    /// Modify response headers before returning to the client.
    ResponseHeaderModifier(HeaderMod),
    /// Return a 3xx redirect without connecting to the upstream.
    RequestRedirect {
        /// Override the `scheme` component of the redirect URL.
        scheme: Option<String>,
        /// Override the `host` component of the redirect URL.
        hostname: Option<String>,
        /// Override the port of the redirect URL.
        port: Option<u16>,
        /// HTTP status code (default 302).
        status_code: u16,
        /// Optional path rewrite applied to the redirect URL.
        path: Option<PathModifier>,
    },
    /// Rewrite the upstream request host and/or path (client-visible URL is unchanged).
    UrlRewrite {
        /// Replacement `Host` header for the upstream request.
        hostname: Option<String>,
        /// Path rewrite applied to the upstream request.
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

/// Per-backend filter slot: `None` for backends without filters (the common
/// case); `Some(Arc<[FilterAction]>)` shares the slice cheaply with each
/// request that selects this backend.
type PerBackendFilterSlot = Option<Arc<[FilterAction]>>;

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
    name: String,
    /// One entry per non-zero-weight backend ref.
    backends: Box<[BackendPool]>,
    /// Slot array: each entry is an index into `backends`.
    /// Length = Σ(weight_i after GCD reduction).
    slots: Box<[u16]>,
    /// Advances monotonically; taken mod `slots.len()` on each request.
    slot_counter: AtomicUsize,
    /// Flat snapshot of all pod addresses for the admin `/routes` endpoint.
    addrs_snapshot: Box<[SocketAddr]>,
    /// Wire protocol for upstream connections, derived from `appProtocol`.
    protocol: BackendProtocol,
    /// TLS configuration from an attached `BackendTLSPolicy`.
    /// When `Some`, the proxy uses these settings instead of `protocol`-derived defaults.
    tls: Option<Arc<UpstreamTls>>,
    /// Per-backend request filters from `HTTPRoute.spec.rules[].backendRefs[].filters`.
    /// Index-aligned with `backends`. `None` for the common case where no backend
    /// declares per-backend filters; when `Some`, each slot is `None` for backends
    /// without filters and `Some(filters)` otherwise. Applied AFTER rule-level
    /// filters in the proxy's `upstream_request_filter` hook.
    per_backend_filters: Option<Box<[PerBackendFilterSlot]>>,
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
            protocol: BackendProtocol::default(),
            tls: None,
            per_backend_filters: None,
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
            protocol: BackendProtocol::default(),
            tls: None,
            per_backend_filters: None,
        }
    }

    fn empty(name: String) -> Self {
        Self {
            name,
            backends: Box::new([]),
            slots: Box::new([]),
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot: Box::new([]),
            protocol: BackendProtocol::default(),
            tls: None,
            per_backend_filters: None,
        }
    }

    /// Set the upstream transport protocol (builder-style).
    pub fn with_protocol(mut self, protocol: BackendProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Attach a `BackendTLSPolicy`-derived TLS configuration (builder-style).
    ///
    /// When set, the proxy uses `tls.sni` for SNI and `tls.ca` for upstream cert
    /// verification, overriding `appProtocol`-based TLS defaults.
    pub fn with_tls(mut self, tls: Arc<UpstreamTls>) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Attach per-backend `RequestHeaderModifier` filter actions (builder-style).
    ///
    /// `per_backend` is index-aligned with the constructor's backendRefs list — one
    /// entry per non-zero-weight backend ref. An empty `Vec<FilterAction>` for a
    /// backend is normalised to `None` so the proxy can short-circuit the common
    /// no-filter case. Constructor side-effects:
    /// - When every entry normalises to `None`, the whole `per_backend_filters`
    ///   field stays `None` (no allocation, no proxy-side overhead).
    /// - When at least one entry is non-empty, the full per-backend slice is
    ///   stored so `next_endpoint_with_filters` can return it.
    ///
    /// Length of `per_backend` MUST match `self.backends.len()` — supplied by the
    /// reconciler from the same `weighted` list that built the backend pools.
    /// Mismatch panics in debug builds and is silently ignored in release.
    #[must_use]
    pub fn with_per_backend_filters(mut self, per_backend: Vec<Vec<FilterAction>>) -> Self {
        debug_assert_eq!(
            per_backend.len(),
            self.backends.len(),
            "per-backend filter list must match the number of pooled backends"
        );
        if per_backend.len() != self.backends.len() {
            return self;
        }
        let any_set = per_backend.iter().any(|f| !f.is_empty());
        if !any_set {
            self.per_backend_filters = None;
            return self;
        }
        let normalised: Box<[Option<Arc<[FilterAction]>>]> = per_backend
            .into_iter()
            .map(|f| {
                if f.is_empty() {
                    None
                } else {
                    Some(Arc::from(f.into_boxed_slice()))
                }
            })
            .collect();
        self.per_backend_filters = Some(normalised);
        self
    }

    /// Service identity used for logging.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wire protocol for upstream connections.
    pub fn protocol(&self) -> BackendProtocol {
        self.protocol
    }

    /// TLS configuration from an attached `BackendTLSPolicy`, if any.
    pub fn upstream_tls(&self) -> Option<&Arc<UpstreamTls>> {
        self.tls.as_ref()
    }

    /// Flat list of all pod addresses — used by the admin `/routes` endpoint.
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.addrs_snapshot
    }

    /// Returns the next endpoint using weighted round-robin.
    ///
    /// Returns `None` when there are no active endpoints.
    #[must_use]
    pub fn next_endpoint(&self) -> Option<SocketAddr> {
        self.next_endpoint_with_filters().map(|(addr, _)| addr)
    }

    /// Returns the next endpoint AND any per-backend filters attached to that
    /// specific backend ref.
    ///
    /// The filter slice is `None` when no per-backend filters were configured for
    /// the rule (the common case — single round-robin tick, no extra indirection)
    /// OR when the specific backend that won this round has no filters of its own.
    /// The proxy applies the returned filters in `upstream_request_filter` after
    /// the rule-level filters from `RouteEntry::filters`.
    #[must_use]
    pub fn next_endpoint_with_filters(&self) -> Option<(SocketAddr, Option<Arc<[FilterAction]>>)> {
        if self.slots.is_empty() {
            return None;
        }
        let slot = self.slot_counter.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let backend_idx = self.slots[slot] as usize;
        let pool = &self.backends[backend_idx];
        let filters = self
            .per_backend_filters
            .as_ref()
            .and_then(|all| all.get(backend_idx).cloned().flatten());
        Some((pool.next(), filters))
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
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// Exact path match (must equal the request path character for character).
    Exact,
    /// Prefix path match (request path must start with the registered prefix).
    Prefix,
    /// Regular-expression path match.
    Regex,
}

impl RouteKind {
    /// Returns the lowercase string representation used in admin API responses.
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
    /// Registered path string (exact, prefix, or regex).
    pub path: String,
    /// How the path is matched.
    pub kind: RouteKind,
    /// Backend group selected when this rule matches.
    pub backend_group: Arc<BackendGroup>,
}

/// A path rule that was silently dropped because an earlier rule already claimed the same slot.
pub struct RouteConflict {
    /// Listener port on which the conflict occurred.
    pub port: u16,
    /// Host pattern where the conflict occurred (`"*"` for catch-all, `"*.example.com"` for wildcard).
    pub host: String,
    /// Path string of the conflicting rule.
    pub path: String,
    /// Match kind of the conflicting rule.
    pub kind: RouteKind,
    /// [`BackendGroup::name`] of the rule that was rejected.
    pub rejected_group: String,
}

/// A single routing candidate: a backend group plus the predicates that must hold
/// for this candidate to be selected, along with metadata for precedence ordering.
pub struct RouteEntry {
    /// Backend group to forward matching requests to.
    pub backend_group: Arc<BackendGroup>,
    /// Method, header, and query predicates that must all pass for this rule to fire.
    pub predicates: MatchPredicates,
    /// Filter actions applied to the request/response when this rule matches.
    pub filters: Arc<[FilterAction]>,
    /// Per-rule timeout overrides.
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

    /// Constructs a redirect-only entry that has no upstream backend.
    ///
    /// Use for `RequestRedirect` filter rules: the proxy fires the redirect before
    /// consulting any upstream, so no `BackendGroup` is needed. The `/routes` admin
    /// endpoint skips these entries (they have no endpoints).
    pub fn redirect_only(
        predicates: MatchPredicates,
        filters: Vec<FilterAction>,
        timeouts: RouteTimeouts,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            backend_group: Arc::new(BackendGroup::new(String::new(), vec![])),
            predicates,
            filters: Arc::from(filters.into_boxed_slice()),
            timeouts,
            route_id,
            created_at,
            error_status: None,
        }
    }

    /// Returns `true` for redirect-only entries that carry no upstream backend.
    pub fn is_redirect_only(&self) -> bool {
        self.backend_group.name().is_empty()
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

// Lock the hot-path RouteEntry and BackendPool sizes to catch accidental growth.
// Update the constant when a deliberate layout change is made.
static_assertions::assert_eq_size!(RouteEntry, [u8; 176]);
// Hot type — review with the team before bumping this number.
static_assertions::assert_eq_size!(BackendPool, [u8; 24]);
