//! Route entry types: backend groups, filter actions, route timeouts, and path-rule metadata.

use super::predicate::MatchPredicates;
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
    #[must_use]
    pub fn is_tls(self) -> bool {
        match self {
            Self::Https | Self::WebSocketTls => true,
            Self::Http1 | Self::H2c | Self::WebSocket => false,
        }
    }

    /// Returns `true` for protocols using HTTP/2 cleartext prior knowledge.
    #[must_use]
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
    /// Expand regex capture groups into a replacement template.
    ///
    /// Backs the Ingress `use-regex` + `rewrite-target` pairing: the request path is
    /// matched against this route's own `ImplementationSpecific` pattern and `$1`…`$n`
    /// references in the template are substituted from the captures. Because the
    /// pattern is the route's own, capture substitution is intrinsically per-path even
    /// though the `rewrite-target` template is Ingress-scoped.
    RegexReplace {
        /// The route's compiled path regex, compiled once at reconcile and shared
        /// (`Arc`) — never recompiled per request.
        regex: Arc<regex::Regex>,
        /// The replacement template, e.g. `/$2`. Missing groups expand to empty.
        replacement: Box<str>,
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
            PathModifier::RegexReplace { regex, replacement } => {
                // The route was already selected by an `is_match` against the same
                // pattern, so `captures` normally succeeds; fall back to the
                // unchanged path defensively rather than panicking if it does not.
                match regex.captures(path) {
                    Some(caps) => {
                        let mut out = String::new();
                        caps.expand(replacement, &mut out);
                        out
                    }
                    None => path.to_string(),
                }
            }
        }
    }
}

/// Error produced when a header name or value is invalid at routing-table build time.
#[non_exhaustive]
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
#[non_exhaustive]
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

/// Per-rule timeout configuration.
///
/// `request` / `backend_request` are parsed from `HTTPRouteRule.timeouts` (Gateway
/// API). `connect` / `read` / `send` are parsed from the Ingress
/// `ingress.coxswain-labs.dev/{connect,read,send}-timeout` annotations and map to the
/// upstream TCP-connect, response-read, and request-send phases respectively.
// intentionally open: field-literal constructed in crates/coxswain-reflector (gateway_api/timeouts.rs and ingress/annotations.rs) and merged in crates/coxswain-proxy/src/common/outcome.rs.
#[derive(Clone, Debug, Default)]
pub struct RouteTimeouts {
    /// Total request timeout (client → proxy → upstream → proxy → client). 504 on expiry.
    pub request: Option<Duration>,
    /// Upstream-only timeout (proxy → upstream response). 502 on expiry.
    pub backend_request: Option<Duration>,
    /// Upstream TCP-connect timeout (`ingress.coxswain-labs.dev/connect-timeout`).
    pub connect: Option<Duration>,
    /// Upstream response-read timeout (`ingress.coxswain-labs.dev/read-timeout`).
    pub read: Option<Duration>,
    /// Upstream request-send timeout (`ingress.coxswain-labs.dev/send-timeout`).
    pub send: Option<Duration>,
}

/// Conditions under which the proxy retries an upstream attempt, as a compact
/// bitset parsed from the `ingress.coxswain-labs.dev/retry-on` annotation.
///
/// Kept `Copy` and allocation-free so a [`RetryPolicy`] adds no heap overhead to
/// the hot [`BackendGroup`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetryOn(u8);

impl RetryOn {
    /// Retry when the upstream TCP connection cannot be established (`connect-failure`).
    pub const CONNECT_FAILURE: Self = Self(0b001);
    /// Retry when establishing the upstream connection times out (`timeout`).
    pub const TIMEOUT: Self = Self(0b010);
    /// Retry when the upstream returns a 5xx response (`5xx`).
    pub const HTTP_5XX: Self = Self(0b100);

    /// The empty set — no conditions.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// `true` when no retry conditions are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// `true` when every bit in `other` is also set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Add the conditions in `other` to this set (in place).
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl std::ops::BitOr for RetryOn {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Per-route upstream retry policy parsed from the Ingress `max-retries` and
/// `retry-on` annotations.
///
/// Carried on [`BackendGroup`] (alongside `protocol`/`tls`) because retrying is an
/// upstream-connection concern; the proxy reads it in `fail_to_connect` and
/// `upstream_response_filter`. A default `RetryPolicy` (`max_retries == 0` or an
/// empty [`RetryOn`]) disables retries entirely.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum number of retries after the initial attempt.
    pub max_retries: u32,
    /// Conditions that trigger a retry.
    pub on: RetryOn,
}

impl RetryPolicy {
    /// Construct a retry policy from a max-retry count and a condition set.
    #[must_use]
    pub fn new(max_retries: u32, on: RetryOn) -> Self {
        Self { max_retries, on }
    }

    /// `true` when this policy will never retry (no budget or no conditions).
    #[must_use]
    pub fn is_disabled(self) -> bool {
        self.max_retries == 0 || self.on.is_empty()
    }
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
#[non_exhaustive]
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
    /// Flat snapshot of all pod addresses for the admin `/api/v1/routes` endpoint.
    addrs_snapshot: Box<[SocketAddr]>,
    /// Wire protocol for upstream connections, derived from `appProtocol`.
    protocol: BackendProtocol,
    /// TLS configuration from an attached `BackendTLSPolicy`.
    /// When `Some`, the proxy uses these settings instead of `protocol`-derived defaults.
    tls: Option<Arc<UpstreamTls>>,
    /// Upstream retry policy from the Ingress `max-retries` / `retry-on` annotations.
    /// Default (disabled) for Gateway API routes and Ingresses without the annotations.
    retry: RetryPolicy,
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
            retry: RetryPolicy::default(),
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
            retry: RetryPolicy::default(),
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
            retry: RetryPolicy::default(),
            per_backend_filters: None,
        }
    }

    /// Set the upstream transport protocol (builder-style).
    #[must_use]
    pub fn with_protocol(mut self, protocol: BackendProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Attach a `BackendTLSPolicy`-derived TLS configuration (builder-style).
    ///
    /// When set, the proxy uses `tls.sni` for SNI and `tls.ca` for upstream cert
    /// verification, overriding `appProtocol`-based TLS defaults.
    #[must_use]
    pub fn with_tls(mut self, tls: Arc<UpstreamTls>) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Attach an upstream retry policy (builder-style).
    ///
    /// Parsed from the Ingress `ingress.coxswain-labs.dev/max-retries` and
    /// `ingress.coxswain-labs.dev/retry-on` annotations. Gateway API routes and
    /// Ingresses without the annotations leave this as the default (disabled) policy.
    #[must_use]
    pub fn with_retries(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
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

    /// Upstream retry policy for this backend group.
    ///
    /// Returns the default (disabled) policy for Gateway API routes and
    /// Ingresses that do not carry the `ingress.coxswain-labs.dev/max-retries` /
    /// `retry-on` annotations.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// Flat list of all pod addresses — used by the admin `/api/v1/routes` endpoint.
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
#[non_exhaustive]
pub struct RouteInfo {
    /// Registered path string (exact, prefix, or regex).
    pub path: String,
    /// How the path is matched.
    pub kind: RouteKind,
    /// Backend group selected when this rule matches.
    pub backend_group: Arc<BackendGroup>,
    /// Source resource identity `"{namespace}/{name}"` of the Ingress/HTTPRoute
    /// that produced this rule. Carried through so the operator UI can deep-link
    /// a compiled row back to its originating resource in the Route Inspector.
    pub route_id: String,
}

/// A path rule that was silently dropped because an earlier rule already claimed the same slot.
#[non_exhaustive]
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
    /// Source resource identity `"{namespace}/{name}"` of the rejected (shadowed)
    /// route, mirroring [`RouteEntry::route_id`]. Lets the operator UI deep-link a
    /// conflict back to the route that was silently dropped. When a shadowed path
    /// group holds several distinct routes, this is the representative
    /// (highest-precedence) one — see `HostRouterBuilder::build`.
    pub rejected_route_id: String,
}

/// A single routing candidate: a backend group plus the predicates that must hold
/// for this candidate to be selected, along with metadata for precedence ordering.
#[non_exhaustive]
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
    /// Canonical rule identifier used as the `route` label on Prometheus metrics
    /// and as the `route_id` field on access-log lines.
    ///
    /// Format: `httproute/<ns>/<name>:<rule_index>` for HTTPRoute rules,
    /// `ingress/<ns>/<name>:<r>.<p>` for Ingress rule/path pairs, and
    /// `ingress/<ns>/<name>:default` for `spec.defaultBackend`. Shared as an
    /// `Arc<str>` so propagating it through `ResolvedRoute` and into hooks is a
    /// refcount bump, not a heap allocation.
    pub metric_route_id: Arc<str>,
    /// Creation timestamp — older routes win ties after predicate-count comparison.
    /// `None` sorts last.
    pub created_at: Option<SystemTime>,
    /// When `Some`, the proxy returns this status code immediately without contacting upstream.
    /// Used for routes with invalid/missing/forbidden backend refs (Gateway API §4.3.4).
    pub error_status: Option<u16>,
    /// Registered path pattern (exact value, prefix, or regex) for this rule.
    ///
    /// Shared as an `Arc<str>` so the access-log `pattern` mode can emit the rule
    /// pattern instead of the concrete request path without a per-request allocation.
    pub path_pattern: Arc<str>,
    /// Per-route request body size limit in bytes, from the
    /// `ingress.coxswain-labs.dev/max-body-size` annotation.
    ///
    /// `Some(n)` rejects requests whose body exceeds `n` bytes with 413 Payload Too
    /// Large — checked up front from `Content-Length` and enforced mid-stream for
    /// chunked bodies. `None` (the default, and the value for all Gateway-API routes)
    /// imposes no limit.
    pub max_body_size: Option<u64>,
    /// IP allow-list (CIDR ranges) from the
    /// `ingress.coxswain-labs.dev/allow-source-range` annotation.
    ///
    /// `Some(nets)` restricts the rule to requests whose real client IP matches at
    /// least one CIDR; clients outside every range are rejected with 403 Forbidden.
    /// `None` (the default, and the value for all Gateway-API routes) admits all
    /// source IPs. Shared as an `Arc` so cloning into the lookup result is a
    /// refcount bump, not a heap copy, on the hot path.
    pub allow_source_range: Option<Arc<Vec<ipnet::IpNet>>>,
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
            metric_route_id: Arc::from(""),
            created_at,
            error_status: None,
            path_pattern: Arc::from(""),
            max_body_size: None,
            allow_source_range: None,
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
            metric_route_id: Arc::from(""),
            created_at,
            error_status: None,
            path_pattern: Arc::from(""),
            max_body_size: None,
            allow_source_range: None,
        }
    }

    /// Constructs a redirect-only entry that has no upstream backend.
    ///
    /// Use for `RequestRedirect` filter rules: the proxy fires the redirect before
    /// consulting any upstream, so no `BackendGroup` is needed. The `/api/v1/routes` admin
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
            metric_route_id: Arc::from(""),
            created_at,
            error_status: None,
            path_pattern: Arc::from(""),
            max_body_size: None,
            allow_source_range: None,
        }
    }

    /// Returns `true` for redirect-only entries that carry no upstream backend.
    #[must_use]
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
            metric_route_id: Arc::from(""),
            created_at,
            error_status: None,
            path_pattern: Arc::from(""),
            max_body_size: None,
            allow_source_range: None,
        }
    }

    /// Set the path pattern this entry was registered under (builder-style).
    ///
    /// Call this immediately after construction, before wrapping in `Arc`, so
    /// the access-log `pattern` mode can emit the rule pattern instead of the
    /// concrete request path.
    #[must_use]
    pub fn with_path_pattern(mut self, pattern: Arc<str>) -> Self {
        self.path_pattern = pattern;
        self
    }

    /// Set the canonical metric/log identifier for this rule (builder-style).
    ///
    /// Call this immediately after construction in every production reconcile
    /// path so the proxy can emit `coxswain_proxy_requests_total{route="…"}`
    /// and the access log carries a matching `route_id` field. Test fixtures
    /// without metric assertions can omit this call — the default empty string
    /// is harmless but produces unlabelled metric series.
    #[must_use]
    pub fn with_metric_route_id(mut self, id: Arc<str>) -> Self {
        self.metric_route_id = id;
        self
    }

    /// Set per-rule timeout overrides (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the timeouts parsed from
    /// `ingress.coxswain-labs.dev/{connect,read,send}-timeout` annotations
    /// without switching to the heavier [`Self::with_filters`] constructor.
    #[must_use]
    pub fn with_timeouts(mut self, timeouts: RouteTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Append filter actions (builder-style).
    ///
    /// Replaces any existing filter list.  Used by the Ingress reconciler to
    /// attach a `rewrite-target`-derived [`FilterAction::UrlRewrite`] without
    /// switching from `path_only` to the heavier `with_filters` constructor
    /// when no other constructor-level parameters change.
    #[must_use]
    pub fn with_filter_actions(mut self, filters: Vec<FilterAction>) -> Self {
        self.filters = Arc::from(filters.into_boxed_slice());
        self
    }

    /// Set the per-route request body size limit in bytes (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the limit parsed from the
    /// `ingress.coxswain-labs.dev/max-body-size` annotation. `None` leaves the
    /// route unlimited (the default).
    #[must_use]
    pub fn with_max_body_size(mut self, max_body_size: Option<u64>) -> Self {
        self.max_body_size = max_body_size;
        self
    }

    /// Set the source-IP allow-list for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the CIDR set parsed from the
    /// `ingress.coxswain-labs.dev/allow-source-range` annotation. `None` admits
    /// all source IPs (the default). The reconciler shares one `Arc` across every
    /// path of an Ingress, so cloning it onto each entry is a refcount bump.
    #[must_use]
    pub fn with_allow_source_range(
        mut self,
        allow_source_range: Option<Arc<Vec<ipnet::IpNet>>>,
    ) -> Self {
        self.allow_source_range = allow_source_range;
        self
    }
}

// Lock the hot-path RouteEntry and BackendPool sizes to catch accidental growth.
// Update the constant when a deliberate layout change is made.
// Bumped 176→192 by adding path_pattern: Arc<str> (16 bytes) for access-log pattern mode.
// Bumped 192→208 by adding metric_route_id: Arc<str> (16 bytes) for Prometheus `route` label and access-log `route_id` join key.
// Bumped 208→256 by extending RouteTimeouts with connect/read/send: 3 × Option<Duration> (48 bytes) for Ingress annotation timeouts.
// Bumped 256→272 by adding max_body_size: Option<u64> (16 bytes) for the ingress.coxswain-labs.dev/max-body-size request-body limit.
// Bumped 272→280 by adding allow_source_range: Option<Arc<Vec<IpNet>>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/allow-source-range IP allow-list.
static_assertions::assert_eq_size!(RouteEntry, [u8; 280]);
// Hot type — review with the team before bumping this number.
static_assertions::assert_eq_size!(BackendPool, [u8; 24]);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // ── PathModifier::RegexReplace ────────────────────────────────────────────────

    fn regex_replace(pattern: &str, template: &str) -> PathModifier {
        PathModifier::RegexReplace {
            regex: Arc::new(regex::Regex::new(pattern).expect("test pattern compiles")),
            replacement: template.into(),
        }
    }

    #[test]
    fn regex_replace_expands_capture_groups() {
        // The canonical nginx pattern: capture the tail and rewrite the upstream path.
        let pm = regex_replace(r"^/something(/|$)(.*)", "/$2");
        assert_eq!(pm.apply("/something/foo/bar"), "/foo/bar");
        assert_eq!(pm.apply("/something/"), "/");
    }

    #[test]
    fn regex_replace_missing_group_expands_empty() {
        // `$3` has no corresponding group → expands to empty, matching the regex crate.
        let pm = regex_replace(r"^/api/(.*)", "/v2/$1$3");
        assert_eq!(pm.apply("/api/users"), "/v2/users");
    }

    #[test]
    fn regex_replace_no_match_falls_back_to_path() {
        // Defensive: `apply` is only reached after `is_match` selected the route, but a
        // non-matching path must not panic — it returns unchanged.
        let pm = regex_replace(r"^/api/(\d+)$", "/n/$1");
        assert_eq!(pm.apply("/api/abc"), "/api/abc");
    }

    // ── BackendGroup round-robin tests ────────────────────────────────────────────

    #[test]
    fn round_robin_cycles() {
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            "10.0.0.3:80".parse().unwrap(),
        ];
        let up = BackendGroup::new("svc".to_string(), addrs.clone());
        let results: Vec<SocketAddr> = (0..6).map(|_| up.next_endpoint().unwrap()).collect();
        assert_eq!(
            results,
            [addrs[0], addrs[1], addrs[2], addrs[0], addrs[1], addrs[2]]
        );
    }

    #[test]
    fn weighted_round_robin_distributes_proportionally() {
        let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:80".parse().unwrap();
        let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

        // Backend A: 2 pods, weight 4.  Backend B: 1 pod, weight 1.
        // Expected: P(A) = 4/5 = 80%.
        let up =
            BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1, a2], 4), (vec![b1], 1)]);

        let n = 1000;
        let mut a_count = 0usize;
        let mut b_count = 0usize;
        for _ in 0..n {
            let addr = up.next_endpoint().unwrap();
            if addr == a1 || addr == a2 {
                a_count += 1;
            } else if addr == b1 {
                b_count += 1;
            }
        }
        assert_eq!(a_count + b_count, n);
        // Allow ±5% tolerance around the expected 80/20 split.
        let a_ratio = a_count as f64 / n as f64;
        assert!(
            (0.75..=0.85).contains(&a_ratio),
            "backend A ratio {a_ratio:.2} out of expected 0.75–0.85"
        );
    }

    #[test]
    fn weighted_zero_weight_backend_gets_no_traffic() {
        let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

        let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 0), (vec![b1], 1)]);
        for _ in 0..100 {
            assert_eq!(up.next_endpoint().unwrap(), b1);
        }
    }

    #[test]
    fn weighted_all_zero_is_empty() {
        let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 0)]);
        assert!(up.next_endpoint().is_none());
    }

    #[test]
    fn weighted_equal_weights_uniform() {
        let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

        // Equal weights → after GCD reduction both get 1 slot → 50/50.
        let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 5), (vec![b1], 5)]);
        let results: Vec<SocketAddr> = (0..4).map(|_| up.next_endpoint().unwrap()).collect();
        // slots = [0, 1] after reduction; cycling: a1, b1, a1, b1
        assert_eq!(results, [a1, b1, a1, b1]);
    }

    // ── BackendProtocol / parse_app_protocol tests ────────────────────────────────

    #[test]
    fn parse_app_protocol_known_values() {
        assert_eq!(
            parse_app_protocol("kubernetes.io/h2c"),
            BackendProtocol::H2c
        );
        assert_eq!(
            parse_app_protocol("kubernetes.io/ws"),
            BackendProtocol::WebSocket
        );
        assert_eq!(
            parse_app_protocol("kubernetes.io/wss"),
            BackendProtocol::WebSocketTls
        );
        assert_eq!(parse_app_protocol("https"), BackendProtocol::Https);
    }

    #[test]
    fn parse_app_protocol_defaults_to_http1() {
        assert_eq!(parse_app_protocol(""), BackendProtocol::Http1);
        assert_eq!(parse_app_protocol("http"), BackendProtocol::Http1);
        assert_eq!(
            parse_app_protocol("example.com/custom"),
            BackendProtocol::Http1
        );
    }

    // ── UpstreamTls / with_tls round-trip tests ───────────────────────────────────

    #[test]
    fn backend_group_with_tls_system_round_trip() {
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let sni: Arc<str> = Arc::from("backend.example.com");
        let tls = Arc::new(UpstreamTls::new(sni.clone(), UpstreamCa::System, 42));
        let group = BackendGroup::new("svc".to_string(), vec![addr]).with_tls(Arc::clone(&tls));

        let got = group.upstream_tls().expect("TLS should be attached");
        assert_eq!(&*got.sni, "backend.example.com");
        assert_eq!(got.group_key, 42);
        assert!(matches!(got.ca, UpstreamCa::System));
    }

    #[test]
    fn backend_group_with_tls_bundle_round_trip() {
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let pem: Arc<[u8]> = Arc::from(b"-----BEGIN CERTIFICATE-----\nfake\n".as_slice());
        let tls = Arc::new(UpstreamTls::new(
            Arc::from("backend.example.com"),
            UpstreamCa::Bundle(Arc::clone(&pem)),
            99,
        ));
        let group = BackendGroup::new("svc".to_string(), vec![addr]).with_tls(Arc::clone(&tls));

        let got = group.upstream_tls().expect("TLS should be attached");
        assert!(matches!(&got.ca, UpstreamCa::Bundle(p) if p.as_ref() == pem.as_ref()));
    }

    #[test]
    fn backend_group_without_tls_returns_none() {
        let addr: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let group = BackendGroup::new("svc".to_string(), vec![addr]);
        assert!(group.upstream_tls().is_none());
    }

    #[test]
    fn upstream_tls_size_unchanged() {
        // BackendGroup now has one extra Option<Arc<UpstreamTls>> = 8 bytes;
        // but RouteEntry holds Arc<BackendGroup>, so RouteEntry size is unaffected.
        // Bumped 176→192: path_pattern: Arc<str> added for access-log pattern mode.
        // Bumped 192→208: metric_route_id: Arc<str> added for Prometheus `route` label.
        // Bumped 208→256: RouteTimeouts gained connect/read/send: 3×Option<Duration>.
        // Bumped 256→272: max_body_size: Option<u64> added for the max-body-size limit.
        // Bumped 272→280: allow_source_range: Option<Arc<Vec<IpNet>>> added for the allow-source-range IP allow-list.
        static_assertions::assert_eq_size!(RouteEntry, [u8; 280]);
    }

    #[test]
    fn upstream_with_protocol_round_trips() {
        let u = BackendGroup::new("ns/svc".to_string(), vec![]).with_protocol(BackendProtocol::H2c);
        assert_eq!(u.protocol(), BackendProtocol::H2c);
    }

    #[test]
    fn upstream_default_protocol_is_http1() {
        let u = BackendGroup::new("ns/svc".to_string(), vec![]);
        assert_eq!(u.protocol(), BackendProtocol::Http1);
    }

    #[test]
    fn with_allow_source_range_round_trips() {
        let group = Arc::new(BackendGroup::new("ns/svc".to_string(), vec![]));
        let bare = RouteEntry::path_only(Arc::clone(&group), "ns/r".to_string(), None);
        assert!(bare.allow_source_range.is_none());

        let nets = Arc::new(vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]);
        let entry = RouteEntry::path_only(group, "ns/r".to_string(), None)
            .with_allow_source_range(Some(Arc::clone(&nets)));
        assert_eq!(entry.allow_source_range.as_deref(), Some(&*nets));
    }

    #[test]
    fn per_backend_filters_returned_with_selected_backend() {
        use crate::routing::{FilterAction, HeaderMod};
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:80".parse().unwrap();
        let hm_a = HeaderMod::parse(&[("x-backend", "a")], &[], &[]).unwrap();
        let hm_b = HeaderMod::parse(&[("x-backend", "b")], &[], &[]).unwrap();
        let group = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a], 1), (vec![b], 1)])
            .with_per_backend_filters(vec![
                vec![FilterAction::RequestHeaderModifier(hm_a)],
                vec![FilterAction::RequestHeaderModifier(hm_b)],
            ]);
        // Round-robin between the two equally-weighted backends. Every endpoint we
        // pick should carry the matching per-backend filter slice.
        let mut saw_a = false;
        let mut saw_b = false;
        for _ in 0..10 {
            let (addr, filters) = group.next_endpoint_with_filters().unwrap();
            let filters = filters.expect("per-backend filter slice must be attached");
            assert_eq!(filters.len(), 1);
            let expected_value = if addr == a { "a" } else { "b" };
            match &filters[0] {
                FilterAction::RequestHeaderModifier(hm) => {
                    let entry = hm
                        .add
                        .iter()
                        .find(|(name, _)| name == "x-backend")
                        .expect("x-backend header must be present");
                    assert_eq!(entry.1, expected_value);
                }
                other => panic!("unexpected filter action: {other:?}"),
            }
            saw_a |= addr == a;
            saw_b |= addr == b;
        }
        assert!(saw_a && saw_b, "both backends should have been selected");
    }

    #[test]
    fn per_backend_filters_all_empty_normalises_to_none() {
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let group = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a], 1)])
            .with_per_backend_filters(vec![vec![]]);
        let (_addr, filters) = group.next_endpoint_with_filters().unwrap();
        assert!(
            filters.is_none(),
            "empty per-backend filters must surface as None"
        );
    }

    #[test]
    fn next_endpoint_without_per_backend_filters_returns_none() {
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let group = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a], 1)]);
        let (_addr, filters) = group.next_endpoint_with_filters().unwrap();
        assert!(filters.is_none());
    }
}
