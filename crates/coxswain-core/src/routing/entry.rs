use crate::routing::predicate::MatchPredicates;
use std::any::Any;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

/// CA bundle source for upstream TLS verification (from `BackendTLSPolicy`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendCaSource {
    /// Use the platform's native root CA store (`wellKnownCACertificates: System`).
    System,
    /// PEM-encoded CA bundle from one or more ConfigMap refs (concatenated).
    Pem(Vec<u8>),
}

/// TLS configuration for a single backend pool, derived from an attached `BackendTLSPolicy`.
pub struct BackendTlsConfig {
    /// SNI hostname sent to the backend, and the name used for certificate verification.
    pub sni_hostname: String,
    /// CA bundle used to verify the backend's certificate.
    pub ca_source: BackendCaSource,
    /// Stable opaque key for Pingora connection-pool isolation.
    ///
    /// Pingora's `Hash for HttpPeer` does not include the `ca` field, so two policies with
    /// identical addr+SNI+verify flags but different CA bundles would share pooled connections.
    /// Setting `peer.group_key = cfg.group_key` ensures the pool keys them apart.
    pub group_key: u64,
    /// Lazily-parsed CA stack; initialised once on first proxy use, then reused for the
    /// lifetime of this `Arc`. Dropping the `Arc` drops the parsed stack with it.
    parsed: OnceLock<Arc<dyn Any + Send + Sync>>,
}

impl BackendTlsConfig {
    pub fn new(sni_hostname: String, ca_source: BackendCaSource, group_key: u64) -> Self {
        Self {
            sni_hostname,
            ca_source,
            group_key,
            parsed: OnceLock::new(),
        }
    }

    /// Get or initialise the parsed CA stack.  The closure is called at most once.
    pub fn parsed_or_init<F>(&self, init: F) -> &Arc<dyn Any + Send + Sync>
    where
        F: FnOnce() -> Arc<dyn Any + Send + Sync>,
    {
        self.parsed.get_or_init(init)
    }
}

impl std::fmt::Debug for BackendTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendTlsConfig")
            .field("sni_hostname", &self.sni_hostname)
            .field("ca_source", &self.ca_source)
            .field("group_key", &self.group_key)
            .finish_non_exhaustive()
    }
}

/// The result of a single `next_endpoint` call: the chosen pod address and the
/// optional per-pool TLS configuration that must be used to reach it.
pub struct Selection<'a> {
    pub addr: SocketAddr,
    pub tls_config: Option<&'a Arc<BackendTlsConfig>>,
}

/// Wire protocol spoken by a backend, derived from `Service.spec.ports[].appProtocol`
/// per [GEP-1911](https://gateway-api.sigs.k8s.io/geps/gep-1911/).
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

/// Parse a raw `appProtocol` string into a `BackendProtocol`.
///
/// Unknown or absent values map to `Http1` (the safe default).
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
    tls_config: Option<Arc<BackendTlsConfig>>,
}

impl BackendPool {
    fn new(addrs: Vec<SocketAddr>, tls_config: Option<Arc<BackendTlsConfig>>) -> Self {
        Self {
            addrs: addrs.into_boxed_slice(),
            rr: AtomicUsize::new(0),
            tls_config,
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
    /// Wire protocol for upstream connections, derived from `appProtocol`.
    protocol: BackendProtocol,
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
        let backends = Box::new([BackendPool::new(endpoints, None)]);
        Self {
            name,
            backends,
            slots,
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot,
            protocol: BackendProtocol::default(),
        }
    }

    /// Weighted constructor for multi-backend Gateway API rules.
    ///
    /// `weighted` is `[(pod_addrs, weight, tls_config), ...]` — one entry per `backendRef`.
    /// Backends with `weight == 0` or empty address lists are dropped.
    /// Returns an empty `BackendGroup` when all weights resolve to zero.
    pub fn weighted(
        name: String,
        weighted: Vec<(Vec<SocketAddr>, u16, Option<Arc<BackendTlsConfig>>)>,
    ) -> Self {
        let pools: Vec<(Vec<SocketAddr>, u16, Option<Arc<BackendTlsConfig>>)> = weighted
            .into_iter()
            .filter(|(addrs, w, _)| *w > 0 && !addrs.is_empty())
            .collect();

        if pools.is_empty() {
            return Self::empty(name);
        }

        let weights: Vec<u16> = pools.iter().map(|(_, w, _)| *w).collect();
        let reduced = gcd_reduce(&weights);

        let mut slots: Vec<u16> = Vec::with_capacity(reduced.iter().map(|&w| w as usize).sum());
        for (idx, &w) in reduced.iter().enumerate() {
            for _ in 0..w {
                slots.push(idx as u16);
            }
        }

        let addrs_snapshot: Box<[SocketAddr]> = pools
            .iter()
            .flat_map(|(addrs, _, _)| addrs.iter().copied())
            .collect();

        let backends: Box<[BackendPool]> = pools
            .into_iter()
            .map(|(addrs, _, tls)| BackendPool::new(addrs, tls))
            .collect();

        Self {
            name,
            backends,
            slots: slots.into_boxed_slice(),
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot,
            protocol: BackendProtocol::default(),
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
        }
    }

    /// Set the upstream transport protocol (builder-style).
    pub fn with_protocol(mut self, protocol: BackendProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set a single TLS config on all pools (builder-style).
    /// Used for single-backend routes; use the `weighted` constructor for per-pool configs.
    pub fn with_tls(mut self, tls: Arc<BackendTlsConfig>) -> Self {
        for pool in self.backends.iter_mut() {
            pool.tls_config = Some(Arc::clone(&tls));
        }
        self
    }

    /// Wire protocol for upstream connections.
    pub fn protocol(&self) -> BackendProtocol {
        self.protocol
    }

    /// Flat list of all pod addresses — used by the admin `/routes` endpoint.
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.addrs_snapshot
    }

    /// Returns the next endpoint using weighted round-robin, along with its TLS config.
    ///
    /// Returns `None` when there are no active endpoints.
    pub fn next_endpoint(&self) -> Option<Selection<'_>> {
        if self.slots.is_empty() {
            return None;
        }
        let slot = self.slot_counter.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let pool = &self.backends[self.slots[slot] as usize];
        Some(Selection {
            addr: pool.next(),
            tls_config: pool.tls_config.as_ref(),
        })
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

#[cfg(test)]
mod backend_protocol_tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(ip: &str, port: u16) -> SocketAddr {
        format!("{ip}:{port}").parse().unwrap()
    }

    fn tls_cfg(sni: &str) -> Arc<BackendTlsConfig> {
        Arc::new(BackendTlsConfig::new(
            sni.to_string(),
            BackendCaSource::System,
            42,
        ))
    }

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
    fn new_group_has_no_tls_by_default() {
        let addrs = vec![addr("10.0.0.1", 80)];
        let g = BackendGroup::new("ns/svc".to_string(), addrs);
        let sel = g.next_endpoint().unwrap();
        assert!(sel.tls_config.is_none());
    }

    #[test]
    fn with_tls_sets_config_on_single_pool() {
        let addrs = vec![addr("10.0.0.1", 443)];
        let cfg = tls_cfg("backend.example.com");
        let g = BackendGroup::new("ns/svc".to_string(), addrs).with_tls(Arc::clone(&cfg));
        let sel = g.next_endpoint().unwrap();
        let found = sel.tls_config.unwrap();
        assert_eq!(found.sni_hostname, "backend.example.com");
        assert_eq!(found.group_key, 42);
    }

    #[test]
    fn weighted_preserves_per_pool_tls_config() {
        let cfg_a = tls_cfg("a.example.com");
        let weighted = vec![
            (vec![addr("10.0.0.1", 443)], 1u16, Some(Arc::clone(&cfg_a))),
            (vec![addr("10.0.0.2", 80)], 1u16, None),
        ];
        let g = BackendGroup::weighted("ns/mixed".to_string(), weighted);
        // Collect 4 selections to cover both pools.
        let selections: Vec<_> = (0..4)
            .map(|_| {
                let s = g.next_endpoint().unwrap();
                (s.addr.port(), s.tls_config.is_some())
            })
            .collect();
        let has_tls = selections.iter().filter(|(_, tls)| *tls).count();
        let no_tls = selections.iter().filter(|(_, tls)| !tls).count();
        assert!(has_tls > 0, "at least one selection should have TLS");
        assert!(no_tls > 0, "at least one selection should have no TLS");
    }

    #[test]
    fn empty_group_returns_none_from_next_endpoint() {
        let g = BackendGroup::new("ns/empty".to_string(), vec![]);
        assert!(g.next_endpoint().is_none());
    }
}
