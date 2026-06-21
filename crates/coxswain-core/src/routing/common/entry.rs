//! Route entry types: filter actions, route timeouts, and path-rule metadata.
//!
//! The upstream backend-selection / load-balancing concern (the
//! [`BackendGroup`](super::backend::BackendGroup) that each route entry carries)
//! lives in the sibling [`super::backend`] module.

use super::auth::IngressAuthConfig;
use super::backend::BackendGroup;
use super::circuit_breaker::CircuitBreakerConfig;
use super::compression::CompressionConfig;
use super::predicate::MatchPredicates;
use super::rate_limit::RateLimitConfig;
use http::{HeaderName, HeaderValue};
use std::sync::Arc;
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
    #[must_use = "the parsed HeaderMod is the result; dropping it discards the validated filter"]
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
    /// Mirror the matched request, fire-and-forget, to a secondary backend.
    ///
    /// The primary request is unaffected by the mirror outcome; the mirror response is
    /// discarded entirely. The backend is resolved to pod endpoints at reconcile time so
    /// the hot path performs no per-request resolution. Shared with the HTTPRoute
    /// `HTTPRequestMirrorFilter` surface (#261).
    ///
    /// Ingress surface: `ingress.coxswain-labs.dev/mirror-target` (#283).
    Mirror {
        /// Pre-resolved mirror backend (round-robins to a concrete endpoint at dispatch time).
        backend: Arc<BackendGroup>,
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
    /// Source resource identity `"{namespace}/{name}"` of the winning route that
    /// claimed this slot. Surfaces in controller Warning Events so operators know
    /// which Ingress took precedence over theirs.
    pub winner_route_id: String,
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
    /// Source-IP block list from the
    /// `ingress.coxswain-labs.dev/deny-source-range` annotation.
    ///
    /// `Some(nets)` rejects any request whose real client IP falls inside any
    /// listed CIDR with 403 Forbidden, **regardless of `allow_source_range`**
    /// (deny is evaluated first). `None` (the default) blocks nothing.
    /// Shared as an `Arc` for the same zero-copy-on-hot-path reason as
    /// `allow_source_range`. A `None` client IP is *not* denied — a block list
    /// only acts on IPs it can positively attribute to a listed range.
    pub deny_source_range: Option<Arc<Vec<ipnet::IpNet>>>,
    /// RFC 7234 response caching opt-in, from the
    /// `ingress.coxswain-labs.dev/cache-enabled` annotation.
    ///
    /// When `true`, the proxy enables its response cache for `GET`/`HEAD`
    /// requests on this route (subject to RFC 7234 cacheability and the
    /// `Authorization`/`Cookie` bypass). `false` (the default, and the value for
    /// all Gateway-API routes until the ExtensionRef binding lands) disables it.
    pub cache_enabled: bool,
    /// Per-class access-log override from `CoxswainIngressClassParameters.spec.accessLog`.
    ///
    /// `None` (the default, and the value for all Gateway-API routes) means the
    /// proxy's global `--access-log` flag governs. `Some(false)` suppresses
    /// the `coxswain_proxy::access` log line for every request on this route
    /// while leaving error logs and metrics unaffected. `Some(true)` is
    /// equivalent to `None` (the per-class field can only suppress, never
    /// force-enable logging when the proxy-wide flag is already off).
    pub access_log_enabled: Option<bool>,
    /// Per-route rate-limiting configuration, from the
    /// `ingress.coxswain-labs.dev/rate-limit-*` annotations or a `RateLimit`
    /// CRD `ExtensionRef` filter.
    ///
    /// `Some(cfg)` enables per-client rate limiting keyed by client IP or a
    /// named request header. `None` (the default) disables rate limiting for
    /// the route. Shared as an `Arc` so cloning into the lookup result is a
    /// refcount bump, not a heap copy, on the hot path.
    pub rate_limit: Option<Arc<RateLimitConfig>>,
    /// Authentication configuration resolved from the
    /// `ingress.coxswain-labs.dev/auth-*` annotations.
    ///
    /// `None` (the default, and the value for all Gateway-API routes until the
    /// `SecurityPolicy` binding in #23) disables authentication — requests
    /// pass through to the upstream without a check.  `Some(cfg)` makes the
    /// proxy enforce auth before touching the upstream.  Shared as an `Arc` so
    /// the per-request cost is a refcount bump.
    pub auth: Option<Arc<IngressAuthConfig>>,
    /// Per-route response-compression configuration from the
    /// `ingress.coxswain-labs.dev/compression-*` annotations.
    ///
    /// `None` (the default, and the value for all Gateway-API routes) disables
    /// compression — upstream responses are forwarded verbatim. `Some(cfg)`
    /// makes the proxy negotiate gzip/brotli with the client and compress the
    /// response stream chunk-by-chunk. Shared as an `Arc` so cloning into the
    /// lookup result is a refcount bump.
    pub compression: Option<Arc<CompressionConfig>>,
    /// Trusted-proxy forwarding configuration from the
    /// `ingress.coxswain-labs.dev/trust-forwarded-for` family of annotations.
    ///
    /// `None` (the default, and the value for all Gateway-API routes) means the
    /// proxy uses the L4 peer address as the client IP. `Some(cfg)` instructs
    /// the proxy to extract the real client IP from a forwarded header (e.g.
    /// `X-Forwarded-For`), optionally only when the L4 peer is in one of the
    /// trusted CIDRs in `cfg.trusted_cidrs`. Shared as an `Arc` so cloning into
    /// the lookup result is a refcount bump.
    pub forwarded_for: Option<Arc<ForwardedForConfig>>,
    /// Per-route circuit-breaker configuration from the
    /// `ingress.coxswain-labs.dev/circuit-breaker-*` annotation family (#282).
    ///
    /// `Some(cfg)` enables an endpoint-level circuit breaker backed by `failsafe`.
    /// When the endpoint's EWMA error rate exceeds `cfg.threshold_pct` over
    /// `cfg.window` (and at least `cfg.min_requests` have been seen), the breaker
    /// opens and subsequent requests to that endpoint are failed fast with 503.
    /// After `cfg.open_duration` a single probe is allowed; success closes the
    /// breaker, failure re-opens it (with exponential backoff up to
    /// `cfg.max_open_duration` if set). `None` (the default, and the value for all
    /// Gateway-API routes) disables the circuit breaker. Shared as an `Arc` so
    /// cloning into the lookup result is a refcount bump.
    pub circuit_breaker: Option<Arc<CircuitBreakerConfig>>,
}

/// Configuration for trusting a forwarded client-IP header on a per-Ingress basis.
///
/// Parsed from the `ingress.coxswain-labs.dev/trust-forwarded-for` family of annotations.
/// When present on a `RouteEntry`, the proxy extracts the real client IP from `header`
/// instead of using the L4 peer address. The `trusted_cidrs` set gates this trust: if
/// non-empty, the header is only trusted when the L4 peer falls inside one of those
/// CIDRs (anti-spoofing guard). An empty `trusted_cidrs` means unconditional trust.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedForConfig {
    /// Header name to read the client IP from (case-insensitive; e.g. `X-Forwarded-For`).
    pub header: Box<str>,
    /// L4-peer CIDR gate. Empty = trust the header unconditionally.
    pub trusted_cidrs: Box<[ipnet::IpNet]>,
}

impl ForwardedForConfig {
    /// Construct a [`ForwardedForConfig`] from its parts.
    #[must_use]
    pub fn new(header: Box<str>, trusted_cidrs: Box<[ipnet::IpNet]>) -> Self {
        Self {
            header,
            trusted_cidrs,
        }
    }
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
            deny_source_range: None,
            cache_enabled: false,
            access_log_enabled: None,
            rate_limit: None,
            auth: None,
            compression: None,
            forwarded_for: None,
            circuit_breaker: None,
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
            deny_source_range: None,
            cache_enabled: false,
            access_log_enabled: None,
            rate_limit: None,
            auth: None,
            compression: None,
            forwarded_for: None,
            circuit_breaker: None,
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
            deny_source_range: None,
            cache_enabled: false,
            access_log_enabled: None,
            rate_limit: None,
            auth: None,
            compression: None,
            forwarded_for: None,
            circuit_breaker: None,
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
            deny_source_range: None,
            cache_enabled: false,
            access_log_enabled: None,
            rate_limit: None,
            auth: None,
            compression: None,
            forwarded_for: None,
            circuit_breaker: None,
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

    /// Set the source-IP block list for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the CIDR set parsed from the
    /// `ingress.coxswain-labs.dev/deny-source-range` annotation. `None` (the
    /// default) blocks nothing. The reconciler shares one `Arc` across every path
    /// of an Ingress, so cloning it onto each entry is a refcount bump.
    /// Deny is enforced before `allow_source_range` in the proxy.
    #[must_use]
    pub fn with_deny_source_range(
        mut self,
        deny_source_range: Option<Arc<Vec<ipnet::IpNet>>>,
    ) -> Self {
        self.deny_source_range = deny_source_range;
        self
    }

    /// Enable RFC 7234 response caching for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the
    /// `ingress.coxswain-labs.dev/cache-enabled` opt-in. `false` (the default)
    /// leaves caching off; the proxy only enables its response cache for routes
    /// where this is `true`.
    #[must_use]
    pub fn with_cache_enabled(mut self, cache_enabled: bool) -> Self {
        self.cache_enabled = cache_enabled;
        self
    }

    /// Set the per-class access-log enabled override for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to propagate the
    /// `CoxswainIngressClassParameters.spec.accessLog` value. `None` (the
    /// default) means the proxy-wide `--access-log` flag governs.
    /// `Some(false)` suppresses the access log for this route; `Some(true)` is
    /// equivalent to `None` (the per-class field can only suppress, never
    /// force-enable when the proxy-wide flag is already off).
    #[must_use]
    pub fn with_access_log_enabled(mut self, access_log_enabled: Option<bool>) -> Self {
        self.access_log_enabled = access_log_enabled;
        self
    }

    /// Set per-route rate-limiting config for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the config parsed from the
    /// `ingress.coxswain-labs.dev/rate-limit-*` annotations, and by the Gateway
    /// API reconciler for `RateLimit` CRD `ExtensionRef` filters. `None`
    /// (the default) disables rate limiting. The reconciler shares one `Arc`
    /// across every path of an Ingress, so cloning it onto each entry is a
    /// refcount bump.
    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: Option<Arc<RateLimitConfig>>) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Set the authentication config for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the config resolved from the
    /// `ingress.coxswain-labs.dev/auth-*` annotations.  `None` (the default,
    /// and the value for all Gateway-API routes) disables authentication.  The
    /// reconciler shares one `Arc` across every path of an Ingress so cloning
    /// onto each entry is a refcount bump.
    #[must_use]
    pub fn with_auth(mut self, auth: Option<Arc<IngressAuthConfig>>) -> Self {
        self.auth = auth;
        self
    }

    /// Set per-route response-compression config for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the config parsed from the
    /// `ingress.coxswain-labs.dev/compression-*` annotations. `None` (the
    /// default, and the value for all Gateway-API routes) disables compression.
    /// The reconciler shares one `Arc` across every path of an Ingress so
    /// cloning onto each entry is a refcount bump.
    #[must_use]
    pub fn with_compression(mut self, compression: Option<Arc<CompressionConfig>>) -> Self {
        self.compression = compression;
        self
    }

    /// Set the trusted-proxy forwarded-IP config for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the config parsed from the
    /// `ingress.coxswain-labs.dev/trust-forwarded-for` family of annotations.
    /// `None` (the default, and the value for all Gateway-API routes) keeps the
    /// L4 peer as the client IP. The reconciler shares one `Arc` across every
    /// path of an Ingress so cloning onto each entry is a refcount bump.
    #[must_use]
    pub fn with_forwarded_for(mut self, forwarded_for: Option<Arc<ForwardedForConfig>>) -> Self {
        self.forwarded_for = forwarded_for;
        self
    }

    /// Set the per-endpoint circuit-breaker config for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the config parsed from the
    /// `ingress.coxswain-labs.dev/circuit-breaker-*` annotation family (#282).
    /// `None` (the default, and the value for all Gateway-API routes) disables
    /// the circuit breaker. The reconciler shares one `Arc` across every path of
    /// an Ingress so cloning onto each entry is a refcount bump.
    #[must_use]
    pub fn with_circuit_breaker(
        mut self,
        circuit_breaker: Option<Arc<CircuitBreakerConfig>>,
    ) -> Self {
        self.circuit_breaker = circuit_breaker;
        self
    }
}

// Lock the hot-path RouteEntry size to catch accidental growth (the BackendPool
// size assertion lives alongside its type in the sibling `backend` module).
// Update the constant when a deliberate layout change is made.
// Bumped 176→192 by adding path_pattern: Arc<str> (16 bytes) for access-log pattern mode.
// Bumped 192→208 by adding metric_route_id: Arc<str> (16 bytes) for Prometheus `route` label and access-log `route_id` join key.
// Bumped 208→256 by extending RouteTimeouts with connect/read/send: 3 × Option<Duration> (48 bytes) for Ingress annotation timeouts.
// Bumped 256→272 by adding max_body_size: Option<u64> (16 bytes) for the ingress.coxswain-labs.dev/max-body-size request-body limit.
// Bumped 272→280 by adding allow_source_range: Option<Arc<Vec<IpNet>>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/allow-source-range IP allow-list.
// cache_enabled: bool (#40) added without a bump — it occupies existing struct padding.
// access_log_enabled: Option<bool> (#279) added without a bump — 1 byte; fits in
//   padding alongside cache_enabled.
// Bumped 280→288 by adding rate_limit: Option<Arc<RateLimitConfig>> (8 bytes, niche pointer) for per-route rate limiting (#25).
// Bumped 288→296 by adding auth: Option<Arc<IngressAuthConfig>> (8 bytes, niche pointer) for ingress.coxswain-labs.dev/auth-* (#24).
// Bumped 296→304 by adding deny_source_range: Option<Arc<Vec<IpNet>>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/deny-source-range IP block-list (#268).
// Bumped 304→312 by adding compression: Option<Arc<CompressionConfig>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/compression-* response compression (#270).
// Bumped 312→320 by adding forwarded_for: Option<Arc<ForwardedForConfig>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/trust-forwarded-for trusted-proxy headers (#271).
// satisfy: Satisfy (#273) added without a bump — 1-byte enum occupies existing struct padding.
// Bumped 320→328 by adding circuit_breaker: Option<Arc<CircuitBreakerConfig>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/circuit-breaker-* per-endpoint circuit breaker (#282).
static_assertions::assert_eq_size!(RouteEntry, [u8; 328]);

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn upstream_tls_size_unchanged() {
        // BackendGroup now has one extra Option<Arc<UpstreamTls>> = 8 bytes;
        // but RouteEntry holds Arc<BackendGroup>, so RouteEntry size is unaffected.
        // Bumped 176→192: path_pattern: Arc<str> added for access-log pattern mode.
        // Bumped 192→208: metric_route_id: Arc<str> added for Prometheus `route` label.
        // Bumped 208→256: RouteTimeouts gained connect/read/send: 3×Option<Duration>.
        // Bumped 256→272: max_body_size: Option<u64> added for the max-body-size limit.
        // Bumped 272→280: allow_source_range: Option<Arc<Vec<IpNet>>> added for the allow-source-range IP allow-list.
        // Bumped 280→288: rate_limit: Option<Arc<RateLimitConfig>> added for per-route rate limiting (#25).
        // Bumped 288→296: auth: Option<Arc<IngressAuthConfig>> added for auth-* annotations (#24).
        // Bumped 296→304: deny_source_range: Option<Arc<Vec<IpNet>>> added for the deny-source-range IP block-list (#268).
        // Bumped 304→312: compression: Option<Arc<CompressionConfig>> added for compression-* annotations (#270).
        // Bumped 312→320: forwarded_for: Option<Arc<ForwardedForConfig>> added for trust-forwarded-for (#271).
        // satisfy: Satisfy (#273) added without a bump — 1-byte enum occupies existing struct padding.
        // Bumped 320→328: circuit_breaker: Option<Arc<CircuitBreakerConfig>> added for circuit-breaker-* annotations (#282).
        static_assertions::assert_eq_size!(RouteEntry, [u8; 328]);
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
}
