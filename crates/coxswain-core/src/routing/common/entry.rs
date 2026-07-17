//! Route-entry metadata: the [`RouteEntry`] routing candidate, its timeout and
//! introspection types, and the per-route `Forwarded`-trust config.
//!
//! The filter actions a route carries live in the sibling [`super::filters`]
//! module; upstream backend-selection / load-balancing (the
//! [`BackendGroup`](super::backend::BackendGroup) each route entry references)
//! lives in [`super::backend`].

use super::auth::IngressAuthConfig;
use super::backend::BackendGroup;
use super::circuit_breaker::CircuitBreakerConfig;
use super::compression::CompressionConfig;
use super::filters::FilterAction;
use super::predicate::MatchPredicates;
use super::rate_limit::RateLimitConfig;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};

/// The shared empty authentication chain — the default for every route with no
/// auth. Cloning it is a refcount bump, so the common no-auth case never
/// allocates.
fn empty_auth_chain() -> Arc<[Arc<IngressAuthConfig>]> {
    static EMPTY: LazyLock<Arc<[Arc<IngressAuthConfig>]>> = LazyLock::new(|| Arc::from(Vec::new()));
    EMPTY.clone()
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

/// How a path rule was registered — for introspection only.
///
/// Deliberately closed: matched exhaustively across the crate boundary on the
/// discovery wire-encode path, so adding a variant is a compiler-enforced change
/// rather than a silent runtime drop. `#[non_exhaustive]` would force a wildcard
/// arm there and defeat that.
// intentionally open: closed enum matched exhaustively cross-crate on the wire-encode path; see doc above.
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
#[derive(Debug, Clone)]
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
    /// Cold-side provenance: `true` when [`Self::error_status`] was derived from the
    /// backend group's resolved endpoints (the reflector's endpoint-dependent branch —
    /// an existing Service with zero ready endpoints ⇒ 503, an invalid/missing backend
    /// or all-zero-weight rule ⇒ 500; see [`crate::endpoints::empty_group_status`]).
    ///
    /// Set by the reflector so the discovery wire encoder can **omit** these statuses:
    /// the client re-derives them from its own endpoint pool at delta-materialization
    /// time, keeping endpoint churn from rewriting route hashes (#383). Endpoint-
    /// independent statuses (e.g. a `502` fail-closed) leave this `false` and ride the
    /// wire baked. Never read on the request hot path — carried along only.
    pub error_status_endpoint_derived: bool,
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
    /// IP allow-list (CIDR ranges), from the Ingress
    /// `ingress.coxswain-labs.dev/ip-access-control` annotation or an
    /// `IpAccessControl` CRD `ExtensionRef` filter (#553).
    ///
    /// `Some(nets)` restricts the rule to requests whose real client IP matches at
    /// least one CIDR; clients outside every range are rejected with 403 Forbidden.
    /// `None` (the default) admits all source IPs. Shared as an `Arc` so cloning
    /// into the lookup result is a refcount bump, not a heap copy, on the hot path.
    pub allow_source_range: Option<Arc<[ipnet::IpNet]>>,
    /// Source-IP block list, from the same `ip-access-control` annotation or
    /// `IpAccessControl` CRD `ExtensionRef` filter as
    /// [`Self::allow_source_range`] (#553).
    ///
    /// `Some(nets)` rejects any request whose real client IP falls inside any
    /// listed CIDR with 403 Forbidden, **regardless of `allow_source_range`**
    /// (deny is evaluated first). `None` (the default) blocks nothing.
    /// Shared as an `Arc` for the same zero-copy-on-hot-path reason as
    /// `allow_source_range`. A `None` client IP is *not* denied — a block list
    /// only acts on IPs it can positively attribute to a listed range.
    pub deny_source_range: Option<Arc<[ipnet::IpNet]>>,
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
    /// Authentication checks the proxy enforces before touching the upstream.
    ///
    /// An **additive chain**: the request must pass *every* check, in order —
    /// the first hard-deny wins (#23). An empty chain (the default) disables
    /// authentication — requests pass straight through. The Ingress
    /// `auth-*` annotations and a route-level `CoxswainExternalAuth`
    /// `extensionRef` each contribute at most one entry; a Gateway-attached
    /// `CoxswainExternalAuth` policy prepends a mandatory entry that a route
    /// cannot remove (GEP-713 override posture). Each entry is an `Arc` so a
    /// Gateway-level config is shared across every route on the Gateway by a
    /// refcount bump; the outer `Arc<[_]>` makes cloning onto a lookup result
    /// cheap on the hot path.
    pub auth: Arc<[Arc<IngressAuthConfig>]>,
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
/// instead of using the L4 peer address. The `trusted_cidrs` set gates this trust
/// (fail-closed): the header is only honored when the L4 peer falls inside one of those
/// CIDRs (anti-spoofing guard). An empty `trusted_cidrs` trusts **no** peer, so the
/// header is ignored and the L4 address is used — a client cannot forge its source IP by
/// setting the header when no trusted proxy is configured. Within a trusted chain the
/// proxy reads the header rightmost-untrusted, so a forged leftmost token is ignored.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedForConfig {
    /// Header name to read the client IP from (case-insensitive; e.g. `X-Forwarded-For`).
    pub header: Box<str>,
    /// L4-peer CIDR gate (fail-closed). Empty = trust no peer; the header is ignored.
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
            error_status_endpoint_derived: false,
            path_pattern: Arc::from(""),
            max_body_size: None,
            allow_source_range: None,
            deny_source_range: None,
            access_log_enabled: None,
            rate_limit: None,
            auth: empty_auth_chain(),
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
            error_status_endpoint_derived: false,
            path_pattern: Arc::from(""),
            max_body_size: None,
            allow_source_range: None,
            deny_source_range: None,
            access_log_enabled: None,
            rate_limit: None,
            auth: empty_auth_chain(),
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
            error_status_endpoint_derived: false,
            path_pattern: Arc::from(""),
            max_body_size: None,
            allow_source_range: None,
            deny_source_range: None,
            access_log_enabled: None,
            rate_limit: None,
            auth: empty_auth_chain(),
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
            error_status_endpoint_derived: false,
            path_pattern: Arc::from(""),
            max_body_size: None,
            allow_source_range: None,
            deny_source_range: None,
            access_log_enabled: None,
            rate_limit: None,
            auth: empty_auth_chain(),
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
    /// Used by the Ingress reconciler to attach the CIDR set resolved from the
    /// `ingress.coxswain-labs.dev/ip-access-control` `IpAccessControl` CR
    /// reference (#553), and by the Gateway API reconciler for `IpAccessControl`
    /// `ExtensionRef` filters. `None` admits all source IPs (the default). The
    /// reconciler shares one `Arc` across every path of an Ingress, so cloning
    /// it onto each entry is a refcount bump.
    #[must_use]
    pub fn with_allow_source_range(
        mut self,
        allow_source_range: Option<Arc<[ipnet::IpNet]>>,
    ) -> Self {
        self.allow_source_range = allow_source_range;
        self
    }

    /// Set the source-IP block list for this route (builder-style).
    ///
    /// Used by the Ingress reconciler to attach the CIDR set resolved from the
    /// `ingress.coxswain-labs.dev/ip-access-control` `IpAccessControl` CR
    /// reference (#553), and by the Gateway API reconciler for `IpAccessControl`
    /// `ExtensionRef` filters. `None` (the default) blocks nothing. The
    /// reconciler shares one `Arc` across every path of an Ingress, so cloning
    /// it onto each entry is a refcount bump. Deny is enforced before
    /// `allow_source_range` in the proxy.
    #[must_use]
    pub fn with_deny_source_range(
        mut self,
        deny_source_range: Option<Arc<[ipnet::IpNet]>>,
    ) -> Self {
        self.deny_source_range = deny_source_range;
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

    /// Set the full additive authentication chain for this route (builder-style).
    ///
    /// Every check runs in order; the first hard-deny wins (#23). An empty
    /// chain disables authentication. Used by the Gateway API reconciler to
    /// combine a Gateway-attached `CoxswainExternalAuth` policy with a
    /// route-level `extensionRef` check.
    #[must_use]
    pub fn with_auth_chain(mut self, auth: Arc<[Arc<IngressAuthConfig>]>) -> Self {
        self.auth = auth;
        self
    }

    /// Set the error status code for this route (builder-style).
    ///
    /// When `Some(code)`, the proxy returns `code` immediately without contacting the
    /// upstream — used for routes with invalid/missing/forbidden backend refs
    /// (Gateway API §4.3.4) and for redirect-only entries that need a non-default code.
    /// `None` (the default from every constructor) means normal forwarding.
    ///
    /// The discovery wire layer uses this setter to round-trip routes that have an
    /// `error_status` set at reconcile time.
    #[must_use]
    pub fn with_error_status(mut self, status: Option<u16>) -> Self {
        self.error_status = status;
        self
    }

    /// Mark [`Self::error_status`] as endpoint-derived (builder-style).
    ///
    /// The reflector sets this to `true` when the status came from the backend group's
    /// resolved endpoints (Service-exists-but-empty ⇒ 503, missing/invalid ⇒ 500). The
    /// discovery wire encoder omits such statuses so the client re-derives them from its
    /// endpoint pool, keeping endpoint churn off the route hashes (#383). Endpoint-
    /// independent statuses (e.g. fail-closed 502) leave this `false` (the default).
    #[must_use]
    pub fn with_error_status_endpoint_derived(mut self, derived: bool) -> Self {
        self.error_status_endpoint_derived = derived;
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
    /// Populated from the `circuitBreaker` facet of the `CoxswainBackendPolicy`
    /// attached to this route's backend `Service` (#478, #554) — the same
    /// resolution path for Gateway API and Ingress routes alike. `None` (the
    /// default) disables the circuit breaker. Resolved per backend Service, so
    /// two paths of one Ingress routing to different Services may carry
    /// different `Arc`s; two entries sharing a backend share one `Arc`, and
    /// cloning it onto each entry is a refcount bump.
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
// access_log_enabled: Option<bool> (#279) added without a bump — 1 byte; fits in
//   existing struct padding.
// Bumped 280→288 by adding rate_limit: Option<Arc<RateLimitConfig>> (8 bytes, niche pointer) for per-route rate limiting (#25).
// Bumped 288→296 by adding auth: Option<Arc<IngressAuthConfig>> (8 bytes, niche pointer) for ingress.coxswain-labs.dev/auth-* (#24).
// Bumped 296→304 by adding deny_source_range: Option<Arc<Vec<IpNet>>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/deny-source-range IP block-list (#268).
// Bumped 304→312 by adding compression: Option<Arc<CompressionConfig>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/compression-* response compression (#270).
// Bumped 312→320 by adding forwarded_for: Option<Arc<ForwardedForConfig>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/trust-forwarded-for trusted-proxy headers (#271).
// satisfy: Satisfy (#273) added without a bump — 1-byte enum occupies existing struct padding.
// Bumped 320→328 by adding circuit_breaker: Option<Arc<CircuitBreakerConfig>> (8 bytes, niche pointer) for the ingress.coxswain-labs.dev/circuit-breaker-* per-endpoint circuit breaker (#282).
// Bumped 328→336 by widening auth: Option<Arc<IngressAuthConfig>> (8 bytes) → Arc<[Arc<IngressAuthConfig>]> (16-byte fat pointer) for the additive ext_authz chain (#23).
// Bumped 336→352 by widening allow_source_range + deny_source_range each from
// Option<Arc<Vec<IpNet>>> (8-byte thin pointer) to Option<Arc<[IpNet]>> (16-byte
// fat pointer) — one fewer heap allocation and indirection, matching the
// Arc<[T]> siblings; +8 bytes each (#620).
static_assertions::assert_eq_size!(RouteEntry, [u8; 352]);

#[cfg(test)]
mod tests {
    use super::*;

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
        // Bumped 328→336: auth widened Option<Arc<_>> → Arc<[Arc<_>]> (additive ext_authz chain, #23).
        // Bumped 336→352: allow_source_range + deny_source_range widened Arc<Vec<IpNet>> → Arc<[IpNet]> (16-byte fat ptr each, #620).
        static_assertions::assert_eq_size!(RouteEntry, [u8; 352]);
    }

    #[test]
    fn error_status_endpoint_derived_defaults_false_and_setter_round_trips() {
        let group = Arc::new(BackendGroup::new("ns/svc".to_string(), vec![]));
        let bare = RouteEntry::path_only(Arc::clone(&group), "ns/r".to_string(), None);
        assert!(
            !bare.error_status_endpoint_derived,
            "provenance flag defaults to false (endpoint-independent)"
        );

        let derived = RouteEntry::path_only(group, "ns/r".to_string(), None)
            .with_error_status(Some(503))
            .with_error_status_endpoint_derived(true);
        assert!(derived.error_status_endpoint_derived);
        assert_eq!(derived.error_status, Some(503));
    }
}
