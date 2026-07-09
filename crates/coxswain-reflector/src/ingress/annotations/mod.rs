//! Annotation key constants and parser for the `ingress.coxswain-labs.dev/*` namespace.
//!
//! The module is split into domain submodules re-exported here:
//!
//! - [`traffic_policy`] — timeout and retry annotations.
//! - [`routing`] — path rewrite and regex opt-in annotations.
//! - [`filters`] — request/response header modifiers, redirect, and ssl-redirect annotations.
//! - [`edge_access`] — source-IP allow/deny, forwarded-for trust.
//! - [`auth`] — request authentication (`auth-*`, #24).
//! - [`client_cert`] — per-host client-certificate mTLS (`auth-tls-*`, #267).
//! - [`caching`] — RFC 7234 response-cache opt-in.
//! - [`session`] — sticky-session (session-affinity) binding.
//!
//! The top-level [`IngressAnnotations::parse`] function is called once per Ingress in
//! [`super::reconcile`] and threads the results into every rule/path entry.
//!
//! ## Structured diagnostics
//!
//! Parse helpers return `None` on invalid input so the annotation is treated as
//! absent — the whole Ingress keeps its routes; only that annotation's effect is
//! suppressed.  Callers that have the annotation-key context push an
//! [`AnnotationIssue`] into the collector returned by [`IngressAnnotations::parse`].
//! The controller consumer converts those into `tracing::warn!` log lines and
//! `Warning` Kubernetes Events; the proxy discards them silently.

pub(crate) mod auth;
pub(crate) mod client_cert;
pub(crate) mod edge_access;
mod filters;
mod routing;
mod session;
pub(crate) mod traffic_policy;

pub use auth::*;
pub use client_cert::*;
pub use edge_access::*;
pub use filters::*;
pub use routing::*;
pub use session::*;
pub use traffic_policy::*;

use coxswain_core::routing::{
    CircuitBreakerConfig, FilterAction, ForwardedForConfig, HeaderMod, LoadBalance, NormalizeLevel,
    PathModifier, RouteTimeouts, SessionAffinity,
};
use std::collections::BTreeMap;

// ── Structured annotation diagnostic ─────────────────────────────────────────

/// A structured annotation parse failure collected by [`IngressAnnotations::parse`].
///
/// The controller consumer converts these into `Warning` Kubernetes Events on the
/// owning Ingress; the proxy discards them silently.  The `tracing::warn!` is emitted
/// by the parse helper itself (both roles); the K8s Event is controller-only.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct AnnotationIssue {
    /// Full annotation key string (e.g. `"ingress.coxswain-labs.dev/connect-timeout"`).
    pub annotation: &'static str,
    /// Operator-facing message reusing today's warn message text.
    pub message: String,
}

// ── Annotation-namespace prefix ──────────────────────────────────────────────

/// The shared prefix for all Coxswain Ingress annotations.
pub const PREFIX: &str = "ingress.coxswain-labs.dev/";

// ── Shared lookup and parse helpers ──────────────────────────────────────────

/// Look up an `ingress.coxswain-labs.dev/*` annotation value by its full key.
///
/// Returns `None` when the `annotations` map is empty or the key is absent.
#[must_use]
pub fn get<'a>(annotations: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    annotations.get(key).map(String::as_str)
}

/// Parse a boolean annotation value: `"true"`/`"false"` (ASCII-case-insensitive).
///
/// Returns `None` on any other value so the caller falls back to the default.
/// Emits a `WARN` on invalid input (without annotation-key context — the caller
/// is expected to also push an [`AnnotationIssue`] with the annotation key).
#[must_use]
pub fn parse_bool(s: &str) -> Option<bool> {
    match s.trim() {
        v if v.eq_ignore_ascii_case("true") => Some(true),
        v if v.eq_ignore_ascii_case("false") => Some(false),
        _ => {
            tracing::warn!(value = s, "invalid boolean annotation value");
            None
        }
    }
}

// ── Parsed annotation set ─────────────────────────────────────────────────────

/// Parsed result of all `ingress.coxswain-labs.dev/*` annotations on a single Ingress.
///
/// Produced by [`IngressAnnotations::parse`] and applied uniformly to every route entry
/// generated from that Ingress (both rule-path entries and the `spec.defaultBackend`).
#[derive(Default)]
pub(super) struct IngressAnnotations {
    /// Partial timeout overrides: the connect/read/send fields come from annotations;
    /// `request` and `backend_request` stay `None` (those come from HTTPRoute/GW API only).
    pub timeouts: RouteTimeouts,
    /// `RetryPolicy` CR reference from `retry` (#551), in intermediate
    /// (pre-resolved) `namespace/name` form. `None` when the annotation is
    /// absent or malformed (WARN emitted). The reconciler resolves this into
    /// the same
    /// [`RetryPolicyConfig`][coxswain_core::routing::RetryPolicyConfig] the
    /// HTTPRoute `ExtensionRef` filter produces (Gateway API parity, #551).
    /// A missing CR fails **open** (no retries) — unlike the auth
    /// annotations, a broken reference degrades gracefully.
    pub retry: Option<auth::SecretRef>,
    /// Path rewrite from `rewrite-target` — emitted as a `FilterAction::UrlRewrite`.
    /// Holds the literal [`PathModifier::ReplaceFullPath`]; on a regex path the
    /// reconciler rebuilds it as [`PathModifier::RegexReplace`] against that path's
    /// own compiled pattern so capture groups (`$1`…`$n`) resolve per-path.
    pub rewrite: Option<PathModifier>,
    /// `use-regex` opt-in: interpret `pathType: ImplementationSpecific` paths as regex.
    pub use_regex: bool,
    /// Request header modifier from `request-header-{set,add,remove}` annotations (#79).
    /// `None` when none of the three annotation keys are present, or when
    /// [`HeaderMod::parse`] rejects the provided values (WARN emitted; modifier skipped).
    pub request_headers: Option<HeaderMod>,
    /// Response header modifier from `response-header-{set,add,remove}` annotations (#79).
    pub response_headers: Option<HeaderMod>,
    /// Request redirect built from `redirect-{scheme,hostname,port,path,status-code}`
    /// annotations (#79).  `Some` iff at least one `redirect-*` key is present; absent
    /// fields default to `None` (original request component preserved by the proxy).
    /// When `Some`, takes precedence over [`Self::ssl_redirect`].
    pub redirect: Option<FilterAction>,
    /// Force HTTP→HTTPS from `ssl-redirect: "true"` (#262).
    /// Ignored when [`Self::redirect`] is `Some`.
    pub ssl_redirect: bool,
    /// Status code for the ssl-redirect (`None` → default `308`).
    pub ssl_redirect_code: Option<u16>,
    /// Per-route request body size limit in bytes from `max-body-size` (#263).
    /// `None` (the default, or an unparseable value) imposes no limit.
    pub max_body_size: Option<u64>,
    /// Source-IP allow-list (CIDR set) from `allow-source-range` (#264).
    /// `None` (the default, or an all-invalid/absent value) admits all source IPs.
    pub allow_source_range: Option<Vec<ipnet::IpNet>>,
    /// Source-IP block list (CIDR set) from `deny-source-range` (#268).
    /// `None` (the default, or an all-invalid/absent value) blocks nothing.
    pub deny_source_range: Option<Vec<ipnet::IpNet>>,
    /// Sticky-session binding from the `session-*` annotations (#15).
    /// `None` (the default, or an invalid/incomplete value) keeps round-robin.
    pub session_affinity: Option<SessionAffinity>,
    /// `RateLimit` CR reference from `rate-limit` (#552), in intermediate
    /// (pre-resolved) `namespace/name` form. `None` when the annotation is
    /// absent or malformed (WARN emitted). The reconciler resolves this into
    /// the same
    /// [`RateLimitConfig`][coxswain_core::routing::RateLimitConfig] the
    /// HTTPRoute/GRPCRoute `ExtensionRef` filter produces (Gateway API
    /// parity, #552). A missing CR fails **open** (no rate limiting) —
    /// unlike the auth annotations, a broken reference degrades gracefully.
    pub rate_limit: Option<auth::SecretRef>,
    /// `Secret` reference from `auth-basic-secret` (#24), in intermediate
    /// (pre-resolved) `namespace/name` form. `None` when the annotation is
    /// absent or malformed (WARN emitted). The reconciler resolves this into
    /// [`IngressAuthConfig::Basic`][coxswain_core::routing::IngressAuthConfig::Basic]
    /// by looking up the labeled htpasswd Secret. Independent of (additive
    /// with) [`Self::auth_ext`] / [`Self::auth_jwt`] — every configured check
    /// must pass.
    pub auth_basic: Option<auth::SecretRef>,
    /// `CoxswainExternalAuth` CR reference from `ext-auth` (#549), in
    /// intermediate (pre-resolved) `namespace/name` form. `None` when the
    /// annotation is absent or malformed (WARN emitted). Independent of
    /// (additive with) [`Self::auth_basic`] / [`Self::auth_jwt`] — the
    /// reconciler resolves this into the same
    /// [`IngressAuthConfig::External`][coxswain_core::routing::IngressAuthConfig::External]
    /// the HTTPRoute `ExtensionRef` filter produces, and every configured
    /// check must pass.
    pub auth_ext: Option<auth::SecretRef>,
    /// `JwtAuth` CR reference from `auth-jwt` (#441), in intermediate
    /// (pre-resolved) `namespace/name` form. `None` when the annotation is
    /// absent or malformed (WARN emitted). Independent of (additive with)
    /// [`Self::auth_basic`] / [`Self::auth_ext`] — the reconciler resolves
    /// this into the same
    /// [`IngressAuthConfig::Jwt`][coxswain_core::routing::IngressAuthConfig::Jwt]
    /// the HTTPRoute `ExtensionRef` filter produces, and every configured
    /// check must pass.
    pub auth_jwt: Option<auth::SecretRef>,
    /// Fire-and-forget mirror backend ref from `mirror-target` (#283), in
    /// intermediate (pre-resolved) form.  `None` when the annotation is absent or
    /// unparseable (WARN emitted; mirror disabled).  The reconciler resolves this
    /// into a `FilterAction::Mirror` by looking up the Service endpoints.
    pub mirror_target: Option<traffic_policy::MirrorTargetRef>,
    /// Upstream keepalive idle timeout from
    /// `ingress.coxswain-labs.dev/upstream-keepalive-timeout` (#266).
    /// `None` (the default, or an absent/invalid value — WARN emitted) defers to
    /// Pingora's built-in behaviour. Applied in the proxy via
    /// `HttpPeer.options.idle_timeout`.
    pub keepalive_timeout: Option<std::time::Duration>,
    /// `Compression` CR reference from `compression` (#550), in intermediate
    /// (pre-resolved) `namespace/name` form. `None` when the annotation is
    /// absent or malformed (WARN emitted). The reconciler resolves this into
    /// the same
    /// [`CompressionConfig`][coxswain_core::routing::CompressionConfig] the
    /// HTTPRoute `ExtensionRef` filter produces (Gateway API parity, #550).
    /// A missing CR fails **open** (no compression) — unlike the auth
    /// annotations, a broken reference degrades gracefully.
    pub compression: Option<auth::SecretRef>,
    /// Trusted-proxy forwarded-IP config from the `trust-forwarded-for` family (#271).
    /// `None` when `trust-forwarded-for` is absent or `"false"`.
    pub forwarded_for: Option<ForwardedForConfig>,
    /// Per-route upstream load-balancing algorithm from `load-balance` (#275, #276).
    /// Defaults to `RoundRobin` when the annotation is absent or carries an unknown value.
    /// The `hash:*` forms carry their consistent-hash attribute inline via
    /// [`LoadBalance::Hash`] (#397).
    pub load_balance: LoadBalance,
    /// Envoy/Istio-style path normalization level from `path-normalize` (#280).
    ///
    /// `None` when the annotation is absent (the host builder uses its default,
    /// `NormalizeLevel::Base`).  Unrecognized values — and the dropped `"none"`
    /// value (#483) — emit `WARN` and fall back to `Base`.
    pub path_normalize: Option<NormalizeLevel>,
    /// Per-route circuit-breaker config from `circuit-breaker-*` annotations (#282).
    ///
    /// `None` (the default) when `circuit-breaker-threshold` is absent or invalid,
    /// disabling the circuit breaker for this route. Gateway-API routes always see
    /// `None` — the circuit breaker is Ingress-only.
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

impl IngressAnnotations {
    /// Parse all `ingress.coxswain-labs.dev/*` annotations from the Ingress metadata map.
    ///
    /// Returns the parsed annotation set together with a list of [`AnnotationIssue`]s
    /// for every value that was invalid and fell back to a default.  The caller is
    /// responsible for forwarding the issues to the controller consumer (which emits
    /// `tracing::warn!` and `Warning` Kubernetes Events); the proxy discards them.
    ///
    /// The Ingress is never rejected — invalid values produce an issue and use the
    /// absent / default behaviour.
    pub(super) fn parse(
        annotations: Option<&BTreeMap<String, String>>,
        route_id: &str,
    ) -> (Self, Vec<AnnotationIssue>) {
        let Some(ann) = annotations else {
            return (Self::default(), Vec::new());
        };

        let mut diag: Vec<AnnotationIssue> = Vec::new();
        // Alias for pushing a diagnostic at the call site that has the annotation key.
        macro_rules! issue {
            ($key:expr, $msg:expr) => {
                diag.push(AnnotationIssue {
                    annotation: $key,
                    message: $msg.into(),
                })
            };
        }

        // ── Timeouts ──────────────────────────────────────────────────────────
        let connect = get(ann, CONNECT_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(ingress = %route_id, annotation = CONNECT_TIMEOUT, value = v, "invalid duration — using default");
                issue!(CONNECT_TIMEOUT, "invalid duration — using default");
            }
            d
        });
        let read = get(ann, READ_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(ingress = %route_id, annotation = READ_TIMEOUT, value = v, "invalid duration — using default");
                issue!(READ_TIMEOUT, "invalid duration — using default");
            }
            d
        });
        let send = get(ann, SEND_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(ingress = %route_id, annotation = SEND_TIMEOUT, value = v, "invalid duration — using default");
                issue!(SEND_TIMEOUT, "invalid duration — using default");
            }
            d
        });

        // ── Retry CR reference (#551) ──────────────────────────────────────────
        let retry = get(ann, traffic_policy::RETRY).and_then(|v| {
            let r = auth::parse_secret_ref(v);
            if r.is_none() {
                issue!(
                    traffic_policy::RETRY,
                    "invalid retry — expected \"namespace/name\"; retries disabled"
                );
            }
            r
        });

        // ── Path rewrite ──────────────────────────────────────────────────────
        let rewrite =
            get(ann, REWRITE_TARGET).map(|v| PathModifier::ReplaceFullPath(v.to_string()));

        // ── Regex path matching opt-in ────────────────────────────────────────
        let use_regex = get(ann, USE_REGEX)
            .and_then(|v| {
                let b = parse_bool(v);
                if b.is_none() {
                    tracing::warn!(ingress = %route_id, annotation = USE_REGEX, value = v, "treating use-regex as false");
                    issue!(USE_REGEX, "invalid boolean — treating use-regex as false");
                }
                b
            })
            .unwrap_or(false);

        // ── Request header modifier (#79) ─────────────────────────────────────
        let request_headers = build_header_mod(
            ann,
            route_id,
            REQUEST_HEADER_ADD,
            REQUEST_HEADER_SET,
            REQUEST_HEADER_REMOVE,
            "request-header",
            &mut diag,
        );

        // ── Response header modifier (#79) ────────────────────────────────────
        let response_headers = build_header_mod(
            ann,
            route_id,
            RESPONSE_HEADER_ADD,
            RESPONSE_HEADER_SET,
            RESPONSE_HEADER_REMOVE,
            "response-header",
            &mut diag,
        );

        // ── Request redirect (#79) ────────────────────────────────────────────
        let has_redirect = [
            REDIRECT_SCHEME,
            REDIRECT_HOSTNAME,
            REDIRECT_PORT,
            REDIRECT_PATH,
            REDIRECT_STATUS_CODE,
        ]
        .iter()
        .any(|k| get(ann, k).is_some());

        let redirect = if has_redirect {
            let scheme = get(ann, REDIRECT_SCHEME).and_then(|v| {
                let s = parse_redirect_scheme(v);
                if s.is_none() {
                    tracing::warn!(ingress = %route_id, annotation = REDIRECT_SCHEME, value = v, "invalid redirect-scheme — field omitted (original request scheme preserved)");
                    issue!(
                        REDIRECT_SCHEME,
                        "invalid redirect-scheme — field omitted (original request scheme preserved)"
                    );
                }
                s
            });
            let hostname = get(ann, REDIRECT_HOSTNAME).map(str::to_string);
            let port = get(ann, REDIRECT_PORT).and_then(|v| match v.trim().parse::<u16>() {
                Ok(p) => Some(p),
                Err(_) => {
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = REDIRECT_PORT,
                        value = v,
                        "invalid redirect-port (expected 0–65535) — field omitted"
                    );
                    issue!(
                        REDIRECT_PORT,
                        "invalid redirect-port (expected 0–65535) — field omitted"
                    );
                    None
                }
            });
            let path =
                get(ann, REDIRECT_PATH).map(|v| PathModifier::ReplaceFullPath(v.to_string()));
            let status_code = get(ann, REDIRECT_STATUS_CODE)
                .and_then(|v| {
                    let c = parse_redirect_status_code(v);
                    if c.is_none() {
                        tracing::warn!(ingress = %route_id, annotation = REDIRECT_STATUS_CODE, value = v, "invalid redirect-status-code — using default 302");
                        issue!(
                            REDIRECT_STATUS_CODE,
                            "invalid redirect-status-code — using default 302"
                        );
                    }
                    c
                })
                .unwrap_or(302);
            Some(FilterAction::RequestRedirect {
                scheme,
                hostname,
                port,
                status_code,
                path,
            })
        } else {
            None
        };

        // ── SSL redirect / force-HTTPS (#262) ────────────────────────────────
        let ssl_redirect = get(ann, SSL_REDIRECT)
            .and_then(|v| {
                let b = parse_bool(v);
                if b.is_none() {
                    tracing::warn!(ingress = %route_id, annotation = SSL_REDIRECT, value = v, "treating ssl-redirect as false");
                    issue!(SSL_REDIRECT, "invalid boolean — treating ssl-redirect as false");
                }
                b
            })
            .unwrap_or(false);

        let ssl_redirect_code = get(ann, SSL_REDIRECT_CODE).and_then(|v| {
            let c = parse_redirect_status_code(v);
            if c.is_none() {
                tracing::warn!(ingress = %route_id, annotation = SSL_REDIRECT_CODE, value = v, "invalid ssl-redirect-code — using default 308");
                issue!(SSL_REDIRECT_CODE, "invalid ssl-redirect-code — using default 308");
            }
            c
        });

        // ── Max body size (#263) ──────────────────────────────────────────────
        let max_body_size = get(ann, MAX_BODY_SIZE).and_then(|v| {
            let n = parse_byte_size(v);
            if n.is_none() {
                issue!(MAX_BODY_SIZE, "invalid max-body-size — no limit applied");
            }
            n
        });

        // ── Allow-source-range (#264) ─────────────────────────────────────────
        let allow_source_range = get(ann, ALLOW_SOURCE_RANGE)
            .and_then(|s| parse_allow_source_range(s, route_id, &mut diag));

        // ── Deny-source-range (#268) ──────────────────────────────────────────
        let deny_source_range = get(ann, DENY_SOURCE_RANGE)
            .and_then(|s| parse_deny_source_range(s, route_id, &mut diag));

        // ── Session affinity (#15) ────────────────────────────────────────────
        let session_affinity = parse_session_affinity(ann, route_id, &mut diag);

        // ── RateLimit CR reference (#552) ─────────────────────────────────────
        let rate_limit = get(ann, traffic_policy::RATE_LIMIT).and_then(|v| {
            let r = auth::parse_secret_ref(v);
            if r.is_none() {
                issue!(
                    traffic_policy::RATE_LIMIT,
                    "invalid rate-limit — expected \"namespace/name\"; rate limiting disabled"
                );
            }
            r
        });

        // ── Basic auth Secret reference (#24) ─────────────────────────────────
        let auth_basic = get(ann, AUTH_BASIC_SECRET).and_then(|v| {
            let r = auth::parse_secret_ref(v);
            if r.is_none() {
                issue!(
                    AUTH_BASIC_SECRET,
                    "invalid auth-basic-secret — expected \"namespace/name\" format; auth disabled"
                );
            }
            r
        });

        // ── External auth CR reference (#549) ─────────────────────────────────
        let auth_ext = get(ann, auth::EXT_AUTH).and_then(|v| {
            let r = auth::parse_secret_ref(v);
            if r.is_none() {
                issue!(
                    auth::EXT_AUTH,
                    "invalid ext-auth — expected \"namespace/name\"; external auth disabled"
                );
            }
            r
        });

        // ── JWT auth CR reference (#441) ──────────────────────────────────────
        let auth_jwt = get(ann, auth::AUTH_JWT).and_then(|v| {
            let r = auth::parse_secret_ref(v);
            if r.is_none() {
                issue!(
                    auth::AUTH_JWT,
                    "invalid auth-jwt — expected \"namespace/name\"; JWT auth disabled"
                );
            }
            r
        });

        // ── Mirror target (#283) ──────────────────────────────────────────────
        let mirror_target = get(ann, MIRROR_TARGET).and_then(|v| {
            let r = traffic_policy::parse_mirror_target(v);
            if r.is_none() {
                issue!(MIRROR_TARGET, "invalid mirror-target — mirror disabled");
            }
            r
        });

        // ── Upstream keepalive timeout (#266) ─────────────────────────────────
        let keepalive_timeout = get(ann, UPSTREAM_KEEPALIVE_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                issue!(
                    UPSTREAM_KEEPALIVE_TIMEOUT,
                    "invalid duration — using Pingora default keepalive timeout"
                );
            }
            d
        });

        // ── Compression CR reference (#550) ───────────────────────────────────
        let compression = get(ann, traffic_policy::COMPRESSION).and_then(|v| {
            let r = auth::parse_secret_ref(v);
            if r.is_none() {
                issue!(
                    traffic_policy::COMPRESSION,
                    "invalid compression — expected \"namespace/name\"; compression disabled"
                );
            }
            r
        });

        // ── Trusted-proxy forwarded-IP headers (#271) ─────────────────────────
        let forwarded_for = edge_access::parse_forwarded_for(ann, route_id, &mut diag);

        // ── Load-balance algorithm (#275, #276) ───────────────────────────────
        let load_balance = get(ann, LOAD_BALANCE)
            .map(|s| traffic_policy::parse_load_balance(s, route_id, &mut diag))
            .unwrap_or_default();

        // ── Path normalization level (#280, hardened #483) ────────────────────
        let path_normalize = get(ann, PATH_NORMALIZE).map(|v| {
            // `none` was dropped in #483: it disabled normalization and re-opened
            // route-match bypass / path-traversal. Reject it with a dedicated
            // migration warning (distinct from a typo) and fall back to `base`.
            if v.trim().eq_ignore_ascii_case("none") {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = PATH_NORMALIZE,
                    value = v,
                    "path-normalize 'none' is no longer supported — it disabled \
                     normalization, enabling path-traversal bypass; falling back to base"
                );
                issue!(
                    PATH_NORMALIZE,
                    "'none' is no longer supported (it disabled normalization, \
                     enabling path-traversal bypass); falling back to base"
                );
                return NormalizeLevel::Base;
            }
            parse_normalize_level(v).unwrap_or_else(|| {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = PATH_NORMALIZE,
                    value = v,
                    "unknown path-normalize value — falling back to base"
                );
                issue!(
                    PATH_NORMALIZE,
                    "unknown path-normalize value — falling back to base"
                );
                NormalizeLevel::Base
            })
        });

        // ── Circuit breaker (#282) ────────────────────────────────────────────
        let circuit_breaker = traffic_policy::parse_circuit_breaker(ann, route_id, &mut diag);

        (
            Self {
                timeouts: RouteTimeouts {
                    request: None,
                    backend_request: None,
                    connect,
                    read,
                    send,
                },
                retry,
                rewrite,
                use_regex,
                request_headers,
                response_headers,
                redirect,
                ssl_redirect,
                ssl_redirect_code,
                max_body_size,
                allow_source_range,
                deny_source_range,
                session_affinity,
                rate_limit,
                auth_basic,
                auth_ext,
                auth_jwt,
                mirror_target,
                keepalive_timeout,
                compression,
                forwarded_for,
                load_balance,
                path_normalize,
                circuit_breaker,
            },
            diag,
        )
    }
}

/// Parse a `path-normalize` annotation value to a [`NormalizeLevel`].
///
/// Accepts `base`, `merge-slashes`, `decode-and-merge-slashes`
/// (ASCII-case-insensitive).  Returns `None` for unrecognized values; the
/// caller emits a `WARN` and falls back to `Base`.  `none` is intentionally
/// *not* accepted here — it was dropped in #483 (it disabled normalization);
/// the caller detects it before delegating and emits a dedicated migration
/// warning.
#[must_use]
pub fn parse_normalize_level(s: &str) -> Option<NormalizeLevel> {
    match s.trim().to_ascii_lowercase().as_str() {
        "base" => Some(NormalizeLevel::Base),
        "merge-slashes" => Some(NormalizeLevel::MergeSlashes),
        "decode-and-merge-slashes" => Some(NormalizeLevel::DecodeAndMergeSlashes),
        _ => None,
    }
}

/// Build a [`HeaderMod`] from the three `add`/`set`/`remove` annotation keys for one
/// modifier group (request or response).  Returns `None` when none of the three keys
/// are present, or when [`HeaderMod::parse`] rejects the collected values (emits a
/// contextual `WARN`, pushes an [`AnnotationIssue`], and drops the entire modifier so
/// the Ingress keeps serving).
fn build_header_mod(
    ann: &BTreeMap<String, String>,
    route_id: &str,
    add_key: &'static str,
    set_key: &'static str,
    remove_key: &'static str,
    label: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<HeaderMod> {
    let has_any = [add_key, set_key, remove_key]
        .iter()
        .any(|k| get(ann, k).is_some());
    if !has_any {
        return None;
    }
    let add_pairs = get(ann, add_key)
        .map(parse_header_pairs)
        .unwrap_or_default();
    let set_pairs = get(ann, set_key)
        .map(parse_header_pairs)
        .unwrap_or_default();
    let remove_names = get(ann, remove_key)
        .map(parse_header_names)
        .unwrap_or_default();
    let add: Vec<(&str, &str)> = add_pairs
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let set: Vec<(&str, &str)> = set_pairs
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let remove: Vec<&str> = remove_names.iter().map(String::as_str).collect();
    match HeaderMod::parse(&add, &set, &remove) {
        Ok(hm) => Some(hm),
        Err(e) => {
            tracing::warn!(
                ingress = %route_id,
                error = %e,
                label,
                "invalid header annotation — skipping header modifier"
            );
            // Use the set key as the representative annotation key for the issue
            // (the annotation group is named by the most specific key the user set).
            let rep_key = if get(ann, set_key).is_some() {
                set_key
            } else if get(ann, add_key).is_some() {
                add_key
            } else {
                remove_key
            };
            diag.push(AnnotationIssue {
                annotation: rep_key,
                message: format!("invalid header annotation — skipping header modifier: {e}"),
            });
            None
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ann(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ── get() ─────────────────────────────────────────────────────────────────

    #[test]
    fn get_returns_value_when_present() {
        let m = ann(&[(CONNECT_TIMEOUT, "5s")]);
        assert_eq!(get(&m, CONNECT_TIMEOUT), Some("5s"));
    }

    #[test]
    fn get_returns_none_when_absent() {
        let m = BTreeMap::new();
        assert_eq!(get(&m, CONNECT_TIMEOUT), None);
    }

    // ── parse_bool() ──────────────────────────────────────────────────────────

    #[test]
    fn parse_bool_valid() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("TRUE"), Some(true));
        assert_eq!(parse_bool("  False  "), Some(false));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_bool_invalid_warns() {
        assert_eq!(parse_bool("yes"), None);
        assert!(logs_contain("invalid boolean annotation value"));
    }

    // ── IngressAnnotations::parse() ───────────────────────────────────────────

    #[test]
    fn parse_returns_defaults_when_no_annotations() {
        let (a, _) = IngressAnnotations::parse(None, "default/test");
        assert!(a.timeouts.connect.is_none());
        assert!(a.retry.is_none());
        assert!(a.rewrite.is_none());
    }

    #[test]
    fn parse_timeout_annotations() {
        let m = ann(&[
            (CONNECT_TIMEOUT, "5s"),
            (READ_TIMEOUT, "30s"),
            (SEND_TIMEOUT, "10s"),
        ]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.timeouts.connect, Some(Duration::from_secs(5)));
        assert_eq!(a.timeouts.read, Some(Duration::from_secs(30)));
        assert_eq!(a.timeouts.send, Some(Duration::from_secs(10)));
        assert!(a.timeouts.request.is_none());
        assert!(a.timeouts.backend_request.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_invalid_timeout_warns_and_uses_default() {
        let m = ann(&[(CONNECT_TIMEOUT, "not-a-duration")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.timeouts.connect.is_none());
        assert!(logs_contain("invalid duration — using default"));
    }

    #[test]
    fn parse_retry_valid_ref() {
        let m = ann(&[(traffic_policy::RETRY, "retry-ns/my-retry")]);
        let (a, diag) = IngressAnnotations::parse(Some(&m), "default/test");
        let r = a.retry.expect("retry must parse");
        assert_eq!(r.namespace, "retry-ns");
        assert_eq!(r.name, "my-retry");
        assert!(diag.is_empty());
    }

    #[test]
    fn parse_retry_absent_is_none() {
        let (a, diag) = IngressAnnotations::parse(None, "default/test");
        assert!(a.retry.is_none());
        assert!(diag.is_empty());
    }

    #[test]
    fn parse_retry_malformed_warns_and_disables() {
        let m = ann(&[(traffic_policy::RETRY, "no-slash-here")]);
        let (a, diag) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.retry.is_none());
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, traffic_policy::RETRY);
    }

    #[test]
    fn parse_rate_limit_valid_ref() {
        let m = ann(&[(traffic_policy::RATE_LIMIT, "rl-ns/my-limit")]);
        let (a, diag) = IngressAnnotations::parse(Some(&m), "default/test");
        let r = a.rate_limit.expect("rate_limit must parse");
        assert_eq!(r.namespace, "rl-ns");
        assert_eq!(r.name, "my-limit");
        assert!(diag.is_empty());
    }

    #[test]
    fn parse_rate_limit_absent_is_none() {
        let (a, diag) = IngressAnnotations::parse(None, "default/test");
        assert!(a.rate_limit.is_none());
        assert!(diag.is_empty());
    }

    #[test]
    fn parse_rate_limit_malformed_warns_and_disables() {
        let m = ann(&[(traffic_policy::RATE_LIMIT, "no-slash-here")]);
        let (a, diag) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.rate_limit.is_none());
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, traffic_policy::RATE_LIMIT);
    }

    #[test]
    fn parse_use_regex_true() {
        let m = ann(&[(USE_REGEX, "true")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.use_regex);
    }

    #[test]
    fn parse_use_regex_false() {
        let m = ann(&[(USE_REGEX, "false")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.use_regex);
    }

    #[test]
    fn parse_use_regex_absent_defaults_false() {
        let (a, _) = IngressAnnotations::parse(None, "default/test");
        assert!(!a.use_regex);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_use_regex_invalid_warns_and_defaults_false() {
        let m = ann(&[(USE_REGEX, "1")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.use_regex);
        assert!(logs_contain("treating use-regex as false"));
    }

    #[test]
    fn parse_rewrite_target() {
        let m = ann(&[(REWRITE_TARGET, "/api")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        match a.rewrite {
            Some(PathModifier::ReplaceFullPath(s)) => assert_eq!(s, "/api"),
            _ => panic!("expected ReplaceFullPath"),
        }
    }

    #[test]
    fn parse_request_header_modifier_set_add_remove() {
        let m = ann(&[
            (REQUEST_HEADER_SET, "X-Set: set-value"),
            (REQUEST_HEADER_ADD, "X-Add: add-value"),
            (REQUEST_HEADER_REMOVE, "X-Remove"),
        ]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        let hm = a
            .request_headers
            .as_ref()
            .expect("expected request_headers");
        assert_eq!(hm.set.len(), 1);
        assert_eq!(hm.add.len(), 1);
        assert_eq!(hm.remove.len(), 1);
        let _ = FilterAction::RequestHeaderModifier(hm.clone());
    }

    #[test]
    fn parse_response_header_modifier_set_add_remove() {
        let m = ann(&[
            (RESPONSE_HEADER_SET, "X-Resp-Set: v1"),
            (RESPONSE_HEADER_ADD, "X-Resp-Add: v2"),
            (RESPONSE_HEADER_REMOVE, "X-Resp-Remove"),
        ]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        let hm = a
            .response_headers
            .as_ref()
            .expect("expected response_headers");
        assert_eq!(hm.set.len(), 1);
        assert_eq!(hm.add.len(), 1);
        assert_eq!(hm.remove.len(), 1);
    }

    #[test]
    fn parse_request_header_absent_when_no_keys() {
        let (a, _) = IngressAnnotations::parse(None, "default/test");
        assert!(a.request_headers.is_none());
        assert!(a.response_headers.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_request_header_invalid_name_warns_and_drops_modifier() {
        let m = ann(&[(REQUEST_HEADER_SET, "X-Bad\x01Name: value")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.request_headers.is_none());
        assert!(logs_contain("invalid header annotation"));
    }

    #[test]
    fn parse_request_header_multi_line_value_with_comma_preserved() {
        let m = ann(&[(
            REQUEST_HEADER_SET,
            "Cache-Control: no-cache, no-store\nX-Foo: bar",
        )]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        let hm = a
            .request_headers
            .as_ref()
            .expect("expected request_headers");
        assert_eq!(hm.set.len(), 2);
    }

    #[test]
    fn parse_redirect_any_key_activates_action() {
        let m = ann(&[(REDIRECT_SCHEME, "https")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.redirect.is_some());
    }

    #[test]
    fn parse_redirect_no_keys_is_none() {
        let (a, _) = IngressAnnotations::parse(None, "default/test");
        assert!(a.redirect.is_none());
    }

    #[test]
    fn parse_redirect_full_annotation_set() {
        let m = ann(&[
            (REDIRECT_SCHEME, "https"),
            (REDIRECT_HOSTNAME, "new.example.com"),
            (REDIRECT_PORT, "8443"),
            (REDIRECT_PATH, "/new-path"),
            (REDIRECT_STATUS_CODE, "301"),
        ]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        match a.redirect {
            Some(FilterAction::RequestRedirect {
                scheme,
                hostname,
                port,
                status_code,
                path,
            }) => {
                assert_eq!(scheme.as_deref(), Some("https"));
                assert_eq!(hostname.as_deref(), Some("new.example.com"));
                assert_eq!(port, Some(8443));
                assert_eq!(status_code, 301);
                assert!(matches!(path, Some(PathModifier::ReplaceFullPath(_))));
            }
            _ => panic!("expected RequestRedirect"),
        }
    }

    #[test]
    fn parse_redirect_absent_fields_default_to_none() {
        let m = ann(&[(REDIRECT_STATUS_CODE, "307")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        match a.redirect {
            Some(FilterAction::RequestRedirect {
                scheme,
                hostname,
                port,
                status_code,
                path,
            }) => {
                assert!(scheme.is_none());
                assert!(hostname.is_none());
                assert!(port.is_none());
                assert_eq!(status_code, 307);
                assert!(path.is_none());
            }
            _ => panic!("expected RequestRedirect"),
        }
    }

    #[test]
    fn parse_redirect_missing_status_code_defaults_to_302() {
        let m = ann(&[(REDIRECT_HOSTNAME, "example.com")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        match a.redirect {
            Some(FilterAction::RequestRedirect { status_code, .. }) => {
                assert_eq!(status_code, 302);
            }
            _ => panic!("expected RequestRedirect"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_redirect_invalid_scheme_warns_and_uses_none() {
        let m = ann(&[(REDIRECT_SCHEME, "ftp")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        match a.redirect {
            Some(FilterAction::RequestRedirect { scheme, .. }) => {
                assert!(scheme.is_none());
                assert!(logs_contain("invalid redirect-scheme"));
            }
            _ => panic!("expected RequestRedirect"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_redirect_invalid_port_warns_and_uses_none() {
        let m = ann(&[(REDIRECT_PORT, "99999")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        match a.redirect {
            Some(FilterAction::RequestRedirect { port, .. }) => {
                assert!(port.is_none());
                assert!(logs_contain("invalid redirect-port"));
            }
            _ => panic!("expected RequestRedirect"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_redirect_invalid_status_code_warns_and_defaults_302() {
        let m = ann(&[(REDIRECT_STATUS_CODE, "200")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        match a.redirect {
            Some(FilterAction::RequestRedirect { status_code, .. }) => {
                assert_eq!(status_code, 302);
                assert!(logs_contain("invalid redirect-status-code"));
            }
            _ => panic!("expected RequestRedirect"),
        }
    }

    #[test]
    fn parse_ssl_redirect_true() {
        let m = ann(&[(SSL_REDIRECT, "true")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.ssl_redirect);
    }

    #[test]
    fn parse_ssl_redirect_false() {
        let m = ann(&[(SSL_REDIRECT, "false")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.ssl_redirect);
    }

    #[test]
    fn parse_ssl_redirect_absent_defaults_false() {
        let (a, _) = IngressAnnotations::parse(None, "default/test");
        assert!(!a.ssl_redirect);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_ssl_redirect_invalid_warns_and_defaults_false() {
        let m = ann(&[(SSL_REDIRECT, "yes")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.ssl_redirect);
        assert!(logs_contain("treating ssl-redirect as false"));
    }

    #[test]
    fn parse_ssl_redirect_code_valid() {
        let m = ann(&[(SSL_REDIRECT_CODE, "301")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.ssl_redirect_code, Some(301));
    }

    #[test]
    fn parse_ssl_redirect_code_absent_is_none() {
        let (a, _) = IngressAnnotations::parse(None, "default/test");
        assert!(a.ssl_redirect_code.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_ssl_redirect_code_invalid_warns_and_is_none() {
        let m = ann(&[(SSL_REDIRECT_CODE, "500")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.ssl_redirect_code.is_none());
        assert!(logs_contain("invalid ssl-redirect-code"));
    }

    #[test]
    fn parse_max_body_size_valid() {
        let m = ann(&[(MAX_BODY_SIZE, "8m")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.max_body_size, Some(8 * 1024 * 1024));
    }

    #[test]
    fn parse_max_body_size_absent_is_none() {
        let (a, _) = IngressAnnotations::parse(None, "default/test");
        assert!(a.max_body_size.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_max_body_size_invalid_warns_and_fails_open() {
        let m = ann(&[(MAX_BODY_SIZE, "garbage")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.max_body_size.is_none());
        assert!(logs_contain("invalid max-body-size"));
    }

    // ── path-normalize (#280) ─────────────────────────────────────────────────

    #[test]
    fn parse_normalize_level_all_variants() {
        assert_eq!(parse_normalize_level("base"), Some(NormalizeLevel::Base));
        assert_eq!(
            parse_normalize_level("merge-slashes"),
            Some(NormalizeLevel::MergeSlashes)
        );
        assert_eq!(
            parse_normalize_level("decode-and-merge-slashes"),
            Some(NormalizeLevel::DecodeAndMergeSlashes)
        );
    }

    #[test]
    fn parse_normalize_level_case_insensitive() {
        assert_eq!(parse_normalize_level("Base"), Some(NormalizeLevel::Base));
        assert_eq!(
            parse_normalize_level("Merge-Slashes"),
            Some(NormalizeLevel::MergeSlashes)
        );
    }

    #[test]
    fn parse_normalize_level_unknown_returns_none() {
        assert!(parse_normalize_level("aggressive").is_none());
        assert!(parse_normalize_level("").is_none());
        // `none` was dropped in #483 — the parser no longer recognises it; the
        // call site detects it separately and falls back to `base`.
        assert!(parse_normalize_level("none").is_none());
    }

    #[test]
    fn parse_annotation_path_normalize_absent_is_none() {
        let (a, _) = IngressAnnotations::parse(None, "default/test");
        assert!(a.path_normalize.is_none());
    }

    #[test]
    fn parse_annotation_path_normalize_base() {
        let m = ann(&[(PATH_NORMALIZE, "base")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.path_normalize, Some(NormalizeLevel::Base));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_annotation_path_normalize_none_warns_and_falls_back_to_base() {
        // #483: `none` is dropped — it warns and resolves to the secure `base`
        // floor, never disabling normalization.
        let m = ann(&[(PATH_NORMALIZE, "none")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.path_normalize, Some(NormalizeLevel::Base));
        assert!(logs_contain("no longer supported"));
    }

    #[test]
    fn parse_annotation_path_normalize_merge_slashes() {
        let m = ann(&[(PATH_NORMALIZE, "merge-slashes")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.path_normalize, Some(NormalizeLevel::MergeSlashes));
    }

    #[test]
    fn parse_annotation_path_normalize_decode_and_merge() {
        let m = ann(&[(PATH_NORMALIZE, "decode-and-merge-slashes")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(
            a.path_normalize,
            Some(NormalizeLevel::DecodeAndMergeSlashes)
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_annotation_path_normalize_unknown_warns_and_falls_back_to_base() {
        let m = ann(&[(PATH_NORMALIZE, "aggressive")]);
        let (a, _) = IngressAnnotations::parse(Some(&m), "default/test");
        // Unknown value → explicit Base (not absent)
        assert_eq!(a.path_normalize, Some(NormalizeLevel::Base));
        assert!(logs_contain("unknown path-normalize value"));
    }

    // ── auth-jwt (#441) ──────────────────────────────────────────────────────

    #[test]
    fn parse_auth_jwt_valid_ref() {
        let m = ann(&[(auth::AUTH_JWT, "auth-ns/my-jwt")]);
        let (a, diag) = IngressAnnotations::parse(Some(&m), "default/test");
        let r = a.auth_jwt.expect("auth_jwt must parse");
        assert_eq!(r.namespace, "auth-ns");
        assert_eq!(r.name, "my-jwt");
        assert!(diag.is_empty());
    }

    #[test]
    fn parse_auth_jwt_absent_is_none() {
        let (a, diag) = IngressAnnotations::parse(None, "default/test");
        assert!(a.auth_jwt.is_none());
        assert!(diag.is_empty());
    }

    #[test]
    fn parse_auth_jwt_malformed_warns_and_disables() {
        let m = ann(&[(auth::AUTH_JWT, "no-slash-here")]);
        let (a, diag) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.auth_jwt.is_none());
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, auth::AUTH_JWT);
    }

    // ── compression (#550) ────────────────────────────────────────────────────

    #[test]
    fn parse_compression_valid_ref() {
        let m = ann(&[(traffic_policy::COMPRESSION, "compress-ns/my-compression")]);
        let (a, diag) = IngressAnnotations::parse(Some(&m), "default/test");
        let r = a.compression.expect("compression must parse");
        assert_eq!(r.namespace, "compress-ns");
        assert_eq!(r.name, "my-compression");
        assert!(diag.is_empty());
    }

    #[test]
    fn parse_compression_absent_is_none() {
        let (a, diag) = IngressAnnotations::parse(None, "default/test");
        assert!(a.compression.is_none());
        assert!(diag.is_empty());
    }

    #[test]
    fn parse_compression_malformed_warns_and_disables() {
        let m = ann(&[(traffic_policy::COMPRESSION, "no-slash-here")]);
        let (a, diag) = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.compression.is_none());
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, traffic_policy::COMPRESSION);
    }
}
