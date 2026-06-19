//! Annotation key constants and parser for the `ingress.coxswain-labs.dev/*` namespace.
//!
//! The module is split into domain submodules re-exported here:
//!
//! - [`traffic_policy`] — timeout, retry, and backend-protocol annotations.
//! - [`routing`] — path rewrite and regex opt-in annotations.
//! - [`filters`] — request/response header modifiers, redirect, and ssl-redirect annotations.
//! - [`security`] — edge access control (source-IP allow-list, rate limiting, auth).
//! - [`caching`] — RFC 7234 response-cache opt-in.
//! - [`session`] — sticky-session (session-affinity) binding.
//!
//! The top-level [`IngressAnnotations::parse`] function is called once per Ingress in
//! [`super::reconcile`] and threads the results into every rule/path entry.
//!
//! ## WARN + default on bad values
//!
//! Every parse helper emits a structured `WARN` tracing event on invalid input and
//! returns `None` so the annotation is treated as absent — the whole Ingress keeps
//! its routes; only that annotation's effect is suppressed.

mod caching;
mod filters;
mod routing;
pub(crate) mod security;
mod session;
pub(crate) mod traffic_policy;

pub use caching::*;
pub use filters::*;
pub use routing::*;
pub use security::*;
pub use session::*;
pub use traffic_policy::*;

use coxswain_core::routing::{
    BackendProtocol, CompressionConfig, FilterAction, ForwardedForConfig, HeaderMod, PathModifier,
    RateLimitConfig, RetryPolicy, RouteTimeouts, SessionAffinity,
};
use security::AuthAnnotation;
use std::collections::BTreeMap;

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
/// Emits a structured `WARN` on any other value and returns `None` so the caller
/// falls back to the default (annotation treated as absent).
#[must_use]
pub fn parse_bool(s: &str) -> Option<bool> {
    match s.trim() {
        v if v.eq_ignore_ascii_case("true") => Some(true),
        v if v.eq_ignore_ascii_case("false") => Some(false),
        _ => {
            tracing::warn!(
                value = s,
                "invalid boolean annotation value (expected true/false)"
            );
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
    /// Retry policy from `max-retries` + `retry-on`.
    pub retries: RetryPolicy,
    /// Path rewrite from `rewrite-target` — emitted as a `FilterAction::UrlRewrite`.
    /// Holds the literal [`PathModifier::ReplaceFullPath`]; on a regex path the
    /// reconciler rebuilds it as [`PathModifier::RegexReplace`] against that path's
    /// own compiled pattern so capture groups (`$1`…`$n`) resolve per-path.
    pub rewrite: Option<PathModifier>,
    /// Explicit backend-protocol override, or `None` to keep the `appProtocol`-derived default.
    pub backend_protocol: Option<BackendProtocol>,
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
    /// RFC 7234 response-cache opt-in from `cache-enabled` (#40).
    /// `false` (the default, or an invalid value) leaves caching off.
    pub cache_enabled: bool,
    /// Sticky-session binding from the `session-*` annotations (#15).
    /// `None` (the default, or an invalid/incomplete value) keeps round-robin.
    pub session_affinity: Option<SessionAffinity>,
    /// Per-route rate-limiting config from the `rate-limit-*` annotations (#25).
    /// `None` (the default, or when `rate-limit-rps` is absent/invalid) disables
    /// rate limiting for the route (fail-open).
    pub rate_limit: Option<RateLimitConfig>,
    /// Auth configuration from the `auth-*` annotations (#24), in intermediate
    /// (pre-resolved) form.  `None` when neither `auth-url` nor
    /// `auth-basic-secret` is present.  The reconciler resolves `Basic(SecretRef)`
    /// into [`IngressAuthConfig`][coxswain_core::routing::IngressAuthConfig] by
    /// looking up the labeled htpasswd Secret.
    pub auth: Option<AuthAnnotation>,
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
    /// Response compression config from the `compression-*` annotations (#270).
    /// `None` when neither `compression-gzip` nor `compression-brotli` is `"true"`.
    pub compression: Option<CompressionConfig>,
    /// Trusted-proxy forwarded-IP config from the `trust-forwarded-for` family (#271).
    /// `None` when `trust-forwarded-for` is absent or `"false"`.
    pub forwarded_for: Option<ForwardedForConfig>,
}

impl IngressAnnotations {
    /// Parse all `ingress.coxswain-labs.dev/*` annotations from the Ingress metadata map.
    ///
    /// `route_id` is used as context in WARN messages so operators can trace the
    /// offending Ingress without digging into log correlations.
    ///
    /// Invalid values emit a `WARN` and fall back to the absent / default behaviour;
    /// the Ingress is never rejected.
    pub(super) fn parse(annotations: Option<&BTreeMap<String, String>>, route_id: &str) -> Self {
        let Some(ann) = annotations else {
            return Self::default();
        };

        // ── Timeouts ──────────────────────────────────────────────────────────
        let connect = get(ann, CONNECT_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = CONNECT_TIMEOUT,
                    value = v,
                    "invalid duration — using default"
                );
            }
            d
        });
        let read = get(ann, READ_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = READ_TIMEOUT,
                    value = v,
                    "invalid duration — using default"
                );
            }
            d
        });
        let send = get(ann, SEND_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = SEND_TIMEOUT,
                    value = v,
                    "invalid duration — using default"
                );
            }
            d
        });

        // ── Retries ───────────────────────────────────────────────────────────
        let max_retries = get(ann, MAX_RETRIES).and_then(|v| {
            let n = parse_u32(v);
            if n.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = MAX_RETRIES,
                    value = v,
                    "invalid integer — using default (no retries)"
                );
            }
            n
        });
        let retry_on = get(ann, RETRY_ON).map(parse_retry_on);
        let retries = match (max_retries, retry_on) {
            (Some(n), Some(on)) => RetryPolicy::new(n, on),
            (Some(n), None) => {
                tracing::warn!(
                    ingress = %route_id,
                    max_retries = n,
                    "max-retries set but retry-on is absent — retries disabled"
                );
                RetryPolicy::default()
            }
            (None, Some(_)) => {
                tracing::warn!(
                    ingress = %route_id,
                    "retry-on set but max-retries is absent — retries disabled"
                );
                RetryPolicy::default()
            }
            (None, None) => RetryPolicy::default(),
        };

        // ── Path rewrite ──────────────────────────────────────────────────────
        let rewrite =
            get(ann, REWRITE_TARGET).map(|v| PathModifier::ReplaceFullPath(v.to_string()));

        // ── Regex path matching opt-in ────────────────────────────────────────
        let use_regex = get(ann, USE_REGEX)
            .and_then(|v| {
                let b = parse_bool(v);
                if b.is_none() {
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = USE_REGEX,
                        value = v,
                        "invalid boolean — treating use-regex as false"
                    );
                }
                b
            })
            .unwrap_or(false);

        // ── Backend protocol ──────────────────────────────────────────────────
        let backend_protocol = get(ann, BACKEND_PROTOCOL).and_then(|v| {
            let p = parse_backend_protocol(v);
            if p.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = BACKEND_PROTOCOL,
                    value = v,
                    "unknown protocol — using appProtocol-derived default"
                );
            }
            p
        });

        // ── Request header modifier (#79) ─────────────────────────────────────
        let request_headers = build_header_mod(
            ann,
            route_id,
            REQUEST_HEADER_ADD,
            REQUEST_HEADER_SET,
            REQUEST_HEADER_REMOVE,
            "request-header",
        );

        // ── Response header modifier (#79) ────────────────────────────────────
        let response_headers = build_header_mod(
            ann,
            route_id,
            RESPONSE_HEADER_ADD,
            RESPONSE_HEADER_SET,
            RESPONSE_HEADER_REMOVE,
            "response-header",
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
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = REDIRECT_SCHEME,
                        value = v,
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
                    None
                }
            });
            let path =
                get(ann, REDIRECT_PATH).map(|v| PathModifier::ReplaceFullPath(v.to_string()));
            let status_code = get(ann, REDIRECT_STATUS_CODE)
                .and_then(|v| {
                    let c = parse_redirect_status_code(v);
                    if c.is_none() {
                        tracing::warn!(
                            ingress = %route_id,
                            annotation = REDIRECT_STATUS_CODE,
                            value = v,
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
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = SSL_REDIRECT,
                        value = v,
                        "invalid boolean — treating ssl-redirect as false"
                    );
                }
                b
            })
            .unwrap_or(false);

        let ssl_redirect_code = get(ann, SSL_REDIRECT_CODE).and_then(|v| {
            let c = parse_redirect_status_code(v);
            if c.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = SSL_REDIRECT_CODE,
                    value = v,
                    "invalid ssl-redirect-code — using default 308"
                );
            }
            c
        });

        // ── Max body size (#263) ──────────────────────────────────────────────
        let max_body_size = get(ann, MAX_BODY_SIZE).and_then(|v| {
            let n = parse_byte_size(v);
            if n.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = MAX_BODY_SIZE,
                    value = v,
                    "invalid max-body-size — no limit applied"
                );
            }
            n
        });

        // ── Allow-source-range (#264) ─────────────────────────────────────────
        let allow_source_range = get(ann, ALLOW_SOURCE_RANGE).and_then(parse_allow_source_range);

        // ── Deny-source-range (#268) ──────────────────────────────────────────
        let deny_source_range = get(ann, DENY_SOURCE_RANGE).and_then(parse_deny_source_range);

        // ── Response caching (#40) ────────────────────────────────────────────
        let cache_enabled = get(ann, CACHE_ENABLED)
            .and_then(parse_cache_enabled)
            .unwrap_or(false);

        // ── Session affinity (#15) ────────────────────────────────────────────
        let session_affinity = parse_session_affinity(ann, route_id);

        // ── Rate limiting (#25) ───────────────────────────────────────────────
        let rate_limit = parse_rate_limit(
            get(ann, RATE_LIMIT_RPS),
            get(ann, RATE_LIMIT_BURST),
            get(ann, RATE_LIMIT_BY),
            route_id,
        );

        // ── External / basic auth (#24) ───────────────────────────────────────
        let auth = security::parse_auth(ann, route_id);

        // ── Mirror target (#283) ──────────────────────────────────────────────
        let mirror_target = get(ann, MIRROR_TARGET).and_then(|v| {
            let r = traffic_policy::parse_mirror_target(v);
            if r.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = MIRROR_TARGET,
                    value = v,
                    "invalid mirror-target — mirror disabled"
                );
            }
            r
        });

        // ── Upstream keepalive timeout (#266) ─────────────────────────────────
        let keepalive_timeout = get(ann, UPSTREAM_KEEPALIVE_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = UPSTREAM_KEEPALIVE_TIMEOUT,
                    value = v,
                    "invalid duration — using Pingora default keepalive timeout"
                );
            }
            d
        });

        // ── Response compression (#270) ───────────────────────────────────────
        let compression = traffic_policy::parse_compression(ann, route_id);

        // ── Trusted-proxy forwarded-IP headers (#271) ─────────────────────────
        let forwarded_for = security::parse_forwarded_for(ann, route_id);

        Self {
            timeouts: RouteTimeouts {
                request: None,
                backend_request: None,
                connect,
                read,
                send,
            },
            retries,
            rewrite,
            backend_protocol,
            use_regex,
            request_headers,
            response_headers,
            redirect,
            ssl_redirect,
            ssl_redirect_code,
            max_body_size,
            allow_source_range,
            deny_source_range,
            cache_enabled,
            session_affinity,
            rate_limit,
            auth,
            mirror_target,
            keepalive_timeout,
            compression,
            forwarded_for,
        }
    }
}

/// Build a [`HeaderMod`] from the three `add`/`set`/`remove` annotation keys for one
/// modifier group (request or response).  Returns `None` when none of the three keys
/// are present, or when [`HeaderMod::parse`] rejects the collected values (emits a
/// contextual `WARN` and drops the entire modifier so the Ingress keeps serving).
fn build_header_mod(
    ann: &BTreeMap<String, String>,
    route_id: &str,
    add_key: &str,
    set_key: &str,
    remove_key: &str,
    label: &str,
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
        let a = IngressAnnotations::parse(None, "default/test");
        assert!(a.timeouts.connect.is_none());
        assert!(a.retries.is_disabled());
        assert!(a.rewrite.is_none());
        assert!(a.backend_protocol.is_none());
    }

    #[test]
    fn parse_timeout_annotations() {
        let m = ann(&[
            (CONNECT_TIMEOUT, "5s"),
            (READ_TIMEOUT, "30s"),
            (SEND_TIMEOUT, "10s"),
        ]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.timeouts.connect.is_none());
        assert!(logs_contain("invalid duration — using default"));
    }

    #[test]
    fn parse_retries_full() {
        use coxswain_core::routing::RetryOn;
        let m = ann(&[(MAX_RETRIES, "3"), (RETRY_ON, "connect-failure,timeout")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.retries.max_retries, 3);
        assert!(a.retries.on.contains(RetryOn::CONNECT_FAILURE));
        assert!(a.retries.on.contains(RetryOn::TIMEOUT));
        assert!(!a.retries.on.contains(RetryOn::HTTP_5XX));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_retries_max_without_on_warns_and_disables() {
        let m = ann(&[(MAX_RETRIES, "3")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.retries.is_disabled());
        assert!(logs_contain("retry-on is absent"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_retries_on_without_max_warns_and_disables() {
        let m = ann(&[(RETRY_ON, "5xx")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.retries.is_disabled());
        assert!(logs_contain("max-retries is absent"));
    }

    #[test]
    fn parse_use_regex_true() {
        let m = ann(&[(USE_REGEX, "true")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.use_regex);
    }

    #[test]
    fn parse_use_regex_false() {
        let m = ann(&[(USE_REGEX, "false")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.use_regex);
    }

    #[test]
    fn parse_use_regex_absent_defaults_false() {
        let a = IngressAnnotations::parse(None, "default/test");
        assert!(!a.use_regex);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_use_regex_invalid_warns_and_defaults_false() {
        let m = ann(&[(USE_REGEX, "1")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.use_regex);
        assert!(logs_contain("treating use-regex as false"));
    }

    #[test]
    fn parse_rewrite_target() {
        let m = ann(&[(REWRITE_TARGET, "/api")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        match a.rewrite {
            Some(PathModifier::ReplaceFullPath(s)) => assert_eq!(s, "/api"),
            _ => panic!("expected ReplaceFullPath"),
        }
    }

    #[test]
    fn parse_backend_protocol_https() {
        let m = ann(&[(BACKEND_PROTOCOL, "HTTPS")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.backend_protocol, Some(BackendProtocol::Https));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_backend_protocol_unknown_annotation_warns() {
        let m = ann(&[(BACKEND_PROTOCOL, "h2c")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.backend_protocol.is_none());
        assert!(logs_contain("unknown backend-protocol value"));
    }

    #[test]
    fn parse_request_header_modifier_set_add_remove() {
        let m = ann(&[
            (REQUEST_HEADER_SET, "X-Set: set-value"),
            (REQUEST_HEADER_ADD, "X-Add: add-value"),
            (REQUEST_HEADER_REMOVE, "X-Remove"),
        ]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(None, "default/test");
        assert!(a.request_headers.is_none());
        assert!(a.response_headers.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_request_header_invalid_name_warns_and_drops_modifier() {
        let m = ann(&[(REQUEST_HEADER_SET, "X-Bad\x01Name: value")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.request_headers.is_none());
        assert!(logs_contain("invalid header annotation"));
    }

    #[test]
    fn parse_request_header_multi_line_value_with_comma_preserved() {
        let m = ann(&[(
            REQUEST_HEADER_SET,
            "Cache-Control: no-cache, no-store\nX-Foo: bar",
        )]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        let hm = a
            .request_headers
            .as_ref()
            .expect("expected request_headers");
        assert_eq!(hm.set.len(), 2);
    }

    #[test]
    fn parse_redirect_any_key_activates_action() {
        let m = ann(&[(REDIRECT_SCHEME, "https")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.redirect.is_some());
    }

    #[test]
    fn parse_redirect_no_keys_is_none() {
        let a = IngressAnnotations::parse(None, "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
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
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.ssl_redirect);
    }

    #[test]
    fn parse_ssl_redirect_false() {
        let m = ann(&[(SSL_REDIRECT, "false")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.ssl_redirect);
    }

    #[test]
    fn parse_ssl_redirect_absent_defaults_false() {
        let a = IngressAnnotations::parse(None, "default/test");
        assert!(!a.ssl_redirect);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_ssl_redirect_invalid_warns_and_defaults_false() {
        let m = ann(&[(SSL_REDIRECT, "yes")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.ssl_redirect);
        assert!(logs_contain("treating ssl-redirect as false"));
    }

    #[test]
    fn parse_ssl_redirect_code_valid() {
        let m = ann(&[(SSL_REDIRECT_CODE, "301")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.ssl_redirect_code, Some(301));
    }

    #[test]
    fn parse_ssl_redirect_code_absent_is_none() {
        let a = IngressAnnotations::parse(None, "default/test");
        assert!(a.ssl_redirect_code.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_ssl_redirect_code_invalid_warns_and_is_none() {
        let m = ann(&[(SSL_REDIRECT_CODE, "500")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.ssl_redirect_code.is_none());
        assert!(logs_contain("invalid ssl-redirect-code"));
    }

    #[test]
    fn parse_max_body_size_valid() {
        let m = ann(&[(MAX_BODY_SIZE, "8m")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.max_body_size, Some(8 * 1024 * 1024));
    }

    #[test]
    fn parse_max_body_size_absent_is_none() {
        let a = IngressAnnotations::parse(None, "default/test");
        assert!(a.max_body_size.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_max_body_size_invalid_warns_and_fails_open() {
        let m = ann(&[(MAX_BODY_SIZE, "garbage")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.max_body_size.is_none());
        assert!(logs_contain("invalid max-body-size"));
    }

    #[test]
    fn parse_cache_enabled_true() {
        let m = ann(&[(CACHE_ENABLED, "true")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.cache_enabled);
    }

    #[test]
    fn parse_cache_enabled_false_and_absent_default_off() {
        let m = ann(&[(CACHE_ENABLED, "false")]);
        assert!(!IngressAnnotations::parse(Some(&m), "default/test").cache_enabled);
        assert!(!IngressAnnotations::parse(None, "default/test").cache_enabled);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_cache_enabled_invalid_warns_and_defaults_off() {
        let m = ann(&[(CACHE_ENABLED, "1")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(!a.cache_enabled);
        assert!(logs_contain("treating cache-enabled as false"));
    }
}
