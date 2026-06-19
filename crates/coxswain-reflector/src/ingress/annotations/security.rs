//! Edge access-control annotation constants and parse helpers.
//!
//! Covers source-IP allow-listing, rate limiting, external / basic
//! authentication (`auth-*` annotations, #24), and per-host client-certificate
//! mTLS (`auth-tls-*` annotations, #267).  Every helper emits a structured
//! `WARN` on invalid input and skips the offending token so a single typo never
//! rejects the whole Ingress.

/// Source-IP allow-list — comma-separated IPv4/IPv6 CIDR blocks (e.g.
/// `"10.0.0.0/8,192.168.1.0/24"`). Bare addresses without a prefix (`10.0.0.1`,
/// `2001:db8::1`) are accepted as host routes (`/32` / `/128`) for parity with
/// nginx-ingress's `whitelist-source-range`. Requests whose real client IP falls
/// outside every range are rejected with 403; absent/empty admits all source IPs.
pub const ALLOW_SOURCE_RANGE: &str = "ingress.coxswain-labs.dev/allow-source-range";

/// Source-IP block list — comma-separated IPv4/IPv6 CIDR blocks. A request whose
/// real client IP falls **inside** any listed range is rejected with 403 Forbidden.
/// Evaluated **before** `allow-source-range`: a denied IP is blocked even when the
/// allow-list would admit it. Absent/empty blocks nothing.
/// Bare addresses without a prefix are accepted as host routes (`/32` / `/128`).
pub const DENY_SOURCE_RANGE: &str = "ingress.coxswain-labs.dev/deny-source-range";

/// Sustained rate limit in requests per second. Must be a positive integer >= 1.
/// When absent or invalid, rate limiting is disabled for the route (fail-open).
pub const RATE_LIMIT_RPS: &str = "ingress.coxswain-labs.dev/rate-limit-rps";

/// Burst size above the sustained RPS — extra requests allowed when the client has
/// been idle. `0` (the default) means no burst above the sustained rate.
pub const RATE_LIMIT_BURST: &str = "ingress.coxswain-labs.dev/rate-limit-burst";

/// Rate-limit key selector. `"ip"` (default) — limit by real client IP;
/// `"header:Name"` — limit by the value of a request header named `Name`.
/// When absent, `"ip"` is used. When present but unparseable, WARN and fail-open.
pub const RATE_LIMIT_BY: &str = "ingress.coxswain-labs.dev/rate-limit-by";

/// Parse the `allow-source-range` value into a CIDR set.
///
/// Splits on `,`, trims, and parses each token as an [`ipnet::IpNet`]; a bare IP
/// without a prefix is promoted to a host network (`/32` / `/128`). Invalid
/// tokens emit a `WARN` and are skipped — the remaining valid ranges still apply.
/// Returns `None` when the value is empty or every token is unparseable, so the
/// caller treats the annotation as absent (admit all) rather than locking out
/// all traffic on a typo.
#[must_use]
pub fn parse_allow_source_range(s: &str) -> Option<Vec<ipnet::IpNet>> {
    parse_cidr_list(s, "allow-source-range")
}

/// Parse the `deny-source-range` value into a CIDR set.
///
/// Splits on `,`, trims, and parses each token as an [`ipnet::IpNet`]; a bare IP
/// without a prefix is promoted to a host network (`/32` / `/128`). Invalid
/// tokens emit a `WARN` and are skipped. Returns `None` when the value is empty
/// or every token is unparseable — the block list is treated as absent (block
/// nothing), so a typo never silently blocks all traffic.
#[must_use]
pub fn parse_deny_source_range(s: &str) -> Option<Vec<ipnet::IpNet>> {
    parse_cidr_list(s, "deny-source-range")
}

/// Shared CIDR-list parser used by both `parse_allow_source_range` and
/// `parse_deny_source_range`. `annotation` is the bare annotation suffix (e.g.
/// `"allow-source-range"`) used in the WARN message to name the source.
fn parse_cidr_list(s: &str, annotation: &str) -> Option<Vec<ipnet::IpNet>> {
    let nets: Vec<ipnet::IpNet> = s
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|token| match parse_cidr_or_host(token) {
            Some(net) => Some(net),
            None => {
                tracing::warn!(
                    token = token,
                    annotation = annotation,
                    "invalid CIDR — skipping token"
                );
                None
            }
        })
        .collect();
    if nets.is_empty() { None } else { Some(nets) }
}

/// Parse a single token as a CIDR block, falling back to a bare host address.
fn parse_cidr_or_host(token: &str) -> Option<ipnet::IpNet> {
    token.parse::<ipnet::IpNet>().ok().or_else(|| {
        token
            .parse::<std::net::IpAddr>()
            .ok()
            .map(ipnet::IpNet::from)
    })
}

/// Parse the three rate-limit annotations into a [`RateLimitConfig`].
///
/// Returns `None` (fail-open) when `rate-limit-rps` is absent or invalid. The
/// `burst` and `by` values use their defaults when absent; invalid values emit a
/// `WARN` and fall back to the default.
///
/// # Arguments
/// * `rps_val` — raw value of `rate-limit-rps` (may be `None` when annotation absent).
/// * `burst_val` — raw value of `rate-limit-burst`.
/// * `by_val` — raw value of `rate-limit-by`.
/// * `route_id` — forwarded from the parent `IngressAnnotations::parse` for log context.
#[must_use]
pub fn parse_rate_limit(
    rps_val: Option<&str>,
    burst_val: Option<&str>,
    by_val: Option<&str>,
    route_id: &str,
) -> Option<coxswain_core::routing::RateLimitConfig> {
    use coxswain_core::routing::{RateLimitConfig, RateLimitKey};
    use std::num::NonZeroU32;

    let rps_str = rps_val?;
    let rps: u32 = match rps_str.trim().parse() {
        Ok(n) if n > 0 => n,
        _ => {
            tracing::warn!(
                ingress = %route_id,
                annotation = RATE_LIMIT_RPS,
                value = rps_str,
                "invalid or zero rate-limit-rps — rate limiting disabled for route"
            );
            return None;
        }
    };
    let requests_per_second =
        NonZeroU32::new(rps).unwrap_or_else(|| panic!("invariant: rps > 0 checked above"));

    let burst: u32 = if let Some(s) = burst_val {
        match s.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = RATE_LIMIT_BURST,
                    value = s,
                    "invalid rate-limit-burst — using 0 (no burst)"
                );
                0
            }
        }
    } else {
        0
    };

    let key = if let Some(s) = by_val {
        match parse_rate_limit_by(s) {
            Some(k) => k,
            None => {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = RATE_LIMIT_BY,
                    value = s,
                    "invalid rate-limit-by — expected \"ip\" or \"header:Name\"; using ip"
                );
                RateLimitKey::ClientIp
            }
        }
    } else {
        RateLimitKey::ClientIp
    };

    Some(RateLimitConfig::new(requests_per_second, burst, key))
}

/// Parse a `rate-limit-by` value: `"ip"` or `"header:Name"`.
///
/// Returns `None` on unrecognised values; the caller logs and defaults to `ip`.
#[must_use]
fn parse_rate_limit_by(s: &str) -> Option<coxswain_core::routing::RateLimitKey> {
    use coxswain_core::routing::RateLimitKey;
    use std::sync::Arc;

    let s = s.trim();
    if s.eq_ignore_ascii_case("ip") {
        return Some(RateLimitKey::ClientIp);
    }
    if let Some(name) = s.strip_prefix("header:") {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        return Some(RateLimitKey::Header(Arc::from(name.to_ascii_lowercase())));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::RateLimitKey;

    #[test]
    fn parse_single_cidr() {
        // References ALLOW_SOURCE_RANGE to satisfy the annotation-coverage gate.
        let _ = ALLOW_SOURCE_RANGE;
        let nets = parse_allow_source_range("10.0.0.0/8").expect("one CIDR");
        assert_eq!(nets, vec!["10.0.0.0/8".parse().expect("valid")]);
    }

    #[test]
    fn parse_multiple_cidrs_trimmed() {
        let nets =
            parse_allow_source_range("10.0.0.0/8, 192.168.1.0/24 ,2001:db8::/32").expect("three");
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn parse_bare_ip_becomes_host_route() {
        let nets = parse_allow_source_range("10.0.0.1,2001:db8::1").expect("two host routes");
        assert_eq!(nets[0], "10.0.0.1/32".parse().expect("valid"));
        assert_eq!(nets[1], "2001:db8::1/128".parse().expect("valid"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_skips_invalid_keeps_valid() {
        let nets = parse_allow_source_range("10.0.0.0/8,not-a-cidr,192.168.0.0/16").expect("two");
        assert_eq!(nets.len(), 2);
        assert!(logs_contain("invalid CIDR"));
    }

    #[test]
    fn parse_all_invalid_is_none() {
        assert!(parse_allow_source_range("nope,also-nope").is_none());
    }

    #[test]
    fn parse_empty_is_none() {
        assert!(parse_allow_source_range("").is_none());
        assert!(parse_allow_source_range("  ,  ").is_none());
    }

    // ── deny-source-range ─────────────────────────────────────────────────────

    #[test]
    fn deny_parse_single_cidr() {
        // References DENY_SOURCE_RANGE to satisfy the annotation-coverage gate.
        let _ = DENY_SOURCE_RANGE;
        let nets = parse_deny_source_range("10.0.0.0/8").expect("one CIDR");
        assert_eq!(
            nets,
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().expect("valid")]
        );
    }

    #[test]
    fn deny_parse_multiple_cidrs_trimmed() {
        let nets =
            parse_deny_source_range("10.0.0.0/8, 192.168.1.0/24 ,2001:db8::/32").expect("three");
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn deny_parse_bare_ip_becomes_host_route() {
        let nets = parse_deny_source_range("10.0.0.1,2001:db8::1").expect("two host routes");
        assert_eq!(
            nets[0],
            "10.0.0.1/32".parse::<ipnet::IpNet>().expect("valid")
        );
        assert_eq!(
            nets[1],
            "2001:db8::1/128".parse::<ipnet::IpNet>().expect("valid")
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn deny_parse_skips_invalid_keeps_valid() {
        let nets = parse_deny_source_range("10.0.0.0/8,not-a-cidr,192.168.0.0/16").expect("two");
        assert_eq!(nets.len(), 2);
        assert!(logs_contain("invalid CIDR"));
    }

    #[test]
    fn deny_parse_all_invalid_is_none() {
        assert!(parse_deny_source_range("nope,also-nope").is_none());
    }

    #[test]
    fn deny_parse_empty_is_none() {
        assert!(parse_deny_source_range("").is_none());
        assert!(parse_deny_source_range("  ,  ").is_none());
    }

    // ── rate-limit annotation coverage ────────────────────────────────────────
    // Each const is referenced to satisfy scripts/check-annotation-coverage.sh.

    #[test]
    fn rate_limit_absent_rps_is_none() {
        let _ = RATE_LIMIT_RPS;
        let _ = RATE_LIMIT_BURST;
        let _ = RATE_LIMIT_BY;
        assert!(parse_rate_limit(None, None, None, "ns/test").is_none());
    }

    #[test]
    fn rate_limit_rps_zero_is_none() {
        assert!(parse_rate_limit(Some("0"), None, None, "ns/test").is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn rate_limit_invalid_rps_warns_and_is_none() {
        assert!(parse_rate_limit(Some("nope"), None, None, "ns/test").is_none());
        assert!(logs_contain("invalid or zero rate-limit-rps"));
    }

    #[test]
    fn rate_limit_basic_ip_config() {
        let cfg = parse_rate_limit(Some("10"), None, None, "ns/test").expect("valid");
        assert_eq!(cfg.requests_per_second.get(), 10);
        assert_eq!(cfg.burst, 0);
        assert_eq!(cfg.key, RateLimitKey::ClientIp);
    }

    #[test]
    fn rate_limit_with_burst() {
        let cfg = parse_rate_limit(Some("5"), Some("20"), None, "ns/test").expect("valid");
        assert_eq!(cfg.requests_per_second.get(), 5);
        assert_eq!(cfg.burst, 20);
    }

    #[test]
    #[tracing_test::traced_test]
    fn rate_limit_invalid_burst_defaults_to_zero() {
        let cfg = parse_rate_limit(Some("5"), Some("bad"), None, "ns/test").expect("valid");
        assert_eq!(cfg.burst, 0);
        assert!(logs_contain("invalid rate-limit-burst"));
    }

    #[test]
    fn rate_limit_by_ip_explicit() {
        let cfg = parse_rate_limit(Some("10"), None, Some("ip"), "ns/test").expect("valid");
        assert_eq!(cfg.key, RateLimitKey::ClientIp);
    }

    #[test]
    fn rate_limit_by_header() {
        let cfg =
            parse_rate_limit(Some("10"), None, Some("header:X-Api-Key"), "ns/test").expect("valid");
        assert_eq!(
            cfg.key,
            RateLimitKey::Header(std::sync::Arc::from("x-api-key"))
        );
    }

    #[test]
    fn rate_limit_by_header_name_is_lowercased() {
        let cfg = parse_rate_limit(Some("10"), None, Some("header:Authorization"), "ns/test")
            .expect("valid");
        assert_eq!(
            cfg.key,
            RateLimitKey::Header(std::sync::Arc::from("authorization"))
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn rate_limit_invalid_by_warns_defaults_to_ip() {
        let cfg =
            parse_rate_limit(Some("10"), None, Some("bad-selector"), "ns/test").expect("valid");
        assert_eq!(cfg.key, RateLimitKey::ClientIp);
        assert!(logs_contain("invalid rate-limit-by"));
    }

    #[test]
    fn rate_limit_by_header_empty_name_is_none() {
        assert!(parse_rate_limit_by("header:").is_none());
        assert!(parse_rate_limit_by("header:  ").is_none());
    }
}

// ── Auth annotations (#24) ───────────────────────────────────────────────────

/// Full URL of the external auth endpoint, e.g.
/// `"http://oauth2-proxy.auth.svc/oauth2/auth"`.  When present, the proxy
/// sends a sub-request (Envoy `ext_authz`-HTTP semantics); 2xx allows and the
/// original request continues; any other status code is returned to the client.
/// Mutually exclusive with `auth-basic-secret` — when both are present a `WARN`
/// is emitted and `auth-url` takes precedence.
pub const AUTH_URL: &str = "ingress.coxswain-labs.dev/auth-url";

/// Maximum time to wait for the auth service to respond before failing the
/// request with 503.  Format is a duration string (`"500ms"`, `"2s"`, etc.).
/// When absent or invalid the default of **2 s** is used.
pub const AUTH_TIMEOUT: &str = "ingress.coxswain-labs.dev/auth-timeout";

/// Comma-separated list of header names to copy from the auth *response* onto
/// the upstream *request* when the auth service returns 2xx.  Mirrors Envoy's
/// `allowed_upstream_headers` / Istio's `headersToUpstreamOnAllow`.
pub const AUTH_RESPONSE_HEADERS: &str = "ingress.coxswain-labs.dev/auth-response-headers";

/// When `"true"`, copy the `Set-Cookie` header from the auth *response* onto
/// the downstream *response* when the auth service denies the request.  Mirrors
/// Envoy's `allowed_client_headers` / Istio's `headersToDownstreamOnDeny`.
/// Enables IdP login-redirect flows (`302 + Set-Cookie`) without leaking other
/// auth-response headers to the client.
pub const AUTH_ALWAYS_SET_COOKIE: &str = "ingress.coxswain-labs.dev/auth-always-set-cookie";

/// Reference to an htpasswd [`Secret`] in `namespace/name` form, e.g.
/// `"default/my-htpasswd"`.  The Secret **must** carry the label
/// `ingress.coxswain-labs.dev/auth-basic: "true"` and store the htpasswd file
/// under the key `auth` (nginx convention).  A missing Secret, an unlabeled
/// Secret, or one without a parseable `auth` key causes the proxy to respond
/// with 503 (fail-closed) and emit a loud `WARN` naming the issue.
///
/// Mutually exclusive with `auth-url`.
pub const AUTH_BASIC_SECRET: &str = "ingress.coxswain-labs.dev/auth-basic-secret";

// ── Intermediate annotation representation (pre-reconcile) ──────────────────

/// A reference to a Kubernetes Secret in `namespace/name` form.
pub(crate) struct SecretRef {
    pub namespace: String,
    pub name: String,
}

/// Intermediate, pre-reconcile auth configuration parsed from the `auth-*`
/// annotations.  Secret references are resolved to credentials by
/// `IngressReconciler::reconcile`; only then does this become an
/// [`IngressAuthConfig`][coxswain_core::routing::IngressAuthConfig].
pub(crate) enum AuthAnnotation {
    /// Delegate auth to an external service (ext_authz HTTP).
    External {
        url: String,
        timeout: std::time::Duration,
        response_headers: Vec<String>,
        always_set_cookie: bool,
    },
    /// Validate `Authorization: Basic` against an htpasswd Secret.
    Basic(SecretRef),
}

// ── Parse helpers ────────────────────────────────────────────────────────────

/// Parse the `auth-*` annotation cluster into an [`AuthAnnotation`].
///
/// Returns `None` when neither `auth-url` nor `auth-basic-secret` is present.
/// When both are present, a `WARN` is emitted and `auth-url` wins.  Invalid
/// values for the optional knobs (`auth-timeout`, `auth-response-headers`,
/// `auth-always-set-cookie`) emit a `WARN` and fall back to safe defaults; the
/// whole auth block is still produced.
#[must_use]
pub(crate) fn parse_auth(
    annotations: &std::collections::BTreeMap<String, String>,
    route_id: &str,
) -> Option<AuthAnnotation> {
    use super::get;

    let url = get(annotations, AUTH_URL);
    let basic = get(annotations, AUTH_BASIC_SECRET);

    if url.is_some() && basic.is_some() {
        tracing::warn!(
            ingress = %route_id,
            "auth-url and auth-basic-secret are mutually exclusive — using auth-url"
        );
    }

    if let Some(u) = url {
        let timeout = get(annotations, AUTH_TIMEOUT)
            .and_then(|v| {
                let d = super::parse_duration(v);
                if d.is_none() {
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = AUTH_TIMEOUT,
                        value = v,
                        "invalid auth-timeout — using default 2s"
                    );
                }
                d
            })
            .unwrap_or_else(|| std::time::Duration::from_secs(2));

        let response_headers = get(annotations, AUTH_RESPONSE_HEADERS)
            .map(parse_auth_response_headers)
            .unwrap_or_default();

        let always_set_cookie = get(annotations, AUTH_ALWAYS_SET_COOKIE)
            .and_then(|v| {
                let b = super::parse_bool(v);
                if b.is_none() {
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = AUTH_ALWAYS_SET_COOKIE,
                        value = v,
                        "invalid auth-always-set-cookie — treating as false"
                    );
                }
                b
            })
            .unwrap_or(false);

        return Some(AuthAnnotation::External {
            url: u.to_string(),
            timeout,
            response_headers,
            always_set_cookie,
        });
    }

    if let Some(ref_str) = basic {
        match parse_secret_ref(ref_str) {
            Some(secret_ref) => return Some(AuthAnnotation::Basic(secret_ref)),
            None => {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = AUTH_BASIC_SECRET,
                    value = ref_str,
                    "invalid auth-basic-secret — expected \"namespace/name\" format; auth disabled"
                );
            }
        }
    }

    None
}

/// Parse a comma-separated list of response-header names to forward upstream.
///
/// Empty tokens are silently filtered. Header names are lower-cased for
/// case-insensitive comparison later.
fn parse_auth_response_headers(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// Parse a `namespace/name` reference.  Returns `None` when the value does not
/// contain exactly one `/` with non-empty parts on both sides.
fn parse_secret_ref(s: &str) -> Option<SecretRef> {
    let (ns, name) = s.split_once('/')?;
    let ns = ns.trim();
    let name = name.trim();
    if ns.is_empty() || name.is_empty() {
        return None;
    }
    Some(SecretRef {
        namespace: ns.to_string(),
        name: name.to_string(),
    })
}

/// Parse an htpasswd file from raw bytes into a list of [`BasicCredential`]s.
///
/// Lines starting with `#` and blank lines are skipped.  Each non-empty,
/// non-comment line must be `username:hash`.  Unsupported hash algorithms (MD5,
/// SHA-256, crypt, …) emit a `WARN` and are skipped — the remaining entries
/// still apply.  An empty or fully-unparseable file produces an empty `Vec`;
/// the caller (reconciler) maps that to [`IngressAuthConfig::Unavailable`] so
/// the proxy fails closed.
///
/// # Supported formats
///
/// - bcrypt: hash prefix `$2a$`, `$2b$`, or `$2y$`
/// - Apache SHA1: hash prefix `{SHA}` (base64-encoded SHA1 of the password)
#[must_use]
pub(crate) fn parse_htpasswd(data: &[u8]) -> Vec<coxswain_core::routing::BasicCredential> {
    use coxswain_core::routing::{BasicCredential, PasswordHash};

    let Ok(text) = std::str::from_utf8(data) else {
        tracing::warn!("htpasswd Secret data is not valid UTF-8 — no credentials loaded");
        return Vec::new();
    };

    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let Some((username, hash)) = line.split_once(':') else {
                tracing::warn!(line = line, "htpasswd line has no ':' separator — skipping");
                return None;
            };
            let username = username.trim();
            let hash = hash.trim();
            if username.is_empty() || hash.is_empty() {
                tracing::warn!(
                    line = line,
                    "htpasswd line has empty username or hash — skipping"
                );
                return None;
            }

            let password_hash = if hash.starts_with("$2a$")
                || hash.starts_with("$2b$")
                || hash.starts_with("$2y$")
            {
                PasswordHash::Bcrypt(hash.into())
            } else if hash.starts_with("{SHA}") {
                PasswordHash::Sha1(hash.into())
            } else {
                tracing::warn!(
                    username = username,
                    hash_prefix = &hash[..hash.len().min(6)],
                    "unsupported htpasswd hash algorithm — skipping entry (supported: bcrypt, SHA1)"
                );
                return None;
            };

            Some(BasicCredential::new(username, password_hash))
        })
        .collect()
}

#[cfg(test)]
mod auth_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ann(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ── Annotation const references (satisfies check-annotation-coverage.sh) ─

    #[test]
    fn auth_url_const_referenced() {
        let _ = AUTH_URL;
    }

    #[test]
    fn auth_timeout_const_referenced() {
        let _ = AUTH_TIMEOUT;
    }

    #[test]
    fn auth_response_headers_const_referenced() {
        let _ = AUTH_RESPONSE_HEADERS;
    }

    #[test]
    fn auth_always_set_cookie_const_referenced() {
        let _ = AUTH_ALWAYS_SET_COOKIE;
    }

    #[test]
    fn auth_basic_secret_const_referenced() {
        let _ = AUTH_BASIC_SECRET;
    }

    // ── parse_auth: ext_authz ─────────────────────────────────────────────────

    #[test]
    fn parse_auth_absent_is_none() {
        let m = ann(&[]);
        assert!(parse_auth(&m, "ns/test").is_none());
    }

    #[test]
    fn parse_auth_url_produces_external() {
        let m = ann(&[(AUTH_URL, "http://authsvc/check")]);
        match parse_auth(&m, "ns/test") {
            Some(AuthAnnotation::External { url, timeout, .. }) => {
                assert_eq!(url, "http://authsvc/check");
                assert_eq!(timeout, std::time::Duration::from_secs(2));
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn parse_auth_timeout_custom() {
        let m = ann(&[(AUTH_URL, "http://svc/"), (AUTH_TIMEOUT, "500ms")]);
        match parse_auth(&m, "ns/test") {
            Some(AuthAnnotation::External { timeout, .. }) => {
                assert_eq!(timeout, std::time::Duration::from_millis(500));
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_auth_invalid_timeout_warns_and_defaults_2s() {
        let m = ann(&[(AUTH_URL, "http://svc/"), (AUTH_TIMEOUT, "bad")]);
        match parse_auth(&m, "ns/test") {
            Some(AuthAnnotation::External { timeout, .. }) => {
                assert_eq!(timeout, std::time::Duration::from_secs(2));
                assert!(logs_contain("invalid auth-timeout"));
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn parse_auth_response_headers_list() {
        let m = ann(&[
            (AUTH_URL, "http://svc/"),
            (AUTH_RESPONSE_HEADERS, "X-User, X-Role ,x-tenant"),
        ]);
        match parse_auth(&m, "ns/test") {
            Some(AuthAnnotation::External {
                response_headers, ..
            }) => {
                assert_eq!(response_headers, vec!["x-user", "x-role", "x-tenant"]);
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn parse_auth_always_set_cookie_true() {
        let m = ann(&[(AUTH_URL, "http://svc/"), (AUTH_ALWAYS_SET_COOKIE, "true")]);
        match parse_auth(&m, "ns/test") {
            Some(AuthAnnotation::External {
                always_set_cookie, ..
            }) => assert!(always_set_cookie),
            _ => panic!("expected External"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_auth_invalid_always_set_cookie_warns_and_defaults_false() {
        let m = ann(&[(AUTH_URL, "http://svc/"), (AUTH_ALWAYS_SET_COOKIE, "yes")]);
        match parse_auth(&m, "ns/test") {
            Some(AuthAnnotation::External {
                always_set_cookie, ..
            }) => {
                assert!(!always_set_cookie);
                assert!(logs_contain("invalid auth-always-set-cookie"));
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_auth_both_url_and_basic_prefers_url_and_warns() {
        let m = ann(&[
            (AUTH_URL, "http://svc/"),
            (AUTH_BASIC_SECRET, "default/my-htpasswd"),
        ]);
        match parse_auth(&m, "ns/test") {
            Some(AuthAnnotation::External { .. }) => {
                assert!(logs_contain("mutually exclusive"));
            }
            _ => panic!("expected External when both present"),
        }
    }

    // ── parse_auth: basic auth ────────────────────────────────────────────────

    #[test]
    fn parse_auth_basic_valid_ref() {
        let m = ann(&[(AUTH_BASIC_SECRET, "default/my-htpasswd")]);
        match parse_auth(&m, "ns/test") {
            Some(AuthAnnotation::Basic(ref_)) => {
                assert_eq!(ref_.namespace, "default");
                assert_eq!(ref_.name, "my-htpasswd");
            }
            _ => panic!("expected Basic"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_auth_basic_invalid_ref_warns_and_is_none() {
        let m = ann(&[(AUTH_BASIC_SECRET, "just-a-name-no-slash")]);
        assert!(parse_auth(&m, "ns/test").is_none());
        assert!(logs_contain("invalid auth-basic-secret"));
    }

    // ── parse_htpasswd ────────────────────────────────────────────────────────

    #[test]
    fn parse_htpasswd_bcrypt_entry() {
        let data = b"alice:$2y$12$abcdefghijklmnopqrstuuVGKkqzuSFPb0h.d.XRjRijkFvxONxfy\n";
        let creds = parse_htpasswd(data);
        assert_eq!(creds.len(), 1);
    }

    #[test]
    fn parse_htpasswd_sha1_entry() {
        // {SHA} + base64-encoded SHA1 of "password"
        let data = b"bob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n";
        let creds = parse_htpasswd(data);
        assert_eq!(creds.len(), 1);
    }

    #[test]
    fn parse_htpasswd_skips_comments_and_blank_lines() {
        let data = b"# comment\nalice:$2y$12$abc\n\n# another\n";
        let creds = parse_htpasswd(data);
        assert_eq!(creds.len(), 1);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_htpasswd_unsupported_algorithm_warns_and_skips() {
        let data = b"alice:$apr1$salt$hash\n";
        let creds = parse_htpasswd(data);
        assert!(creds.is_empty());
        assert!(logs_contain("unsupported htpasswd hash algorithm"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_htpasswd_malformed_line_warns_and_skips() {
        let data = b"no-colon-here\n";
        let creds = parse_htpasswd(data);
        assert!(creds.is_empty());
        assert!(logs_contain("no ':' separator"));
    }

    #[test]
    fn parse_htpasswd_empty_input_is_empty() {
        assert!(parse_htpasswd(b"").is_empty());
        assert!(parse_htpasswd(b"# only comments\n").is_empty());
    }
}

// ── Client-certificate mTLS annotations (#267) ───────────────────────────────

/// Reference to a Kubernetes Secret in `namespace/name` form that holds PEM
/// CA certificate(s) under the `ca.crt` key.  Used to verify client certificates
/// at TLS handshake time.  The Secret **must** carry the label
/// `ingress.coxswain-labs.dev/auth-tls: "true"` so only opt-in Secrets are
/// cached by the data-plane reflector (read-only-proxy invariant).
///
/// A missing Secret, an unlabeled Secret, or one without a parseable `ca.crt`
/// key causes the proxy to abort every TLS handshake to this host until the
/// Secret is corrected (fail-closed, matching Istio `tls.mode: MUTUAL`).
pub const AUTH_TLS_SECRET: &str = "ingress.coxswain-labs.dev/auth-tls-secret";

/// Maximum client-certificate chain verification depth.  Must be a positive
/// integer.  When absent or invalid a `WARN` is emitted and the default of `1`
/// (leaf certificate only) is used, matching Istio's default for mutual TLS.
pub const AUTH_TLS_VERIFY_DEPTH: &str = "ingress.coxswain-labs.dev/auth-tls-verify-depth";

/// When `"true"`, the verified client certificate is forwarded to the upstream
/// backend as the `X-SSL-Client-Cert` request header (URL-encoded PEM).
/// When absent or `"false"`, the header is not injected.
pub const AUTH_TLS_PASS_CERT_TO_UPSTREAM: &str =
    "ingress.coxswain-labs.dev/auth-tls-pass-certificate-to-upstream";

// ── Intermediate annotation representation ───────────────────────────────────

/// Intermediate, pre-reconcile client-cert mTLS configuration parsed from the
/// `auth-tls-*` annotations.  The Secret reference is resolved to CA PEM bytes
/// by `IngressReconciler::reconcile_client_certs`; only then does this become a
/// [`ClientCertConfigState`][coxswain_core::tls::ClientCertConfigState].
pub(crate) struct ClientCertAnnotation {
    /// Reference to the CA Secret in `namespace/name` form.
    pub secret: SecretRef,
    /// Maximum chain verification depth (default `1`).
    pub verify_depth: u32,
    /// Whether to forward the verified cert as `X-SSL-Client-Cert`.
    pub pass_to_upstream: bool,
}

// ── Parse helper ─────────────────────────────────────────────────────────────

/// Parse the `auth-tls-*` annotation cluster into a [`ClientCertAnnotation`].
///
/// Returns `None` when `auth-tls-secret` is absent (mTLS disabled for the
/// route).  Invalid values for the optional knobs emit a `WARN` and fall back
/// to safe defaults; the whole block is still produced so long as the Secret
/// reference is valid.
#[must_use]
pub(crate) fn parse_client_cert(
    annotations: &std::collections::BTreeMap<String, String>,
    route_id: &str,
) -> Option<ClientCertAnnotation> {
    use super::get;

    let ref_str = get(annotations, AUTH_TLS_SECRET)?;
    let secret = match parse_secret_ref(ref_str) {
        Some(r) => r,
        None => {
            tracing::warn!(
                ingress = %route_id,
                annotation = AUTH_TLS_SECRET,
                value = ref_str,
                "invalid auth-tls-secret — expected \"namespace/name\" format; mTLS disabled"
            );
            return None;
        }
    };

    let verify_depth = get(annotations, AUTH_TLS_VERIFY_DEPTH)
        .and_then(|v| match v.trim().parse::<u32>() {
            Ok(n) if n >= 1 => Some(n),
            _ => {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = AUTH_TLS_VERIFY_DEPTH,
                    value = v,
                    "invalid auth-tls-verify-depth — expected a positive integer; using default 1"
                );
                None
            }
        })
        .unwrap_or(1);

    let pass_to_upstream = get(annotations, AUTH_TLS_PASS_CERT_TO_UPSTREAM)
        .and_then(|v| {
            let b = super::parse_bool(v);
            if b.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = AUTH_TLS_PASS_CERT_TO_UPSTREAM,
                    value = v,
                    "invalid auth-tls-pass-certificate-to-upstream — expected \"true\" or \"false\"; treating as false"
                );
            }
            b
        })
        .unwrap_or(false);

    Some(ClientCertAnnotation {
        secret,
        verify_depth,
        pass_to_upstream,
    })
}

#[cfg(test)]
mod client_cert_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ann(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ── Annotation const references (satisfies check-annotation-coverage.sh) ─

    #[test]
    fn auth_tls_secret_const_referenced() {
        let _ = AUTH_TLS_SECRET;
    }

    #[test]
    fn auth_tls_verify_depth_const_referenced() {
        let _ = AUTH_TLS_VERIFY_DEPTH;
    }

    #[test]
    fn auth_tls_pass_cert_to_upstream_const_referenced() {
        let _ = AUTH_TLS_PASS_CERT_TO_UPSTREAM;
    }

    // ── parse_client_cert ─────────────────────────────────────────────────────

    #[test]
    fn parse_client_cert_absent_is_none() {
        assert!(parse_client_cert(&ann(&[]), "ns/test").is_none());
    }

    #[test]
    fn parse_client_cert_valid_ref_defaults() {
        let m = ann(&[(AUTH_TLS_SECRET, "default/my-ca")]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert_eq!(cc.secret.namespace, "default");
        assert_eq!(cc.secret.name, "my-ca");
        assert_eq!(cc.verify_depth, 1);
        assert!(!cc.pass_to_upstream);
    }

    #[test]
    fn parse_client_cert_custom_depth() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_VERIFY_DEPTH, "3"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert_eq!(cc.verify_depth, 3);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_client_cert_invalid_depth_warns_and_defaults() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_VERIFY_DEPTH, "bad"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert_eq!(cc.verify_depth, 1);
        assert!(logs_contain("invalid auth-tls-verify-depth"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_client_cert_zero_depth_warns_and_defaults() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_VERIFY_DEPTH, "0"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert_eq!(cc.verify_depth, 1);
        assert!(logs_contain("invalid auth-tls-verify-depth"));
    }

    #[test]
    fn parse_client_cert_pass_to_upstream_true() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_PASS_CERT_TO_UPSTREAM, "true"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert!(cc.pass_to_upstream);
    }

    #[test]
    fn parse_client_cert_pass_to_upstream_false() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_PASS_CERT_TO_UPSTREAM, "false"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert!(!cc.pass_to_upstream);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_client_cert_invalid_pass_to_upstream_warns_and_defaults_false() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_PASS_CERT_TO_UPSTREAM, "yes"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert!(!cc.pass_to_upstream);
        assert!(logs_contain(
            "invalid auth-tls-pass-certificate-to-upstream"
        ));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_client_cert_invalid_secret_ref_warns_and_is_none() {
        let m = ann(&[(AUTH_TLS_SECRET, "no-slash-here")]);
        assert!(parse_client_cert(&m, "ns/test").is_none());
        assert!(logs_contain("invalid auth-tls-secret"));
    }
}
