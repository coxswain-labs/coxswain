//! Edge access-control annotation parsing: source-IP allow/deny ranges, the
//! trust-forwarded-for cluster (with the anti-spoofing CIDR guard), and rate
//! limiting.
//!
//! Every helper emits a structured `WARN` on invalid input and skips the
//! offending token so a single typo never rejects the whole Ingress.

use super::AnnotationIssue;

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

/// Master switch for trusting a forwarded client-IP header on this Ingress.
/// When `"true"`, the proxy reads the client IP from the header named by
/// `forwarded-for-header` (default `X-Forwarded-For`) instead of the L4 peer.
/// When combined with `forwarded-for-trusted-cidrs`, the header is only trusted
/// when the L4 peer IP falls inside one of those CIDRs (anti-spoofing guard).
/// When absent or `"false"`, the L4 peer address is always used (current behavior).
pub const TRUST_FORWARDED_FOR: &str = "ingress.coxswain-labs.dev/trust-forwarded-for";

/// Header name from which to read the real client IP when `trust-forwarded-for`
/// is `"true"`.  Defaults to `X-Forwarded-For` when absent.  The proxy performs a
/// case-insensitive header lookup, so `x-forwarded-for`, `X-Forwarded-For`, and
/// `CF-Connecting-IP` are all valid values.  The first non-private IP in the
/// header value is used as the client IP.
pub const FORWARDED_FOR_HEADER: &str = "ingress.coxswain-labs.dev/forwarded-for-header";

/// Comma-separated IPv4/IPv6 CIDR blocks that identify trusted upstream proxies.
/// When set, the forwarded header is only trusted when the L4 peer IP falls
/// inside one of these CIDRs; requests from outside the list use the L4 peer
/// address directly, preventing spoofing from untrusted callers.  When absent,
/// the header is trusted unconditionally (suitable when Coxswain is always behind
/// a controlled proxy).  Bare addresses without a prefix are accepted as host
/// routes (`/32` / `/128`).
pub const FORWARDED_FOR_TRUSTED_CIDRS: &str =
    "ingress.coxswain-labs.dev/forwarded-for-trusted-cidrs";

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
/// all traffic on a typo. `route_id` names the Ingress in skipped-token WARNs.
/// `diag` collects machine-readable issues alongside the warn log.
#[must_use]
pub fn parse_allow_source_range(
    s: &str,
    route_id: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<Vec<ipnet::IpNet>> {
    parse_cidr_list(s, ALLOW_SOURCE_RANGE, route_id, diag)
}

/// Parse the `deny-source-range` value into a CIDR set.
///
/// Splits on `,`, trims, and parses each token as an [`ipnet::IpNet`]; a bare IP
/// without a prefix is promoted to a host network (`/32` / `/128`). Invalid
/// tokens emit a `WARN` and are skipped. Returns `None` when the value is empty
/// or every token is unparseable — the block list is treated as absent (block
/// nothing), so a typo never silently blocks all traffic. `route_id` names the
/// Ingress in skipped-token WARNs.
#[must_use]
pub fn parse_deny_source_range(
    s: &str,
    route_id: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<Vec<ipnet::IpNet>> {
    parse_cidr_list(s, DENY_SOURCE_RANGE, route_id, diag)
}

/// Parse the `trust-forwarded-for` annotation cluster into a [`ForwardedForConfig`].
///
/// Returns `None` when `trust-forwarded-for` is absent or does not parse as
/// `"true"` — the proxy uses the L4 peer address as the client IP (current
/// behavior, fail-safe). When truthy, the header name defaults to
/// `X-Forwarded-For` when `forwarded-for-header` is absent. Invalid CIDR tokens
/// in `forwarded-for-trusted-cidrs` emit a `WARN` and are skipped. An empty
/// `trusted_cidrs` after parsing is **fail-closed**: the proxy trusts no peer and
/// ignores the forwarded header (using the L4 peer address), so this parser emits a
/// `WARN` telling the operator the header will not be honored until they configure
/// `forwarded-for-trusted-cidrs`.
///
/// # Arguments
/// * `annotations` — raw annotation map for the Ingress.
/// * `route_id` — human-readable identifier used in `WARN` log messages.
/// * `diag` — collects machine-readable issues alongside the warn log.
#[must_use]
pub fn parse_forwarded_for(
    annotations: &std::collections::BTreeMap<String, String>,
    route_id: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<coxswain_core::routing::ForwardedForConfig> {
    use coxswain_core::routing::ForwardedForConfig;

    let trust = super::get(annotations, TRUST_FORWARDED_FOR)?;
    if !super::parse_bool(trust).unwrap_or(false) {
        if super::parse_bool(trust).is_none() {
            tracing::warn!(
                ingress = %route_id,
                annotation = TRUST_FORWARDED_FOR,
                value = trust,
                "invalid trust-forwarded-for — expected \"true\" or \"false\"; treating as false"
            );
            diag.push(AnnotationIssue {
                annotation: TRUST_FORWARDED_FOR,
                message: format!(
                    "invalid trust-forwarded-for value '{trust}' — expected \"true\" or \"false\"; treating as false"
                ),
            });
        }
        return None;
    }

    let header: Box<str> = super::get(annotations, FORWARDED_FOR_HEADER)
        .filter(|s| !s.trim().is_empty())
        .map(|s| Box::from(s.trim()))
        .unwrap_or_else(|| Box::from("X-Forwarded-For"));

    let trusted_cidrs: Box<[ipnet::IpNet]> = super::get(annotations, FORWARDED_FOR_TRUSTED_CIDRS)
        .and_then(|s| parse_cidr_list(s, FORWARDED_FOR_TRUSTED_CIDRS, route_id, diag))
        .unwrap_or_default()
        .into_boxed_slice();

    if trusted_cidrs.is_empty() {
        tracing::warn!(
            ingress = %route_id,
            annotation = TRUST_FORWARDED_FOR,
            "trust-forwarded-for is enabled but no forwarded-for-trusted-cidrs are set — \
             the forwarded header will NOT be honored (fail-closed anti-spoofing); the L4 \
             peer address is used until trusted proxy CIDRs are configured"
        );
        diag.push(AnnotationIssue {
            annotation: TRUST_FORWARDED_FOR,
            message: "trust-forwarded-for enabled without forwarded-for-trusted-cidrs — \
                      header ignored (fail-closed); configure trusted proxy CIDRs to honor it"
                .to_string(),
        });
    }

    Some(ForwardedForConfig::new(header, trusted_cidrs))
}

/// Shared CIDR-list parser used by `parse_allow_source_range`,
/// `parse_deny_source_range`, and `parse_forwarded_for`. `annotation_key` is the
/// full annotation key constant (e.g. `ALLOW_SOURCE_RANGE`) used in WARN messages
/// and diagnostic issues.
fn parse_cidr_list(
    s: &str,
    annotation_key: &'static str,
    route_id: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<Vec<ipnet::IpNet>> {
    let nets: Vec<ipnet::IpNet> = s
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|token| match parse_cidr_or_host(token) {
            Some(net) => Some(net),
            None => {
                tracing::warn!(
                    ingress = %route_id,
                    token = token,
                    annotation = annotation_key,
                    "invalid CIDR — skipping token"
                );
                diag.push(AnnotationIssue {
                    annotation: annotation_key,
                    message: format!("invalid CIDR token '{token}' — skipping"),
                });
                None
            }
        })
        .collect();
    if nets.is_empty() { None } else { Some(nets) }
}

/// Parse a single token as a CIDR block, falling back to a bare host address
/// (`10.0.0.1` → `10.0.0.1/32`, `2001:db8::1` → `2001:db8::1/128`).
///
/// Shared with the Gateway-API `IpAccessControl` filter resolver so both the
/// Ingress annotation and the Gateway CRD promote bare IPs to host routes
/// identically.
pub(crate) fn parse_cidr_or_host(token: &str) -> Option<ipnet::IpNet> {
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
/// * `has_auth` — `true` when either `auth-url` or `auth-basic-secret` is also set on the
///   same Ingress; used to suppress the key-rotation-bypass advisory for auth-gated routes.
/// * `diag` — collects machine-readable issues alongside the warn log.
#[must_use]
pub fn parse_rate_limit(
    rps_val: Option<&str>,
    burst_val: Option<&str>,
    by_val: Option<&str>,
    route_id: &str,
    has_auth: bool,
    diag: &mut Vec<AnnotationIssue>,
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
            diag.push(AnnotationIssue {
                annotation: RATE_LIMIT_RPS,
                message: format!(
                    "invalid or zero rate-limit-rps '{rps_str}' — rate limiting disabled"
                ),
            });
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
                diag.push(AnnotationIssue {
                    annotation: RATE_LIMIT_BURST,
                    message: "invalid rate-limit-burst — using 0 (no burst)".into(),
                });
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
                diag.push(AnnotationIssue {
                    annotation: RATE_LIMIT_BY,
                    message: "invalid rate-limit-by — expected \"ip\" or \"header:Name\"; using ip"
                        .into(),
                });
                RateLimitKey::ClientIp
            }
        }
    } else {
        RateLimitKey::ClientIp
    };

    if matches!(key, RateLimitKey::Header(_)) && !has_auth {
        tracing::warn!(
            ingress = %route_id,
            annotation = RATE_LIMIT_BY,
            "header keying allows rate-limit bypass via header-value rotation; \
             pair with rate-limit-by: ip or an auth-* annotation"
        );
        diag.push(AnnotationIssue {
            annotation: RATE_LIMIT_BY,
            message: "header keying allows rate-limit bypass via header-value rotation; \
                      pair with rate-limit-by: ip or an auth-* annotation"
                .into(),
        });
    }

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
        let nets =
            parse_allow_source_range("10.0.0.0/8", "test-ingress", &mut vec![]).expect("one CIDR");
        assert_eq!(nets, vec!["10.0.0.0/8".parse().expect("valid")]);
    }

    #[test]
    fn parse_multiple_cidrs_trimmed() {
        let nets = parse_allow_source_range(
            "10.0.0.0/8, 192.168.1.0/24 ,2001:db8::/32",
            "test-ingress",
            &mut vec![],
        )
        .expect("three");
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn parse_bare_ip_becomes_host_route() {
        let nets = parse_allow_source_range("10.0.0.1,2001:db8::1", "test-ingress", &mut vec![])
            .expect("two host routes");
        assert_eq!(nets[0], "10.0.0.1/32".parse().expect("valid"));
        assert_eq!(nets[1], "2001:db8::1/128".parse().expect("valid"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_skips_invalid_keeps_valid() {
        let nets = parse_allow_source_range(
            "10.0.0.0/8,not-a-cidr,192.168.0.0/16",
            "test-ingress",
            &mut vec![],
        )
        .expect("two");
        assert_eq!(nets.len(), 2);
        assert!(logs_contain("invalid CIDR"));
    }

    #[test]
    fn parse_all_invalid_is_none() {
        assert!(parse_allow_source_range("nope,also-nope", "test-ingress", &mut vec![]).is_none());
    }

    #[test]
    fn parse_empty_is_none() {
        assert!(parse_allow_source_range("", "test-ingress", &mut vec![]).is_none());
        assert!(parse_allow_source_range("  ,  ", "test-ingress", &mut vec![]).is_none());
    }

    // ── deny-source-range ─────────────────────────────────────────────────────

    #[test]
    fn deny_parse_single_cidr() {
        // References DENY_SOURCE_RANGE to satisfy the annotation-coverage gate.
        let _ = DENY_SOURCE_RANGE;
        let nets =
            parse_deny_source_range("10.0.0.0/8", "test-ingress", &mut vec![]).expect("one CIDR");
        assert_eq!(
            nets,
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().expect("valid")]
        );
    }

    #[test]
    fn deny_parse_multiple_cidrs_trimmed() {
        let nets = parse_deny_source_range(
            "10.0.0.0/8, 192.168.1.0/24 ,2001:db8::/32",
            "test-ingress",
            &mut vec![],
        )
        .expect("three");
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn deny_parse_bare_ip_becomes_host_route() {
        let nets = parse_deny_source_range("10.0.0.1,2001:db8::1", "test-ingress", &mut vec![])
            .expect("two host routes");
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
        let nets = parse_deny_source_range(
            "10.0.0.0/8,not-a-cidr,192.168.0.0/16",
            "test-ingress",
            &mut vec![],
        )
        .expect("two");
        assert_eq!(nets.len(), 2);
        assert!(logs_contain("invalid CIDR"));
    }

    #[test]
    fn deny_parse_all_invalid_is_none() {
        assert!(parse_deny_source_range("nope,also-nope", "test-ingress", &mut vec![]).is_none());
    }

    #[test]
    fn deny_parse_empty_is_none() {
        assert!(parse_deny_source_range("", "test-ingress", &mut vec![]).is_none());
        assert!(parse_deny_source_range("  ,  ", "test-ingress", &mut vec![]).is_none());
    }

    // ── trust-forwarded-for ───────────────────────────────────────────────────

    fn ann(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn forwarded_for_absent_is_none() {
        // References all three consts to satisfy check-annotation-coverage.sh part (a).
        let _ = TRUST_FORWARDED_FOR;
        let _ = FORWARDED_FOR_HEADER;
        let _ = FORWARDED_FOR_TRUSTED_CIDRS;
        assert!(parse_forwarded_for(&ann(&[]), "ns/test", &mut vec![]).is_none());
    }

    #[test]
    fn forwarded_for_false_is_none() {
        let m = ann(&[(TRUST_FORWARDED_FOR, "false")]);
        assert!(parse_forwarded_for(&m, "ns/test", &mut vec![]).is_none());
    }

    #[test]
    fn forwarded_for_true_defaults_to_x_forwarded_for() {
        let m = ann(&[(TRUST_FORWARDED_FOR, "true")]);
        let cfg = parse_forwarded_for(&m, "ns/test", &mut vec![]).expect("Some");
        assert_eq!(&*cfg.header, "X-Forwarded-For");
        assert!(cfg.trusted_cidrs.is_empty());
    }

    #[test]
    fn forwarded_for_empty_trusted_cidrs_pushes_fail_closed_diag() {
        // trust-forwarded-for enabled without trusted CIDRs is fail-closed at the
        // proxy; the parser must surface that the header will be ignored.
        let m = ann(&[(TRUST_FORWARDED_FOR, "true")]);
        let mut diag = vec![];
        let cfg = parse_forwarded_for(&m, "ns/test", &mut diag).expect("Some");
        assert!(cfg.trusted_cidrs.is_empty());
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, TRUST_FORWARDED_FOR);
    }

    #[test]
    fn forwarded_for_custom_header() {
        let m = ann(&[
            (TRUST_FORWARDED_FOR, "true"),
            (FORWARDED_FOR_HEADER, "CF-Connecting-IP"),
        ]);
        let cfg = parse_forwarded_for(&m, "ns/test", &mut vec![]).expect("Some");
        assert_eq!(&*cfg.header, "CF-Connecting-IP");
    }

    #[test]
    fn forwarded_for_trusted_cidrs_populated() {
        let m = ann(&[
            (TRUST_FORWARDED_FOR, "true"),
            (FORWARDED_FOR_TRUSTED_CIDRS, "10.0.0.0/8,192.168.0.0/16"),
        ]);
        let cfg = parse_forwarded_for(&m, "ns/test", &mut vec![]).expect("Some");
        assert_eq!(cfg.trusted_cidrs.len(), 2);
    }

    #[test]
    #[tracing_test::traced_test]
    fn forwarded_for_bad_cidr_warns_and_is_skipped() {
        let m = ann(&[
            (TRUST_FORWARDED_FOR, "true"),
            (FORWARDED_FOR_TRUSTED_CIDRS, "10.0.0.0/8,not-a-cidr"),
        ]);
        let cfg = parse_forwarded_for(&m, "ns/test", &mut vec![]).expect("Some");
        assert_eq!(cfg.trusted_cidrs.len(), 1);
        assert!(logs_contain("invalid CIDR"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn forwarded_for_invalid_bool_warns_and_is_none() {
        let m = ann(&[(TRUST_FORWARDED_FOR, "yes")]);
        assert!(parse_forwarded_for(&m, "ns/test", &mut vec![]).is_none());
        assert!(logs_contain("invalid trust-forwarded-for"));
    }

    // ── rate-limit annotation coverage ────────────────────────────────────────
    // Each const is referenced to satisfy scripts/check-annotation-coverage.sh.

    #[test]
    fn rate_limit_absent_rps_is_none() {
        let _ = RATE_LIMIT_RPS;
        let _ = RATE_LIMIT_BURST;
        let _ = RATE_LIMIT_BY;
        assert!(parse_rate_limit(None, None, None, "ns/test", false, &mut vec![]).is_none());
    }

    #[test]
    fn rate_limit_rps_zero_is_none() {
        assert!(parse_rate_limit(Some("0"), None, None, "ns/test", false, &mut vec![]).is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn rate_limit_invalid_rps_warns_and_is_none() {
        assert!(
            parse_rate_limit(Some("nope"), None, None, "ns/test", false, &mut vec![]).is_none()
        );
        assert!(logs_contain("invalid or zero rate-limit-rps"));
    }

    #[test]
    fn rate_limit_basic_ip_config() {
        let cfg =
            parse_rate_limit(Some("10"), None, None, "ns/test", false, &mut vec![]).expect("valid");
        assert_eq!(cfg.requests_per_second.get(), 10);
        assert_eq!(cfg.burst, 0);
        assert_eq!(cfg.key, RateLimitKey::ClientIp);
    }

    #[test]
    fn rate_limit_with_burst() {
        let cfg = parse_rate_limit(Some("5"), Some("20"), None, "ns/test", false, &mut vec![])
            .expect("valid");
        assert_eq!(cfg.requests_per_second.get(), 5);
        assert_eq!(cfg.burst, 20);
    }

    #[test]
    #[tracing_test::traced_test]
    fn rate_limit_invalid_burst_defaults_to_zero() {
        let cfg = parse_rate_limit(Some("5"), Some("bad"), None, "ns/test", false, &mut vec![])
            .expect("valid");
        assert_eq!(cfg.burst, 0);
        assert!(logs_contain("invalid rate-limit-burst"));
    }

    #[test]
    fn rate_limit_by_ip_explicit() {
        let cfg = parse_rate_limit(Some("10"), None, Some("ip"), "ns/test", false, &mut vec![])
            .expect("valid");
        assert_eq!(cfg.key, RateLimitKey::ClientIp);
    }

    #[test]
    fn rate_limit_by_header() {
        let cfg = parse_rate_limit(
            Some("10"),
            None,
            Some("header:X-Api-Key"),
            "ns/test",
            true, // has_auth=true: test the key type; bypass-warning tested separately
            &mut vec![],
        )
        .expect("valid");
        assert_eq!(
            cfg.key,
            RateLimitKey::Header(std::sync::Arc::from("x-api-key"))
        );
    }

    #[test]
    fn rate_limit_by_header_name_is_lowercased() {
        let cfg = parse_rate_limit(
            Some("10"),
            None,
            Some("header:Authorization"),
            "ns/test",
            true, // has_auth=true: test lowercasing; bypass-warning tested separately
            &mut vec![],
        )
        .expect("valid");
        assert_eq!(
            cfg.key,
            RateLimitKey::Header(std::sync::Arc::from("authorization"))
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn rate_limit_invalid_by_warns_defaults_to_ip() {
        let cfg = parse_rate_limit(
            Some("10"),
            None,
            Some("bad-selector"),
            "ns/test",
            false,
            &mut vec![],
        )
        .expect("valid");
        assert_eq!(cfg.key, RateLimitKey::ClientIp);
        assert!(logs_contain("invalid rate-limit-by"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn rate_limit_by_header_without_auth_warns() {
        let mut diag = vec![];
        let cfg = parse_rate_limit(
            Some("10"),
            None,
            Some("header:X-Api-Key"),
            "ns/test",
            false,
            &mut diag,
        )
        .expect("valid");
        assert_eq!(
            cfg.key,
            RateLimitKey::Header(std::sync::Arc::from("x-api-key"))
        );
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, RATE_LIMIT_BY);
        assert!(logs_contain("header keying allows rate-limit bypass"));
    }

    #[test]
    fn rate_limit_by_header_with_auth_no_warn() {
        let mut diag = vec![];
        let cfg = parse_rate_limit(
            Some("10"),
            None,
            Some("header:X-Api-Key"),
            "ns/test",
            true,
            &mut diag,
        )
        .expect("valid");
        assert_eq!(
            cfg.key,
            RateLimitKey::Header(std::sync::Arc::from("x-api-key"))
        );
        assert!(diag.is_empty());
    }

    #[test]
    fn rate_limit_by_header_empty_name_is_none() {
        assert!(parse_rate_limit_by("header:").is_none());
        assert!(parse_rate_limit_by("header:  ").is_none());
    }
}
