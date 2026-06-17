//! Edge access-control annotation constants and parse helpers.
//!
//! Covers source-IP allow-listing and per-route rate limiting; the home for the
//! v0.3 security annotations as they land (client-cert mTLS, `satisfy`, external
//! auth). Every helper emits a structured `WARN` on invalid input and skips the
//! offending token so a single typo never rejects the whole Ingress.

/// Source-IP allow-list — comma-separated IPv4/IPv6 CIDR blocks (e.g.
/// `"10.0.0.0/8,192.168.1.0/24"`). Bare addresses without a prefix (`10.0.0.1`,
/// `2001:db8::1`) are accepted as host routes (`/32` / `/128`) for parity with
/// nginx-ingress's `whitelist-source-range`. Requests whose real client IP falls
/// outside every range are rejected with 403; absent/empty admits all source IPs.
pub const ALLOW_SOURCE_RANGE: &str = "ingress.coxswain-labs.dev/allow-source-range";

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
    let nets: Vec<ipnet::IpNet> = s
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|token| match parse_cidr_or_host(token) {
            Some(net) => Some(net),
            None => {
                tracing::warn!(
                    token = token,
                    "invalid CIDR in allow-source-range — skipping token"
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
        assert!(logs_contain("invalid CIDR in allow-source-range"));
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
