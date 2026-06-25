//! Source-IP access control: effective-client-IP resolution (with the
//! Forwarded-For anti-spoofing gate) and the CIDR allow/deny-list checks that
//! the request lifecycle applies before forwarding upstream.

use coxswain_core::routing::ForwardedForConfig;
use pingora_proxy::Session;

/// Private and reserved IP ranges that are never treated as a real client IP when
/// extracting from a forwarded header.  Includes RFC 1918 private ranges, loopback,
/// link-local, ULA (fc00::/7), and the unspecified address.
static PRIVATE_NETS: std::sync::LazyLock<[ipnet::IpNet; 9]> = std::sync::LazyLock::new(|| {
    [
        "10.0.0.0/8"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "172.16.0.0/12"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "192.168.0.0/16"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "127.0.0.0/8"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "169.254.0.0/16"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "::1/128"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "fe80::/10"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "fc00::/7"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "::/128"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
    ]
});

/// Scan a comma-separated header value for the first non-private, non-loopback
/// IP address.  Returns `None` when every token is private, unparseable, or the
/// value is empty.
///
/// "First" is left-to-right per the XFF convention: the leftmost value is the
/// one closest to the original client and furthest from potential LB injection.
fn first_non_private_ip(header_value: &str) -> Option<std::net::IpAddr> {
    header_value
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse::<std::net::IpAddr>().ok())
        .find(|ip| !PRIVATE_NETS.iter().any(|n| n.contains(ip)))
}

/// Resolve the effective client IP for the current request.
///
/// Resolution order (per `ForwardedForConfig` doc):
/// 1. If no config → L4 IP (current behavior).
/// 2. If `trusted_cidrs` non-empty AND L4 IP ∉ any CIDR → L4 IP (anti-spoofing).
/// 3. Else extract the first non-private IP from the configured header; fall back
///    to L4 IP when absent or all entries are private.
pub(crate) fn resolve_client_ip(
    session: &Session,
    real_client_addr: Option<std::net::SocketAddr>,
    fwd: Option<&ForwardedForConfig>,
) -> Option<std::net::IpAddr> {
    let l4_ip = real_client_addr.map(|a| a.ip()).or_else(|| {
        session
            .as_downstream()
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip())
    });

    let Some(cfg) = fwd else {
        return l4_ip;
    };

    // Anti-spoofing gate: if trusted CIDRs are configured, only trust the header
    // when the L4 peer is within one of those CIDRs.
    if !cfg.trusted_cidrs.is_empty()
        && !l4_ip.is_some_and(|ip| cfg.trusted_cidrs.iter().any(|n| n.contains(&ip)))
    {
        return l4_ip;
    }

    // Trust the header: grab the forwarded-IP value and find the first public IP.
    let header_ip = session
        .req_header()
        .headers
        .get(cfg.header.as_ref())
        .and_then(|v| v.to_str().ok())
        .and_then(first_non_private_ip);

    header_ip.or(l4_ip)
}

/// Returns `true` if `client_ip` is admitted by the CIDR allow-list `nets`.
///
/// Fail-closed: a `None` client IP (the peer could not be determined) is
/// rejected — an un-attributable request must not pass a security allow-list.
/// Matching is strict (no IPv4-mapped-IPv6 normalization), matching `ipnet`'s
/// default and the `TrustedSources` PROXY-protocol check.
#[must_use]
pub(crate) fn ip_allowed(client_ip: Option<std::net::IpAddr>, nets: &[ipnet::IpNet]) -> bool {
    client_ip.is_some_and(|ip| nets.iter().any(|n| n.contains(&ip)))
}

/// Returns `true` if `client_ip` falls inside any CIDR in the deny-list `nets`.
///
/// Inverse-fail-open on identity: a `None` client IP (peer could not be determined)
/// is **not** considered to match any CIDR and is therefore **not** denied — a block
/// list only blocks IPs it can positively attribute to a listed range. This is the
/// inverse of [`ip_allowed`]'s fail-closed semantics.
/// Matching is strict (no IPv4-mapped-IPv6 normalization).
#[must_use]
pub(crate) fn ip_denied(client_ip: Option<std::net::IpAddr>, nets: &[ipnet::IpNet]) -> bool {
    client_ip.is_some_and(|ip| nets.iter().any(|n| n.contains(&ip)))
}

#[cfg(test)]
mod tests {
    use super::{ip_allowed, ip_denied};
    use std::net::IpAddr;

    fn nets(cidrs: &[&str]) -> Vec<ipnet::IpNet> {
        cidrs
            .iter()
            .map(|c| c.parse().expect("valid CIDR"))
            .collect()
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().expect("valid IP"))
    }

    #[test]
    fn in_range_v4_allowed() {
        assert!(ip_allowed(ip("10.1.2.3"), &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn out_of_range_v4_rejected() {
        assert!(!ip_allowed(ip("192.168.0.1"), &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn in_range_v6_allowed() {
        assert!(ip_allowed(ip("2001:db8::1"), &nets(&["2001:db8::/32"])));
    }

    #[test]
    fn out_of_range_v6_rejected() {
        assert!(!ip_allowed(ip("2001:dead::1"), &nets(&["2001:db8::/32"])));
    }

    #[test]
    fn matches_second_cidr_in_list() {
        assert!(ip_allowed(
            ip("192.168.1.5"),
            &nets(&["10.0.0.0/8", "192.168.1.0/24"])
        ));
    }

    #[test]
    fn missing_client_ip_is_rejected_fail_closed() {
        // A peer we cannot attribute must never pass a security allow-list.
        assert!(!ip_allowed(None, &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn empty_allow_list_rejects_everything() {
        assert!(!ip_allowed(ip("10.0.0.1"), &[]));
    }

    #[test]
    fn v4_mapped_v6_does_not_match_v4_cidr() {
        // Strict matching: an IPv4-mapped IPv6 client does NOT satisfy an IPv4 CIDR.
        // Locks the documented behavior so leniency would be a deliberate change.
        assert!(!ip_allowed(ip("::ffff:10.0.0.1"), &nets(&["10.0.0.0/8"])));
    }

    // ── ip_denied ─────────────────────────────────────────────────────────────

    #[test]
    fn in_range_v4_denied() {
        assert!(ip_denied(ip("10.1.2.3"), &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn out_of_range_v4_not_denied() {
        assert!(!ip_denied(ip("192.168.0.1"), &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn in_range_v6_denied() {
        assert!(ip_denied(ip("2001:db8::1"), &nets(&["2001:db8::/32"])));
    }

    #[test]
    fn out_of_range_v6_not_denied() {
        assert!(!ip_denied(ip("2001:dead::1"), &nets(&["2001:db8::/32"])));
    }

    #[test]
    fn missing_client_ip_is_not_denied_fail_open() {
        // A peer we cannot attribute must NOT be auto-denied — a block list only
        // blocks IPs it can positively attribute to a listed range.
        assert!(!ip_denied(None, &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn empty_deny_list_denies_nothing() {
        assert!(!ip_denied(ip("10.0.0.1"), &[]));
    }

    #[test]
    fn v4_mapped_v6_does_not_match_deny_v4_cidr() {
        // Strict matching: an IPv4-mapped IPv6 client does NOT match an IPv4 deny CIDR.
        assert!(!ip_denied(ip("::ffff:10.0.0.1"), &nets(&["10.0.0.0/8"])));
    }

    // ── first_non_private_ip ──────────────────────────────────────────────────

    #[test]
    fn first_non_private_ip_skips_private_finds_public() {
        let result = super::first_non_private_ip("10.0.0.1, 203.0.113.5, 198.51.100.1");
        assert_eq!(result, "203.0.113.5".parse::<IpAddr>().ok());
    }

    #[test]
    fn first_non_private_ip_single_public() {
        let result = super::first_non_private_ip("1.2.3.4");
        assert_eq!(result, "1.2.3.4".parse::<IpAddr>().ok());
    }

    #[test]
    fn first_non_private_ip_all_private_is_none() {
        let result = super::first_non_private_ip("10.0.0.1, 192.168.0.1, 172.16.0.1");
        assert!(result.is_none());
    }

    #[test]
    fn first_non_private_ip_empty_is_none() {
        assert!(super::first_non_private_ip("").is_none());
        assert!(super::first_non_private_ip("  ,  ").is_none());
    }

    #[test]
    fn first_non_private_ip_loopback_is_private() {
        assert!(super::first_non_private_ip("127.0.0.1").is_none());
        assert!(super::first_non_private_ip("::1").is_none());
    }

    // ── resolve_client_ip: unit tests (no Session available; tested via integration) ─
    // The per-request happy/sad path is covered by the e2e security-plane tests.
}
