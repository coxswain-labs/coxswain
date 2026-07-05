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

/// Walk a comma-separated forwarded-for header **right-to-left** and return the
/// first address that is not a known trusted-proxy hop — the real client as far
/// as the trust chain can attest ("rightmost-untrusted").
///
/// Each hop a trusted proxy appends is the address *it* received from; reading
/// from the right we skip our own trusted proxies (`trusted`) and private/reserved
/// infrastructure until we reach the first address we did not receive from a
/// trusted hop. Everything to the *left* of that is client-controlled and ignored
/// — which is what defeats `X-Forwarded-For: <forged>, <real>` spoofing (the old
/// leftmost-wins scan returned the attacker-supplied `<forged>` token).
///
/// Addresses are canonicalized with [`std::net::IpAddr::to_canonical`] so an
/// IPv4-mapped IPv6 form (`::ffff:a.b.c.d`) is classified and returned as its
/// IPv4 address. Returns `None` when every token is a trusted/private hop,
/// unparseable, or the value is empty.
fn rightmost_untrusted_ip(
    header_value: &str,
    trusted: &[ipnet::IpNet],
) -> Option<std::net::IpAddr> {
    header_value
        .rsplit(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .find(|ip| {
            !trusted.iter().any(|n| n.contains(ip)) && !PRIVATE_NETS.iter().any(|n| n.contains(ip))
        })
}

/// Resolve the effective client IP for the current request.
///
/// Resolution order:
/// 1. No `ForwardedForConfig` → the L4 peer address.
/// 2. Config present but the L4 peer is **not** inside `trusted_cidrs` → the L4
///    peer address. The empty-`trusted_cidrs` case lands here: an empty trust set
///    trusts no peer, so the forwarded header is ignored (fail-closed). Only a
///    configured trusted proxy can have its forwarded header honored.
/// 3. L4 peer trusted → the rightmost-untrusted address from the configured header
///    (see [`rightmost_untrusted_ip`]), falling back to the L4 peer when the header
///    is absent or yields no untrusted address.
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

    // Fail-closed anti-spoofing gate: only honor the forwarded header when the L4
    // peer is a configured trusted proxy. An empty `trusted_cidrs` matches no peer,
    // so the header is ignored and the L4 address wins — a client cannot forge its
    // source IP by setting the header when no trust is configured.
    let l4_trusted = l4_ip.is_some_and(|ip| cfg.trusted_cidrs.iter().any(|n| n.contains(&ip)));
    if !l4_trusted {
        return l4_ip;
    }

    let header_ip = session
        .req_header()
        .headers
        .get(cfg.header.as_ref())
        .and_then(|v| v.to_str().ok())
        .and_then(|hv| rightmost_untrusted_ip(hv, &cfg.trusted_cidrs));

    header_ip.or(l4_ip)
}

/// Returns `true` if `client_ip` is admitted by the CIDR allow-list `nets`.
///
/// Fail-closed: a `None` client IP (the peer could not be determined) is
/// rejected — an un-attributable request must not pass a security allow-list.
/// The client IP is canonicalized ([`std::net::IpAddr::to_canonical`]) before
/// matching, so an IPv4-mapped IPv6 form (`::ffff:a.b.c.d`) is tested as its IPv4
/// address and cannot slip past a v4 allow-list by presenting the mapped form.
#[must_use]
pub(crate) fn ip_allowed(client_ip: Option<std::net::IpAddr>, nets: &[ipnet::IpNet]) -> bool {
    client_ip.is_some_and(|ip| {
        let ip = ip.to_canonical();
        nets.iter().any(|n| n.contains(&ip))
    })
}

/// Returns `true` if `client_ip` falls inside any CIDR in the deny-list `nets`.
///
/// Inverse-fail-open on identity: a `None` client IP (peer could not be determined)
/// is **not** considered to match any CIDR and is therefore **not** denied — a block
/// list only blocks IPs it can positively attribute to a listed range. This is the
/// inverse of [`ip_allowed`]'s fail-closed semantics.
/// The client IP is canonicalized ([`std::net::IpAddr::to_canonical`]) before
/// matching, so an IPv4-mapped IPv6 form cannot evade a v4 deny CIDR.
#[must_use]
pub(crate) fn ip_denied(client_ip: Option<std::net::IpAddr>, nets: &[ipnet::IpNet]) -> bool {
    client_ip.is_some_and(|ip| {
        let ip = ip.to_canonical();
        nets.iter().any(|n| n.contains(&ip))
    })
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
    fn v4_mapped_v6_matches_v4_cidr() {
        // Canonicalized matching: an IPv4-mapped IPv6 client is tested as its IPv4
        // address, so it satisfies an IPv4 CIDR — no mapped-form allow-list bypass.
        assert!(ip_allowed(ip("::ffff:10.0.0.1"), &nets(&["10.0.0.0/8"])));
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
    fn v4_mapped_v6_matches_deny_v4_cidr() {
        // Canonicalized matching: an IPv4-mapped IPv6 client cannot evade an IPv4
        // deny CIDR by presenting the mapped form.
        assert!(ip_denied(ip("::ffff:10.0.0.1"), &nets(&["10.0.0.0/8"])));
    }

    // ── rightmost_untrusted_ip ────────────────────────────────────────────────

    #[test]
    fn rightmost_untrusted_ignores_left_forged_entry() {
        // Attacker forges the leftmost token; the trusted LB appends the real
        // client to the right. Rightmost-untrusted returns the real client — the
        // forgery to its left is ignored.
        let trusted = nets(&["192.0.2.0/24"]);
        let r = super::rightmost_untrusted_ip("1.1.1.1, 203.0.113.7", &trusted);
        assert_eq!(r, "203.0.113.7".parse::<IpAddr>().ok());
    }

    #[test]
    fn rightmost_untrusted_skips_trailing_trusted_hops() {
        // chain: realclient, trusted-hop-1, trusted-hop-2 — skip both trusted hops.
        let trusted = nets(&["192.0.2.0/24", "198.51.100.0/24"]);
        let r = super::rightmost_untrusted_ip("203.0.113.7, 192.0.2.5, 198.51.100.9", &trusted);
        assert_eq!(r, "203.0.113.7".parse::<IpAddr>().ok());
    }

    #[test]
    fn rightmost_untrusted_skips_private_hops() {
        // Private/reserved infra is skipped even with no configured trusted CIDRs.
        let r = super::rightmost_untrusted_ip("203.0.113.7, 10.0.0.5", &[]);
        assert_eq!(r, "203.0.113.7".parse::<IpAddr>().ok());
    }

    #[test]
    fn rightmost_untrusted_single_public() {
        // Single-hop LB: the header carries just the real client.
        let r = super::rightmost_untrusted_ip("1.2.3.4", &[]);
        assert_eq!(r, "1.2.3.4".parse::<IpAddr>().ok());
    }

    #[test]
    fn rightmost_untrusted_all_trusted_is_none() {
        let trusted = nets(&["192.0.2.0/24"]);
        assert!(super::rightmost_untrusted_ip("192.0.2.1, 192.0.2.2", &trusted).is_none());
    }

    #[test]
    fn rightmost_untrusted_all_private_is_none() {
        assert!(super::rightmost_untrusted_ip("10.0.0.1, 192.168.0.1, 172.16.0.1", &[]).is_none());
    }

    #[test]
    fn rightmost_untrusted_empty_is_none() {
        assert!(super::rightmost_untrusted_ip("", &[]).is_none());
        assert!(super::rightmost_untrusted_ip("  ,  ", &[]).is_none());
    }

    #[test]
    fn rightmost_untrusted_loopback_is_private() {
        assert!(super::rightmost_untrusted_ip("127.0.0.1", &[]).is_none());
        assert!(super::rightmost_untrusted_ip("::1", &[]).is_none());
    }

    #[test]
    fn rightmost_untrusted_canonicalizes_mapped_v6() {
        // A mapped-v6 real client is returned as its canonical v4 form.
        let r = super::rightmost_untrusted_ip("::ffff:203.0.113.7", &[]);
        assert_eq!(r, "203.0.113.7".parse::<IpAddr>().ok());
    }

    // ── resolve_client_ip: unit tests (no Session available; tested via integration) ─
    // The per-request happy/sad path is covered by the e2e security-plane tests.
}
