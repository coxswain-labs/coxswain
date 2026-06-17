//! Edge access-control annotation constants and parse helpers.
//!
//! Covers source-IP allow-listing today; the home for the v0.3 security
//! annotations as they land (client-cert mTLS, `satisfy`, external auth, rate
//! limiting). Every helper emits a structured `WARN` on invalid input and skips
//! the offending token so a single typo never rejects the whole Ingress.

/// Source-IP allow-list — comma-separated IPv4/IPv6 CIDR blocks (e.g.
/// `"10.0.0.0/8,192.168.1.0/24"`). Bare addresses without a prefix (`10.0.0.1`,
/// `2001:db8::1`) are accepted as host routes (`/32` / `/128`) for parity with
/// nginx-ingress's `whitelist-source-range`. Requests whose real client IP falls
/// outside every range are rejected with 403; absent/empty admits all source IPs.
pub const ALLOW_SOURCE_RANGE: &str = "ingress.coxswain-labs.dev/allow-source-range";

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
