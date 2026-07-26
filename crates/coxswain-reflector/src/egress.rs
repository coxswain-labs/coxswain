//! Control-plane egress guard for tenant-authored URLs (#664).
//!
//! `JwtAuth.spec.jwks.remote.uri` is a **namespaced-CRD field a tenant
//! controls**, fetched by the privileged controller from inside the cluster
//! network. Without a guard, a tenant can point it at cloud metadata
//! (`169.254.169.254`), an internal ClusterIP, or a node-local port and read
//! the controller's fetch outcome back through the route's `Unavailable` →
//! `Jwt` status transition (blind SSRF).
//!
//! [`EgressPolicy`] is the trust boundary: the **tenant** picks which URL to
//! fetch, the **operator** picks which destinations the controller may ever
//! connect to (`--egress-allow-cidr`). The default is public-internet-only.
//! [`GuardedResolver`] enforces this on the **resolved socket address**, not
//! the URL string — the only point that simultaneously defeats DNS rebinding
//! (a public hostname whose A/AAAA record points at a private IP), exotic IP
//! encodings, and multi-hop redirects. `JwtAuth` is the only tenant-authored
//! URL the controller fetches today, but this module is the reusable guard
//! for the next one.
//!
//! A literal IP host bypasses DNS resolution entirely at the `hyper-util`
//! connector layer (`SocketAddrs::try_parse`), so [`GuardedResolver`] alone is
//! not sufficient — callers building the request (`crate::jwks::fetch_one`)
//! must also check a literal-IP host with [`EgressPolicy::permits`] before
//! ever calling `.send()`.

use std::net::IpAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Reserved and special-purpose IP ranges (IANA IPv4/IPv6 special-purpose
/// registries) that are never a legitimate controller-egress destination
/// unless the operator explicitly allowlists them: this-network, RFC 1918
/// private space, CGNAT (RFC 6598), loopback, link-local (incl. cloud
/// metadata), documentation/benchmarking ranges, multicast, reserved, the
/// IPv4 broadcast address, and their IPv6 equivalents (loopback, ULA,
/// link-local, documentation, the IPv4-IPv6 translation range, multicast).
///
/// Deliberately **not** the same table as
/// `coxswain_proxy::policy::access_control::PRIVATE_NETS`: that table answers
/// a different question (is this `X-Forwarded-For` token a plausible client
/// IP), `coxswain-proxy` and `coxswain-reflector` don't depend on each other,
/// and this SSRF set is a strict superset (CGNAT, documentation ranges,
/// multicast, `240.0.0.0/4`) — widening the XFF table to match would silently
/// change anti-spoofing classification.
static RESERVED_NETS: std::sync::LazyLock<[ipnet::IpNet; 24]> = std::sync::LazyLock::new(|| {
    [
        // IPv4
        net("0.0.0.0/8"),          // "this" network
        net("10.0.0.0/8"),         // RFC 1918
        net("100.64.0.0/10"),      // CGNAT, RFC 6598
        net("127.0.0.0/8"),        // loopback
        net("169.254.0.0/16"),     // link-local (cloud metadata lives here)
        net("172.16.0.0/12"),      // RFC 1918
        net("192.0.0.0/24"),       // IETF protocol assignments
        net("192.0.2.0/24"),       // documentation (TEST-NET-1)
        net("192.88.99.0/24"),     // deprecated 6to4 relay anycast
        net("192.168.0.0/16"),     // RFC 1918
        net("198.18.0.0/15"),      // benchmarking
        net("198.51.100.0/24"),    // documentation (TEST-NET-2)
        net("203.0.113.0/24"),     // documentation (TEST-NET-3)
        net("224.0.0.0/4"),        // multicast
        net("240.0.0.0/4"),        // reserved
        net("255.255.255.255/32"), // limited broadcast
        // IPv6
        net("::/128"),        // unspecified
        net("::1/128"),       // loopback
        net("64:ff9b::/96"),  // NAT64 (embeds an IPv4 address; canonicalized separately)
        net("100::/64"),      // discard-only
        net("2001:db8::/32"), // documentation
        net("fc00::/7"),      // unique local (ULA)
        net("fe80::/10"),     // link-local
        net("ff00::/8"),      // multicast
    ]
});

fn net(cidr: &str) -> ipnet::IpNet {
    cidr.parse()
        .unwrap_or_else(|e| panic!("invariant: static CIDR literal {cidr:?} parses: {e}"))
}

/// True if `ip` falls in a reserved/special-purpose range ([`RESERVED_NETS`]).
/// Canonicalizes IPv4-mapped IPv6 (`::ffff:a.b.c.d`) before matching so a
/// mapped-form literal can't slip past the IPv4 entries.
fn is_reserved(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    RESERVED_NETS.iter().any(|n| n.contains(&ip))
}

/// Which destinations the controller may connect to when fetching a
/// tenant-named URL. Immutable once built — the reconciler constructs one
/// [`EgressPolicy`] from `--egress-allow-cidr` at startup and shares it across
/// every guarded client.
#[derive(Clone, Debug, Default)]
pub(crate) struct EgressPolicy {
    /// Operator-supplied additional ranges (e.g. an in-cluster identity
    /// provider's ClusterIP CIDR). Checked before falling back to
    /// [`is_reserved`], so an explicit allow always wins.
    allow: Arc<[ipnet::IpNet]>,
}

impl EgressPolicy {
    /// Build a policy from `--egress-allow-cidr`. Empty means
    /// public-internet-only (every reserved/special-purpose range denied).
    #[must_use]
    pub(crate) fn new(allow: Vec<ipnet::IpNet>) -> Self {
        Self {
            allow: Arc::from(allow),
        }
    }

    /// True if the controller may connect to `ip`: allowlisted, or outside
    /// every reserved range. `ip` is canonicalized internally, so callers
    /// need not fold IPv4-mapped IPv6 themselves.
    #[must_use]
    pub(crate) fn permits(&self, ip: IpAddr) -> bool {
        let canonical = ip.to_canonical();
        self.allow.iter().any(|n| n.contains(&canonical)) || !is_reserved(canonical)
    }

    /// True if the controller may connect to `ip` **without** TLS.
    ///
    /// Stricter than [`Self::permits`]: a plaintext fetch to an otherwise-fine
    /// public IP is still refused, because there is no certificate to prove
    /// the response actually came from the intended issuer (a network
    /// position that can answer that IP can inject a malicious JWKS and
    /// silently take over token verification). Plaintext is only ever
    /// acceptable to a destination the operator explicitly named.
    ///
    /// Callers only ever apply this to a **literal IP** (`jwks::check_url`
    /// never resolves a hostname before deciding whether to allow `http://`),
    /// so an in-cluster identity provider that must be reached over plaintext
    /// has to be named by its stable ClusterIP/CIDR, not a DNS name — a
    /// hostname target always requires `https://`.
    #[must_use]
    pub(crate) fn permits_plaintext(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|n| n.contains(&ip.to_canonical()))
    }
}

/// Error from [`GuardedResolver::resolve`] when every address a hostname
/// resolved to is disallowed. Named as a `reqwest`-facing `BoxError` (the
/// trait's own error type), not a crate error — see
/// [`crate::jwks::JwksFetchError`] for the caller-facing typed error, which
/// wraps whatever `reqwest` surfaces from a failed connect.
#[derive(Debug, thiserror::Error)]
#[error(
    "{host} resolved only to disallowed destinations for controller egress; \
     add its CIDR to --egress-allow-cidr if this is an intentional in-cluster target"
)]
struct AllResolvedAddressesBlocked {
    host: Box<str>,
}

/// DNS resolver that filters every resolved address through [`EgressPolicy`]
/// before `reqwest` ever dials it — this is address pinning: the socket the
/// connector opens is exactly one this resolver already approved, so there is
/// no separate resolve-then-connect window for a DNS answer to change under
/// us (`reqwest`'s own default resolver is a private type, so this wraps
/// `tokio::net::lookup_host`, the same `getaddrinfo` path, directly).
///
/// Does **not** cover a URL whose host is already an IP literal — `hyper-util`
/// short-circuits DNS resolution entirely for those
/// (`HttpConnector::call_async`'s `SocketAddrs::try_parse` fast path), so
/// [`crate::jwks::fetch_one`] checks a literal-IP host with
/// [`EgressPolicy::permits`] up front, before this resolver is ever reached.
pub(crate) struct GuardedResolver {
    policy: EgressPolicy,
}

impl GuardedResolver {
    pub(crate) fn new(policy: EgressPolicy) -> Self {
        Self { policy }
    }
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed: Vec<_> = resolved.filter(|addr| policy.permits(addr.ip())).collect();
            if allowed.is_empty() {
                return Err(Box::new(AllResolvedAddressesBlocked { host: host.into() })
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|e| panic!("test IP {s:?}: {e}"))
    }

    #[test]
    fn metadata_ip_is_denied_by_default() {
        let policy = EgressPolicy::default();
        assert!(!policy.permits(ip("169.254.169.254")));
    }

    #[test]
    fn loopback_is_denied_by_default() {
        let policy = EgressPolicy::default();
        assert!(!policy.permits(ip("127.0.0.1")));
        assert!(!policy.permits(ip("::1")));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_canonicalized_before_matching() {
        let policy = EgressPolicy::default();
        assert!(!policy.permits(ip("::ffff:169.254.169.254")));
    }

    #[test]
    fn public_ip_is_permitted_by_default() {
        let policy = EgressPolicy::default();
        assert!(policy.permits(ip("93.184.216.34"))); // example.com-era public IP
        assert!(policy.permits(ip("2606:2800:220:1:248:1893:25c8:1946")));
    }

    #[test]
    fn allowlisted_private_range_is_permitted() {
        let policy = EgressPolicy::new(vec![net("10.0.0.0/8")]);
        assert!(policy.permits(ip("10.1.2.3")));
        // A different private range not in the allowlist stays denied.
        assert!(!policy.permits(ip("192.168.1.1")));
    }

    #[test]
    fn plaintext_requires_explicit_allowlisting_even_for_public_ips() {
        let policy = EgressPolicy::default();
        assert!(!policy.permits_plaintext(ip("93.184.216.34")));

        let policy = EgressPolicy::new(vec![net("10.0.0.0/8")]);
        assert!(policy.permits_plaintext(ip("10.1.2.3")));
        assert!(!policy.permits_plaintext(ip("93.184.216.34")));
    }

    #[test]
    fn cgnat_and_documentation_ranges_are_denied() {
        let policy = EgressPolicy::default();
        assert!(!policy.permits(ip("100.64.0.1"))); // CGNAT
        assert!(!policy.permits(ip("192.0.2.1"))); // TEST-NET-1
        assert!(!policy.permits(ip("198.51.100.1"))); // TEST-NET-2
    }

    #[test]
    fn ipv6_multicast_is_denied() {
        let policy = EgressPolicy::default();
        assert!(!policy.permits(ip("ff02::1")));
    }

    // `GuardedResolver` itself: these exercise the actual `Resolve::resolve`
    // implementation (real `tokio::net::lookup_host`, no mocking) so a
    // predicate inversion or a dropped filter — bugs no `EgressPolicy` unit
    // test above can catch, since they'd live entirely inside `resolve` —
    // fails a test rather than silently shipping. "localhost" is used because
    // it resolves via the OS hosts file with no network dependency and always
    // lands in a denied range (127.0.0.0/8 and/or ::1/128).

    #[tokio::test]
    async fn resolver_blocks_a_hostname_resolving_to_loopback_by_default() {
        let resolver = GuardedResolver::new(EgressPolicy::default());
        let name: Name = "localhost".parse().expect("valid DNS name");
        let result = resolver.resolve(name).await;
        assert!(
            result.is_err(),
            "localhost resolves to loopback, which must be denied by default"
        );
    }

    #[tokio::test]
    async fn resolver_permits_a_hostname_resolving_into_an_allowlisted_range() {
        let resolver =
            GuardedResolver::new(EgressPolicy::new(vec![net("127.0.0.0/8"), net("::1/128")]));
        let name: Name = "localhost".parse().expect("valid DNS name");
        let result = resolver.resolve(name).await;
        assert!(
            result.is_ok(),
            "an allowlisted loopback range must let the resolution through"
        );
    }
}
