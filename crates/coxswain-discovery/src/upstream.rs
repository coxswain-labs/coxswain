//! Runtime-swappable routing-stream upstream (#601).
//!
//! The routing-stream upstream — which controller/relay a proxy streams its
//! routing snapshots from — used to be a process-start CLI arg, so repointing a
//! proxy between the controller and a relay meant a pod rollout that cut
//! long-lived data-plane traffic. This module makes the upstream **runtime
//! controlled**, mirroring the SVID-rotation force-reconnect that already ships:
//! a lock-free [`SharedUpstream`] cell + a `watch` the reconnect supervisor
//! selects on.
//!
//! Two writers populate the cell: the proxy-side bootstrap loop (the upstream
//! pointer rides the bootstrap response) and the routing-stream loop (a live
//! [`crate::proto::v1::PreferredUpstream`] directive). Applying a swap forces one
//! control-stream reconnect only — the data-plane listeners are never recycled,
//! so the proxy keeps serving its last-good routing snapshot throughout.

use coxswain_core::Shared;

use crate::auth::SpiffeMatcher;

/// A resolved routing-stream upstream: the endpoint(s) to dial plus the SPIFFE
/// identity the server's SVID must present. Both change together on a
/// controller↔relay repoint (a relay's endpoint and its `coxswain-relay` SA
/// differ from the controller's endpoint and `coxswain-controller` SA), so they
/// are stored as one atomically-swapped unit — never a torn (endpoint, matcher)
/// pair that could dial a relay while verifying the controller's identity.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct UpstreamTarget {
    /// Routing Service endpoint(s) to dial (`"https://host:port"`). More than
    /// one enables HA via `Channel::balance_list`; a runtime directive supplies
    /// exactly one.
    pub endpoints: Vec<String>,
    /// SPIFFE identity the upstream server's SVID must match at the mTLS
    /// handshake. Verified by `SpiffeServerCertVerifier`; a mismatch fails the
    /// handshake closed rather than streaming routing from an unverified peer.
    pub expected_server: SpiffeMatcher,
}

impl UpstreamTarget {
    /// Construct a single-endpoint upstream target.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, expected_server: SpiffeMatcher) -> Self {
        Self {
            endpoints: vec![endpoint.into()],
            expected_server,
        }
    }
}

/// Lock-free cell holding the current [`UpstreamTarget`], or `None` until the
/// first bootstrap delivers one. Mirrors [`crate::svid::SharedSvid`]: the
/// reconnect supervisor reads it on every connect attempt, so a swap is picked
/// up on the next (force-triggered) reconnect.
pub type SharedUpstream = Shared<Option<UpstreamTarget>>;

/// Namespace label of an in-cluster service-DNS endpoint.
///
/// Kubernetes service DNS is `<service>.<namespace>.svc[.cluster.local]`, so the
/// server's namespace is the second label of the host. Returns `None` for
/// anything that is not recognizable `…svc…` service DNS (IP literals, test
/// loopback addresses), letting the caller fall back to a default namespace.
#[must_use]
pub fn namespace_from_service_dns(endpoint: &str) -> Option<String> {
    let after_scheme = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
    let mut labels = host.split('.');
    let _service = labels.next()?;
    let namespace = labels.next().filter(|ns| !ns.is_empty())?;
    (labels.next() == Some("svc")).then(|| namespace.to_owned())
}

/// Build the expected-server [`SpiffeMatcher`] for an upstream from its endpoint
/// and ServiceAccount short-name.
///
/// Mirrors the controller-side derivation exactly:
/// `spiffe://<trust_domain>/ns/<endpoint-ns>/sa/<expected_server_sa>`, where
/// `<endpoint-ns>` is the namespace label of the endpoint's service DNS. A
/// non-cluster endpoint (test loopback) falls back to `fallback_namespace`.
#[must_use]
pub fn expected_server_matcher(
    trust_domain: &str,
    endpoint: &str,
    expected_server_sa: &str,
    fallback_namespace: &str,
) -> SpiffeMatcher {
    let namespace =
        namespace_from_service_dns(endpoint).unwrap_or_else(|| fallback_namespace.to_owned());
    SpiffeMatcher::Exact(format!(
        "spiffe://{trust_domain}/ns/{namespace}/sa/{expected_server_sa}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_parsed_from_cluster_service_dns() {
        assert_eq!(
            namespace_from_service_dns("https://coxswain-relay.team-a.svc:50051").as_deref(),
            Some("team-a"),
        );
        assert_eq!(
            namespace_from_service_dns(
                "https://coxswain-controller-discovery.coxswain-system.svc.cluster.local:50051"
            )
            .as_deref(),
            Some("coxswain-system"),
        );
    }

    #[test]
    fn non_cluster_endpoint_has_no_namespace() {
        assert_eq!(namespace_from_service_dns("https://localhost:50051"), None);
        assert_eq!(namespace_from_service_dns("https://10.0.0.1:50051"), None);
    }

    #[test]
    fn matcher_uses_endpoint_namespace_and_sa() {
        let matcher = expected_server_matcher(
            "cluster.local",
            "https://coxswain-relay.team-a.svc:50051",
            "coxswain-relay",
            "fallback-ns",
        );
        assert_eq!(
            matcher,
            SpiffeMatcher::Exact("spiffe://cluster.local/ns/team-a/sa/coxswain-relay".to_owned()),
        );
    }

    #[test]
    fn matcher_falls_back_for_non_cluster_endpoint() {
        let matcher = expected_server_matcher(
            "cluster.local",
            "https://localhost:50051",
            "coxswain-controller",
            "fallback-ns",
        );
        assert_eq!(
            matcher,
            SpiffeMatcher::Exact(
                "spiffe://cluster.local/ns/fallback-ns/sa/coxswain-controller".to_owned()
            ),
        );
    }
}
