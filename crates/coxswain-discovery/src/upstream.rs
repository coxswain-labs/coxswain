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
//!
//! Both writers go through [`UpstreamPolicy`], so **a node never takes an
//! identity off the wire**. The pointer arrives as `(endpoint,
//! expected_server_sa)`, and deriving the expected SVID from those fields would
//! let whoever sent them choose the server *and* the identity that server must
//! present — a compromised relay could then repoint its leaves at a discovery
//! server of its own. Instead the policy resolves the pointer against the three
//! upstreams the node can name from its own launch config, so the sender may
//! only select one of them, never define a fourth.

use coxswain_core::Shared;

use crate::auth::SpiffeMatcher;

/// A resolved routing-stream upstream: the endpoint(s) to dial plus the SPIFFE
/// identity the server's SVID must present. Both change together on a
/// controller↔relay repoint (a relay's endpoint and its `coxswain-relay` SA
/// differ from the controller's endpoint and `coxswain-controller` SA), so they
/// are stored as one atomically-swapped unit — never a torn (endpoint, matcher)
/// pair that could dial a relay while verifying the controller's identity.
#[derive(Clone, Debug)]
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

/// The default Kubernetes cluster DNS domain, the only suffix
/// [`UpstreamPolicy`] accepts after the `svc` label besides none at all.
const CLUSTER_DOMAIN_LABELS: [&str; 2] = ["cluster", "local"];

/// The parsed shape of an in-cluster service-DNS endpoint.
struct ServiceDns {
    /// First host label — the `Service` name.
    service: String,
    /// Second host label — the `Service`'s namespace.
    namespace: String,
    /// Whether the name *ends* at `.svc` or at the default cluster domain,
    /// rather than carrying further labels.
    ///
    /// Split out rather than folded into the parse because the two callers need
    /// different answers. [`UpstreamPolicy::resolve`] judges **wire input** and
    /// must require it: `…svc.attacker.example` satisfies a "third label is
    /// `svc`" rule while resolving to a name the sender controls.
    /// [`namespace_from_service_dns`] reads only the node's **own launch flag**,
    /// where there is no adversary and rejecting a non-default cluster domain
    /// would just break an operator who hand-wrote a valid FQDN.
    ends_at_cluster_domain: bool,
    /// Whether the scheme is `https` — read from the same parse, because it is
    /// the scheme `tonic` reads to decide whether to run TLS at all.
    is_https: bool,
}

/// Parse an in-cluster service-DNS endpoint.
///
/// Kubernetes service DNS is `<service>.<namespace>.svc[.<cluster-domain>]`, so
/// the first two labels of the host name the Service and its namespace. Returns
/// `None` for anything that is not that shape — IP literals, test loopback
/// addresses, a host with fewer than three labels.
///
/// The host comes from [`http::Uri`], which is the **same parser
/// `tonic::Endpoint` uses to dial**. That is load-bearing rather than
/// incidental: a hand-rolled "strip the scheme, cut at the last colon" parse
/// disagrees with RFC 3986 authority syntax, so
/// `https://coxswain-relay.team-a.svc:50051@evil.example` reads as host
/// `coxswain-relay.team-a.svc` to the hand-rolled version (everything before the
/// colon) while the dialer treats that whole span as *userinfo* and connects to
/// `evil.example`. Validating one host and connecting to another defeats
/// [`UpstreamPolicy`] entirely, so both sides must go through one parser.
fn service_dns_parts(endpoint: &str) -> Option<ServiceDns> {
    let uri: http::Uri = endpoint.parse().ok()?;
    let host = uri.host()?;
    // A trailing dot is the explicit-root form of the same name.
    let host = host.strip_suffix('.').unwrap_or(host);
    let mut labels = host.split('.');
    let service = labels.next().filter(|svc| !svc.is_empty())?;
    let namespace = labels.next().filter(|ns| !ns.is_empty())?;
    if labels.next() != Some("svc") {
        return None;
    }
    let suffix: Vec<&str> = labels.collect();
    Some(ServiceDns {
        service: service.to_owned(),
        namespace: namespace.to_owned(),
        ends_at_cluster_domain: suffix.is_empty() || suffix == CLUSTER_DOMAIN_LABELS,
        is_https: uri.scheme_str() == Some("https"),
    })
}

/// Namespace label of an in-cluster service-DNS endpoint.
///
/// Kubernetes service DNS is `<service>.<namespace>.svc[.<cluster-domain>]`, so
/// the server's namespace is the second label of the host. Returns `None` for
/// anything that is not recognizable `…svc…` service DNS (IP literals, test
/// loopback addresses), letting the caller fall back to a default namespace.
///
/// Accepts any cluster-domain suffix. Its input is the node's own launch flag,
/// not wire input — an operator on a cluster whose kubelet `--cluster-domain` is
/// not `cluster.local` may legitimately hand-write that FQDN, and refusing it
/// would silently mis-derive the controller's namespace. The stricter suffix
/// rule belongs to [`UpstreamPolicy::resolve`], which judges what a peer sent.
#[must_use]
pub fn namespace_from_service_dns(endpoint: &str) -> Option<String> {
    service_dns_parts(endpoint).map(|parts| parts.namespace)
}

/// Build the expected-server [`SpiffeMatcher`] for an upstream from its endpoint
/// and ServiceAccount short-name.
///
/// Mirrors the controller-side derivation exactly:
/// `spiffe://<trust_domain>/ns/<endpoint-ns>/sa/<expected_server_sa>`, where
/// `<endpoint-ns>` is the namespace label of the endpoint's service DNS. A
/// non-cluster endpoint (test loopback) falls back to `fallback_namespace`.
///
/// **Only the no-policy path calls this.** Both remaining call sites are the
/// `upstream_policy == None` branch, which `coxswain-bin` never takes — it
/// populates the policy on every client it builds. Deriving the expected
/// identity from a wire-supplied `(endpoint, sa)` pair is precisely the fail-open
/// shape [`UpstreamPolicy`] exists to remove, so nothing new may call this:
/// resolve through [`UpstreamPolicy::resolve`] instead.
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

/// Why [`UpstreamPolicy::resolve`] refused a wire-supplied upstream.
///
/// Every variant means the node keeps its current upstream and keeps serving —
/// a refused pointer is never fatal, because the alternative (following it) is
/// exactly the outcome the policy exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamRejection {
    /// The endpoint's scheme is not `https`.
    ///
    /// Load-bearing, not cosmetic: `tonic` decides whether to run the TLS
    /// handshake *at all* from the scheme alone — with anything but `https` it
    /// drops the configured client SVID and server verifier on the floor and
    /// connects in cleartext. An `http://` pointer at a perfectly legal host
    /// would therefore stream the node's whole routing world unencrypted to
    /// whatever answers, with neither side's identity checked, so the scheme is
    /// as much a part of the upstream's identity as the host.
    #[error("upstream endpoint {endpoint} is not https; refusing to stream routing without mTLS")]
    NotHttps {
        /// The endpoint as received.
        endpoint: String,
    },
    /// The endpoint's host is not `<service>.<namespace>.svc[.cluster.local]`,
    /// so it cannot be any of the three legal in-cluster upstreams.
    #[error("upstream endpoint {endpoint} is not cluster service DNS")]
    NotServiceDns {
        /// The endpoint as received.
        endpoint: String,
    },
    /// The host parsed as service DNS but names none of the three legal
    /// upstreams — a relay in a foreign namespace, or an unrelated Service.
    #[error("upstream {service}.{namespace}.svc is not a legal upstream for this node")]
    UnknownUpstream {
        /// Service label of the rejected host.
        service: String,
        /// Namespace label of the rejected host.
        namespace: String,
    },
    /// The host is legal but the sender's `expected_server_sa` disagrees with
    /// the ServiceAccount this node derives for it — a controller/leaf naming
    /// drift, or a sender probing for one.
    #[error(
        "upstream {service}.{namespace}.svc expects ServiceAccount {expected}, pointer claimed {claimed}"
    )]
    ServiceAccountMismatch {
        /// Service label of the host.
        service: String,
        /// Namespace label of the host.
        namespace: String,
        /// The ServiceAccount this node derives locally.
        expected: String,
        /// The ServiceAccount the sender claimed.
        claimed: String,
    },
}

/// Service and ServiceAccount names the controller renders its discovery tiers
/// under.
///
/// Supplied by `coxswain-bin`, which owns the controller-side constants these
/// mirror. Passing them in keeps the crate graph intact — `coxswain-discovery`
/// must not depend on `coxswain-controller` — and follows the precedent the
/// bootstrap server already sets by taking `shared_relay_sa` as config.
#[derive(Clone, Debug)]
pub struct UpstreamNames {
    /// Name of the controller's routing-stream `Service`
    /// (`coxswain-controller-discovery`). Distinct from the bootstrap Service.
    pub controller_service: String,
    /// The controller's ServiceAccount (`coxswain-controller`).
    pub controller_sa: String,
    /// The per-namespace relay's `Service` and ServiceAccount name — one string,
    /// because the controller renders both under `coxswain-relay`.
    pub relay: String,
    /// The shared relay's `Service` and ServiceAccount name, likewise one string
    /// (`coxswain-relay-shared`).
    pub shared_relay: String,
}

/// One upstream this node will accept, fully resolved from local config.
#[derive(Clone, Debug)]
struct LegalUpstream {
    service: String,
    namespace: String,
    service_account: String,
}

/// The closed set of routing-stream upstreams a node will accept.
///
/// An upstream pointer — a `PreferredUpstream` directive, or the pointer riding
/// a bootstrap response — names both the endpoint to dial *and* the SPIFFE
/// identity to then trust there. Deriving the identity from those wire fields
/// lets whoever sent the pointer choose the server **and** the identity that
/// server must present, so a compromised relay could point its leaves at a
/// discovery server of its own. This type removes that: the pointer may only
/// *select* one of the three upstreams the node can name from its own launch
/// config, never *define* a fourth.
///
/// The three, and how each is derived:
///
/// | Upstream | Host | Trusted identity |
/// |---|---|---|
/// | Controller | `<controller-service>.<install-ns>.svc` | `…/ns/<install-ns>/sa/<controller-sa>` |
/// | Namespace relay | `<relay>.<own-ns>.svc` | `…/ns/<own-ns>/sa/<relay>` |
/// | Shared relay | `<shared-relay>.<install-ns>.svc` | `…/ns/<install-ns>/sa/<shared-relay>` |
///
/// **Host is pinned; port is not.** The controller's stream port is a
/// controller-side flag a node never receives — its bootstrap endpoint is a
/// different Service on a different port. Pinning host plus identity makes the
/// port irrelevant: whatever answers must present the pinned SVID, so a
/// different port on a legal host is either that same workload or nothing.
///
/// Only the *namespace* relay is namespace-scoped to this node. A leaf will not
/// accept another tenant's relay even though that host is legal service DNS.
#[derive(Clone, Debug)]
pub struct UpstreamPolicy {
    trust_domain: String,
    /// The three legal upstreams, precomputed at construction so `resolve` is a
    /// scan of three string comparisons with no allocation before the match.
    legal: [LegalUpstream; 3],
}

impl UpstreamPolicy {
    /// Build the policy for a node in `pod_namespace`, with coxswain installed
    /// in `install_namespace`.
    ///
    /// `install_namespace` is the namespace label of the node's own
    /// `--discovery-bootstrap-endpoint` — the controller and the shared relay
    /// both live there — and `pod_namespace` is the node's own, which bounds
    /// which namespace relay it may be pointed at.
    #[must_use]
    pub fn new(
        trust_domain: impl Into<String>,
        install_namespace: &str,
        pod_namespace: &str,
        names: &UpstreamNames,
    ) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            legal: [
                LegalUpstream {
                    service: names.controller_service.clone(),
                    namespace: install_namespace.to_owned(),
                    service_account: names.controller_sa.clone(),
                },
                LegalUpstream {
                    service: names.relay.clone(),
                    namespace: pod_namespace.to_owned(),
                    service_account: names.relay.clone(),
                },
                LegalUpstream {
                    service: names.shared_relay.clone(),
                    namespace: install_namespace.to_owned(),
                    service_account: names.shared_relay.clone(),
                },
            ],
        }
    }

    /// Resolve a wire-supplied endpoint and ServiceAccount claim into a target
    /// whose expected identity is derived **locally**.
    ///
    /// `claimed_sa` is cross-checked against the locally-derived ServiceAccount
    /// but never trusted as its source: a disagreement is rejected so a
    /// controller/node naming drift surfaces loudly rather than silently
    /// downgrading to whatever the sender asked for. Rejecting adds no
    /// denial-of-service surface — a sender that wants to withhold a repoint can
    /// simply not send the pointer.
    ///
    /// The returned target keeps the caller's `endpoint` verbatim (so the port
    /// floats) while carrying a matcher this node built from its own config.
    ///
    /// # Errors
    ///
    /// [`UpstreamRejection`] when the endpoint is not cluster service DNS, names
    /// none of the three legal upstreams, or carries a mismatched ServiceAccount
    /// claim.
    pub fn resolve(
        &self,
        endpoint: &str,
        claimed_sa: &str,
    ) -> Result<UpstreamTarget, UpstreamRejection> {
        let Some(parts) = service_dns_parts(endpoint) else {
            return Err(UpstreamRejection::NotServiceDns {
                endpoint: endpoint.to_owned(),
            });
        };
        // `tonic` runs the TLS handshake only for `https`, so a non-https
        // pointer would disable the very SVID check the rest of this function
        // establishes — the scheme is part of the upstream's identity.
        if !parts.is_https {
            return Err(UpstreamRejection::NotHttps {
                endpoint: endpoint.to_owned(),
            });
        }
        if !parts.ends_at_cluster_domain {
            return Err(UpstreamRejection::NotServiceDns {
                endpoint: endpoint.to_owned(),
            });
        }
        let ServiceDns {
            service, namespace, ..
        } = parts;
        let Some(legal) = self
            .legal
            .iter()
            .find(|l| l.service == service && l.namespace == namespace)
        else {
            return Err(UpstreamRejection::UnknownUpstream { service, namespace });
        };
        if claimed_sa != legal.service_account {
            return Err(UpstreamRejection::ServiceAccountMismatch {
                service,
                namespace,
                expected: legal.service_account.clone(),
                claimed: claimed_sa.to_owned(),
            });
        }
        let matcher = SpiffeMatcher::Exact(format!(
            "spiffe://{}/ns/{}/sa/{}",
            self.trust_domain, legal.namespace, legal.service_account
        ));
        Ok(UpstreamTarget::new(endpoint.to_owned(), matcher))
    }
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

    // ── UpstreamPolicy (#665) ─────────────────────────────────────────────────

    /// The policy a dedicated proxy in `team-a` gets, with coxswain installed in
    /// `coxswain-system`. Mirrors what `coxswain-bin` builds in production.
    fn policy() -> UpstreamPolicy {
        UpstreamPolicy::new(
            "cluster.local",
            "coxswain-system",
            "team-a",
            &UpstreamNames {
                controller_service: "coxswain-controller-discovery".to_owned(),
                controller_sa: "coxswain-controller".to_owned(),
                relay: "coxswain-relay".to_owned(),
                shared_relay: "coxswain-relay-shared".to_owned(),
            },
        )
    }

    fn exact(matcher: &SpiffeMatcher) -> &str {
        match matcher {
            SpiffeMatcher::Exact(id) => id,
            other => panic!("expected an Exact matcher, got {other:?}"),
        }
    }

    #[test]
    fn each_legal_upstream_resolves_to_its_locally_derived_identity() {
        let p = policy();
        for (endpoint, sa, expected_id) in [
            (
                "https://coxswain-controller-discovery.coxswain-system.svc:50051",
                "coxswain-controller",
                "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-controller",
            ),
            (
                "https://coxswain-relay.team-a.svc:50051",
                "coxswain-relay",
                "spiffe://cluster.local/ns/team-a/sa/coxswain-relay",
            ),
            (
                "https://coxswain-relay-shared.coxswain-system.svc:50051",
                "coxswain-relay-shared",
                "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-relay-shared",
            ),
        ] {
            let target = p
                .resolve(endpoint, sa)
                .unwrap_or_else(|e| panic!("{endpoint} must be a legal upstream, got {e}"));
            assert_eq!(
                exact(&target.expected_server),
                expected_id,
                "{endpoint} must verify against the identity this node derives locally"
            );
            assert_eq!(
                target.endpoints,
                vec![endpoint.to_owned()],
                "{endpoint} must be dialled verbatim"
            );
        }
    }

    #[test]
    fn fully_qualified_and_floating_port_forms_resolve() {
        let p = policy();
        for endpoint in [
            "https://coxswain-relay.team-a.svc.cluster.local:50051",
            "https://coxswain-relay.team-a.svc.:50051",
            "https://coxswain-relay.team-a.svc.cluster.local.:50051",
            // The controller's stream port is a controller-side flag a leaf never
            // receives, so the port must not participate in the match.
            "https://coxswain-relay.team-a.svc:19090",
            "https://coxswain-relay.team-a.svc",
        ] {
            let target = p
                .resolve(endpoint, "coxswain-relay")
                .unwrap_or_else(|e| panic!("{endpoint} must resolve, got {e}"));
            assert_eq!(
                exact(&target.expected_server),
                "spiffe://cluster.local/ns/team-a/sa/coxswain-relay",
                "{endpoint} must still pin the namespace relay's identity"
            );
        }
    }

    #[test]
    fn relay_in_a_foreign_namespace_is_rejected() {
        // The tenant-isolation case: `coxswain-relay.team-b.svc` is perfectly
        // well-formed service DNS for a real relay — just not THIS node's. A
        // compromised relay naming a peer tenant's must not be followed.
        let err = policy()
            .resolve("https://coxswain-relay.team-b.svc:50051", "coxswain-relay")
            .expect_err("a relay outside this node's own namespace must be rejected");
        assert_eq!(
            err,
            UpstreamRejection::UnknownUpstream {
                service: "coxswain-relay".to_owned(),
                namespace: "team-b".to_owned(),
            }
        );
    }

    #[test]
    fn attacker_chosen_host_is_rejected() {
        let p = policy();
        for endpoint in [
            // A host the attacker controls, claiming an identity it can present.
            "https://evil.team-a.svc:50051",
            // The controller's Service name, but in the attacker's namespace.
            "https://coxswain-controller-discovery.team-a.svc:50051",
            // The shared relay's name outside the install namespace.
            "https://coxswain-relay-shared.team-a.svc:50051",
        ] {
            assert!(
                matches!(
                    p.resolve(endpoint, "coxswain-relay"),
                    Err(UpstreamRejection::UnknownUpstream { .. })
                ),
                "{endpoint} must not be an acceptable upstream"
            );
        }
    }

    #[test]
    fn service_account_claim_must_agree_with_the_local_derivation() {
        // The claim is cross-checked, never trusted as the matcher's source: a
        // legal host carrying a foreign SA claim is refused rather than silently
        // downgraded to whatever the sender asked for.
        let err = policy()
            .resolve("https://coxswain-relay.team-a.svc:50051", "attacker-sa")
            .expect_err("a mismatched ServiceAccount claim must be rejected");
        assert_eq!(
            err,
            UpstreamRejection::ServiceAccountMismatch {
                service: "coxswain-relay".to_owned(),
                namespace: "team-a".to_owned(),
                expected: "coxswain-relay".to_owned(),
                claimed: "attacker-sa".to_owned(),
            }
        );
    }

    #[test]
    fn host_validated_is_the_host_dialled() {
        // The bypass class this policy must not have: an endpoint whose host
        // LOOKS legal to a hand-rolled parse but resolves elsewhere in the
        // dialer. Both forms below read as `coxswain-relay.team-a.svc` under a
        // "strip the scheme, cut at the last colon, third label is svc" parse,
        // yet `tonic::Endpoint` connects somewhere the sender chose. Validating
        // one host and connecting to another would defeat the whole policy, so
        // each case is checked against the parser the dialer actually uses.
        let p = policy();
        for (endpoint, really_dials) in [
            // RFC 3986 userinfo: everything before `@` is credentials, not host.
            (
                "https://coxswain-relay.team-a.svc:50051@evil.example",
                "evil.example",
            ),
            // Extra labels after `svc`: a name wholly under the sender's zone.
            (
                "https://coxswain-relay.team-a.svc.attacker.example:50051",
                "coxswain-relay.team-a.svc.attacker.example",
            ),
        ] {
            let dialled = endpoint
                .parse::<http::Uri>()
                .ok()
                .and_then(|u| u.host().map(str::to_owned));
            assert_eq!(
                dialled.as_deref(),
                Some(really_dials),
                "premise: {endpoint} really dials {really_dials}"
            );
            assert!(
                p.resolve(endpoint, "coxswain-relay").is_err(),
                "{endpoint} dials {really_dials}, not a legal upstream, and must be rejected"
            );
        }
    }

    #[test]
    fn a_non_https_upstream_is_rejected_even_at_a_legal_host() {
        // `tonic` decides whether to run TLS *from the scheme alone*: with
        // anything but `https` it drops the client SVID and the server verifier
        // and connects in cleartext. So a legal host reached over `http://`
        // would stream the whole routing world unencrypted, with neither side's
        // identity checked — the host being legal is precisely what makes this
        // dangerous rather than merely broken.
        let p = policy();
        for endpoint in [
            "http://coxswain-relay.team-a.svc:50051",
            "http://coxswain-controller-discovery.coxswain-system.svc:50051",
            "ftp://coxswain-relay.team-a.svc:50051",
        ] {
            let err = p
                .resolve(endpoint, "coxswain-relay")
                .expect_err("a non-https upstream must be rejected");
            assert!(
                matches!(err, UpstreamRejection::NotHttps { .. }),
                "{endpoint} must be refused for its scheme, got {err:?}"
            );
        }
    }

    #[test]
    fn policy_is_strict_about_the_cluster_domain_but_the_flag_parser_is_not() {
        // Two different jobs. `resolve` judges what a peer sent, so an unknown
        // suffix is a name the sender controls and must be refused. The bare
        // parser reads the node's OWN launch flag, where a non-default kubelet
        // `--cluster-domain` is a legitimate operator choice — refusing it there
        // would mis-derive the controller's namespace and wedge bootstrap.
        let endpoint = "https://coxswain-relay.team-a.svc.cluster.internal:50051";
        assert!(
            policy().resolve(endpoint, "coxswain-relay").is_err(),
            "a peer-supplied non-default cluster domain must not be treated as legal"
        );
        assert_eq!(
            namespace_from_service_dns(endpoint).as_deref(),
            Some("team-a"),
            "the node's own launch flag must still parse on a non-default cluster domain"
        );
    }

    #[test]
    fn non_service_dns_endpoints_are_rejected() {
        let p = policy();
        for endpoint in ["https://localhost:50051", "https://10.0.0.1:50051", ""] {
            assert!(
                matches!(
                    p.resolve(endpoint, "coxswain-relay"),
                    Err(UpstreamRejection::NotServiceDns { .. })
                ),
                "{endpoint:?} is not cluster service DNS and must be rejected"
            );
        }
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
