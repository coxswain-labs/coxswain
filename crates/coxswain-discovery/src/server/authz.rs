//! `Scope::Namespace` subscribe authorizers (#582/#584).
//!
//! The [`ScopeAuthorizer`] trait gates the relay tier's namespace-aggregation
//! scope: the fail-closed [`DenyAllNamespaces`] default and the provenance-backed
//! [`ProvisionedRelayAuthorizer`] the controller wires in where relays are
//! provisioned.

use std::collections::HashSet;

use coxswain_core::Shared;
use coxswain_core::identity::SpiffeId;

use crate::auth::PeerSvid;

/// Authorizes a [`Scope::Namespace`](crate::subscription::Scope::Namespace) subscribe (#582, the relay tier's upstream
/// aggregation scope).
///
/// `Namespace` fans out every dedicated Gateway's routing world in one
/// namespace to a single stream, so a wrongly-authorized subscriber gets a much
/// bigger blast radius than a single `Scope::Gateway` binding — hence a
/// dedicated seam rather than reusing the private Gateway-scope SVID binding
/// check. The shipped provenance-backed implementation is
/// [`ProvisionedRelayAuthorizer`]; a [`DiscoveryService`](crate::DiscoveryService) with none wired in
/// defaults to [`DenyAllNamespaces`].
pub trait ScopeAuthorizer: Send + Sync {
    /// Returns `true` if `peer` may open a `Namespace{namespace}` subscribe.
    fn allows_namespace(&self, peer: &PeerSvid, namespace: &str) -> bool;
}

/// Fail-closed default [`ScopeAuthorizer`]: denies every `Namespace` subscribe.
///
/// The fail-closed default until the provenance-backed [`ProvisionedRelayAuthorizer`]
/// is wired in via [`DiscoveryService::with_scope_authorizer`](crate::DiscoveryService::with_scope_authorizer): without a
/// provisioned relay there is no legitimate `Namespace` subscriber to allow.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllNamespaces;

impl ScopeAuthorizer for DenyAllNamespaces {
    fn allows_namespace(&self, _peer: &PeerSvid, _namespace: &str) -> bool {
        false
    }
}

/// Provenance-backed [`ScopeAuthorizer`] (#584): authorizes a `Namespace{ns}`
/// subscribe only for the relay ServiceAccount the controller provisioned in
/// `ns`.
///
/// `provisioned` is the live set of namespaces where the operator currently has
/// a relay — published by the controller's relay convergence from the *same*
/// computation that drives provisioning, so the grant cannot drift from the
/// rendered Deployment. Authorization is the conjunction of two independent
/// facts, both deny-by-default:
///
/// 1. **Provenance** — `ns` is in `provisioned` (a namespace with no dedicated
///    Gateway, hence no relay, is absent and rejected).
/// 2. **Identity** — some peer URI SAN parses to a SPIFFE ID whose namespace and
///    ServiceAccount are exactly `(ns, relay_sa)` in `trust_domain`.
///
/// A Kubernetes projected token cryptographically binds the SVID's namespace to
/// the pod's own namespace, so the worst a forged label buys an attacker is a
/// `Namespace` stream for **their own** namespace — never a peer tenant's.
/// The trust domain is already enforced at the TLS handshake (the discovery
/// server's mTLS client-cert verifier); re-checking it here is defense-in-depth,
/// not the primary control.
#[derive(Clone)]
// intentionally open: constructed only via `new`; all fields private
pub struct ProvisionedRelayAuthorizer {
    /// Namespaces with a controller-provisioned relay, kept live by the operator.
    provisioned: Shared<HashSet<String>>,
    /// The ServiceAccount name every provisioned relay runs as (`coxswain-relay`).
    relay_sa: String,
    /// Trust domain the relay SVID must carry.
    trust_domain: String,
}

impl ProvisionedRelayAuthorizer {
    /// Build an authorizer over the operator's live provisioned-relay set.
    ///
    /// `provisioned` is shared with the controller's relay convergence (its
    /// writer); `relay_sa` is the fixed relay ServiceAccount name; `trust_domain`
    /// is the cluster SPIFFE trust domain.
    #[must_use]
    pub fn new(
        provisioned: Shared<HashSet<String>>,
        relay_sa: impl Into<String>,
        trust_domain: impl Into<String>,
    ) -> Self {
        Self {
            provisioned,
            relay_sa: relay_sa.into(),
            trust_domain: trust_domain.into(),
        }
    }
}

impl ScopeAuthorizer for ProvisionedRelayAuthorizer {
    fn allows_namespace(&self, peer: &PeerSvid, namespace: &str) -> bool {
        // No fail-open: an absent PeerSvid reaches the call site as empty SANs.
        if peer.uri_sans.is_empty() {
            return false;
        }
        // Provenance gate: the operator must currently have a relay in `namespace`.
        if !self.provisioned.load().contains(namespace) {
            return false;
        }
        // Identity gate: some SVID is exactly the relay SA in this namespace.
        peer.uri_sans.iter().any(|uri| {
            SpiffeId::parse(uri.as_str()).is_ok_and(|id| {
                id.trust_domain() == self.trust_domain
                    && id.namespace() == namespace
                    && id.service_account() == self.relay_sa
            })
        })
    }
}
