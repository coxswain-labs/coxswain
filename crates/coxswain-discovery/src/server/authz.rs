//! `Scope::Namespace` subscribe authorizers, and the relay-identity gate for
//! `RosterReport` (#582/#584/#666).
//!
//! The [`ScopeAuthorizer`] trait gates two things: the relay tier's
//! namespace-aggregation subscribe scope, and which stream may fold a roster into
//! the node registry. Both default to the fail-closed [`DenyAll`]; the
//! provenance-backed [`ProvisionedRelayAuthorizer`] is what the controller wires
//! in where relays are provisioned.

use std::collections::HashSet;

use coxswain_core::Shared;
use coxswain_core::identity::SpiffeId;

use crate::auth::PeerSvid;
use crate::subscription::Scope;

/// Authorizes a [`Scope::Namespace`] subscribe (#582, the relay tier's upstream
/// aggregation scope) and a `RosterReport` fold (#666, the relay tier's
/// leaf-roster upload).
///
/// `Namespace` fans out every dedicated Gateway's routing world in one
/// namespace to a single stream, so a wrongly-authorized subscriber gets a much
/// bigger blast radius than a single `Scope::Gateway` binding — hence a
/// dedicated seam rather than reusing the private Gateway-scope SVID binding
/// check. A `RosterReport` folds sender-controlled rows straight into the node
/// registry that the #531 convergence gate reads, so it needs the same
/// dedicated seam rather than an ambient "any connected stream" trust. The
/// shipped provenance-backed implementation is [`ProvisionedRelayAuthorizer`]; a
/// [`DiscoveryService`](crate::DiscoveryService) with none wired in defaults to
/// [`DenyAll`].
pub trait ScopeAuthorizer: Send + Sync {
    /// Returns `true` if `peer` may open a `Namespace{namespace}` subscribe.
    fn allows_namespace(&self, peer: &PeerSvid, namespace: &str) -> bool;

    /// Returns `true` if `peer` may submit a `RosterReport` on a stream
    /// subscribed at `scope`.
    fn allows_roster(&self, peer: &PeerSvid, scope: &Scope) -> bool;
}

/// Fail-closed default [`ScopeAuthorizer`]: denies every `Namespace` subscribe
/// and every `RosterReport`.
///
/// The fail-closed default until the provenance-backed [`ProvisionedRelayAuthorizer`]
/// is wired in via [`DiscoveryService::with_scope_authorizer`](crate::DiscoveryService::with_scope_authorizer): without a
/// provisioned relay there is no legitimate `Namespace` subscriber, or roster
/// reporter, to allow.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAll;

impl ScopeAuthorizer for DenyAll {
    fn allows_namespace(&self, _peer: &PeerSvid, _namespace: &str) -> bool {
        false
    }

    fn allows_roster(&self, _peer: &PeerSvid, _scope: &Scope) -> bool {
        false
    }
}

/// Plain-data config for [`ProvisionedRelayAuthorizer::new`], grouped so the
/// constructor stays a single argument as the identity surface has grown
/// (#666 added the shared-relay identity alongside the namespace-relay one).
/// Mirrors [`crate::bootstrap_server::UpstreamResolverConfig`] in the same
/// crate, which groups the same kind of relay-identity constants for the
/// upstream-resolution seam.
pub struct RelayAuthzConfig {
    /// Namespaces with a controller-provisioned relay, kept live by the operator.
    pub provisioned: Shared<HashSet<String>>,
    /// The ServiceAccount name every provisioned namespace relay runs as
    /// (`coxswain-relay`).
    pub relay_sa: String,
    /// Trust domain every relay SVID must carry.
    pub trust_domain: String,
    /// The shared relay's fixed ServiceAccount name (`coxswain-relay-shared`),
    /// distinct from `relay_sa`.
    pub shared_relay_sa: String,
    /// Namespace the shared relay runs in (the coxswain install namespace).
    pub install_namespace: String,
}

/// Provenance-backed [`ScopeAuthorizer`] (#584, #666): authorizes a
/// `Namespace{ns}` subscribe only for the relay ServiceAccount the controller
/// provisioned in `ns`, and a `RosterReport` only for the relay tier whose
/// identity matches the stream's own subscribed scope.
///
/// `provisioned` is the live set of namespaces where the operator currently has
/// a relay — published by the controller's relay convergence from the *same*
/// computation that drives provisioning, so the grant cannot drift from the
/// rendered Deployment. Namespace authorization is the conjunction of two
/// independent facts, both deny-by-default:
///
/// 1. **Provenance** — `ns` is in `provisioned` (a namespace with no dedicated
///    Gateway, hence no relay, is absent and rejected).
/// 2. **Identity** — some peer URI SAN parses to a SPIFFE ID whose namespace and
///    ServiceAccount are exactly `(ns, relay_sa)` in `trust_domain`.
///
/// A Kubernetes projected token cryptographically binds the SVID's namespace to
/// the pod's own namespace, so the worst a forged ServiceAccount name buys an
/// attacker is a grant for **their own** namespace — never a peer tenant's. The
/// shared relay has no per-namespace provenance set (it is cluster-wide by
/// design), so its identity check pins the namespace directly: the SVID must be
/// exactly `(trust_domain, install_namespace, shared_relay_sa)`, unforgeable for
/// the same reason — no tenant namespace can mint a token bound to
/// `install_namespace`. The trust domain is already enforced at the TLS
/// handshake (the discovery server's mTLS client-cert verifier); re-checking it
/// here is defense-in-depth, not the primary control.
#[derive(Clone)]
pub struct ProvisionedRelayAuthorizer {
    provisioned: Shared<HashSet<String>>,
    relay_sa: String,
    trust_domain: String,
    shared_relay_sa: String,
    install_namespace: String,
}

impl ProvisionedRelayAuthorizer {
    /// Build an authorizer over the operator's live provisioned-relay set and
    /// the relay tier's fixed identity constants.
    #[must_use]
    pub fn new(config: RelayAuthzConfig) -> Self {
        Self {
            provisioned: config.provisioned,
            relay_sa: config.relay_sa,
            trust_domain: config.trust_domain,
            shared_relay_sa: config.shared_relay_sa,
            install_namespace: config.install_namespace,
        }
    }

    /// Whether `peer` is exactly the shared relay's identity: SVID
    /// `(trust_domain, install_namespace, shared_relay_sa)`. No provenance gate
    /// — the shared relay is a single cluster-wide singleton, not a per-namespace
    /// grant, so the identity triple alone is the whole check.
    fn is_shared_relay_identity(&self, peer: &PeerSvid) -> bool {
        if peer.uri_sans.is_empty() {
            return false;
        }
        peer.uri_sans.iter().any(|uri| {
            SpiffeId::parse(uri.as_str()).is_ok_and(|id| {
                id.trust_domain() == self.trust_domain
                    && id.namespace() == self.install_namespace
                    && id.service_account() == self.shared_relay_sa
            })
        })
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

    fn allows_roster(&self, peer: &PeerSvid, scope: &Scope) -> bool {
        match scope {
            // The namespace relay's roster is authorized by the same
            // provenance + identity check as its own subscribe.
            Scope::Namespace { namespace } => self.allows_namespace(peer, namespace),
            // The shared relay has no per-namespace provenance grant; its
            // identity alone is the check.
            Scope::SharedPool => self.is_shared_relay_identity(peer),
            // No leaf ever reports a roster.
            Scope::Gateway { .. } => false,
        }
    }
}
