//! [`RoutingSource`] trait: the seam between routing-snapshot providers and the
//! proxy data plane.
//!
//! Moving the trait here (rather than leaving it in `coxswain-proxy`) lets
//! `coxswain-discovery` implement it for [`crate::client::DiscoveryClient`]
//! without creating a circular dependency between the two crates.

use crate::routing::{SharedGatewayRoutingTable, SharedIngressRoutingTable};
use crate::tls::{SharedClientCertStore, SharedListenerHostnames, SharedTlsStore};

/// Source of routing snapshots for the proxy data plane.
///
/// Implementations expose [`crate::Shared`] handles to the Ingress routing
/// table, the Gateway-API routing table, the TLS cert store, and the
/// per-Ingress client-certificate mTLS config store. The proxy holds these
/// handles and consults them on the hot path; `Shared` is cheap to clone and
/// the `load()` call is a single atomic pointer read.
pub trait RoutingSource: Send + Sync {
    /// Handle to the Ingress-flavored routing table snapshot.
    #[must_use]
    fn ingress_routes(&self) -> SharedIngressRoutingTable;

    /// Handle to the Gateway-API-flavored routing table snapshot.
    #[must_use]
    fn gateway_routes(&self) -> SharedGatewayRoutingTable;

    /// Handle to the TLS certificate store snapshot.
    #[must_use]
    fn tls_store(&self) -> SharedTlsStore;

    /// Handle to the per-Ingress client-certificate mTLS config store (#267).
    #[must_use]
    fn client_cert_store(&self) -> SharedClientCertStore;

    /// Handle to the per-port HTTPS Gateway-listener hostname snapshot for
    /// misdirected-request detection (GEP-3567, #96).
    ///
    /// The default returns an empty snapshot (check inactive) so
    /// [`coxswain_discovery::DiscoveryClient`] and other wire-backed
    /// implementations compile unchanged until the discovery wire format is
    /// extended to carry listener-hostnames data.
    #[must_use]
    fn listener_hostnames(&self) -> SharedListenerHostnames {
        SharedListenerHostnames::new()
    }
}
