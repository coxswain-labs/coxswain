//! [`RoutingSource`] trait: the seam between routing-snapshot providers and the
//! proxy data plane.
//!
//! Moving the trait here (rather than leaving it in `coxswain-proxy`) lets
//! `coxswain-discovery` implement it for [`crate::client::DiscoveryClient`]
//! without creating a circular dependency between the two crates.

use crate::routing::{
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable, SharedUdpRouteTable,
};
use crate::tls::{SharedClientCertStore, SharedListenerHostnames, SharedPortTlsStore};

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

    /// Handle to the per-port TLS terminate cert store snapshot (#472).
    #[must_use]
    fn tls_store(&self) -> SharedPortTlsStore;

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

    /// Handle to the TLS passthrough routing table snapshot for TLSRoute / GEP-2643.
    ///
    /// The default returns an empty table (no passthrough routes, all connections
    /// on the passthrough port are dropped) so wire-backed implementations compile
    /// unchanged until the discovery wire format is extended to carry passthrough data.
    #[must_use]
    fn passthrough_routes(&self) -> SharedTlsPassthroughTable {
        SharedTlsPassthroughTable::new()
    }

    /// Handle to the TLS terminate routing table snapshot for TLSRouteModeTerminate (#481).
    ///
    /// The default returns an empty table so existing implementations compile unchanged
    /// until wired.
    #[must_use]
    fn terminate_routes(&self) -> SharedTlsPassthroughTable {
        SharedTlsPassthroughTable::new()
    }

    /// Handle to the port-keyed TCP routing table snapshot for TCPRoute / GEP-1901 (#505).
    ///
    /// The default returns an empty table (no TCP routes, all connections on a
    /// TCP-proxy port are dropped) so existing implementations compile unchanged
    /// until wired.
    #[must_use]
    fn tcp_routes(&self) -> SharedTcpRouteTable {
        SharedTcpRouteTable::new()
    }

    /// Handle to the port-keyed UDP routing table snapshot for UDPRoute / GEP-2645 (#506).
    ///
    /// The default returns an empty table (no UDP routes, all datagrams on a
    /// UDP-proxy port are dropped) so existing implementations compile unchanged
    /// until wired.
    #[must_use]
    fn udp_routes(&self) -> SharedUdpRouteTable {
        SharedUdpRouteTable::new()
    }
}
