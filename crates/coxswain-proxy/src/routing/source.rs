//! Abstraction over how routing data reaches the proxy.
//!
//! [`KubernetesSource`] wraps the `Shared` handles that the controller's
//! reconciler writes into, exposing them via the [`RoutingSource`] trait so
//! the proxy stays agnostic to where its routing snapshots come from.
//!
//! The [`RoutingSource`] trait itself lives in `coxswain-core` so that
//! `coxswain-discovery` can implement it for `DiscoveryClient` without a
//! circular dependency. It is re-exported here for backwards compatibility.

use coxswain_core::routing::{
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable, SharedUdpRouteTable,
};
use coxswain_core::tls::{SharedClientCertStore, SharedListenerHostnames, SharedPortTlsStore};

pub use coxswain_core::RoutingSource;

/// Routing source backed by in-process Kubernetes reflectors.
///
/// Holds cheap clones of the `Shared` handles that the controller's
/// reconciler writes into. Construction takes the same four handles that
/// will be threaded into the per-source proxies, so the `RoutingSource`
/// trait is purely a passive view over what the rest of the binary already
/// owns — no new lifecycle, no new spawned tasks.
#[non_exhaustive]
pub struct KubernetesSource {
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    tls_store: SharedPortTlsStore,
    client_cert_store: SharedClientCertStore,
    listener_hostnames: SharedListenerHostnames,
    passthrough_routes: SharedTlsPassthroughTable,
    terminate_routes: SharedTlsPassthroughTable,
    tcp_routes: SharedTcpRouteTable,
    udp_routes: SharedUdpRouteTable,
}

/// The L4 routing-table handles [`KubernetesSource::new`] groups to stay under
/// the workspace 7-argument limit: TLS passthrough, TLS terminate (#481),
/// TCP proxy (#505), and UDP proxy (#506) — the four port-keyed tables that
/// bypass the L7 routing tables entirely.
// intentionally open: field-literal constructed by callers of `KubernetesSource::new`.
pub struct L4RoutingTables {
    /// SNI-keyed routing table for TLSRoute `mode: Passthrough` listeners.
    pub passthrough_routes: SharedTlsPassthroughTable,
    /// SNI-keyed routing table for TLSRoute `mode: Terminate` listeners (#481).
    pub terminate_routes: SharedTlsPassthroughTable,
    /// Port-keyed routing table for TCPRoute listeners (#505).
    pub tcp_routes: SharedTcpRouteTable,
    /// Port-keyed routing table for UDPRoute listeners (#506).
    pub udp_routes: SharedUdpRouteTable,
}

impl KubernetesSource {
    /// Construct a `KubernetesSource` from existing shared handles.
    #[must_use]
    pub fn new(
        ingress_routes: SharedIngressRoutingTable,
        gateway_routes: SharedGatewayRoutingTable,
        tls_store: SharedPortTlsStore,
        client_cert_store: SharedClientCertStore,
        listener_hostnames: SharedListenerHostnames,
        l4_tables: L4RoutingTables,
    ) -> Self {
        Self {
            ingress_routes,
            gateway_routes,
            tls_store,
            client_cert_store,
            listener_hostnames,
            passthrough_routes: l4_tables.passthrough_routes,
            terminate_routes: l4_tables.terminate_routes,
            tcp_routes: l4_tables.tcp_routes,
            udp_routes: l4_tables.udp_routes,
        }
    }
}

impl RoutingSource for KubernetesSource {
    fn ingress_routes(&self) -> SharedIngressRoutingTable {
        self.ingress_routes.clone()
    }

    fn gateway_routes(&self) -> SharedGatewayRoutingTable {
        self.gateway_routes.clone()
    }

    fn tls_store(&self) -> SharedPortTlsStore {
        self.tls_store.clone()
    }

    fn client_cert_store(&self) -> SharedClientCertStore {
        self.client_cert_store.clone()
    }

    fn listener_hostnames(&self) -> SharedListenerHostnames {
        self.listener_hostnames.clone()
    }

    fn passthrough_routes(&self) -> SharedTlsPassthroughTable {
        self.passthrough_routes.clone()
    }

    fn terminate_routes(&self) -> SharedTlsPassthroughTable {
        self.terminate_routes.clone()
    }

    fn tcp_routes(&self) -> SharedTcpRouteTable {
        self.tcp_routes.clone()
    }

    fn udp_routes(&self) -> SharedUdpRouteTable {
        self.udp_routes.clone()
    }
}
