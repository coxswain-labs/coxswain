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
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTlsPassthroughTable,
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
        passthrough_routes: SharedTlsPassthroughTable,
    ) -> Self {
        Self {
            ingress_routes,
            gateway_routes,
            tls_store,
            client_cert_store,
            listener_hostnames,
            passthrough_routes,
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
}
