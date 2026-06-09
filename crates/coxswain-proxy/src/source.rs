//! Abstraction over how routing data reaches the proxy.
//!
//! Today, every proxy embeds its own Kubernetes reflectors and builds its
//! routing tables directly from watch events. [`KubernetesSource`] is the
//! `RoutingSource` implementation that exposes those reflector-backed
//! snapshots to the proxy.
//!
//! Future impl: `XdsSource` — connect to a controller xDS endpoint when
//! `--source=xds` is implemented. The trait is the seam that lets the proxy
//! crate stay agnostic to "where does the routing table come from".

use coxswain_core::routing::{SharedGatewayRoutingTable, SharedIngressRoutingTable};
use coxswain_core::tls::SharedTlsStore;

/// Source of routing snapshots for the proxy data plane.
///
/// Implementations expose `Shared` handles to the Ingress routing table, the
/// Gateway-API routing table, and the TLS cert store. The proxy holds these
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
}

/// Routing source backed by in-process Kubernetes reflectors.
///
/// Holds cheap clones of the `Shared` handles that the controller's
/// reconciler writes into. Construction takes the same three handles that
/// will be threaded into the per-source proxies, so the `RoutingSource`
/// trait is purely a passive view over what the rest of the binary already
/// owns — no new lifecycle, no new spawned tasks.
#[non_exhaustive]
pub struct KubernetesSource {
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    tls_store: SharedTlsStore,
}

impl KubernetesSource {
    /// Construct a `KubernetesSource` from existing shared handles.
    #[must_use]
    pub fn new(
        ingress_routes: SharedIngressRoutingTable,
        gateway_routes: SharedGatewayRoutingTable,
        tls_store: SharedTlsStore,
    ) -> Self {
        Self {
            ingress_routes,
            gateway_routes,
            tls_store,
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

    fn tls_store(&self) -> SharedTlsStore {
        self.tls_store.clone()
    }
}
