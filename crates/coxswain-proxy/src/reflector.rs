//! Routing-table-build pipeline wiring for the `proxy` pod role.
//!
//! The actual reflector machinery — the K8s watch streams, the debounced
//! rebuild loop, and the `build_routes` / `build_tls` passes — lives in the
//! [`coxswain_reflector`] crate (which both the proxy and controller pods
//! depend on; neither pod depends on the other). This module is the thin
//! adaptor that constructs and exposes those primitives in the shape the
//! proxy data plane expects.
//!
//! The proxy pod has zero K8s write permissions. The [`Reconciler`] returned
//! here calls only `list` and `watch` on the Kubernetes API; status writes
//! live exclusively in [`coxswain_controller`], which the proxy crate does
//! not import.

use coxswain_core::ownership::OwnedGateways;
use coxswain_core::routing::{SharedGatewayRoutingTable, SharedIngressRoutingTable};
use coxswain_core::tls::SharedTlsStore;
use coxswain_reflector::{
    IngressDefaultBackend, IngressPorts, Reconciler, ReconcilerHealth, ReconcilerOptions,
    ReconcilerOutputs, SharedGatewayListenerHealth,
};

use crate::source::KubernetesSource;

/// Configuration bundle for the proxy-side routing-table-build pipeline.
///
/// Constructed by the bin layer from `CommonArgs` + `ProxyArgs` and handed to
/// [`spawn_routing_table_builder`]. The fields here are exactly the inputs
/// today's in-process wiring already supplied to the reconciler; the change
/// is that they now flow through a proxy-crate-owned entry point instead of
/// being constructed in `main.rs`. Not `#[non_exhaustive]` — it's an internal
/// wiring struct only `coxswain-bin` builds.
pub struct ProxyReflectorConfig {
    /// `GatewayClass`/`IngressClass`/`HTTPRoute` `controllerName` claim.
    pub controller_name: String,
    /// Optional cluster scope. `None` means cluster-wide.
    pub watch_namespace: Option<String>,
    /// Static Ingress listener ports (used by route builders + the controller's
    /// `PortUnavailable` status condition; both pods receive identical values
    /// from the operator).
    pub ingress_ports: IngressPorts,
    /// Optional cluster-wide default backend for unmatched Ingress traffic.
    pub ingress_default_backend: Option<IngressDefaultBackend>,
    /// Health-registry handles produced by the bin's `HealthRegistry::register`
    /// calls. The reflector pipeline flips the per-source checks on first
    /// `InitDone` and flips `routing_table_built` / `routing_table_loaded` on
    /// the first successful publish.
    pub health: ReconcilerHealth,
}

/// Spawned routing-table-build pipeline.
///
/// Holds the [`KubernetesSource`] the Pingora proxy services consume from,
/// the shared TLS handles, and the [`Reconciler`] background service the
/// caller must register with the Pingora server.
pub struct ProxyReflector {
    /// Source the proxy services read routing tables from.
    pub source: KubernetesSource,
    /// Reflector + rebuild background service. Register with the server via
    /// `pingora_core::services::background::background_service`.
    pub reconciler: Reconciler,
    /// Shared listener-health handle. Today this is consumed by
    /// `HotReloader` to know when new ports need binding; future cleanup
    /// can switch `HotReloader` to read `SharedGatewayRoutingTable` directly
    /// and drop this field.
    pub tls_health: SharedGatewayListenerHealth,
}

/// Build the proxy-side reflector pipeline and return the components the
/// caller wires into the Pingora server.
///
/// # Errors
///
/// None. Constructing the [`Reconciler`] is infallible; failures surface
/// later, at run-time, via the health-registry checks.
#[must_use]
pub fn spawn_routing_table_builder(config: ProxyReflectorConfig) -> ProxyReflector {
    let ProxyReflectorConfig {
        controller_name,
        watch_namespace,
        ingress_ports,
        ingress_default_backend,
        health,
    } = config;

    let ingress_routes = SharedIngressRoutingTable::new();
    let gateway_routes = SharedGatewayRoutingTable::new();
    let tls_store = SharedTlsStore::new();
    let tls_health = SharedGatewayListenerHealth::new();
    let owned_gateways = OwnedGateways::new();

    let reconciler = Reconciler::new(
        ReconcilerOutputs::new(
            ingress_routes.clone(),
            gateway_routes.clone(),
            tls_store.clone(),
            tls_health.clone(),
        ),
        owned_gateways,
        health,
        controller_name,
        {
            let mut opts = ReconcilerOptions::default();
            opts.watch_namespace = watch_namespace;
            opts.ingress_default_backend = ingress_default_backend;
            opts.ingress_ports = ingress_ports;
            opts
        },
    );

    let source = KubernetesSource::new(ingress_routes, gateway_routes, tls_store);

    ProxyReflector {
        source,
        reconciler,
        tls_health,
    }
}
