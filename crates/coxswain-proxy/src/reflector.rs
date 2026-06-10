//! Routing-table-build pipeline wiring for the `proxy` pod role.
//!
//! The actual reflector machinery — the K8s watch streams, the debounced
//! rebuild loop, and the `build_routes` / `build_tls` passes — lives in the
//! [`coxswain_reflector`] crate (which both the proxy and controller pods
//! depend on; neither pod depends on the other). This module is the thin
//! adaptor that constructs and exposes those primitives in the shape the
//! proxy data plane expects.
//!
//! The proxy pod has zero K8s write permissions. The [`SharedProxyReconciler`] returned
//! here calls only `list` and `watch` on the Kubernetes API; status writes
//! live exclusively in [`coxswain_controller`], which the proxy crate does
//! not import.

use coxswain_core::cluster::SharedClusterSummary;
use coxswain_core::ownership::OwnedGateways;
use coxswain_core::routing::{SharedGatewayRoutingTable, SharedIngressRoutingTable};
use coxswain_core::tls::SharedTlsStore;
use coxswain_reflector::{
    DedicatedConfig, DedicatedOutputs, DedicatedProxyReconciler, IngressDefaultBackend,
    IngressPorts, ReconcilerHealth, ReconcilerOptions, ReconcilerOutputs,
    SharedGatewayListenerHealth, SharedProxyReconciler,
};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

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
/// the shared TLS handles, and the [`SharedProxyReconciler`] background
/// service the caller must register with the Pingora server.
pub struct ProxyReflector {
    /// Source the proxy services read routing tables from.
    pub source: KubernetesSource,
    /// Reflector + rebuild background service. Register with the server via
    /// `pingora_core::services::background::background_service`.
    pub reconciler: SharedProxyReconciler,
    /// Shared listener-health handle. Consumed by `ListenerSpecsAdapter` in
    /// `coxswain-bin` to derive the desired `HashSet<ListenerSpec>` and feed
    /// it to the `ProxyAcceptor` for dynamic port bind/unbind.
    pub tls_health: SharedGatewayListenerHealth,
}

/// Build the proxy-side reflector pipeline and return the components the
/// caller wires into the Pingora server.
///
/// # Errors
///
/// None. Constructing the [`SharedProxyReconciler`] is infallible; failures
/// surface later, at run-time, via the health-registry checks.
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
    let cluster_summary = SharedClusterSummary::new();
    let owned_gateways = OwnedGateways::new();
    // Proxy pods never hold a leader-election lease; pass a always-false handle
    // so the reflector pipeline's shared shape stays uniform across pod roles.
    // The summary the proxy writes here is unused (proxy doesn't serve `/cluster`).
    let leader = Arc::new(AtomicBool::new(false));

    let reconciler = SharedProxyReconciler::new(
        ReconcilerOutputs::new(
            ingress_routes.clone(),
            gateway_routes.clone(),
            tls_store.clone(),
            tls_health.clone(),
            cluster_summary,
        ),
        owned_gateways,
        leader,
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

/// Configuration bundle for the dedicated-proxy routing-table-build pipeline.
///
/// Parallel to [`ProxyReflectorConfig`] but carrying the dedicated-mode
/// identifiers + RBAC opt-in flags instead of the shared pool's
/// `IngressDefaultBackend` / `watch_namespace`. Constructed by the bin layer
/// from `serve proxy --gateway` args.
pub struct DedicatedProxyReflectorConfig {
    /// `GatewayClass`/`HTTPRoute` `controllerName` claim.
    pub controller_name: String,
    /// Name of the target Gateway.
    pub gateway_name: String,
    /// Namespace of the target Gateway.
    pub gateway_namespace: String,
    /// Permit cluster-wide HTTPRoute reads (gates listeners with
    /// `allowedRoutes.namespaces.from: All`).
    pub allow_cluster_wide_route_read: bool,
    /// Permit cluster-wide Namespace reads (gates listeners with
    /// `allowedRoutes.namespaces.from: Selector`).
    pub allow_cluster_wide_namespace_read: bool,
    /// Namespaces the proxy is permitted to watch backend resources in.
    /// Rendered by the controller from the Gateway's desired-namespace set
    /// (issue #209). Empty list falls back to cluster-wide watches; production
    /// invocations always set this.
    pub watch_namespaces: Vec<String>,
    /// Health-registry handles produced by the bin's `HealthRegistry::register`
    /// calls.
    pub health: ReconcilerHealth,
}

/// Spawned dedicated-proxy routing-table-build pipeline.
///
/// Holds the [`KubernetesSource`] consumed by the Pingora `GatewayProxy`
/// service (the dedicated pod registers no `IngressProxy`), the shared TLS
/// handles, and the [`DedicatedProxyReconciler`] the caller registers with
/// the Pingora server.
pub struct DedicatedProxyReflector {
    /// Source the `GatewayProxy` service reads its routing table from.
    pub source: KubernetesSource,
    /// Reflector + rebuild background service.
    pub reconciler: DedicatedProxyReconciler,
    /// Shared per-listener health. Consumed by `ListenerSpecsAdapter` for
    /// dynamic port management and the admin `/status` endpoint.
    pub tls_health: SharedGatewayListenerHealth,
}

/// Build the dedicated-proxy reflector pipeline.
///
/// # Errors
///
/// None. Failures surface at run-time via the health-registry checks.
#[must_use]
pub fn spawn_dedicated_routing_table_builder(
    config: DedicatedProxyReflectorConfig,
) -> DedicatedProxyReflector {
    let DedicatedProxyReflectorConfig {
        controller_name,
        gateway_name,
        gateway_namespace,
        allow_cluster_wide_route_read,
        allow_cluster_wide_namespace_read,
        watch_namespaces,
        health,
    } = config;

    // The Ingress routing table is constructed but never written: the
    // dedicated pod registers no `IngressProxy`. Keeping a placeholder
    // `SharedIngressRoutingTable` here lets `KubernetesSource` stay
    // identically-shaped across the two proxy modes.
    let ingress_routes = SharedIngressRoutingTable::new();
    let gateway_routes = SharedGatewayRoutingTable::new();
    let tls_store = SharedTlsStore::new();
    let tls_health = SharedGatewayListenerHealth::new();
    let owned_gateways = OwnedGateways::new();
    let _leader: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    let mut dedicated_config = DedicatedConfig::new(
        controller_name,
        gateway_name.clone(),
        gateway_namespace.clone(),
    );
    dedicated_config.allow_cluster_wide_route_read = allow_cluster_wide_route_read;
    dedicated_config.allow_cluster_wide_namespace_read = allow_cluster_wide_namespace_read;
    dedicated_config.watch_namespaces = watch_namespaces;

    let reconciler = DedicatedProxyReconciler::new(
        dedicated_config,
        DedicatedOutputs::new(
            gateway_routes.clone(),
            tls_store.clone(),
            tls_health.clone(),
        ),
        owned_gateways,
        health,
    );

    let source = KubernetesSource::new(ingress_routes, gateway_routes, tls_store);

    DedicatedProxyReflector {
        source,
        reconciler,
        tls_health,
    }
}
