//! Kubernetes reflector pipeline and shared infrastructure for Coxswain.
//!
//! This crate is the K8s side of Coxswain — it owns the reflector spawn helpers,
//! the Gateway API type aliases, the namespace-scoping helper, the
//! `IngressDefaultBackend` type, the endpoint resolution helper, the route /
//! TLS table rebuild pipeline ([`SharedProxyReconciler`]), and the CRD-presence probe.
//!
//! Both [`coxswain_proxy`] and [`coxswain_controller`] depend on this crate.
//! Neither depends on the other — the read-only-proxy invariant is enforced at
//! the crate dependency graph as well as at runtime: the proxy pod never
//! invokes any code path from `coxswain-controller`, so it has no way to issue
//! a Kubernetes write API call.
//!
//! ## Module layout
//!
//! - [`gw_types`] — re-exports Gateway API types from the active channel with
//!   project-canonical aliases (`HTTPRoute` → `HttpRoute` etc.).
//! - [`k8s_utils`] — generic helpers like `scoped_api`.
//! - [`keys`] — `ListenerKey`, `RouteParentKey` used by routing/status maps.
//! - [`endpoints`] — `EndpointSlice` resolution into backend addresses.
//! - [`tls`] — PEM extraction from `kubernetes.io/tls` Secrets.
//! - [`status`] — `Shared{GatewayListener,Route,BackendTlsPolicy}Status` types.
//! - [`ingress`] — `Ingress` → routing-table-entry translation.
//! - [`gateway_api`] — `HTTPRoute` → routing-table-entry translation, plus
//!   per-Route and per-Policy status computation.
//! - [`reconciler`] — debounced rebuild loop that drives all of the above off
//!   reflector store snapshots.
//! - [`reference_grants`] — `ReferenceGrant` flattening consumed by the
//!   proxy reconciler (shared-pool and dedicated-mode snapshots alike).
//! - [`port_alloc`] — internal target-port allocator for shared-mode
//!   per-Gateway addressing (#472).
//! - [`crds`] — startup probe for Gateway API CRD presence.

pub mod cluster;
pub mod crds;
pub mod duration;
pub mod endpoints;
pub mod gateway_api;
pub mod gw_types;
pub mod ingress;
pub mod k8s_utils;
pub mod keys;
pub mod metrics;
pub mod port_alloc;
pub mod reconciler;
pub mod reference_grants;
pub mod status;
pub mod tls;

#[cfg(test)]
mod tests;

pub use cluster::{ClusterSummaryInputs, build_cluster_summary};
pub use coxswain_core::fleet::SharedFleet;
pub use crds::gateway_api_crds_present;
pub use ingress::IngressPorts;
pub use metrics::{MetricsPrefix, ReflectorMetrics};
pub use reconciler::listener_merge::{EffectiveListenerPort, effective_listener_ports};
pub use reconciler::{
    ControllerReconciler, IngressDefaultBackend, IngressDefaultBackendParseError, IngressEvent,
    ReconcilerHealth, ReconcilerOptions, ReconcilerOutputs, SharedProxyReconciler,
    StatusSubscriptions,
};
pub use status::{
    BackendTlsPolicyStatus, BackendTlsPolicyStatusMap, ClientTrafficPolicyStatus,
    ClientTrafficPolicyStatusMap, GatewayListenerStatus, ListenerInfo, ListenerReadiness,
    ListenerSource, ListenerStatusKey, RouteParentStatus, RouteStatusMap,
    SharedBackendTlsPolicyStatus, SharedClientTrafficPolicyStatus, SharedGatewayListenerStatus,
    SharedRouteStatus,
};
