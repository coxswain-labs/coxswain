//! Kubernetes reflector pipeline and shared infrastructure for Coxswain.
//!
//! This crate is the K8s side of Coxswain — it owns the reflector spawn helpers,
//! the Gateway API type aliases, the namespace-scoping helper, the
//! `IngressDefaultBackend` type, the endpoint resolution helper, the route /
//! TLS table rebuild pipeline ([`Reconciler`]), and the CRD-presence probe.
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
//! - [`keys`] — `ListenerKey`, `RouteParentKey` used by routing/health maps.
//! - [`endpoints`] — `EndpointSlice` resolution into backend addresses.
//! - [`tls`] — `Shared{GatewayListener,HttpRoute,BackendTlsPolicy}Health` types
//!   plus PEM extraction from `kubernetes.io/tls` Secrets.
//! - [`ingress`] — `Ingress` → routing-table-entry translation.
//! - [`gateway_api`] — `HTTPRoute` → routing-table-entry translation, plus
//!   per-Route and per-Policy health computation.
//! - [`reconciler`] — debounced rebuild loop that drives all of the above off
//!   reflector store snapshots.
//! - [`crds`] — startup probe for Gateway API CRD presence.

pub mod cluster;
pub mod crds;
pub mod endpoints;
pub mod gateway_api;
pub mod gw_types;
pub mod ingress;
pub mod k8s_utils;
pub mod keys;
pub mod reconciler;
pub mod tls;

#[cfg(test)]
mod tests;

pub use cluster::{ClusterSummaryInputs, build_cluster_summary};
pub use crds::gateway_api_crds_present;
pub use ingress::IngressPorts;
pub use reconciler::{
    IngressDefaultBackend, IngressDefaultBackendParseError, Reconciler, ReconcilerHealth,
    ReconcilerOptions, ReconcilerOutputs,
};
pub use tls::{
    GatewayListenerHealth, ListenerInfo, ListenerTlsOutcome, SharedBackendTlsPolicyHealth,
    SharedGatewayListenerHealth, SharedHttpRouteHealth,
};
