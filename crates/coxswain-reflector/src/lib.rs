//! Kubernetes reflector pipeline and shared infrastructure for Coxswain.
//!
//! This crate is the K8s side of Coxswain — it owns the reflector spawn helpers,
//! the Gateway API type aliases, the namespace-scoping helper, the
//! `IngressDefaultBackend` type, the endpoint resolution helper, the route /
//! TLS table rebuild pipeline ([`SharedProxyReconciler`]), and the CRD-presence probe.
//!
//! Both `coxswain_proxy` and `coxswain_controller` depend on this crate.
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
//! - [`capabilities`] — per-kind and per-field Gateway API capability
//!   detection, so the controller degrades to whatever CRD set is installed
//!   instead of wedging on an older one.
//! - `fingerprint` — shared `resourceVersion`-based fingerprint primitives
//!   used by the partitioned rebuild below.
//!
//! ## Partitioned incremental rebuild (#511)
//!
//! `reconciler::proxy::rebuild()` used to reconstruct the entire Gateway API
//! routing world — every `HTTPRoute`/`GRPCRoute`, every backend resolution,
//! every filter/auth/policy lookup — on every single triggering watch event,
//! regardless of what actually changed (O(total-state) per event). Two
//! caches, both owned across rebuilds by the debounce loop
//! (`reconciler::cache::ReflectorCaches`, since `rebuild()` itself has no
//! handle to what it published last cycle), flatten this:
//!
//! - **Endpoint-resolution model** ([`endpoints::pool::EndpointCache`]):
//!   endpoints are canonically modeled as `(namespace, service, port)`
//!   resources ([`coxswain_core::endpoints`], settled jointly with #383,
//!   which serializes this same model onto the discovery wire). One
//!   grouping pass over the `EndpointSlice` store per rebuild fingerprints
//!   each `(namespace, service)` group; `endpoints::resolve()`'s O(all
//!   slices) scan runs only for a group whose fingerprint moved, in place of
//!   running once per backend reference every rebuild.
//! - **Partitioned route recompile** (`reconciler::gateway_partition`,
//!   `reconciler::cache::PartitionCache`): the compiled Gateway routing
//!   table is a set of `(port, host)` partitions, each an
//!   `Arc<HostRouter>` (`coxswain_core::routing::common::port`). A
//!   partition's fingerprint XOR-folds every route bound to it (via
//!   `gateway_api::http_route_fingerprint`/`grpc_route_fingerprint`) plus a
//!   `global_epoch` covering inputs a per-route static scan can't precisely
//!   attribute — `targetRef`-based policy attachment, a `BasicAuth` CR's own
//!   `secretRef`, GEP-3155 backend client certs, `ReferenceGrant`s. Only
//!   partitions whose fingerprint changed are recompiled via
//!   `HostRouterBuilder`; every other partition splices its cached
//!   `Arc<HostRouter>` in directly
//!   (`coxswain_core::routing::common::port::PortTableBuilder::insert_compiled_exact_host`
//!   and its wildcard/catchall siblings) — no `matchit`/`RegexSet`
//!   recompilation. Dedicated (per-cut-over-Gateway) snapshots keep their own
//!   `PartitionCache`, keyed per Gateway so their `(port, host)` keys can't
//!   collide with the shared pool's or each other's.
//!
//! Both caches degrade safely: any fingerprint miss (new partition, changed
//! inputs, cache never populated) recomputes fresh rather than risking a
//! stale reuse. `build_ingress_routes` is **not** partitioned — Ingress's
//! annotation-driven reconcile still fully rebuilds every rebuild; only the
//! Gateway API (HTTPRoute/GRPCRoute) path is in scope for #511.

pub mod capabilities;
pub mod cluster;
pub mod duration;
pub mod endpoints;
pub(crate) mod fingerprint;
pub mod gateway_api;
pub mod gw_types;
pub mod ingress;
pub mod jwks;
pub mod k8s_utils;
pub mod keys;
pub mod merged_store;
pub mod metrics;
pub mod port_alloc;
pub mod reconciler;
pub mod reference_grants;
pub mod status;
pub mod status_queue;
pub mod tls;

#[cfg(test)]
mod tests;

pub use cluster::{ClusterSummaryInputs, build_cluster_summary};
pub use coxswain_core::fleet::SharedFleet;
pub use ingress::IngressPorts;
pub use jwks::JwksCacheHandle;
pub use k8s_utils::{WatchScope, WatchScopeError};
pub use merged_store::MergedStore;
pub use metrics::{MetricsPrefix, ReflectorMetrics};
pub use reconciler::listener_merge::{EffectiveListenerPort, effective_listener_ports};
pub use reconciler::{
    ControllerReconciler, DebounceSettings, DebounceSettingsError, IngressDefaultBackend,
    IngressDefaultBackendParseError, IngressEvent, OperatorStores, ReconcilerHealth,
    ReconcilerOptions, ReconcilerOutputs, SharedProxyReconciler, StatusStores,
};
pub use status::{
    BackendTlsPolicyStatus, BackendTlsPolicyStatusHandle, BackendTlsPolicyStatusMap,
    ClientTrafficPolicyStatus, ClientTrafficPolicyStatusHandle, ClientTrafficPolicyStatusMap,
    CoxswainBackendPolicyStatus, CoxswainBackendPolicyStatusHandle, CoxswainBackendPolicyStatusMap,
    CoxswainExternalAuthStatus, CoxswainExternalAuthStatusHandle, CoxswainExternalAuthStatusMap,
    GatewayListenerStatus, GatewayListenerStatusHandle, ListenerInfo, ListenerReadiness,
    ListenerSource, ListenerStatusKey, RouteParentStatus, RouteStatusHandle, RouteStatusMap,
};
pub use status_queue::{StatusKey, StatusKind, StatusWorkqueue};
