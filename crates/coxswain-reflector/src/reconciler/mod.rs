//! Reconciler types — one per pod role.
//!
//! The reconciler is the K8s watch + rebuild pipeline that turns reflector
//! snapshots into routing tables, TLS stores, and status-health maps. Each pod
//! role has its own reconciler type with a focused output set:
//!
//! - [`SharedProxyReconciler`] — `serve proxy --shared` and `serve dev`.
//!   Cluster-wide watches; builds Ingress + Gateway routes, TLS store, listener
//!   health, route health, policy health, and the cluster summary.
//! - `DedicatedProxyReconciler` (Step 7) — `serve proxy --gateway`.
//!   Namespace-narrowed watches scoped to one Gateway; builds only that
//!   Gateway's routes + TLS store.
//! - `ControllerReconciler` (Step 7) — `serve controller`. Cluster-wide
//!   watches; builds the health maps, the cluster summary, and the owned-gateway
//!   set the status writer subscribes to. Does not build routing tables or the
//!   TLS store — the controller pod doesn't serve traffic.
//!
//! Helper functions shared across reconcilers (ownership computation, grant
//! flattening, routing-table builds, TLS build) live as `pub(super)` free
//! items in this module's siblings, called from each reconciler's own
//! orchestration.

pub mod controller;
pub mod shared_proxy;

pub use controller::ControllerReconciler;
pub use shared_proxy::{
    IngressDefaultBackend, IngressDefaultBackendParseError, ReconcilerHealth, ReconcilerOptions,
    ReconcilerOutputs, SharedProxyReconciler,
};
