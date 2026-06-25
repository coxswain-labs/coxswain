//! Reconciler types — one per pod role.
//!
//! The reconciler is the K8s watch + rebuild pipeline that turns reflector
//! snapshots into routing tables, TLS stores, and status-health maps. Each pod
//! role has its own reconciler type with a focused output set:
//!
//! - [`SharedProxyReconciler`] — `serve proxy --shared`.
//!   Cluster-wide watches; builds Ingress + Gateway routes, TLS store, listener
//!   health, route health, policy health, and the cluster summary. Also
//!   publishes per-cut-over-Gateway snapshots into the dedicated registry the
//!   discovery server serves to dedicated proxies (#426).
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
pub mod proxy;

pub use controller::ControllerReconciler;
pub use proxy::{
    IngressDefaultBackend, IngressDefaultBackendParseError, IngressEvent, ReconcilerHealth,
    ReconcilerOptions, ReconcilerOutputs, SharedProxyReconciler, StatusSubscriptions,
};
