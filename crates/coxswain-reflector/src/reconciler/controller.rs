//! `ControllerReconciler` — the reconciler the controller pod consumes.
//!
//! Today this is a type alias for [`super::SharedProxyReconciler`]: the
//! controller pod and the shared-proxy pod run the same watch + rebuild
//! pipeline. A future step narrows the controller's reconciler to skip
//! building routing tables and the TLS cert store (the controller doesn't
//! serve traffic), shaving the per-rebuild cost. That implementation split
//! is tracked as a follow-up to issue #206; callers that target the
//! [`ControllerReconciler`] name will not need to change when it lands.

pub use super::shared_proxy::SharedProxyReconciler as ControllerReconciler;
