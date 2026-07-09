//! Ingress reconciler: translates `Ingress` resources into routing-table entries and TLS certs.

pub mod annotations;
mod backend;
mod class;
mod ports;
mod reconcile;
mod reconcile_helpers;
mod tls;

pub(crate) use class::resolve_class_params;
// Re-exported for test helpers in `tests/mod.rs` that build `IngressClassContext`.
#[cfg(test)]
pub(crate) use class::ResolvedClassParams;
pub use class::{claimed_ingress_class, is_default_ingress_class};
pub use ports::IngressPorts;
pub use reconcile::{IngressClassContext, IngressCrRefStores, IngressExtensionStores};

/// Zero-sized handle namespacing the Ingress reconciliation entry points.
/// The actual translation logic lives in the `reconcile` and `tls` submodules.
#[non_exhaustive]
pub struct IngressReconciler;

#[cfg(test)]
mod tests;
