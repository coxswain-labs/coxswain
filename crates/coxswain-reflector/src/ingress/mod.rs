//! Ingress reconciler: translates `Ingress` resources into routing-table entries and TLS certs.

pub mod annotations;
mod backend;
mod class;
mod ports;
mod reconcile;
mod tls;

pub use class::{claimed_ingress_class, is_default_ingress_class};
pub use ports::IngressPorts;

/// Zero-sized handle namespacing the Ingress reconciliation entry points.
/// The actual translation logic lives in the `reconcile` and `tls` submodules.
#[non_exhaustive]
pub struct IngressReconciler;

#[cfg(test)]
mod tests;
