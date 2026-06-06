mod backend;
mod class;
mod ports;
mod reconcile;
mod tls;

pub use class::{claimed_ingress_class, is_default_ingress_class};
pub use ports::IngressPorts;

pub struct IngressReconciler;

#[cfg(test)]
mod tests;
