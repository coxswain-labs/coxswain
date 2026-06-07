//! Kubernetes controller for Coxswain.
//!
//! Runs reflector-backed stores for all relevant resources (`HTTPRoute`, `Ingress`,
//! `Gateway`, `Secret`, `EndpointSlice`, …), debounces updates into routing-table
//! rebuilds, and writes Gateway API status conditions back through a leader-elected
//! [`Controller`].

mod controller;
pub(crate) mod endpoints;
pub(crate) mod gateway_api;
pub(crate) mod gw_types;
pub(crate) mod ingress;
pub(crate) mod k8s_utils;
pub(crate) mod keys;
mod reconciler;
mod tls;

#[cfg(test)]
mod tests;

pub use controller::{Controller, ControllerConfig, ControllerConfigError, StatusAddress};
pub use ingress::IngressPorts;
pub use reconciler::{
    IngressDefaultBackend, IngressDefaultBackendParseError, Reconciler, ReconcilerHealth,
    ReconcilerOptions,
};
pub use tls::{
    GatewayListenerHealth, ListenerInfo, ListenerTlsOutcome, SharedBackendTlsPolicyHealth,
    SharedGatewayListenerHealth,
};
