//! Kubernetes status writer for Coxswain.
//!
//! This crate runs in the controller pod role. It does not start any reflectors
//! of its own — those live in [`coxswain_reflector`] — but it consumes the
//! shared health channels published by the reflector pipeline and writes
//! Gateway API / Ingress `status` patches back to the API server through a
//! leader-elected [`Controller`].
//!
//! The proxy pod role does not depend on this crate; the read-only-proxy
//! invariant is enforced structurally.

mod controller;
mod metrics;
mod operator;
mod status_common;
mod status_writer;

pub use controller::{
    Controller, ControllerConfig, ControllerConfigError, LeaseSettings, StatusAddress,
    StatusHealthChannels,
};
pub use operator::{Operator, OperatorConfig};
pub use status_writer::{StatusWriterConfig, StatusWriterError, spawn_status_writer};

// Re-export reflector primitives that bin or downstream crates expect to reach
// from `coxswain_controller::…`. Direct re-exports keep callers compiling
// without forcing every site to learn the new crate name.
pub use coxswain_core::cluster::SharedClusterSummary;
pub use coxswain_reflector::{
    GatewayListenerHealth, IngressPorts, ListenerInfo, ListenerTlsOutcome,
    SharedBackendTlsPolicyHealth, SharedGatewayListenerHealth, SharedHttpRouteHealth,
    gateway_api_crds_present,
};

// The status writer no longer instantiates a reconciler directly — bin owns
// the wiring — but the types it produces still need to be reachable from the
// controller crate's API surface for the dev role's combined startup.
pub use coxswain_reflector::reconciler::{
    ControllerReconciler, ReconcilerHealth, ReconcilerOptions, ReconcilerOutputs,
    SharedProxyReconciler,
};
pub use coxswain_reflector::{IngressDefaultBackend, IngressDefaultBackendParseError};
