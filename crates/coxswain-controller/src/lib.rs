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
pub mod identity;
mod metrics;
mod operator;
mod status_common;
mod status_writer;

pub use controller::{
    Controller, ControllerConfig, ControllerConfigError, LeaseSettings, StatusAddress,
    StatusChannels,
};
pub use operator::{OperatorConfig, ProxyPoolConfig, RelayConfig};
pub use status_writer::{StatusWriterConfig, StatusWriterError, spawn_status_writer};

/// Fixed `ServiceAccount` (and `Deployment`/`Service`) name of every
/// controller-provisioned namespace relay (#584).
///
/// Public so `coxswain-bin` builds the discovery
/// [`coxswain_discovery::ProvisionedRelayAuthorizer`] from the *same* constant the
/// operator renders the relay `ServiceAccount` with — the provisioned identity and
/// the authorized identity stay in lockstep by construction.
pub const RELAY_SERVICE_ACCOUNT: &str = "coxswain-relay";

/// Fixed `ServiceAccount` (and `Deployment`/`Service`) name of the single
/// controller-provisioned **shared-pool** relay (#605).
///
/// Distinct from [`RELAY_SERVICE_ACCOUNT`] (the per-namespace dedicated relay): the
/// shared relay fronts the install's shared proxy pool, lives in the install
/// namespace, and subscribes `Scope::SharedPool`. Public so `coxswain-bin` builds
/// the discovery upstream resolver (#601/#605) with the *same* name + SA the
/// operator renders the shared relay with — the endpoint the pool is repointed to
/// and the `expected_server_sa` the pool verifies stay in lockstep by construction.
pub const SHARED_RELAY_SERVICE_ACCOUNT: &str = "coxswain-relay-shared";

/// The dedicated relay's downstream routing (Stream) port.
///
/// Public so `coxswain-bin` builds the discovery best-upstream resolver (#601)
/// with the *same* port the operator renders the relay Service with — a leaf's
/// bootstrap-delivered relay endpoint stays in lockstep with the rendered
/// Service by construction.
pub const RELAY_DISCOVERY_PORT: u16 = 50051;

// Re-export reflector primitives that bin or downstream crates expect to reach
// from `coxswain_controller::…`. Direct re-exports keep callers compiling
// without forcing every site to learn the new crate name.
pub use coxswain_core::cluster::SharedClusterSummary;
pub use coxswain_reflector::{
    BackendTlsPolicyStatusHandle, GatewayListenerStatus, GatewayListenerStatusHandle, IngressPorts,
    ListenerInfo, ListenerReadiness, RouteStatusHandle,
};

// The status writer no longer instantiates a reconciler directly — bin owns
// the wiring — but the types it produces still need to be reachable from the
// controller crate's API surface for the dev role's combined startup.
pub use coxswain_reflector::reconciler::{
    ControllerReconciler, ReconcilerHealth, ReconcilerOptions, ReconcilerOutputs,
    SharedProxyReconciler,
};
pub use coxswain_reflector::{IngressDefaultBackend, IngressDefaultBackendParseError};
pub use identity::ca::{CaError, CertAuthority, IssuedServerSvid};
pub use identity::publisher::{TRUST_BUNDLE_CM_NAME, spawn_trust_publisher};
pub use identity::reject_hook::BootstrapRejectHook;
pub use identity::store::{CaMode, CaStoreError, load_or_generate};
pub use identity::token_review::KubeTokenAuthenticator;
