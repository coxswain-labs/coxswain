//! Shared data-plane primitives for Coxswain.
//!
//! Provides the routing table, atomic [`Shared<T>`] snapshot wrapper, TLS cert
//! store, Kubernetes ownership helpers, `ReferenceGrant` evaluation logic, the
//! fleet discovery snapshot, the [`RoutingSource`] trait, the
//! [`SharedGatewayListenerStatus`] shared cell, and the
//! [`DedicatedRoutingRegistry`] per-Gateway snapshot registry — all used by
//! both the controller and proxy crates.

pub mod cluster;
pub mod crd;
pub mod dedicated_registry;
pub mod fleet;
pub mod health;
pub mod identity;
pub mod listener_status;
pub mod naming;
pub mod node_registry;
pub mod ownership;
pub mod publish_index;
pub mod reference_grants;
pub mod routing;
pub mod shared;
pub mod source;
pub mod tls;
pub mod workqueue;

pub use dedicated_registry::{DedicatedRoutingRegistry, DedicatedRoutingSnapshot};
pub use fleet::{Component, FleetEntry, FleetSnapshot, SharedFleet};
pub use health::{
    CheckState, HealthRegistry, HealthSnapshot, LivenessGate, SubsystemHandle, SubsystemSnapshot,
};
pub use identity::{
    AuthnError, CsrPem, IssuedSvid, IssuerError, SpiffeId, SpiffeIdError, SvidIssuer,
    TokenAuthenticator,
};
pub use listener_status::SharedGatewayListenerStatus;
pub use node_registry::{NodeEntry, NodeRegistry, NodeScope, SharedNodeRegistry};
pub use publish_index::{PublishStamp, SharedGatewayPublishIndex};
pub use shared::Shared;
pub use source::RoutingSource;
pub use workqueue::{RateLimitConfig, RateLimitingWorkqueue};
