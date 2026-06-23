//! Shared data-plane primitives for Coxswain.
//!
//! Provides the routing table, atomic [`Shared<T>`] snapshot wrapper, TLS cert
//! store, Kubernetes ownership helpers, `ReferenceGrant` evaluation logic, the
//! fleet discovery snapshot, the [`RoutingSource`] trait, and the
//! [`SharedGatewayListenerHealth`] shared cell — all used by both the
//! controller and proxy crates.

pub mod cluster;
pub mod crd;
pub mod fleet;
pub mod health;
pub mod identity;
pub mod listener_health;
pub mod node_registry;
pub mod ownership;
pub mod reference_grants;
pub mod routing;
pub mod shared;
pub mod source;
pub mod tls;

pub use fleet::{Component, FleetEntry, FleetSnapshot, SharedFleet};
pub use health::{CheckState, HealthRegistry, HealthSnapshot, SubsystemHandle, SubsystemSnapshot};
pub use identity::{
    AuthnError, CsrPem, IssuedSvid, IssuerError, SpiffeId, SpiffeIdError, SvidIssuer,
    TokenAuthenticator,
};
pub use listener_health::SharedGatewayListenerHealth;
pub use node_registry::{NodeEntry, NodeRegistry, SharedNodeRegistry};
pub use shared::Shared;
pub use source::RoutingSource;
