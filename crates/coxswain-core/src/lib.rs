//! Shared data-plane primitives for Coxswain.
//!
//! Provides the routing table, atomic [`Shared<T>`] snapshot wrapper, TLS cert store,
//! Kubernetes ownership helpers, `ReferenceGrant` evaluation logic, and the fleet
//! discovery snapshot used by both the controller and proxy crates.

pub mod cluster;
pub mod crd;
pub mod fleet;
pub mod health;
pub mod listener_health;
pub mod ownership;
pub mod reference_grants;
pub mod routing;
pub mod shared;
pub mod tls;

pub use fleet::{Component, FleetEntry, FleetSnapshot, SharedFleet};
pub use health::{CheckState, HealthRegistry, HealthSnapshot, SubsystemHandle, SubsystemSnapshot};
pub use shared::Shared;
