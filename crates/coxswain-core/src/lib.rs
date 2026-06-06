//! Shared data-plane primitives for Coxswain.
//!
//! Provides the routing table, atomic [`Shared<T>`] snapshot wrapper, TLS cert store,
//! Kubernetes ownership helpers, and `ReferenceGrant` evaluation logic used by both
//! the controller and proxy crates.

pub mod ownership;
pub mod reference_grants;
pub mod routing;
pub mod shared;
pub mod tls;

pub use shared::Shared;

#[cfg(test)]
mod tests;
