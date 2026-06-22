//! Controller-side identity primitives: CA management, token review, and trust
//! bundle publishing.
//!
//! Implements the [`coxswain_core::SvidIssuer`] and
//! [`coxswain_core::TokenAuthenticator`] traits defined in `coxswain-core`
//! so the generic [`coxswain_discovery::BootstrapService`] can be wired to
//! concrete controller logic without creating a crate cycle.

pub mod ca;
pub mod reject_hook;
pub mod store;
pub mod token_review;
