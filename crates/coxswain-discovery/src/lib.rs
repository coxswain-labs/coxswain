//! `coxswain-discovery` — the gRPC discovery control plane.
//!
//! This crate owns the bidirectional gRPC stream between the controller (server)
//! and proxy nodes (clients). The controller compiles K8s-derived routing
//! snapshots into a wire DTO and pushes them over the stream; proxies apply the
//! snapshot to their in-process [`Shared`] routing table without ever touching
//! the Kubernetes API.
//!
//! The crate depends only on [`coxswain_core`] (epic design decision #9 in
//! #238: `coxswain-admin` and `coxswain-discovery` communicate through
//! `coxswain-core` `Shared` handles wired by `coxswain-bin`).
//!
//! [`Shared`]: coxswain_core::Shared

pub mod auth;
pub mod client;
pub mod error;
pub mod proto;
pub mod registry;
pub mod server;
pub mod subscription;
pub mod version;
pub mod wire;

pub use error::{DiscoveryError, WireError};
pub use subscription::Scope;
pub use version::ContentHash;
