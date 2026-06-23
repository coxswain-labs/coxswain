//! `coxswain-discovery` — the gRPC discovery control plane.
//!
//! This crate owns the bidirectional gRPC stream between the controller (server)
//! and proxy nodes (clients). The controller compiles K8s-derived routing
//! snapshots into a wire DTO and pushes them over the stream; proxies apply the
//! snapshot to their in-process [`Shared`] routing table without ever touching
//! the Kubernetes API.
//!
//! Two tonic listeners are wired by `coxswain-bin`:
//!
//! - **Stream listener** (port 50051, mTLS mandatory): [`DiscoveryService`] +
//!   [`DiscoveryServerTls`].  Proxy must present a valid SVID.
//! - **Bootstrap listener** (port 50052, server-auth-only TLS):
//!   [`BootstrapService`] + [`DiscoveryBootstrapServerTls`].  Proxy presents
//!   a ServiceAccount token + CSR; the controller signs a short-lived SVID.
//!
//! The crate depends only on [`coxswain_core`] (epic design decision #9 in
//! #238: `coxswain-admin` and `coxswain-discovery` communicate through
//! `coxswain-core` `Shared` handles wired by `coxswain-bin`).
//!
//! [`Shared`]: coxswain_core::Shared

pub mod auth;
pub mod bootstrap_client;
pub mod bootstrap_server;
pub mod client;
pub mod error;
pub mod proto;
pub mod registry;
pub mod server;
pub mod subscription;
pub mod svid;
pub mod transport;
pub mod version;
pub mod wire;

pub use auth::{
    DiscoveryBootstrapClientTls, DiscoveryBootstrapServerTls, DiscoveryClientTls,
    DiscoveryServerTls, SpiffeMatcher,
};
pub use bootstrap_client::{
    BootstrapClient, BootstrapClientConfig, BootstrapClientHandle, BootstrapRunner,
};
pub use bootstrap_server::{BootstrapService, NoOpRejectHook, RejectHook};
pub use client::{DiscoveryClient, DiscoveryClientConfig, Supervisor};
pub use error::{AuthError, DiscoveryError, WireError};
pub use server::{DiscoveryService, SnapshotSource};
pub use subscription::Scope;
pub use svid::{SharedSvid, SvidMaterial};
pub use transport::serve_discovery_with_tls;
pub use version::{ContentHash, WIRE_VERSION};
