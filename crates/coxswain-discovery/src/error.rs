//! Error type for the discovery control plane.

use thiserror::Error;

/// Errors raised by the discovery server, client, and wire codec.
///
/// Variants are seeded minimally here; subsequent tickets (T4 client, T5 server,
/// T6 mTLS) extend this set. The type is `#[non_exhaustive]` so additions are
/// not breaking changes for downstream crates.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The peer advertised a wire-protocol version this build cannot speak.
    ///
    /// The proxy backs off permanently on this error; operator action (image
    /// upgrade) is required to resolve the mismatch.
    #[error("discovery wire version mismatch: server={server}, client={client}")]
    WireVersionMismatch {
        /// Wire version advertised by the server.
        server: u32,
        /// Wire version this client speaks.
        client: u32,
    },
}
