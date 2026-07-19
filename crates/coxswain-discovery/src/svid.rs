//! SVID material shared between the bootstrap client and the discovery client supervisor.
//!
//! [`SvidMaterial`] carries the cert PEM, private key PEM, and CA bundle PEM
//! needed to construct a [`crate::auth::DiscoveryClientTls`].  It lives in a
//! [`SharedSvid`] cell so the bootstrap loop can atomically publish a fresh
//! SVID while the supervisor reads it lock-free on the next reconnect.

use coxswain_core::Shared;

// ── SvidMaterial ─────────────────────────────────────────────────────────────

/// A freshly-issued SVID, ready to configure an mTLS discovery channel.
pub struct SvidMaterial {
    /// PEM-encoded SVID certificate chain (proxy client cert).
    pub cert_pem: Vec<u8>,
    /// PEM-encoded SVID private key (stays inside the proxy process).
    pub key_pem: Vec<u8>,
    /// PEM-encoded CA bundle from the trust-bundle ConfigMap.
    pub ca_bundle_pem: Vec<u8>,
    /// SVID expiry as Unix seconds (UTC).
    pub not_after_unix: i64,
}

/// A lock-free cell holding the latest [`SvidMaterial`], or `None` before the
/// first successful bootstrap.
pub type SharedSvid = Shared<Option<SvidMaterial>>;
