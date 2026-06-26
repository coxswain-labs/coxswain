//! Connection acceptance and TLS termination — the L4/TLS edge of the data plane.
//!
//! [`accept`] runs the listener accept loop (TLS handshake + PROXY-protocol
//! parsing) and seeds the per-connection [`crate::ctx::ConnectionInfo`]; [`tls`]
//! selects SNI certificates and extracts mTLS client certificates; [`upstream_ca`]
//! caches CA bundles used to verify upstream TLS peers. Everything here runs
//! before a request reaches the routing layer.

pub(crate) mod accept;
pub(crate) mod passthrough;
pub(crate) mod tls;
pub(crate) mod upstream_ca;
