//! Connection acceptance and TLS termination — the L4/TLS edge of the data plane.
//!
//! [`accept`] runs the listener accept loop (TLS handshake + PROXY-protocol
//! parsing) and seeds the per-connection [`crate::ctx::ConnectionInfo`]; [`tls`]
//! selects SNI certificates and extracts mTLS client certificates; [`upstream_ca`]
//! caches CA bundles used to verify upstream TLS peers; [`passthrough`] extracts
//! the ClientHello SNI and splices TLSRoute `mode: Passthrough` connections;
//! [`terminate`] handles TLSRoute `mode: Terminate` connections (#481); [`tcp`]
//! handles TCPRoute raw-TCP connections (#505); [`udp`] handles UDPRoute datagram
//! forwarding (#506); [`peek`] holds the retry wait shared by the `MSG_PEEK` loops
//! in [`accept`] and [`passthrough`].
//! Everything here runs before a request reaches the routing layer.

pub(crate) mod accept;
pub(crate) mod passthrough;
pub(crate) mod peek;
pub(crate) mod tcp;
pub(crate) mod terminate;
pub(crate) mod tls;
pub(crate) mod udp;
pub(crate) mod upstream_ca;

/// Buffer size for each direction of a raw-byte splice (~16 KiB).
///
/// Shared by every L4 splice path ([`tcp`], [`passthrough`], [`terminate`]) —
/// all move raw bytes with no protocol parsing, so they size their copy buffers
/// identically.
pub(crate) const SPLICE_BUF: usize = 16 * 1024;
