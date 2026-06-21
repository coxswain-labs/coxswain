//! mTLS authentication for the discovery channel.
//!
//! Verifies SPIFFE URI-SAN on both ends of the connection (epic design decision
//! #4 in #238). A SAN mismatch at the TLS handshake is a hard error; the proxy
//! stays `NotReady` and does not fall back to an unauthenticated channel.
//! Implementation lands in T6 (#238).
