//! Discovery gRPC client: runs inside the proxy role.
//!
//! Owns the reconnect supervisor (jittered exponential backoff 250ms → 30s),
//! sends `Subscribe` on connect, drives `Ack`/`Nack` after each snapshot, and
//! feeds the decoded wire DTO into the proxy's `Shared` routing table. The
//! `Shared` cell is never zeroed during reconnect; the last-good snapshot is
//! served throughout. Implementation lands in T4 (#238).
