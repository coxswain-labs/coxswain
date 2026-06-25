//! Request-to-backend resolution: the lock-free routing table lookup and the
//! outcome handling that sits between a match and the upstream connection.
//!
//! [`engine`] wraps the `ArcSwap`-backed routing snapshot and performs the
//! hot-path `find()`; [`outcome`] resolves a [`coxswain_core::routing::RouteOutcome`]
//! into a concrete match (writing error responses for the miss variants) and
//! merges per-route timeouts; [`source`] abstracts over where routing snapshots
//! come from (`KubernetesSource` in the dev role, `DiscoveryClient` in the proxy role).

pub(crate) mod engine;
pub(crate) mod outcome;
pub(crate) mod source;
