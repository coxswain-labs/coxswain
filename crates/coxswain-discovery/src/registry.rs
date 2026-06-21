//! Connected-node registry for the discovery server.
//!
//! Tracks per-stream state (node ID, scope, last-acked version, liveness) so
//! the controller can answer "are all proxies in sync?" through the admin UI
//! without a separate telemetry message. State is stored in a `coxswain-core`
//! `Shared` handle wired by `coxswain-bin`. Implementation lands in T5 (#238).
