//! Discovery gRPC server: runs inside the controller role.
//!
//! Implements the `Discovery` tonic service, watches the controller's `Shared`
//! routing snapshot, and fans out `Snapshot` messages to connected proxy clients.
//! Tracks per-stream ACK state in the registry so the admin UI can surface
//! "are all proxies in sync?" without extra telemetry messages. Implementation
//! lands in T5 (#238).
