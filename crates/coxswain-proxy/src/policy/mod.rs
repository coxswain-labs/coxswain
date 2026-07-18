//! Stateful per-route enforcement subsystems applied during the request
//! lifecycle — distinct from [`crate::filters`], which dispatch off declarative
//! Gateway-API/Ingress `FilterAction` variants.
//!
//! Each submodule owns a self-contained policy with its own per-process or
//! per-request state: [`auth`] (ext_authz + basic auth), [`grpc_channel`]
//! (pooled gRPC ext_authz channels), [`rate_limit`] (per-route GCRA limiters),
//! [`circuit_breaker`] (per-endpoint state machines), [`affinity`] (session
//! affinity pins), [`access_control`] (source-IP allow/deny), [`client_cert`]
//! (per-Ingress mTLS guard + forwarding), [`misdirected`] (GEP-3567 421 guard),
//! and [`compression`] (response encoders).

pub(crate) mod access_control;
pub(crate) mod affinity;
pub(crate) mod auth;
pub(crate) mod circuit_breaker;
pub(crate) mod client_cert;
pub(crate) mod compression;
pub(crate) mod grpc_channel;
pub(crate) mod misdirected;
pub(crate) mod rate_limit;
