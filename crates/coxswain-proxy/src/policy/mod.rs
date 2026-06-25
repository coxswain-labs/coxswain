//! Stateful per-route enforcement subsystems applied during the request
//! lifecycle — distinct from [`crate::filters`], which dispatch off declarative
//! Gateway-API/Ingress `FilterAction` variants.
//!
//! Each submodule owns a self-contained policy with its own per-process or
//! per-request state: [`auth`] (ext_authz + basic auth), [`rate_limit`]
//! (per-route GCRA limiters), [`circuit_breaker`] (per-endpoint state machines),
//! [`affinity`] (session affinity pins), [`access_control`] (source-IP allow/deny),
//! [`compression`] (response encoders), and [`cache`] (Pingora cache hooks).

pub(crate) mod access_control;
pub(crate) mod affinity;
pub(crate) mod auth;
pub(crate) mod cache;
pub(crate) mod circuit_breaker;
pub(crate) mod compression;
pub(crate) mod rate_limit;
