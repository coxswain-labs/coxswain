//! Primitives shared by `IngressProxy` and `GatewayProxy`.
//!
//! The hot-path `ProxyHttp` hook bodies live in [`hooks`]; the per-request
//! context, the redirect/outcome helpers, the filter set, and the typed
//! routing engine are reused verbatim between the two proxies.

pub(crate) mod affinity;
pub mod ctx;
pub mod engine;
pub mod filter;
pub(crate) mod hooks;
pub(crate) mod outcome;
pub(crate) mod redirect;
