//! Black-box integration test harness for Coxswain.
//!
//! Re-exports the [`Harness`] entry point, fixture path constants, and all harness
//! utilities used by the `tests/gateway_api.rs` and `tests/ingress.rs` test suites.

pub mod fixtures;
pub mod harness;

pub use fixtures::FixtureVars;
pub use harness::{
    ControllerOptions, ControllerProcess, DedicatedProxyProcess, GeneratedCert, Harness,
    HttpClient, IngressClassGuard, NamespaceGuard, bootstrap,
};
