//! Black-box integration test harness for Coxswain.
//!
//! Re-exports the [`Harness`] entry point, fixture path constants, and all harness
//! utilities used by the by-plane integration suite under `tests/` (`routing`,
//! `tls`, `status_conditions`, `provisioning_rbac`, `resilience`, `observability`,
//! and the `security`/`traffic_policy` placeholders).

pub mod fixtures;
pub mod harness;

pub use fixtures::FixtureVars;
pub use harness::{
    ControllerOptions, ControllerProcess, GeneratedCert, Harness, HttpClient, IngressClassGuard,
    NamespaceGuard, bootstrap, bootstrap_cluster,
};
