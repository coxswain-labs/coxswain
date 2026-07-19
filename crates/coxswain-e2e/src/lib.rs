//! Black-box integration test harness for Coxswain.
//!
//! Re-exports the [`Harness`] entry point, fixture path constants, and all harness
//! utilities used by the by-plane integration suite under `tests/` (`routing`,
//! `tls`, `status_conditions`, `provisioning`, `resilience`, `observability`,
//! `discovery`, and the `security`/`traffic_policy` planes).
//!
//! # Charter
//!
//! Mechanizable rules are enforced by CI gates and not restated here:
//! `scripts/check-no-e2e-sleeps.sh`, `check-e2e-single-poller.sh`,
//! `check-annotation-coverage.sh`, `check-e2e-plane-layout.sh`,
//! `check-e2e-images-pinned.sh`, `check-e2e-mutators-serialized.sh`. Each
//! carries a `scripts/tests/<gate>/{good,bad}` fixture pair proving it fires.
//!
//! The rules a script can't check are enforced by review, as the **E2E test
//! construction** dimension of `.claude/agents/code-review.md` — assert backend
//! identity and the negative, render observed world state in every `on_timeout`,
//! stay black-box, and mutate only your own namespace. They live there rather
//! than here because each has a *silent* failure mode: a test that violates one
//! still passes, so a rule kept only as prose in a crate header is a rule
//! nobody applies at the moment it matters.
//!
//! A flaky test is a failing test — never a longer wait or a retry-to-green.
//! Quarantine it (`#[ignore]`) with a tracking issue, or name the post-condition
//! that was not polled.
//!
//! This list was once introduced as a "14-point rubric" while enumerating seven
//! points, two of the fourteen defined nowhere at all. The count is gone; the
//! rules that earn their place are enforced where they get applied.

pub mod fixtures;
pub mod harness;
pub mod jwt;

pub use fixtures::FixtureVars;
pub use harness::{
    ControllerOptions, ControllerProcess, GeneratedCert, Harness, HttpClient, IngressClassGuard,
    MtlsCerts, NamespaceGuard, StaticRsaCert, bootstrap, bootstrap_cluster,
};
