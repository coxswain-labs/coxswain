//! Black-box integration test harness for Coxswain — and the **charter** for how
//! tests in this crate are written.
//!
//! Re-exports the [`Harness`] entry point, fixture path constants, and all harness
//! utilities used by the by-plane integration suite under `tests/` (`routing`,
//! `tls`, `status_conditions`, `provisioning`, `resilience`, `observability`,
//! `discovery`, and the `security`/`traffic_policy` planes).
//!
//! # Charter
//!
//! The mechanizable rules are enforced by CI gates and not restated here:
//! `scripts/check-no-e2e-sleeps.sh`, `check-e2e-single-poller.sh`,
//! `check-annotation-coverage.sh`, `check-e2e-plane-layout.sh`,
//! `check-e2e-images-pinned.sh`, `check-e2e-mutators-serialized.sh`. Each one
//! carries a `scripts/tests/<gate>/{good,bad}` fixture pair proving it fires.
//!
//! The rules below are the behavioural ones a script can't check — honour them
//! when adding a test. They are deliberately unnumbered: this list previously
//! claimed to be a "14-point rubric" while enumerating seven points, with two of
//! the fourteen defined nowhere at all. A count nobody can reconcile is worse
//! than no count, so the rules stand on their own.
//!
//! - **Black-box only.** A test knows only what a real operator or HTTP
//!   client knows: it applies YAML and observes status conditions and live
//!   responses. It never reaches into controller/proxy internals, in-process
//!   state, or private types — assert through the public contract or not at all.
//! - **Atomic on a shared fixture.** One behaviour per test (possibly
//!   multi-step: apply → serve → mutate → re-assert). The cluster and the shared
//!   controller release are a fixture concurrent tests treat as **read-only** —
//!   if a test needs to reconfigure the shared controller, it joins the serial
//!   group (see `.config/nextest.toml`), it does not race the default-config
//!   majority.
//! - **Mutate only what you own.** A test creates and mutates resources in
//!   its **own namespace** (via [`NamespaceGuard`]) and nothing else. No edits to
//!   shared/global objects, other tests' namespaces, or cluster-scoped state that
//!   another test reads. This is what keeps the partition-local majority parallel.
//! - **Assert the contract, including identity and the negative.** Don't
//!   assert "got a 200" — assert the response came from the **expected backend**
//!   (echo-server identity headers) so a mis-route can't pass. For teardown,
//!   assert the **negative**: a deleted route stops serving (404 / connection
//!   refused), a migrated-away endpoint goes dark. Prefer a namespace-scoped
//!   assertion over a cluster-global one wherever the behaviour allows it.
//! - **Zero-tolerance flakes.** A flaky test is a failing test. Never paper
//!   over it with a retry-to-green or a longer blind wait. Quarantine it
//!   (`#[ignore]`) **with a tracking issue** in the attribute comment, or fix the
//!   missing post-condition. Retrying until green hides the very race that the
//!   poll-the-real-condition rule exists to surface.
//! - **Self-diagnosing failures.** Every waiter's `on_timeout` closure must
//!   fetch and render the last-observed world state — expected vs actual vs
//!   conditions / pod status / HTTP code — so a CI timeout is diagnosable **from
//!   the log alone**, without re-running under `RUST_LOG`. A bare "timed out" is a
//!   bug in the test, not just bad luck.
//! - **Behaviour + outcome naming.** A test name reads as a spec line:
//!   `deleted_route_stops_serving`, `host_pool_round_robins`,
//!   `gateway_becomes_accepted_and_programmed` — not `test_routing` or `filters`.
//!   The body reads arrange → act → assert.

pub mod fixtures;
pub mod harness;
pub mod jwt;

pub use fixtures::FixtureVars;
pub use harness::{
    ControllerOptions, ControllerProcess, GeneratedCert, Harness, HttpClient, IngressClassGuard,
    MtlsCerts, NamespaceGuard, StaticRsaCert, bootstrap, bootstrap_cluster,
};
