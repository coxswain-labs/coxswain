#![allow(missing_docs)]
// `mod common;` pulls this whole module into every integration-test binary, so
// helpers used by only some binaries (e.g. the dedicated-proxy vocabulary, used
// by provisioning/status_conditions/resilience but not routing/tls) appear
// "unused" in the others. `dead_code` here is structural to Rust's test-binary
// model, not a silenced smell — mirrors the file-level `missing_docs` allow used
// across this crate's tests and harness.
#![allow(dead_code)]

pub mod dedicated;
pub mod discovery;
pub mod grpc_echo;
