//! First-party kopium-generated Kubernetes Gateway API bindings (#510).
//!
//! Replaces the `coxswain-labs/gateway-api-rs` fork: `src/apis/**` and
//! `src/constants.rs` are generated wholesale from the tag pinned in the
//! repo-root `.gateway-api-version` file by the `xtask` crate (a repo-root
//! sibling of `crates/`, not a dependency of this crate or vice versa) —
//! regenerate with `cargo run -p xtask -- gateway-api-types`.
//!
//! `apis::standard` is always available; `apis::experimental` is gated behind
//! the `experimental` feature (alpha-channel kinds, opt-in for
//! contributor/CI use only — never enabled in release builds).

pub mod apis;
pub mod constants;
pub mod duration;

#[cfg(feature = "experimental")]
pub use apis::experimental;
pub use apis::standard::*;
pub use duration::Duration;
