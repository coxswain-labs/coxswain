//! Cross-cutting unit tests for the dedicated-mode operator.
//!
//! Per-file tests live in `#[cfg(test)] mod tests` blocks inside their
//! module's `.rs`; this directory hosts tests that cover the operator's
//! public-ish contract (Gateway status semantics, address resolution,
//! patch idempotence) where a sibling module makes the boundaries clearer.

mod status;
