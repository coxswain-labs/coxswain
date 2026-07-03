//! Aggregates the `standard` and (feature-gated) `experimental` Gateway API channels.
//! Regenerate with `cargo run -p xtask -- gateway-api-types` — do not edit by hand.

#[cfg(feature = "experimental")]
pub mod experimental;
pub mod standard;
