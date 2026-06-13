//! Re-exports Gateway API types from the standard channel.
//!
//! Import as `use crate::gw_types::v::...` instead of hard-coding the
//! channel path. The admin crate always uses the standard channel (no
//! experimental feature flag).
//!
//! The `HttpRoute` alias exists to satisfy the `upper_case_acronyms` lint at
//! the crate boundary — all internal code uses the alias, never the raw
//! `HTTPRoute` name.

pub use gateway_api::apis::standard as v;

/// Project-canonical alias for `HTTPRoute` — avoids the `upper_case_acronyms`
/// clippy lint at every call site.
pub use v::httproutes::HTTPRoute as HttpRoute;
