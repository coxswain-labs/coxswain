//! Proxy-side runtime configuration types.
//!
//! These enums and structs are set once at startup from CLI flags (via
//! `coxswain-bin`) and stored on the proxy instances. They are intentionally
//! independent of the bin crate so the proxy crate remains self-contained.

/// Controls what the access log emits for the `path` field.
///
/// The architecturally correct home for PII scrubbing is the log-collection
/// pipeline. This enum exists for two narrower cases: operators whose pipeline
/// genuinely cannot filter, and the `Pattern` mode, which records the
/// *matched rule's path pattern* — information only the proxy holds cheaply
/// without duplicating route config downstream.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessLogPathMode {
    /// Emit the concrete request path as received (default).
    Full,
    /// Emit the matched rule's registered path pattern instead of the
    /// concrete request path (e.g. `/users/` instead of `/users/42/orders/7`).
    /// When no route matched, emits `"/"` as a stable placeholder.
    Pattern,
    /// Omit the `path` field from the access log entirely.
    None,
}
