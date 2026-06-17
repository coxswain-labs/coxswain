//! Prometheus metrics for the response cache.
//!
//! Registered against the global default registry on first access and exposed
//! by `coxswain-admin`'s `prometheus::gather()` call. The names are the literal
//! ones in the issue acceptance criteria (`coxswain_cache_{hits,misses}_total`),
//! intentionally without the `coxswain_proxy_*` subsystem prefix the proxy's own
//! metrics use.

use prometheus::{IntCounterVec, Opts, register_int_counter_vec};
use std::sync::OnceLock;

/// Counter: responses served from cache, labelled by matched route.
///
/// # Panics
///
/// Panics if a series with this name was already registered through a different
/// path. The [`OnceLock`] makes that unreachable in practice; a failure
/// indicates a duplicate-registration bug.
pub fn cache_hits_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_cache_hits_total",
                "Responses served from the in-memory response cache, by route",
            ),
            &["route"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cacheable requests that missed and went to the upstream, by route.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`cache_hits_total`].
pub fn cache_misses_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_cache_misses_total",
                "Cacheable requests that missed the cache and went upstream, by route",
            ),
            &["route"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}
