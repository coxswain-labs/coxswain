//! Prometheus metrics for the response cache.
//!
//! Registered against the global default registry on first access and exposed
//! by `coxswain-admin`'s `prometheus::gather()` call. The names are the literal
//! ones in the issue acceptance criteria (`coxswain_cache_{hits,misses}_total`),
//! intentionally without the `coxswain_proxy_*` subsystem prefix the proxy's own
//! metrics use.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use pingora_cache::eviction::EvictionManager;
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts, register_int_counter_vec};

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

/// Counter: cumulative cache purge outcomes, by result.
///
/// Labels: `result` (`hit` — an entry was removed; `miss` — no matching entry).
/// A purge that reports `miss` is not an error (the entry may already have been
/// evicted or never cached); the split lets the fleet-wide purge path (`#359`)
/// distinguish effective purges from no-ops.
///
/// Uses the `coxswain_proxy_*` subsystem prefix because the cache runs in the
/// proxy process, unlike the legacy `coxswain_cache_{hits,misses}_total` names.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`cache_hits_total`].
pub fn cache_purges_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_cache_purges_total",
                "Cumulative response-cache purge outcomes, by result",
            ),
            &["result"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

// ── cache depth collector ───────────────────────────────────────────────────

/// Prometheus collector that exposes the eviction manager's live depth.
///
/// `coxswain_proxy_cache_entries`, `coxswain_proxy_cache_bytes`, and
/// `coxswain_proxy_cache_evictions_total` are *pull* metrics: their source of
/// truth is the LRU eviction manager (which Pingora mutates internally on every
/// admission), so they are read at scrape time rather than maintained by our own
/// emission. This keeps them always-fresh with no background sampler.
///
/// `evicted_items()` is already cumulative (Pingora documents it as built "to
/// play well with Prometheus counter"); we forward its delta into a real
/// `IntCounter` so the series keeps Counter semantics. The atomic swap makes the
/// delta exact even if two scrapes race.
struct CacheDepthCollector {
    eviction: &'static (dyn EvictionManager + Sync),
    entries: IntGauge,
    bytes: IntGauge,
    evictions: IntCounter,
    last_evicted: AtomicU64,
}

impl CacheDepthCollector {
    fn new(eviction: &'static (dyn EvictionManager + Sync)) -> Self {
        // These metrics are owned by (and registered through) this collector, so
        // they are constructed unregistered via `new`, never `register_*`.
        let entries = IntGauge::new(
            "coxswain_proxy_cache_entries",
            "Entries currently tracked by the response cache",
        )
        .unwrap_or_else(|e| panic!("invariant: invalid metric definition — this is a bug: {e}"));
        let bytes = IntGauge::new(
            "coxswain_proxy_cache_bytes",
            "Total body bytes currently held by the response cache",
        )
        .unwrap_or_else(|e| panic!("invariant: invalid metric definition — this is a bug: {e}"));
        let evictions = IntCounter::new(
            "coxswain_proxy_cache_evictions_total",
            "Cumulative entries evicted from the response cache under capacity pressure",
        )
        .unwrap_or_else(|e| panic!("invariant: invalid metric definition — this is a bug: {e}"));
        Self {
            eviction,
            entries,
            bytes,
            evictions,
            last_evicted: AtomicU64::new(0),
        }
    }
}

impl Collector for CacheDepthCollector {
    fn desc(&self) -> Vec<&Desc> {
        let mut descs = self.entries.desc();
        descs.extend(self.bytes.desc());
        descs.extend(self.evictions.desc());
        descs
    }

    fn collect(&self) -> Vec<MetricFamily> {
        self.entries.set(self.eviction.total_items() as i64);
        self.bytes.set(self.eviction.total_size() as i64);

        // Advance the counter by however much `evicted_items` rose since the last
        // scrape. The swap attributes each unit of increase to exactly one caller,
        // so concurrent scrapes neither double-count nor drop.
        let current = self.eviction.evicted_items() as u64;
        let previous = self.last_evicted.swap(current, Ordering::Relaxed);
        if let Some(delta) = current.checked_sub(previous) {
            self.evictions.inc_by(delta);
        }

        let mut families = self.entries.collect();
        families.extend(self.bytes.collect());
        families.extend(self.evictions.collect());
        families
    }
}

/// Register the cache-depth collector against the default registry.
///
/// Called once per process from [`crate::ResponseCache::with_max_bytes`].
/// Registration failure (a collector for these names already exists) is ignored:
/// production builds exactly one cache, and tests that build several only observe
/// the first — depth unit tests use a private registry instead.
pub(crate) fn register_cache_depth_collector(eviction: &'static (dyn EvictionManager + Sync)) {
    let collector = CacheDepthCollector::new(eviction);
    // Ignore AlreadyReg: only the first cache in a process wins the global names.
    let _ = prometheus::default_registry().register(Box::new(collector));
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_cache::eviction::lru::Manager as LruManager;
    use std::time::SystemTime;

    use crate::cache_key;

    /// A small LRU over which the collector reads depth. Leaked for the `'static`
    /// the collector requires, mirroring `ResponseCache::with_max_bytes`.
    fn lru(max_bytes: usize) -> &'static LruManager<8> {
        Box::leak(Box::new(LruManager::with_capacity(max_bytes, 16)))
    }

    #[test]
    fn depth_collector_reports_live_entries_and_bytes() {
        let eviction = lru(1 << 20);
        eviction.admit(
            cache_key("GET", "h", "/a").to_compact(),
            123,
            SystemTime::now(),
        );

        let collector = CacheDepthCollector::new(eviction);
        // collect() pulls from the eviction manager into the owned gauges.
        let _ = collector.collect();

        assert_eq!(
            collector.entries.get(),
            1,
            "one admitted entry must show as coxswain_proxy_cache_entries=1"
        );
        assert_eq!(
            collector.bytes.get(),
            123,
            "the admitted body size must show as coxswain_proxy_cache_bytes"
        );
    }

    #[test]
    fn depth_collector_counts_evictions_under_pressure() {
        // Capacity smaller than two entries forces the second admit to evict the first.
        let eviction = lru(100);
        eviction.admit(
            cache_key("GET", "h", "/a").to_compact(),
            80,
            SystemTime::now(),
        );
        eviction.admit(
            cache_key("GET", "h", "/b").to_compact(),
            80,
            SystemTime::now(),
        );

        let collector = CacheDepthCollector::new(eviction);
        let _ = collector.collect();

        assert!(
            collector.evictions.get() >= 1,
            "exceeding capacity must increment coxswain_proxy_cache_evictions_total; got {}",
            collector.evictions.get()
        );
    }

    #[test]
    fn depth_collector_registers_into_a_registry() {
        let eviction = lru(1 << 20);
        let registry = prometheus::Registry::new();
        registry
            .register(Box::new(CacheDepthCollector::new(eviction)))
            .expect("collector must register against a fresh registry");

        let names: Vec<_> = registry
            .gather()
            .into_iter()
            .map(|f| f.name().to_owned())
            .collect();
        for expected in [
            "coxswain_proxy_cache_entries",
            "coxswain_proxy_cache_bytes",
            "coxswain_proxy_cache_evictions_total",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "{expected} must be gathered from the registry; got {names:?}"
            );
        }
    }
}
