//! In-memory RFC 7234 response cache for the proxy data plane.
//!
//! Coxswain's response cache is built on Pingora's caching framework
//! ([`pingora_cache`]): the proxy's `ProxyHttp` cache hooks drive lookup,
//! admission, and `Vary`/`Age`/`304` handling, while this crate owns the
//! *storage backend* and the operator-facing surface around it (cache-key
//! derivation, purge, and metrics).
//!
//! The backend is deliberately hidden behind Pingora's [`Storage`] trait.
//! [`ResponseCache`] currently wraps the built-in in-memory [`MemCache`] paired
//! with a sharded LRU eviction manager, but because Pingora's
//! `HttpCache::enable` takes `&'static dyn Storage`, swapping in a distributed
//! (e.g. Redis) backend later is a change confined to this crate — the proxy
//! hooks, the admin purge endpoint, and the metrics are unaffected.
//!
//! This crate is shared by `coxswain-proxy` (which enables the cache per route
//! and serves hits) and `coxswain-admin` (which purges entries on operator
//! request) so that neither role has to depend on the other.

mod metrics;

pub use metrics::{cache_hits_total, cache_misses_total, cache_purges_total};

use pingora_cache::eviction::EvictionManager;
use pingora_cache::eviction::lru::Manager as LruManager;
use pingora_cache::trace::Span;
use pingora_cache::{CacheKey, MemCache, PurgeType, Storage};

/// Number of LRU shards in the eviction manager.
///
/// Sharding spreads eviction bookkeeping across independent locks so admission
/// under concurrency does not serialize on a single mutex. Eight is the order
/// Pingora uses in its own examples and is ample for one in-memory cache.
const LRU_SHARDS: usize = 8;

/// Per-shard entry-count preallocation hint for the LRU.
///
/// The cache is bounded by *bytes* (`max_bytes`), not entry count, so an
/// undersized guess only costs a reallocation as the LRU grows — never a
/// premature eviction.
const LRU_SHARD_CAPACITY: usize = 1024;

/// Derive the cache key for a request.
///
/// The `namespace` is the request host (so entries are scoped per host) and the
/// `primary` component is `"{method} {path_and_query}"`. Admission (the proxy's
/// `cache_key_callback`) and purge ([`ResponseCache::purge`]) **must** agree on
/// this derivation or a purge would target a different hash than the stored
/// entry — both therefore route through this single function.
#[must_use]
pub fn cache_key(method: &str, host: &str, path_and_query: &str) -> CacheKey {
    let mut primary = String::with_capacity(method.len() + 1 + path_and_query.len());
    primary.push_str(method);
    primary.push(' ');
    primary.push_str(path_and_query);
    CacheKey::new(host.to_owned(), primary, String::new())
}

/// Handle to the process-wide in-memory response cache.
///
/// Cheap to copy — it holds two `'static` references, not the cache itself.
/// Construct exactly once per process with [`ResponseCache::with_max_bytes`].
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct ResponseCache {
    storage: &'static MemCache,
    eviction: &'static LruManager<LRU_SHARDS>,
}

impl ResponseCache {
    /// Build the cache with a maximum total body size of `max_bytes`.
    ///
    /// The storage and eviction manager are leaked to obtain the `'static`
    /// lifetime Pingora's `HttpCache::enable` requires; this is intended to run
    /// once per process at startup. Calling it repeatedly (e.g. across tests)
    /// leaks a bounded amount of memory per call.
    #[must_use]
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        let storage: &'static MemCache = Box::leak(Box::new(MemCache::new()));
        let eviction: &'static LruManager<LRU_SHARDS> = Box::leak(Box::new(
            LruManager::with_capacity(max_bytes, LRU_SHARD_CAPACITY),
        ));
        // Expose the eviction manager's depth on the proxy `/metrics` (pull-based).
        metrics::register_cache_depth_collector(eviction);
        Self { storage, eviction }
    }

    /// The storage backend, for `Session::cache.enable`.
    #[must_use]
    pub fn storage(&self) -> &'static (dyn Storage + Sync) {
        self.storage
    }

    /// The eviction manager, for `Session::cache.enable`.
    #[must_use]
    pub fn eviction(&self) -> &'static (dyn EvictionManager + Sync) {
        self.eviction
    }

    /// Purge the cached `GET {host}{path}` entry, returning whether one was removed.
    ///
    /// The eviction manager is informed so its byte accounting stays in sync
    /// with storage (mirroring Pingora's own invalidation path).
    ///
    /// Only the non-varied `GET` variant is addressable: an entry stored under a
    /// `Vary` variance hashes differently and is not reached by a host/path
    /// purge, and `HEAD` responses are keyed separately. This matches the
    /// per-route admin purge contract — it is not a wildcard flush.
    pub async fn purge(&self, host: &str, path: &str) -> bool {
        let key = cache_key("GET", host, path).to_compact();
        let span = Span::inactive();
        let purged = matches!(
            self.storage
                .purge(&key, PurgeType::Invalidation, &span.handle())
                .await,
            Ok(true)
        );
        if purged {
            self.eviction.remove(&key);
        }
        metrics::cache_purges_total()
            .with_label_values(&[if purged { "hit" } else { "miss" }])
            .inc();
        purged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_cache::key::CacheHashKey;

    #[test]
    fn cache_key_is_deterministic_for_identical_inputs() {
        let a = cache_key("GET", "example.com", "/a");
        let b = cache_key("GET", "example.com", "/a");
        assert_eq!(
            a.primary(),
            b.primary(),
            "identical method/host/path must hash to the same primary key"
        );
    }

    #[test]
    fn cache_key_differs_by_method_host_and_path() {
        let base = cache_key("GET", "example.com", "/a").primary();
        assert_ne!(
            base,
            cache_key("HEAD", "example.com", "/a").primary(),
            "method must be part of the key (GET and HEAD are distinct entries)"
        );
        assert_ne!(
            base,
            cache_key("GET", "other.com", "/a").primary(),
            "host must scope the key"
        );
        assert_ne!(
            base,
            cache_key("GET", "example.com", "/b").primary(),
            "path must be part of the key"
        );
    }

    #[tokio::test]
    async fn purge_returns_false_when_entry_absent() {
        let cache = ResponseCache::with_max_bytes(1024);
        let miss_before = cache_purges_total().with_label_values(&["miss"]).get();

        assert!(
            !cache.purge("example.com", "/missing").await,
            "purging an entry that was never cached must report nothing removed"
        );

        assert_eq!(
            cache_purges_total().with_label_values(&["miss"]).get(),
            miss_before + 1,
            "a no-op purge must increment coxswain_proxy_cache_purges_total{{miss}}"
        );
    }
}
