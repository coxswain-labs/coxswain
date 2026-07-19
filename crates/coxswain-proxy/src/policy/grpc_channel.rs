//! Per-process connection pool of tonic HTTP/2 channels for the gRPC ext_authz
//! transport (#544).
//!
//! # Design
//! The gRPC ext_authz check (`crate::policy::auth`) runs on the hot request path
//! for every request to an auth-protected route. Dialling a fresh tonic
//! [`Channel`] per check pays a TCP handshake + HTTP/2 preface (~2 RTT) and
//! churns one connection per unary RPC. This cache keeps a warm [`Channel`] per
//! resolved auth-endpoint [`SocketAddr`], reaching parity with the HTTP
//! transport's pooled `reqwest::Client`. HTTP/2 multiplexes concurrent `Check`
//! RPCs over the one connection, and [`Channel`] is `Arc`-backed — cloning it out
//! of the map is a pointer bump.
//!
//! Channels are built with [`Endpoint::connect_lazy`], so the build path stays
//! synchronous (no `.await`, no lock held across a yield); tonic reconnects a
//! lazy channel transparently if its live TCP connection drops (e.g. the pod
//! restarts in place, same address).
//!
//! Endpoint *replacement* (scale-down/rollout — a new pod, a new `SocketAddr`)
//! is handled differently, by construction rather than by reconnect: the cache
//! is keyed by `SocketAddr`, so a replaced endpoint simply gets a fresh entry on
//! its first check, while the old, now-dead address's entry is never selected
//! again by the round-robin picker in `crate::policy::auth` — no explicit
//! invalidation logic exists or is needed. See "Memory bounding" below for how
//! that stale entry is eventually reclaimed.
//!
//! `connect_timeout` is a fixed pool-internal constant, deliberately *not*
//! derived from any particular route's `ExtAuthConfig.timeout` — the cache is
//! keyed only by `SocketAddr`, so two routes/policies sharing one auth-service
//! pod but configuring different timeouts would otherwise leave the first
//! caller's value baked into the channel for both. The per-request deadline is
//! enforced independently by the caller's `tokio::time::timeout(cfg.timeout, ..)`
//! around the whole RPC (connect included, since `connect_lazy` defers the
//! actual connect to the first send), so this constant only needs to be
//! "generous enough that a healthy pod's handshake never trips it."
//!
//! # Memory bounding
//! [`GrpcAuthChannelCache::sweep`], called periodically (~60 s) from a background
//! service, applies second-chance eviction: an entry touched since the previous
//! sweep survives, an untouched one is dropped. A stale entry left behind by
//! endpoint replacement goes idle (never selected again) and is reclaimed on the
//! next sweep — bounding the map to the live endpoint set.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};

/// Generous fixed bound on the underlying TCP/H2 connect a cold cache entry
/// performs. Deliberately not tied to any caller's `cfg.timeout` — see the
/// module doc. Large enough that a healthy pod under normal load never trips
/// it; a genuinely wedged/unreachable pod is still bounded by the caller's own
/// outer per-request timeout regardless of this value.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// One pooled channel plus its second-chance "used since last sweep" flag.
struct CachedChannel {
    channel: Channel,
    recently_used: AtomicBool,
}

/// Process-wide pool of warm gRPC channels keyed by resolved auth endpoint.
///
/// Cheap to clone: the inner map is `Arc`-shared, so both `IngressProxy` and
/// `GatewayProxy` hold a clone of the same pool via [`crate::ProxyServices`].
#[derive(Clone, Default)]
pub struct GrpcAuthChannelCache {
    inner: Arc<DashMap<SocketAddr, CachedChannel>>,
}

impl GrpcAuthChannelCache {
    /// Construct an empty pool. Call once at process startup.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a warm [`Channel`] for `addr`, building a lazy one on first use.
    ///
    /// The returned channel is a cheap `Arc` clone of the pooled connection; the
    /// caller issues the unary `Check` on it and bounds the whole call —
    /// including a cold entry's deferred connect — with its own per-request
    /// `tokio::time::timeout`. See the module doc for why `connect_timeout` is
    /// not a parameter here.
    ///
    /// # Errors
    /// Returns the tonic error only when the `http://{addr}` URI fails to parse —
    /// unreachable for a real [`SocketAddr`], but surfaced so the caller degrades
    /// (fail-closed/open) instead of unwrapping.
    #[must_use = "the pooled channel must be used to issue the ext_authz check"]
    pub fn get_or_connect(&self, addr: SocketAddr) -> Result<Channel, tonic::transport::Error> {
        // Fast path: read-only lookup, no write lock (`DashMap::entry` is
        // disallowed — it always takes an exclusive shard lock).
        if let Some(entry) = self.inner.get(&addr) {
            entry.recently_used.store(true, Ordering::Relaxed);
            return Ok(entry.channel.clone());
        }
        // Slow path: build a lazy channel. `from_shared` is the only fallible
        // step and never fails for a SocketAddr-derived URI; `connect_lazy`
        // defers the actual connect to the first RPC, so this stays synchronous.
        // A concurrent miss on the same addr races harmlessly here (mirrors
        // `RateLimiterRegistry::get_or_build`): each racer returns the channel
        // it built itself, and `insert` leaves exactly one entry in the map —
        // the loser's channel is simply dropped unused.
        let channel = Endpoint::from_shared(format!("http://{addr}"))?
            .connect_timeout(CONNECT_TIMEOUT)
            .connect_lazy();
        self.inner.insert(
            addr,
            CachedChannel {
                channel: channel.clone(),
                recently_used: AtomicBool::new(true),
            },
        );
        Ok(channel)
    }

    /// Evict channels not used since the previous sweep (second-chance).
    ///
    /// An entry accessed via [`Self::get_or_connect`] since the last sweep has its
    /// flag set; `retain` clears the flag and keeps it. An untouched entry (flag
    /// already clear) is dropped, closing its idle connection. Call periodically
    /// from a background service to bound the pool to the live endpoint set.
    pub fn sweep(&self) {
        self.inner
            .retain(|_, entry| entry.recently_used.swap(false, Ordering::Relaxed));
    }

    /// Number of pooled channels. Test/introspection only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the pool holds no channels.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap_or_else(|e| panic!("bad addr {s}: {e}"))
    }

    // `connect_lazy` requires a tokio runtime context to construct the channel's
    // internal machinery, so the cache tests run under `#[tokio::test]`.

    #[tokio::test]
    async fn get_or_connect_reuses_channel_for_same_addr() {
        let cache = GrpcAuthChannelCache::new();
        let a = addr("10.0.0.1:9000");
        let _ = cache.get_or_connect(a).expect("first build");
        let _ = cache.get_or_connect(a).expect("second (cached)");
        assert_eq!(cache.len(), 1, "repeat addr must not add a second entry");
    }

    #[tokio::test]
    async fn get_or_connect_grows_per_distinct_addr() {
        let cache = GrpcAuthChannelCache::new();
        let _ = cache.get_or_connect(addr("10.0.0.1:9000")).expect("a");
        let _ = cache.get_or_connect(addr("10.0.0.2:9000")).expect("b");
        assert_eq!(cache.len(), 2, "distinct addrs get distinct channels");
    }

    #[tokio::test]
    async fn sweep_grants_one_grace_then_evicts_idle() {
        let cache = GrpcAuthChannelCache::new();
        let _ = cache.get_or_connect(addr("10.0.0.1:9000")).expect("build");
        // Insert set the flag: the first sweep clears it but keeps the entry.
        cache.sweep();
        assert_eq!(cache.len(), 1, "one grace period after last use");
        // No access since: the second sweep evicts it.
        cache.sweep();
        assert!(cache.is_empty(), "idle channel evicted on the next sweep");
    }

    #[tokio::test]
    async fn sweep_keeps_recently_used_channel() {
        let cache = GrpcAuthChannelCache::new();
        let a = addr("10.0.0.1:9000");
        let _ = cache.get_or_connect(a).expect("build");
        cache.sweep(); // clears the insert flag
        let _ = cache.get_or_connect(a).expect("touch"); // re-arms it
        cache.sweep(); // sees the touch → keeps
        assert_eq!(cache.len(), 1, "a channel used each interval survives");
    }
}
