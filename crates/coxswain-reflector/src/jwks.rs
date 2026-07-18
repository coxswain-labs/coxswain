//! Controller-side JWKS fetch/cache for `JwtAuth` (#441).
//!
//! Remote JWKS resolution happens **here** — never in `coxswain-proxy` — so the
//! read-only data plane never egresses to an identity provider (the Istio
//! model, not Envoy's default proxy-side fetch). [`JwksCacheHandle`] is a
//! cloneable, lock-free-read handle: [`run`] is the sole writer (spawned once,
//! controller role only — see [`crate::reconciler::ReconcilerOptions::fetch_remote_jwks`]),
//! and the reconcile rebuild reads it synchronously via [`JwksCacheHandle::get`]
//! when resolving a `JwtAuth` CR that names a [`coxswain_core::crd::RemoteJwks`].
//!
//! Inline JWKS ([`coxswain_core::crd::InlineJwks`]) never touches this cache — the reflector reads
//! `spec.jwks.inline.jwks` directly at resolve time.

use crate::MergedStore;
use arc_swap::ArcSwap;
use coxswain_core::crd::JwtAuth;
#[cfg(test)]
use kube::runtime::reflector;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Default refetch interval when a [`coxswain_core::crd::RemoteJwks::refresh_interval`] is absent
/// or unparseable. The response's `Cache-Control` header is not consulted.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(300);

/// Floor on the refetch interval — clamps an implausibly small
/// operator-supplied `refreshInterval` so a misconfiguration cannot hammer
/// the identity provider.
const MIN_REFRESH: Duration = Duration::from_secs(30);

/// Per-fetch HTTP timeout. A hung identity provider must not stall the refresh
/// of every other tracked URI.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the background task rescans the `JwtAuth` store for due URIs.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Outcome of the most recent fetch attempt for one JWKS URI.
#[derive(Clone, Debug)]
enum CacheState {
    /// Fetched successfully; verbatim JWKS JSON response body.
    Resolved(Arc<str>),
    /// The most recent attempt failed (network error, non-2xx, or a body that
    /// isn't valid UTF-8). Routes referencing this URI fail closed
    /// ([`coxswain_core::routing::IngressAuthConfig::Unavailable`]) until a
    /// retry succeeds — stale keys are never served past their fetch failure,
    /// matching the ext_authz "broken backend fails closed" precedent.
    Failed,
}

/// One cache entry: the last-known state plus when it's next due for refetch.
#[derive(Clone)]
struct CacheEntry {
    state: CacheState,
    next_due: Instant,
}

struct JwksCacheInner {
    entries: ArcSwap<HashMap<Box<str>, CacheState>>,
    tx: watch::Sender<u64>,
}

/// Shared, cloneable handle to the controller-side JWKS cache.
///
/// [`Self::get`] is synchronous and lock-free (`ArcSwap`) — the reconcile
/// rebuild reads it on every pass without blocking on network I/O.
/// [`Self::subscribe`] lets the rebuild-trigger loop wake up when a fetch
/// changes the cache (a new URI resolves, an existing one's content rotates,
/// or a healthy URI starts failing), so a route's `Unavailable` → `Jwt`
/// transition (or vice versa) is picked up without waiting for an unrelated
/// reconcile.
#[non_exhaustive]
#[derive(Clone)]
pub struct JwksCacheHandle(Arc<JwksCacheInner>);

impl Default for JwksCacheHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksCacheHandle {
    /// Construct an empty cache (generation 0).
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(JwksCacheInner {
            entries: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Resolved JWKS JSON text for `uri`, if the most recent fetch succeeded.
    /// `None` when unresolved — not yet fetched, or the most recent attempt
    /// failed — callers fail the referencing route closed.
    #[must_use]
    pub fn get(&self, uri: &str) -> Option<Arc<str>> {
        match self.0.entries.load().get(uri) {
            Some(CacheState::Resolved(text)) => Some(Arc::clone(text)),
            _ => None,
        }
    }

    /// Returns a `watch::Receiver` for subscribing to cache-change notifications.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }

    /// Current cache generation — bumped by `Self::publish` on every fetch
    /// that changes the cache. Because the reconcile bakes resolved JWKS
    /// *text* into a route's compiled config (`jwt_auth::resolve_spec`), a
    /// key rotation moves this counter but no watched-resource `resourceVersion`;
    /// the partitioned rebuild folds this into its global epoch so a rotated-out
    /// key can't survive on a reused partition (#511).
    #[must_use]
    pub fn generation(&self) -> u64 {
        *self.0.tx.borrow()
    }

    /// Publish a new full snapshot and bump the generation counter.
    fn publish(&self, snapshot: HashMap<Box<str>, CacheState>) {
        self.0.entries.store(Arc::new(snapshot));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }
}

/// Background task: fetch and periodically refresh every remote JWKS
/// referenced by a live `JwtAuth` CR, publishing results into `cache`.
///
/// Runs forever — like every other watch task `spawn_tasks` hands to its
/// `JoinSet`, shutdown is cooperative-free: the caller aborts this task by
/// dropping the `JoinSet` (see `SharedProxyReconciler::start`), not via a
/// per-task signal. Controller role only (see
/// [`crate::reconciler::ReconcilerOptions::fetch_remote_jwks`]) — the proxy
/// never runs this task, so the read-only data plane never egresses to an
/// identity provider.
pub async fn run(cache: JwksCacheHandle, jwt_auths: MergedStore<JwtAuth>, client: reqwest::Client) {
    let mut local: HashMap<Box<str>, CacheEntry> = HashMap::new();
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    loop {
        ticker.tick().await;
        tick(&cache, &jwt_auths, &client, &mut local).await;
    }
}

/// One refresh pass: rescan the store for live remote-JWKS URIs, drop entries
/// no longer referenced, fetch every due URI concurrently, and publish if
/// anything changed.
async fn tick(
    cache: &JwksCacheHandle,
    jwt_auths: &MergedStore<JwtAuth>,
    client: &reqwest::Client,
    local: &mut HashMap<Box<str>, CacheEntry>,
) {
    let now = Instant::now();

    // Desired URI → refresh interval (the minimum across every CR that shares
    // the URI, so one impatient operator can't be starved by another's laxer
    // setting).
    let mut desired: HashMap<Box<str>, Duration> = HashMap::new();
    for cr in jwt_auths.state() {
        let Some(remote) = cr.spec.jwks.remote.as_ref() else {
            continue;
        };
        let interval = remote
            .refresh_interval
            .as_deref()
            .and_then(crate::duration::parse_duration)
            .map(|d| d.max(MIN_REFRESH))
            .unwrap_or(DEFAULT_REFRESH);
        desired
            .entry(Box::from(remote.uri.as_str()))
            .and_modify(|cur: &mut Duration| *cur = (*cur).min(interval))
            .or_insert(interval);
    }

    // Drop cache entries for URIs no CR references anymore.
    local.retain(|uri, _| desired.contains_key(uri));

    let due: Vec<Box<str>> = desired
        .keys()
        .filter(|uri| local.get(uri.as_ref()).is_none_or(|e| now >= e.next_due))
        .cloned()
        .collect();
    if due.is_empty() {
        return;
    }

    let fetches = due.iter().map(|uri| fetch_one(client, uri));
    let results = futures::future::join_all(fetches).await;

    for (uri, result) in due.into_iter().zip(results) {
        let interval = desired[&uri];
        let state = match result {
            Ok(text) => CacheState::Resolved(text),
            Err(e) => {
                tracing::warn!(
                    jwks_uri = %uri,
                    error = %e,
                    "JWKS fetch failed — route(s) referencing it fail closed until the next retry"
                );
                CacheState::Failed
            }
        };
        local.insert(
            uri,
            CacheEntry {
                state,
                next_due: now + interval,
            },
        );
    }

    let snapshot: HashMap<Box<str>, CacheState> = local
        .iter()
        .map(|(uri, entry)| (uri.clone(), entry.state.clone()))
        .collect();
    cache.publish(snapshot);
}

/// Fetch one JWKS URI, bounded by [`FETCH_TIMEOUT`].
///
/// Returns the verbatim response body text on a `2xx`; any other outcome
/// (network error, non-2xx status, timeout, non-UTF-8 body) is an `Err`. Body
/// *content* validation (is this actually a parseable JWK Set?) happens in
/// `coxswain-proxy`, which is the sole JWKS-parsing/crypto boundary in the
/// codebase (see [`coxswain_core::routing::JwtConfig`]'s module doc).
async fn fetch_one(client: &reqwest::Client, uri: &str) -> Result<Arc<str>, reqwest::Error> {
    let resp = client
        .get(uri)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await?
        .error_for_status()?;
    let text = resp.text().await?;
    Ok(Arc::from(text))
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;

    #[test]
    fn empty_cache_resolves_nothing() {
        let cache = JwksCacheHandle::new();
        assert!(cache.get("https://issuer.example.com/jwks.json").is_none());
    }

    #[test]
    fn publish_makes_resolved_entries_visible_and_bumps_generation() {
        let cache = JwksCacheHandle::new();
        let mut rx = cache.subscribe();
        let initial = *rx.borrow();

        let mut snapshot = HashMap::new();
        snapshot.insert(
            Box::from("https://issuer.example.com/jwks.json"),
            CacheState::Resolved(Arc::from(r#"{"keys":[]}"#)),
        );
        cache.publish(snapshot);

        assert_eq!(
            cache.get("https://issuer.example.com/jwks.json").as_deref(),
            Some(r#"{"keys":[]}"#)
        );
        assert!(
            rx.has_changed().unwrap_or(false) || *rx.borrow_and_update() != initial,
            "publish must bump the generation counter"
        );
    }

    #[test]
    fn failed_entry_resolves_to_none() {
        let cache = JwksCacheHandle::new();
        let mut snapshot = HashMap::new();
        snapshot.insert(
            Box::from("https://issuer.example.com/jwks.json"),
            CacheState::Failed,
        );
        cache.publish(snapshot);
        assert!(
            cache.get("https://issuer.example.com/jwks.json").is_none(),
            "a Failed entry must resolve to None (fail-closed)"
        );
    }

    #[tokio::test]
    async fn tick_drops_entries_no_longer_referenced() {
        // A URI present in `local` but no longer referenced by any CR must be
        // pruned even without a network call. `reqwest::Client::builder().build()`
        // still requires an installed rustls crypto provider even though this
        // test never sends a request (the `rustls-no-provider` feature checks at
        // construction time); `.ok()` because a prior test in this binary may
        // have already installed one.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let cache = JwksCacheHandle::new();
        let jwt_auths = empty_store();
        let client = reqwest::Client::builder().build().expect("client");
        let mut local = HashMap::new();
        local.insert(
            Box::from("https://stale.example.com/jwks.json"),
            CacheEntry {
                state: CacheState::Resolved(Arc::from("{}")),
                next_due: Instant::now() + Duration::from_secs(3600),
            },
        );
        tick(&cache, &jwt_auths, &client, &mut local).await;
        assert!(local.is_empty(), "stale entry must be pruned");
    }

    fn empty_store() -> MergedStore<JwtAuth> {
        let (reader, mut writer) = reflector::store();
        writer.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        MergedStore::single(reader)
    }
}
