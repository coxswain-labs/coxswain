//! Controller-side JWKS fetch/cache for `JwtAuth` (#441).
//!
//! Remote JWKS resolution happens **here** — never in `coxswain-proxy` — so the
//! read-only data plane never egresses to an identity provider (the Istio
//! model, not Envoy's default proxy-side fetch). [`JwksCacheHandle`] is a
//! cloneable, lock-free-read handle: `run` is the sole writer (spawned once,
//! controller role only — see [`crate::reconciler::ReconcilerOptions::fetch_remote_jwks`]),
//! and the reconcile rebuild reads it synchronously via [`JwksCacheHandle::get`]
//! when resolving a `JwtAuth` CR that names a [`coxswain_core::crd::RemoteJwks`].
//!
//! Inline JWKS ([`coxswain_core::crd::InlineJwks`]) never touches this cache — the reflector reads
//! `spec.jwks.inline.jwks` directly at resolve time.
//!
//! `remote.uri` is a tenant-authored URL fetched by the privileged controller
//! (#664) — `fetch_one` enforces the `crate::egress` guard on it: `https`
//! is required unless the destination is operator-allowlisted, a literal-IP
//! host is checked against the same policy the caller's `reqwest::Client` was
//! built with (see `crate::egress::GuardedResolver`, wired in at
//! [`crate::reconciler`]'s client construction — DNS-resolved hosts are
//! covered there, not here), and the response body is capped.

use crate::MergedStore;
use crate::egress::EgressPolicy;
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

/// Cap on a JWKS response body (#664): a legitimate key set is a handful of
/// keys, at most a few KiB. 1 MiB is generous headroom while still bounding
/// what a compromised or malicious endpoint can make the controller buffer.
const MAX_JWKS_BODY_BYTES: usize = 1 << 20;

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
pub(crate) async fn run(
    cache: JwksCacheHandle,
    jwt_auths: MergedStore<JwtAuth>,
    client: reqwest::Client,
    policy: EgressPolicy,
) {
    let mut local: HashMap<Box<str>, CacheEntry> = HashMap::new();
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    loop {
        ticker.tick().await;
        tick(&cache, &jwt_auths, &client, &policy, &mut local).await;
    }
}

/// One refresh pass: rescan the store for live remote-JWKS URIs, drop entries
/// no longer referenced, fetch every due URI concurrently, and publish if
/// anything changed.
async fn tick(
    cache: &JwksCacheHandle,
    jwt_auths: &MergedStore<JwtAuth>,
    client: &reqwest::Client,
    policy: &EgressPolicy,
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

    let fetches = due.iter().map(|uri| fetch_one(client, uri, policy));
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

/// Why a JWKS fetch failed. Every variant leaves the URI's cache entry
/// [`CacheState::Failed`] (fail-closed) — this only exists to give the
/// `tracing::warn!` in [`tick`] a precise, `Display`-able cause.
#[derive(Debug, thiserror::Error)]
enum JwksFetchError {
    /// `uri` isn't a valid absolute URL at all.
    #[error("not a valid URL")]
    InvalidUri,
    /// Plaintext (`http`) to anything other than a literal IP the operator
    /// allowlisted via `--egress-allow-cidr`. `https` is always permitted;
    /// `http` never is otherwise — a hostname target can't be checked here at
    /// all (no DNS lookup happens before the connector itself resolves it,
    /// see [`check_url`]), so `http` to a hostname is refused unconditionally,
    /// not just when unlisted — see [`EgressPolicy::permits_plaintext`].
    #[error(
        "http:// is only permitted to a literal IP address listed in --egress-allow-cidr \
         (a hostname target must use https://)"
    )]
    PlaintextNotAllowed,
    /// The host is a literal IP outside the controller's egress policy (#664)
    /// — see [`crate::egress`].
    #[error("blocked by the controller's egress policy; see --egress-allow-cidr")]
    Blocked,
    /// A non-`2xx` response. Redirects are disabled on the client (#664), so
    /// a `3xx` lands here rather than being silently followed.
    #[error("server responded {0}")]
    Status(reqwest::StatusCode),
    /// The response body exceeded [`MAX_JWKS_BODY_BYTES`].
    #[error("response body exceeded the {MAX_JWKS_BODY_BYTES}-byte cap")]
    BodyTooLarge,
    /// The body isn't valid UTF-8.
    #[error("response body is not valid UTF-8")]
    NotUtf8,
    /// Network error, TLS error, resolver-rejected (see
    /// [`crate::egress::GuardedResolver`]), or timeout.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

/// Reject a request before it's ever sent, for anything decidable from the
/// URL alone: scheme, and a literal-IP host (hyper-util skips DNS resolution
/// entirely for those — `SocketAddrs::try_parse` — so
/// [`crate::egress::GuardedResolver`], wired into the client's DNS resolver,
/// never sees them; this is the only place they're checked).
///
/// `Url::host_str` brackets an IPv6 literal (`"[::1]"`), so it is stripped
/// before parsing — mirroring `hyper_util`'s own
/// `trim_start_matches('[').trim_end_matches(']')` in `HttpConnector::call_async`,
/// the exact bracket-stripping that feeds its `SocketAddrs::try_parse` fast
/// path. Without this, `https://[::ffff:169.254.169.254]/` (or any bracketed
/// IPv6/IPv4-mapped literal) would parse as a non-IP "hostname" here, skip
/// this check entirely, and still hit the DNS fast path downstream — bypassing
/// the guard through the one case it exists to cover.
fn check_url(uri: &str, policy: &EgressPolicy) -> Result<(), JwksFetchError> {
    let parsed = reqwest::Url::parse(uri).map_err(|_| JwksFetchError::InvalidUri)?;
    let Some(host) = parsed.host_str() else {
        return Err(JwksFetchError::InvalidUri);
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let literal_ip = host.parse::<std::net::IpAddr>().ok();

    match parsed.scheme() {
        "https" => {}
        "http" => {
            let permitted = literal_ip.is_some_and(|ip| policy.permits_plaintext(ip));
            if !permitted {
                return Err(JwksFetchError::PlaintextNotAllowed);
            }
        }
        _ => return Err(JwksFetchError::InvalidUri),
    }

    if let Some(ip) = literal_ip
        && !policy.permits(ip)
    {
        return Err(JwksFetchError::Blocked);
    }
    Ok(())
}

/// Fetch one JWKS URI, bounded by [`FETCH_TIMEOUT`] and guarded against SSRF
/// (#664, [`crate::egress`]).
///
/// Returns the verbatim response body text on a `2xx`; any other outcome
/// (blocked destination, network error, non-2xx status, timeout, oversized or
/// non-UTF-8 body) is an `Err`. Body *content* validation (is this actually a
/// parseable JWK Set?) happens in `coxswain-proxy`, which is the sole
/// JWKS-parsing/crypto boundary in the codebase (see
/// [`coxswain_core::routing::JwtConfig`]'s module doc).
async fn fetch_one(
    client: &reqwest::Client,
    uri: &str,
    policy: &EgressPolicy,
) -> Result<Arc<str>, JwksFetchError> {
    check_url(uri, policy)?;

    let mut resp = client.get(uri).timeout(FETCH_TIMEOUT).send().await?;
    if !resp.status().is_success() {
        return Err(JwksFetchError::Status(resp.status()));
    }
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_JWKS_BODY_BYTES as u64)
    {
        return Err(JwksFetchError::BodyTooLarge);
    }

    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_JWKS_BODY_BYTES {
            return Err(JwksFetchError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let text = String::from_utf8(body).map_err(|_| JwksFetchError::NotUtf8)?;
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
        let policy = EgressPolicy::default();
        tick(&cache, &jwt_auths, &client, &policy, &mut local).await;
        assert!(local.is_empty(), "stale entry must be pruned");
    }

    fn empty_store() -> MergedStore<JwtAuth> {
        let (reader, mut writer) = reflector::store();
        writer.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        MergedStore::single(reader)
    }

    #[test]
    fn https_to_any_host_passes_the_url_check() {
        let policy = EgressPolicy::default();
        check_url("https://issuer.example.com/jwks.json", &policy).expect("https is allowed");
    }

    #[test]
    fn http_to_a_hostname_is_rejected_without_dns() {
        // No allowlist can vouch for a hostname without resolving it, and
        // `check_url` never performs DNS — see its doc comment.
        let policy = EgressPolicy::new(vec!["10.0.0.0/8".parse().expect("cidr")]);
        let err = check_url("http://issuer.example.com/jwks.json", &policy)
            .expect_err("http to a hostname must be rejected");
        assert!(matches!(err, JwksFetchError::PlaintextNotAllowed));
    }

    #[test]
    fn http_to_an_allowlisted_literal_ip_is_permitted() {
        let policy = EgressPolicy::new(vec!["10.0.0.0/8".parse().expect("cidr")]);
        check_url("http://10.1.2.3/jwks.json", &policy)
            .expect("http to an allowlisted literal IP is permitted");
    }

    #[test]
    fn https_to_a_reserved_literal_ip_is_blocked_without_dns() {
        let policy = EgressPolicy::default();
        let err = check_url("https://169.254.169.254/latest/meta-data/", &policy)
            .expect_err("metadata IP must be blocked");
        assert!(matches!(err, JwksFetchError::Blocked));
    }

    #[test]
    fn bracketed_ipv6_literal_host_is_blocked() {
        // `Url::host_str()` brackets an IPv6 literal; a naive `.parse::<IpAddr>()`
        // on the unmodified `host_str()` would treat this as an opaque hostname
        // and skip the reserved-range check entirely (#664 regression).
        let policy = EgressPolicy::default();
        let err = check_url("https://[fd00::1]/jwks.json", &policy)
            .expect_err("ULA IPv6 literal must be blocked");
        assert!(matches!(err, JwksFetchError::Blocked));
    }

    #[test]
    fn bracketed_ipv4_mapped_ipv6_literal_host_is_blocked() {
        let policy = EgressPolicy::default();
        let err = check_url(
            "https://[::ffff:169.254.169.254]/latest/meta-data/",
            &policy,
        )
        .expect_err("IPv4-mapped IPv6 metadata literal must be blocked");
        assert!(matches!(err, JwksFetchError::Blocked));
    }

    #[test]
    fn non_http_scheme_is_rejected() {
        let policy = EgressPolicy::default();
        let err =
            check_url("file:///etc/passwd", &policy).expect_err("non-http scheme must be rejected");
        assert!(matches!(err, JwksFetchError::InvalidUri));
    }

    #[test]
    fn unparseable_uri_is_rejected() {
        let policy = EgressPolicy::default();
        let err = check_url("not a url", &policy).expect_err("unparseable URI must be rejected");
        assert!(matches!(err, JwksFetchError::InvalidUri));
    }
}
