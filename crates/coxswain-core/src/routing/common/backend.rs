//! Upstream backend selection and load balancing.
//!
//! This module owns the data-plane concern of choosing *which* upstream pod a
//! request is forwarded to: the weighted [`BackendGroup`] (two-level weighted
//! round-robin over backends and their pods), the per-route load-balancing
//! algorithms ([`LoadBalance`]: round-robin, least-connections, EWMA, and
//! consistent [`HashSource`] hashing), and sticky [`SessionAffinity`]. The
//! route-entry and filter data model that *carries* a [`BackendGroup`] lives in
//! the sibling [`super::entry`] module.

use super::filters::FilterAction;
use super::retry::RetryPolicy;
use super::upstream_tls::{BackendProtocol, UpstreamTls};
use http::HeaderName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// Sticky-session (session-affinity) configuration attached to a [`BackendGroup`].
///
/// Stateless by construction (no server-side session map): the pin is encoded in the
/// request itself, so affinity is naturally per-process and survives nothing across
/// replicas — which is exactly the contract. Populated today only from the Ingress
/// `ingress.coxswain-labs.dev/session-*` annotations; a backend with no affinity
/// binding keeps plain weighted round-robin.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum SessionAffinity {
    /// Cookie mode: the proxy injects a cookie whose value is the endpoint token
    /// (`hex(affinity_token(addr))`) on the first response, and pins subsequent
    /// requests carrying it to that endpoint. A token that no longer matches any live
    /// endpoint (pod removed/scaled away) falls back to round-robin and re-pins.
    Cookie {
        /// Cookie name to emit and read back (default `__coxswain_session`).
        cookie_name: Arc<str>,
    },
    /// Header mode: the value of `header` is rendezvous-hashed over the live endpoint
    /// set to consistently select one endpoint. No cookie is injected; a request
    /// without the header degrades to round-robin.
    Header {
        /// Request header whose value selects the endpoint.
        header: HeaderName,
    },
}

/// Request attribute to extract as the consistent-hash key for [`LoadBalance::Hash`].
///
/// The proxy extracts the value per request, hashes it with FNV-1a, and selects the
/// upstream via rendezvous (HRW) hashing — only the keys whose owner is removed remap
/// on endpoint changes. All variants fall back to round-robin when the attribute is
/// absent or empty.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashSource {
    /// Path + query of the request URI (`/path?query`).
    Uri,
    /// Resolved real client IP — honours `trust-forwarded-for` (#271) configuration.
    SourceIp,
    /// Value of a specific request header (case-insensitive lookup).
    Header(HeaderName),
    /// Value of a specific named cookie from the `Cookie` header.
    Cookie(Arc<str>),
}

/// The original construction inputs to a [`BackendGroup`], retained for wire serialisation.
///
/// Preserved behind an `Arc` on [`BackendGroup`] so the discovery wire layer can
/// faithfully reconstruct the exact per-backend (addresses, weight) grouping that was
/// passed to [`BackendGroup::new`] or [`BackendGroup::weighted`].  The spec is never
/// read on the request hot path — it exists only for `to_wire` and admin introspection.
#[non_exhaustive]
pub struct BackendGroupSpec {
    /// Per-backend (endpoint-addresses, weight) groups, in construction order.
    ///
    /// Empty when the group was constructed with all-zero or all-empty backends.
    /// For [`BackendGroup::new`] this is always `[(all_endpoints, 1)]` (one backend,
    /// uniform weight). For [`BackendGroup::weighted`] this mirrors the filtered
    /// (non-zero weight, non-empty addrs) input list with the original pre-GCD weights.
    pub weighted: Box<[(Box<[SocketAddr]>, u16)]>,
}

/// Per-route upstream load-balancing algorithm from the
/// `ingress.coxswain-labs.dev/load-balance` annotation.
///
/// Gateway API routes always carry `RoundRobin` (the annotation is Ingress-only).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum LoadBalance {
    /// Standard weighted round-robin (the default; current behaviour).
    #[default]
    RoundRobin,
    /// Route to the endpoint with the fewest active in-flight connections.
    LeastConn,
    /// Route to the endpoint with the lowest exponentially-weighted moving average
    /// response latency (`α = 1/8`). New or idle endpoints (never sampled) are
    /// probed first so the estimate stays fresh.
    Ewma,
    /// Rendezvous (HRW) consistent hash on the carried [`HashSource`] attribute.
    /// The attribute is extracted and hashed by the proxy (via
    /// [`BackendGroup::hash_by`]) before calling [`BackendGroup::select_upstream`];
    /// selection falls back to round-robin when the attribute value is unavailable
    /// at request time. Folding the source into the variant makes "hash without a
    /// source" and "source without hash" unrepresentable (#397).
    Hash(HashSource),
}

/// Deterministic FNV-1a hash of a byte slice.
///
/// Used for both the per-endpoint affinity token ([`affinity_token`]) and the
/// header-mode affinity key (over the request header's value). Chosen over
/// `std::hash::DefaultHasher` precisely because its output is stable across process
/// restarts and crate versions — a cookie minted by one replica must resolve on
/// another, and a header value must map to the same endpoint every time.
#[must_use]
pub fn affinity_hash(bytes: &[u8]) -> u64 {
    affinity_hash_parts(&[bytes])
}

/// Deterministic FNV-1a hash over the concatenation of `parts`, without allocating
/// a joined buffer.
///
/// Hashing `[a, b, c]` yields exactly the same value as [`affinity_hash`] over
/// `a ++ b ++ c`, because FNV-1a is a left-to-right byte fold. This lets the proxy
/// hash `path + "?" + query` as the consistent-hash key with no intermediate
/// `String` on the request path (#397).
#[must_use]
pub fn affinity_hash_parts(parts: &[&[u8]]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for part in parts {
        for &b in *part {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}

/// Stable per-endpoint affinity token: the [`affinity_hash`] of the address (a family
/// tag plus IP octets plus port).
///
/// Cookie mode renders this as hex into the `Set-Cookie` value and parses it back to
/// locate the pinned endpoint. Distinct endpoints (differing IP or port) hash to
/// distinct tokens; the same endpoint always hashes the same. No heap allocation — the
/// byte sequence is assembled on the stack.
#[must_use]
pub fn affinity_token(addr: SocketAddr) -> u64 {
    // 1 family tag + up to 16 IPv6 octets + 2 port bytes.
    let mut buf = [0u8; 19];
    let mut len = 0;
    let mut push = |b: u8| {
        buf[len] = b;
        len += 1;
    };
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            push(4);
            for b in v4.octets() {
                push(b);
            }
        }
        std::net::IpAddr::V6(v6) => {
            push(6);
            for b in v6.octets() {
                push(b);
            }
        }
    }
    for b in addr.port().to_be_bytes() {
        push(b);
    }
    affinity_hash(&buf[..len])
}

/// One pooled endpoint indexed for affinity lookup: its address, its stable token, and
/// the index of the backend pool it belongs to (to recover that backend's per-backend
/// filters on a pinned selection).
#[derive(Clone, Copy)]
struct AffinityEndpoint {
    addr: SocketAddr,
    token: u64,
    backend_idx: u16,
}

/// Per-endpoint accounting state for non-`RoundRobin` algorithms.
///
/// Built once in [`BackendGroup::with_load_balance`]; all fields are atomics so
/// the hot-path read + update is lock-free and never holds a guard across `.await`.
struct LbEndpoint {
    addr: SocketAddr,
    /// Owning backend pool index — used to recover per-backend filters from
    /// [`BackendGroup::per_backend_filters`], matching the layout of [`AffinityEndpoint`].
    backend_idx: u16,
    /// Stable endpoint token (`affinity_token(addr)`) for rendezvous scoring in `Hash` mode.
    /// Populated for all non-`RoundRobin` algorithms; ignored by `LeastConn` and `Ewma`.
    token: u64,
    /// Active in-flight request count (incremented on selection, decremented on completion/release).
    active: AtomicU32,
    /// Smoothed response latency in nanoseconds (`0` = never sampled).
    ewma_ns: AtomicU64,
}

/// Result of [`BackendGroup::select_upstream`]: the chosen endpoint, any per-backend
/// filters, and an optional tracking index for `LeastConn`/`Ewma` accounting.
#[non_exhaustive]
pub struct Selected {
    /// Pod address to connect to.
    pub addr: SocketAddr,
    /// Per-backend filters attached to this specific backend ref, if any.
    pub filters: Option<Arc<[FilterAction]>>,
    /// Flat index into the `lb_endpoints` slice for post-request accounting.
    ///
    /// `None` for `RoundRobin` and `Hash` (stateless algorithms). When `Some`,
    /// the proxy must call [`BackendGroup::release`] (on a retriable failure, before
    /// re-selecting) or [`BackendGroup::complete`] (at request end) exactly once to
    /// keep counters balanced.
    pub track: Option<u32>,
}

/// One backend service's resolved pod endpoints with a round-robin counter.
struct BackendPool {
    addrs: Box<[SocketAddr]>,
    rr: AtomicUsize,
}

impl BackendPool {
    fn new(addrs: Vec<SocketAddr>) -> Self {
        assert!(
            !addrs.is_empty(),
            "BackendPool requires at least one address"
        );
        Self {
            addrs: addrs.into_boxed_slice(),
            rr: AtomicUsize::new(0),
        }
    }

    fn next(&self) -> SocketAddr {
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.addrs.len();
        self.addrs[idx]
    }
}

/// Per-backend filter slot: `None` for backends without filters (the common
/// case); `Some(Arc<[FilterAction]>)` shares the slice cheaply with each
/// request that selects this backend.
type PerBackendFilterSlot = Option<Arc<[FilterAction]>>;

/// A named group of pod endpoints with two-level weighted round-robin selection.
///
/// Level 1 — backend selection: a GCD-reduced slot array maps request indices to
/// one of the backend pools proportional to their weights.
/// Level 2 — pod selection: within the chosen pool, a per-pool atomic counter
/// does fair round-robin across that backend's pods.
///
/// This gives exact per-backend traffic ratios regardless of pod count, and fair
/// pod distribution within each backend.
#[non_exhaustive]
pub struct BackendGroup {
    /// Service identity — used for logging only.
    name: String,
    /// Original construction inputs — retained for wire-DTO serialisation.
    ///
    /// Preserved behind an `Arc` so the discovery wire layer can round-trip the
    /// per-backend (addresses, weight) grouping, which is otherwise flattened and
    /// GCD-reduced during construction. Never read on the request hot path.
    spec: Arc<BackendGroupSpec>,
    /// One entry per non-zero-weight backend ref.
    backends: Box<[BackendPool]>,
    /// Slot array: each entry is an index into `backends`.
    /// Length = Σ(weight_i after GCD reduction).
    slots: Box<[u16]>,
    /// Advances monotonically; taken mod `slots.len()` on each request.
    slot_counter: AtomicUsize,
    /// Flat snapshot of all pod addresses for the admin `/api/v1/routes` endpoint.
    addrs_snapshot: Box<[SocketAddr]>,
    /// Wire protocol for upstream connections, derived from `appProtocol`.
    protocol: BackendProtocol,
    /// TLS configuration from an attached `BackendTLSPolicy`.
    /// When `Some`, the proxy uses these settings instead of `protocol`-derived defaults.
    tls: Option<Arc<UpstreamTls>>,
    /// Upstream retry policy from the Ingress `max-retries` / `retry-on` annotations.
    /// Default (disabled) for Gateway API routes and Ingresses without the annotations.
    retry: RetryPolicy,
    /// Per-backend request filters from `HTTPRoute.spec.rules[].backendRefs[].filters`.
    /// Index-aligned with `backends`. `None` for the common case where no backend
    /// declares per-backend filters; when `Some`, each slot is `None` for backends
    /// without filters and `Some(filters)` otherwise. Applied AFTER rule-level
    /// filters in the proxy's `upstream_request_filter` hook.
    per_backend_filters: Option<Box<[PerBackendFilterSlot]>>,
    /// Sticky-session configuration; `None` (the common case) means plain weighted
    /// round-robin. Set from the Ingress `session-*` annotations.
    session_affinity: Option<SessionAffinity>,
    /// Flat affinity lookup index over every pooled endpoint, built once in
    /// [`BackendGroup::with_session_affinity`]. `None` when affinity is off (zero
    /// overhead). Carries each endpoint's stable token and owning backend index so a
    /// pinned selection can recover the right per-backend filters.
    affinity_endpoints: Option<Box<[AffinityEndpoint]>>,
    /// How long an idle upstream connection stays in Pingora's keepalive pool before
    /// being evicted, from the Ingress
    /// `ingress.coxswain-labs.dev/upstream-keepalive-timeout` annotation.
    ///
    /// `None` (the default, or an invalid/absent annotation) defers to Pingora's
    /// built-in behaviour: connections remain in the pool until the pool's LRU
    /// capacity is exhausted. Populated from the Ingress
    /// `upstream-keepalive-timeout` annotation or, for Gateway API routes, the
    /// `CoxswainBackendPolicy` `spec.timeouts.idle` field (#354). Applied
    /// per-request in `upstream_peer` via `HttpPeer.options.idle_timeout`.
    keepalive_timeout: Option<std::time::Duration>,
    /// Upstream TCP-connect timeout for this backend, from a `CoxswainBackendPolicy`
    /// `spec.timeouts.connect` field attached to the target `Service` (#354).
    ///
    /// `None` (the default) defers to the per-route connect timeout (Ingress
    /// `connect-timeout` annotation) or, failing that, the Gateway API
    /// `backendRequest` budget. When `Some`, the proxy applies it to
    /// `HttpPeer.options.connection_timeout` in `upstream_peer`, after any
    /// route-level connect override but before the `backendRequest` fallback.
    connect_timeout: Option<std::time::Duration>,
    /// Per-route upstream load-balancing algorithm from the
    /// `ingress.coxswain-labs.dev/load-balance` annotation.
    ///
    /// `RoundRobin` (the default) delegates to the existing weighted slot array;
    /// any other value activates [`Self::lb_endpoints`] for per-request selection.
    /// `Hash` carries its [`HashSource`] inline (#397) — the proxy reads it via
    /// [`BackendGroup::hash_by`] to pick the request attribute to hash.
    load_balance: LoadBalance,
    /// Per-endpoint accounting index for non-`RoundRobin` algorithms.
    ///
    /// `None` when `load_balance == RoundRobin` (zero overhead on the hot path).
    /// Built by [`BackendGroup::with_load_balance`]; covers every pooled address
    /// with its owning backend index, stable token, active-connection counter, and EWMA latency.
    lb_endpoints: Option<Box<[LbEndpoint]>>,
}

/// Manual `Debug` implementation that avoids the `FilterAction` ↔ `BackendGroup` cycle.
///
/// `per_backend_filters` contains `Arc<[FilterAction]>` slices; `FilterAction::Mirror`
/// embeds `Arc<BackendGroup>` — making these types mutually recursive. Deriving `Debug`
/// on either would require the other to implement `Debug` first, creating a compile-time
/// cycle. The manual impl below shows the identifying fields (`name`, endpoint count)
/// without recursing into `per_backend_filters`, breaking the cycle.
impl std::fmt::Debug for BackendGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendGroup")
            .field("name", &self.name)
            .field("endpoints", &self.addrs_snapshot.len())
            .field("backends", &self.backends.len())
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl BackendGroup {
    /// All endpoints with equal weight (weight-1 uniform round-robin).
    /// Used by Ingress reconciler and single-backend Gateway API rules.
    pub fn new(name: String, endpoints: Vec<SocketAddr>) -> Self {
        if endpoints.is_empty() {
            return Self::empty(name);
        }
        let spec = Arc::new(BackendGroupSpec {
            weighted: Box::new([(endpoints.clone().into_boxed_slice(), 1u16)]),
        });
        let addrs_snapshot = endpoints.clone().into_boxed_slice();
        let slots = vec![0u16].into_boxed_slice();
        let backends = Box::new([BackendPool::new(endpoints)]);
        Self {
            name,
            spec,
            backends,
            slots,
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot,
            protocol: BackendProtocol::default(),
            tls: None,
            retry: RetryPolicy::default(),
            per_backend_filters: None,
            session_affinity: None,
            affinity_endpoints: None,
            keepalive_timeout: None,
            connect_timeout: None,
            load_balance: LoadBalance::default(),
            lb_endpoints: None,
        }
    }

    /// Weighted constructor for multi-backend Gateway API rules.
    ///
    /// `weighted` is `[(pod_addrs_for_backend, weight), ...]` — one entry per
    /// `backendRef`. Backends with `weight == 0` or empty address lists are
    /// dropped. Returns an empty `BackendGroup` when all weights resolve to zero.
    pub fn weighted(name: String, weighted: Vec<(Vec<SocketAddr>, u16)>) -> Self {
        let pools: Vec<(Vec<SocketAddr>, u16)> = weighted
            .into_iter()
            .filter(|(addrs, w)| *w > 0 && !addrs.is_empty())
            .collect();

        if pools.is_empty() {
            return Self::empty(name);
        }

        // Capture spec BEFORE GCD reduction so original weights are preserved.
        let spec = Arc::new(BackendGroupSpec {
            weighted: pools
                .iter()
                .map(|(addrs, w)| (addrs.clone().into_boxed_slice(), *w))
                .collect(),
        });

        let weights: Vec<u16> = pools.iter().map(|(_, w)| *w).collect();
        let reduced = gcd_reduce(&weights);

        let mut slots: Vec<u16> = Vec::with_capacity(reduced.iter().map(|&w| w as usize).sum());
        for (idx, &w) in reduced.iter().enumerate() {
            for _ in 0..w {
                slots.push(idx as u16);
            }
        }

        let addrs_snapshot: Box<[SocketAddr]> = pools
            .iter()
            .flat_map(|(addrs, _)| addrs.iter().copied())
            .collect();

        let backends: Box<[BackendPool]> = pools
            .into_iter()
            .map(|(addrs, _)| BackendPool::new(addrs))
            .collect();

        Self {
            name,
            spec,
            backends,
            slots: slots.into_boxed_slice(),
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot,
            protocol: BackendProtocol::default(),
            tls: None,
            retry: RetryPolicy::default(),
            per_backend_filters: None,
            session_affinity: None,
            affinity_endpoints: None,
            keepalive_timeout: None,
            connect_timeout: None,
            load_balance: LoadBalance::default(),
            lb_endpoints: None,
        }
    }

    fn empty(name: String) -> Self {
        Self {
            name,
            spec: Arc::new(BackendGroupSpec {
                weighted: Box::new([]),
            }),
            backends: Box::new([]),
            slots: Box::new([]),
            slot_counter: AtomicUsize::new(0),
            addrs_snapshot: Box::new([]),
            protocol: BackendProtocol::default(),
            tls: None,
            retry: RetryPolicy::default(),
            per_backend_filters: None,
            session_affinity: None,
            affinity_endpoints: None,
            keepalive_timeout: None,
            connect_timeout: None,
            load_balance: LoadBalance::default(),
            lb_endpoints: None,
        }
    }

    /// Set the upstream transport protocol (builder-style).
    #[must_use]
    pub fn with_protocol(mut self, protocol: BackendProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Attach a `BackendTLSPolicy`-derived TLS configuration (builder-style).
    ///
    /// When set, the proxy uses `tls.sni` for SNI and `tls.ca` for upstream cert
    /// verification, overriding `appProtocol`-based TLS defaults.
    #[must_use]
    pub fn with_tls(mut self, tls: Arc<UpstreamTls>) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Attach an upstream retry policy (builder-style).
    ///
    /// Parsed from the Ingress `ingress.coxswain-labs.dev/max-retries` and
    /// `ingress.coxswain-labs.dev/retry-on` annotations. Gateway API routes and
    /// Ingresses without the annotations leave this as the default (disabled) policy.
    #[must_use]
    pub fn with_retries(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Set the upstream keepalive idle timeout (builder-style).
    ///
    /// Parsed from the Ingress
    /// `ingress.coxswain-labs.dev/upstream-keepalive-timeout` annotation.
    /// `None` (the default, or when the annotation is absent or invalid) leaves
    /// Pingora's built-in keepalive behaviour unchanged — connections stay in the
    /// pool until the global LRU capacity forces eviction.
    ///
    /// Gateway API routes always leave this `None`; the annotation is Ingress-only.
    #[must_use]
    pub fn with_keepalive_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.keepalive_timeout = timeout;
        self
    }

    /// Set the upstream TCP-connect timeout (builder-style).
    ///
    /// Populated from a `CoxswainBackendPolicy` `spec.timeouts.connect` field
    /// attached to the target `Service` (#354). `None` (the default) leaves the
    /// connect timeout to the per-route override or the `backendRequest` budget;
    /// see [`Self::connect_timeout`] for the proxy-side precedence.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the upstream load-balancing algorithm (builder-style).
    ///
    /// Builds the per-endpoint accounting index when `lb != RoundRobin`. Call
    /// after the constructor (and, if used, after [`Self::with_per_backend_filters`]);
    /// the index records backend indices so filter recovery reads `per_backend_filters`
    /// at lookup time. Gateway API routes always keep the default `RoundRobin`.
    /// `Hash` carries its key attribute ([`HashSource`]) inline (#397).
    #[must_use]
    pub fn with_load_balance(mut self, lb: LoadBalance) -> Self {
        let is_round_robin = matches!(lb, LoadBalance::RoundRobin);
        self.load_balance = lb;
        if is_round_robin {
            self.lb_endpoints = None;
            return self;
        }
        let mut index = Vec::with_capacity(self.addrs_snapshot.len());
        for (backend_idx, pool) in self.backends.iter().enumerate() {
            for &addr in &*pool.addrs {
                index.push(LbEndpoint {
                    addr,
                    // backend count is bounded by backendRefs (<= a handful);
                    // the cast is lossless in every realistic configuration.
                    backend_idx: backend_idx as u16,
                    token: affinity_token(addr),
                    active: AtomicU32::new(0),
                    ewma_ns: AtomicU64::new(0),
                });
            }
        }
        self.lb_endpoints = if index.is_empty() {
            None
        } else {
            Some(index.into_boxed_slice())
        };
        self
    }

    /// The consistent-hash attribute configured for this group, if any.
    ///
    /// Derived from [`LoadBalance::Hash`]'s carried [`HashSource`] (#397); `None` for
    /// every other algorithm. The proxy reads this in `request_filter` to determine
    /// which request attribute to extract and hash before calling
    /// [`Self::select_upstream`].
    pub fn hash_by(&self) -> Option<&HashSource> {
        match &self.load_balance {
            LoadBalance::Hash(source) => Some(source),
            _ => None,
        }
    }

    /// Attach per-backend `RequestHeaderModifier` filter actions (builder-style).
    ///
    /// `per_backend` is index-aligned with the constructor's backendRefs list — one
    /// entry per non-zero-weight backend ref. An empty `Vec<FilterAction>` for a
    /// backend is normalised to `None` so the proxy can short-circuit the common
    /// no-filter case. Constructor side-effects:
    /// - When every entry normalises to `None`, the whole `per_backend_filters`
    ///   field stays `None` (no allocation, no proxy-side overhead).
    /// - When at least one entry is non-empty, the full per-backend slice is
    ///   stored so `next_endpoint_with_filters` can return it.
    ///
    /// Length of `per_backend` MUST match `self.backends.len()` — supplied by the
    /// reconciler from the same `weighted` list that built the backend pools.
    /// Mismatch panics in debug builds and is silently ignored in release.
    #[must_use]
    pub fn with_per_backend_filters(mut self, per_backend: Vec<Vec<FilterAction>>) -> Self {
        debug_assert_eq!(
            per_backend.len(),
            self.backends.len(),
            "per-backend filter list must match the number of pooled backends"
        );
        if per_backend.len() != self.backends.len() {
            return self;
        }
        let any_set = per_backend.iter().any(|f| !f.is_empty());
        if !any_set {
            self.per_backend_filters = None;
            return self;
        }
        let normalised: Box<[Option<Arc<[FilterAction]>>]> = per_backend
            .into_iter()
            .map(|f| {
                if f.is_empty() {
                    None
                } else {
                    Some(Arc::from(f.into_boxed_slice()))
                }
            })
            .collect();
        self.per_backend_filters = Some(normalised);
        self
    }

    /// Attach sticky-session configuration (builder-style).
    ///
    /// `None` leaves the group on plain weighted round-robin (zero overhead). When
    /// `Some`, a flat affinity index is precomputed over every currently-pooled
    /// endpoint so the proxy's per-request token/hash lookups never touch the backend
    /// pools' atomics. Call after the constructor (and, if used, after
    /// [`Self::with_per_backend_filters`]); the index records backend indices, so
    /// filter recovery reads the latest `per_backend_filters` at lookup time.
    #[must_use]
    pub fn with_session_affinity(mut self, affinity: Option<SessionAffinity>) -> Self {
        match affinity {
            None => {
                self.session_affinity = None;
                self.affinity_endpoints = None;
            }
            Some(cfg) => {
                let mut index = Vec::with_capacity(self.addrs_snapshot.len());
                for (backend_idx, pool) in self.backends.iter().enumerate() {
                    for &addr in &*pool.addrs {
                        index.push(AffinityEndpoint {
                            addr,
                            token: affinity_token(addr),
                            // backend count is bounded by backendRefs (<= a handful);
                            // the cast is lossless in every realistic configuration.
                            backend_idx: backend_idx as u16,
                        });
                    }
                }
                self.session_affinity = Some(cfg);
                self.affinity_endpoints = Some(index.into_boxed_slice());
            }
        }
        self
    }

    /// Per-backend filters attached to `backend_idx`, mirroring the lookup in
    /// [`Self::next_endpoint_with_filters`]. `None` when no filters apply.
    fn filters_for_backend(&self, backend_idx: usize) -> Option<Arc<[FilterAction]>> {
        self.per_backend_filters
            .as_ref()
            .and_then(|all| all.get(backend_idx).cloned().flatten())
    }

    /// Sticky-session configuration for this group, if any.
    pub fn session_affinity(&self) -> Option<&SessionAffinity> {
        self.session_affinity.as_ref()
    }

    /// Resolve a cookie-mode affinity token to its pinned endpoint.
    ///
    /// Returns the endpoint and its per-backend filters when `token` still matches a
    /// live endpoint. `None` means the pinned pod was removed/scaled away — the proxy
    /// then falls back to round-robin and re-establishes affinity. Affinity is off
    /// when no index was built, which also yields `None`.
    #[must_use]
    pub fn endpoint_by_token(
        &self,
        token: u64,
    ) -> Option<(SocketAddr, Option<Arc<[FilterAction]>>)> {
        let index = self.affinity_endpoints.as_ref()?;
        // Endpoint counts are small (pods of one Service); a linear scan beats a map's
        // allocation and indirection and stays cache-friendly.
        index
            .iter()
            .find(|e| e.token == token)
            .map(|e| (e.addr, self.filters_for_backend(e.backend_idx as usize)))
    }

    /// Resolve a header-mode affinity key to an endpoint via rendezvous hashing.
    ///
    /// Each live endpoint is scored by mixing `key_hash` with its stable token; the
    /// highest score wins. Rendezvous (HRW) hashing keeps the same key on the same
    /// endpoint as long as that endpoint exists, and re-maps only the affected keys
    /// when an endpoint joins or leaves. `None` when affinity is off or the group has
    /// no endpoints.
    #[must_use]
    pub fn endpoint_by_hash(
        &self,
        key_hash: u64,
    ) -> Option<(SocketAddr, Option<Arc<[FilterAction]>>)> {
        let index = self.affinity_endpoints.as_ref()?;
        index
            .iter()
            .max_by_key(|e| rendezvous_score(key_hash, e.token))
            .map(|e| (e.addr, self.filters_for_backend(e.backend_idx as usize)))
    }

    /// Per-backend filters for a specific pinned endpoint address.
    ///
    /// Used by the proxy when honoring a session-affinity pin in `upstream_peer`: the
    /// pin carries only the address, so this recovers the owning backend's filters the
    /// same way [`Self::next_endpoint_with_filters`] would have. `None` when the
    /// address has no affinity index entry or its backend declares no filters.
    #[must_use]
    pub fn filters_for_endpoint(&self, addr: SocketAddr) -> Option<Arc<[FilterAction]>> {
        let index = self.affinity_endpoints.as_ref()?;
        index
            .iter()
            .find(|e| e.addr == addr)
            .and_then(|e| self.filters_for_backend(e.backend_idx as usize))
    }

    /// Service identity used for logging.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wire protocol for upstream connections.
    pub fn protocol(&self) -> BackendProtocol {
        self.protocol
    }

    /// TLS configuration from an attached `BackendTLSPolicy`, if any.
    pub fn upstream_tls(&self) -> Option<&Arc<UpstreamTls>> {
        self.tls.as_ref()
    }

    /// Upstream retry policy for this backend group.
    ///
    /// Returns the default (disabled) policy for Gateway API routes and
    /// Ingresses that do not carry the `ingress.coxswain-labs.dev/max-retries` /
    /// `retry-on` annotations.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// Upstream keepalive idle timeout from the
    /// `ingress.coxswain-labs.dev/upstream-keepalive-timeout` annotation, if any.
    ///
    /// `None` means "use Pingora's default" (connections stay in the LRU pool until
    /// evicted by capacity pressure). The proxy applies this to
    /// `HttpPeer.options.idle_timeout` in `upstream_peer`.
    pub fn keepalive_timeout(&self) -> Option<std::time::Duration> {
        self.keepalive_timeout
    }

    /// Upstream TCP-connect timeout from an attached `CoxswainBackendPolicy`
    /// `spec.timeouts.connect`, if any (#354).
    ///
    /// `None` means "no per-backend connect override" — the proxy falls back to
    /// the per-route Ingress `connect-timeout` or the Gateway API `backendRequest`
    /// budget. When `Some`, the proxy applies it to
    /// `HttpPeer.options.connection_timeout` in `upstream_peer`, taking precedence
    /// over the `backendRequest` fallback but not over an explicit route-level
    /// connect override.
    pub fn connect_timeout(&self) -> Option<std::time::Duration> {
        self.connect_timeout
    }

    /// The original construction inputs to this group, for wire-DTO serialisation.
    ///
    /// Contains the per-backend (endpoint-addresses, weight) list as passed to
    /// [`Self::new`] or [`Self::weighted`] (with zero-weight and empty backends
    /// already filtered out).  The discovery wire layer uses this to faithfully
    /// round-trip the backend configuration, since weights are GCD-reduced and
    /// per-backend grouping is flattened in the runtime selection structures.
    pub fn spec(&self) -> &BackendGroupSpec {
        &self.spec
    }

    /// The upstream load-balancing algorithm for this group.
    ///
    /// Used by the discovery wire layer to serialise and reconstruct the
    /// `ingress.coxswain-labs.dev/load-balance` annotation value. Only
    /// [`LoadBalance::Hash`]'s [`HashSource`] was previously exposed via
    /// [`Self::hash_by`]; this getter surfaces the full discriminant.
    pub fn load_balance(&self) -> &LoadBalance {
        &self.load_balance
    }

    /// Per-backend request filters attached to this group, if any.
    ///
    /// Returns `None` when no per-backend filters were configured (the common case).
    /// When `Some`, the slice is index-aligned with [`BackendGroupSpec::weighted`] —
    /// `None` slots are backends without filters; `Some(arc)` shares the filter list
    /// cheaply with each selection. Used by the discovery wire layer to serialise
    /// `HTTPRoute.spec.rules[].backendRefs[].filters`.
    ///
    /// # Errors (construction)
    ///
    /// Empty is normalised to `None` in [`Self::with_per_backend_filters`]; if all
    /// backends had empty filter lists this returns `None`, not `Some([None, None, …])`.
    pub fn per_backend_filters(&self) -> Option<&[Option<Arc<[FilterAction]>>]> {
        self.per_backend_filters.as_deref()
    }

    /// Flat list of all pod addresses — used by the admin `/api/v1/routes` endpoint.
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.addrs_snapshot
    }

    /// Returns the next endpoint using weighted round-robin.
    ///
    /// Returns `None` when there are no active endpoints.
    #[must_use]
    pub fn next_endpoint(&self) -> Option<SocketAddr> {
        self.next_endpoint_with_filters().map(|(addr, _)| addr)
    }

    /// Returns the next endpoint AND any per-backend filters attached to that
    /// specific backend ref.
    ///
    /// The filter slice is `None` when no per-backend filters were configured for
    /// the rule (the common case — single round-robin tick, no extra indirection)
    /// OR when the specific backend that won this round has no filters of its own.
    /// The proxy applies the returned filters in `upstream_request_filter` after
    /// the rule-level filters from `RouteEntry::filters`.
    #[must_use]
    pub fn next_endpoint_with_filters(&self) -> Option<(SocketAddr, Option<Arc<[FilterAction]>>)> {
        if self.slots.is_empty() {
            return None;
        }
        let slot = self.slot_counter.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let backend_idx = self.slots[slot] as usize;
        let pool = &self.backends[backend_idx];
        let filters = self
            .per_backend_filters
            .as_ref()
            .and_then(|all| all.get(backend_idx).cloned().flatten());
        Some((pool.next(), filters))
    }

    /// Select the next upstream endpoint using the configured load-balancing algorithm.
    ///
    /// `hash_key` is the pre-computed FNV-1a hash of the request attribute for `Hash`
    /// mode — extracted and hashed by the proxy (see `ctx.hash_key`) before this call.
    /// All other algorithms ignore it. Returns `None` when the group has no endpoints.
    ///
    /// Callers that receive a `Selected` with `track: Some(idx)` MUST call either
    /// [`Self::release`] (before re-selecting on a retry) or [`Self::complete`] (at
    /// request end) exactly once; this keeps `LeastConn` and `Ewma` counters balanced.
    #[must_use]
    pub fn select_upstream(&self, hash_key: Option<u64>) -> Option<Selected> {
        match &self.load_balance {
            LoadBalance::RoundRobin => {
                let (addr, filters) = self.next_endpoint_with_filters()?;
                Some(Selected {
                    addr,
                    filters,
                    track: None,
                })
            }
            LoadBalance::Hash(_) => {
                let eps = self.lb_endpoints.as_deref()?;
                let Some(key) = hash_key else {
                    // Key unavailable (attribute absent/empty): fall back to round-robin.
                    let (addr, filters) = self.next_endpoint_with_filters()?;
                    return Some(Selected {
                        addr,
                        filters,
                        track: None,
                    });
                };
                // Rendezvous (HRW): score each endpoint by mixing key with its stable
                // token; the highest score wins. Only keys whose owner was removed
                // remap on endpoint changes — no full reshuffling.
                let ep = eps.iter().max_by_key(|e| rendezvous_score(key, e.token))?;
                let filters = self.filters_for_backend(ep.backend_idx as usize);
                Some(Selected {
                    addr: ep.addr,
                    filters,
                    track: None,
                })
            }
            LoadBalance::LeastConn => {
                let eps = self.lb_endpoints.as_deref()?;
                // Linear scan for minimum active count; ties break by index order
                // (natural pool order — deterministic, no allocation).
                let (idx, _) = eps
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.active.load(Ordering::Relaxed))?;
                let ep = &eps[idx];
                ep.active.fetch_add(1, Ordering::Relaxed);
                let filters = self.filters_for_backend(ep.backend_idx as usize);
                Some(Selected {
                    addr: ep.addr,
                    filters,
                    track: Some(idx as u32),
                })
            }
            LoadBalance::Ewma => {
                let eps = self.lb_endpoints.as_deref()?;
                // `0` (never sampled) sorts first so new/idle endpoints are probed
                // before stale estimates from prior traffic.
                let (idx, _) = eps
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.ewma_ns.load(Ordering::Relaxed))?;
                let ep = &eps[idx];
                let filters = self.filters_for_backend(ep.backend_idx as usize);
                Some(Selected {
                    addr: ep.addr,
                    filters,
                    track: Some(idx as u32),
                })
            }
        }
    }

    /// Undo in-flight accounting for a prior [`Self::select_upstream`] call.
    ///
    /// Called on a retriable failure before re-invoking `select_upstream` for the
    /// retry attempt. `idx` is the `Selected::track` value from the call being
    /// released. No-op for `RoundRobin` and `Hash` (where `track` is always `None`).
    pub fn release(&self, idx: u32) {
        let eps = match self.lb_endpoints.as_deref() {
            Some(e) => e,
            None => return,
        };
        if let Some(ep) = eps.get(idx as usize)
            && matches!(self.load_balance, LoadBalance::LeastConn)
        {
            ep.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Record the completion of a request selected by [`Self::select_upstream`].
    ///
    /// - `LeastConn`: decrements the active-connection counter.
    /// - `Ewma`: folds `elapsed` into the endpoint's smoothed latency
    ///   (`α = 1/8`; `new = if old==0 { sample } else { old − old/8 + sample/8 }`).
    ///   A `None` elapsed is ignored (no update).
    /// - `RoundRobin`/`Hash`: no-op (`track` is always `None` for these algorithms).
    ///
    /// `idx` must be the `Selected::track` value from the original selection and must
    /// be called exactly once per tracked selection to keep counters balanced.
    pub fn complete(&self, idx: u32, elapsed: Option<Duration>) {
        let eps = match self.lb_endpoints.as_deref() {
            Some(e) => e,
            None => return,
        };
        let ep = match eps.get(idx as usize) {
            Some(e) => e,
            None => return,
        };
        match &self.load_balance {
            LoadBalance::LeastConn => {
                ep.active.fetch_sub(1, Ordering::Relaxed);
            }
            LoadBalance::Ewma => {
                if let Some(d) = elapsed {
                    let sample = d.as_nanos().min(u64::MAX as u128) as u64;
                    let old = ep.ewma_ns.load(Ordering::Relaxed);
                    let new = if old == 0 {
                        sample
                    } else {
                        old.saturating_sub(old / 8).saturating_add(sample / 8)
                    };
                    ep.ewma_ns.store(new, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }
}

/// Reduce a slice of weights by their GCD so the slot array stays compact.
fn gcd_reduce(weights: &[u16]) -> Vec<u16> {
    let g = weights.iter().copied().fold(0u16, gcd);
    if g <= 1 {
        weights.to_vec()
    } else {
        weights.iter().map(|&w| w / g).collect()
    }
}

fn gcd(a: u16, b: u16) -> u16 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Rendezvous (HRW) score for a `(key, endpoint-token)` pair.
///
/// Combines the two with a SplitMix64 finalizer so the ordering of scores is well
/// distributed (a plain XOR would bias toward tokens that share high bits with the
/// key). The endpoint with the maximum score owns the key.
fn rendezvous_score(key_hash: u64, token: u64) -> u64 {
    let mut z = key_hash ^ token.rotate_left(32);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

// Hot type — review with the team before bumping this number.
static_assertions::assert_eq_size!(BackendPool, [u8; 24]);

#[cfg(test)]
mod tests {
    use super::super::entry::{ForwardedForConfig, RouteEntry};
    use super::super::filters::HeaderMod;
    use super::super::upstream_tls::UpstreamCa;
    use super::*;
    use http::HeaderValue;
    use std::net::SocketAddr;

    // ── BackendGroup round-robin tests ────────────────────────────────────────────

    #[test]
    fn round_robin_cycles() {
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            "10.0.0.3:80".parse().unwrap(),
        ];
        let up = BackendGroup::new("svc".to_string(), addrs.clone());
        let results: Vec<SocketAddr> = (0..6).map(|_| up.next_endpoint().unwrap()).collect();
        assert_eq!(
            results,
            [addrs[0], addrs[1], addrs[2], addrs[0], addrs[1], addrs[2]]
        );
    }

    #[test]
    fn weighted_round_robin_distributes_proportionally() {
        let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:80".parse().unwrap();
        let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

        // Backend A: 2 pods, weight 4.  Backend B: 1 pod, weight 1.
        // Expected: P(A) = 4/5 = 80%.
        let up =
            BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1, a2], 4), (vec![b1], 1)]);

        let n = 1000;
        let mut a_count = 0usize;
        let mut b_count = 0usize;
        for _ in 0..n {
            let addr = up.next_endpoint().unwrap();
            if addr == a1 || addr == a2 {
                a_count += 1;
            } else if addr == b1 {
                b_count += 1;
            }
        }
        assert_eq!(a_count + b_count, n);
        // Allow ±5% tolerance around the expected 80/20 split.
        let a_ratio = a_count as f64 / n as f64;
        assert!(
            (0.75..=0.85).contains(&a_ratio),
            "backend A ratio {a_ratio:.2} out of expected 0.75–0.85"
        );
    }

    #[test]
    fn weighted_zero_weight_backend_gets_no_traffic() {
        let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

        let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 0), (vec![b1], 1)]);
        for _ in 0..100 {
            assert_eq!(up.next_endpoint().unwrap(), b1);
        }
    }

    #[test]
    fn weighted_all_zero_is_empty() {
        let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 0)]);
        assert!(up.next_endpoint().is_none());
    }

    #[test]
    fn weighted_equal_weights_uniform() {
        let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

        // Equal weights → after GCD reduction both get 1 slot → 50/50.
        let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 5), (vec![b1], 5)]);
        let results: Vec<SocketAddr> = (0..4).map(|_| up.next_endpoint().unwrap()).collect();
        // slots = [0, 1] after reduction; cycling: a1, b1, a1, b1
        assert_eq!(results, [a1, b1, a1, b1]);
    }

    // ── UpstreamTls / with_tls round-trip tests ───────────────────────────────────

    #[test]
    fn backend_group_with_tls_system_round_trip() {
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let sni: Arc<str> = Arc::from("backend.example.com");
        let tls = Arc::new(UpstreamTls::new(sni.clone(), UpstreamCa::System, 42));
        let group = BackendGroup::new("svc".to_string(), vec![addr]).with_tls(Arc::clone(&tls));

        let got = group.upstream_tls().expect("TLS should be attached");
        assert_eq!(&*got.sni, "backend.example.com");
        assert_eq!(got.group_key, 42);
        assert!(matches!(got.ca, UpstreamCa::System));
    }

    #[test]
    fn backend_group_with_tls_bundle_round_trip() {
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let pem: Arc<[u8]> = Arc::from(b"-----BEGIN CERTIFICATE-----\nfake\n".as_slice());
        let tls = Arc::new(UpstreamTls::new(
            Arc::from("backend.example.com"),
            UpstreamCa::Bundle(Arc::clone(&pem)),
            99,
        ));
        let group = BackendGroup::new("svc".to_string(), vec![addr]).with_tls(Arc::clone(&tls));

        let got = group.upstream_tls().expect("TLS should be attached");
        assert!(matches!(&got.ca, UpstreamCa::Bundle(p) if p.as_ref() == pem.as_ref()));
    }

    #[test]
    fn backend_group_without_tls_returns_none() {
        let addr: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let group = BackendGroup::new("svc".to_string(), vec![addr]);
        assert!(group.upstream_tls().is_none());
    }

    #[test]
    fn with_allow_source_range_round_trips() {
        let group = Arc::new(BackendGroup::new("ns/svc".to_string(), vec![]));
        let bare = RouteEntry::path_only(Arc::clone(&group), "ns/r".to_string(), None);
        assert!(bare.allow_source_range.is_none());

        let nets = Arc::new(vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]);
        let entry = RouteEntry::path_only(group, "ns/r".to_string(), None)
            .with_allow_source_range(Some(Arc::clone(&nets)));
        assert_eq!(entry.allow_source_range.as_deref(), Some(&*nets));
    }

    #[test]
    fn with_deny_source_range_round_trips() {
        let group = Arc::new(BackendGroup::new("ns/svc".to_string(), vec![]));
        let bare = RouteEntry::path_only(Arc::clone(&group), "ns/r".to_string(), None);
        assert!(bare.deny_source_range.is_none());

        let nets = Arc::new(vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]);
        let entry = RouteEntry::path_only(group, "ns/r".to_string(), None)
            .with_deny_source_range(Some(Arc::clone(&nets)));
        assert_eq!(entry.deny_source_range.as_deref(), Some(&*nets));
    }

    #[test]
    fn with_forwarded_for_round_trips() {
        let group = Arc::new(BackendGroup::new("ns/svc".to_string(), vec![]));
        let bare = RouteEntry::path_only(Arc::clone(&group), "ns/r".to_string(), None);
        assert!(bare.forwarded_for.is_none());

        let cfg = Arc::new(ForwardedForConfig::new(
            Box::from("X-Forwarded-For"),
            Box::from(["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()].as_slice()),
        ));
        let entry = RouteEntry::path_only(group, "ns/r".to_string(), None)
            .with_forwarded_for(Some(Arc::clone(&cfg)));
        assert_eq!(entry.forwarded_for.as_deref(), Some(cfg.as_ref()));
    }

    #[test]
    fn per_backend_filters_returned_with_selected_backend() {
        use crate::routing::{FilterAction, HeaderMod};
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:80".parse().unwrap();
        let hm_a = HeaderMod::parse(&[("x-backend", "a")], &[], &[]).unwrap();
        let hm_b = HeaderMod::parse(&[("x-backend", "b")], &[], &[]).unwrap();
        let group = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a], 1), (vec![b], 1)])
            .with_per_backend_filters(vec![
                vec![FilterAction::RequestHeaderModifier(hm_a)],
                vec![FilterAction::RequestHeaderModifier(hm_b)],
            ]);
        // Round-robin between the two equally-weighted backends. Every endpoint we
        // pick should carry the matching per-backend filter slice.
        let mut saw_a = false;
        let mut saw_b = false;
        for _ in 0..10 {
            let (addr, filters) = group.next_endpoint_with_filters().unwrap();
            let filters = filters.expect("per-backend filter slice must be attached");
            assert_eq!(filters.len(), 1);
            let expected_value = if addr == a { "a" } else { "b" };
            match &filters[0] {
                FilterAction::RequestHeaderModifier(hm) => {
                    let entry = hm
                        .add
                        .iter()
                        .find(|(name, _)| name == "x-backend")
                        .expect("x-backend header must be present");
                    assert_eq!(entry.1, expected_value);
                }
                other => panic!("unexpected filter action: {other:?}"),
            }
            saw_a |= addr == a;
            saw_b |= addr == b;
        }
        assert!(saw_a && saw_b, "both backends should have been selected");
    }

    #[test]
    fn per_backend_filters_all_empty_normalises_to_none() {
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let group = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a], 1)])
            .with_per_backend_filters(vec![vec![]]);
        let (_addr, filters) = group.next_endpoint_with_filters().unwrap();
        assert!(
            filters.is_none(),
            "empty per-backend filters must surface as None"
        );
    }

    #[test]
    fn next_endpoint_without_per_backend_filters_returns_none() {
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let group = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a], 1)]);
        let (_addr, filters) = group.next_endpoint_with_filters().unwrap();
        assert!(filters.is_none());
    }

    // ── Session affinity ──────────────────────────────────────────────────────────

    fn cookie_group(addrs: &[&str]) -> BackendGroup {
        let parsed: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        BackendGroup::new("ns/svc".to_string(), parsed).with_session_affinity(Some(
            SessionAffinity::Cookie {
                cookie_name: Arc::from("__coxswain_session"),
            },
        ))
    }

    #[test]
    fn affinity_token_is_deterministic_and_distinct_per_endpoint() {
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:80".parse().unwrap();
        // Stable across calls (the cookie must survive a process restart / rebuild).
        assert_eq!(affinity_token(a), affinity_token(a));
        // Distinct endpoints get distinct tokens (port/IP both fold in).
        assert_ne!(affinity_token(a), affinity_token(b));
        let a_alt_port: SocketAddr = "10.0.0.1:81".parse().unwrap();
        assert_ne!(affinity_token(a), affinity_token(a_alt_port));
    }

    #[test]
    fn endpoint_by_token_pins_to_the_matching_endpoint() {
        let group = cookie_group(&["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"]);
        let target: SocketAddr = "10.0.0.2:80".parse().unwrap();
        let (addr, _) = group
            .endpoint_by_token(affinity_token(target))
            .expect("token of a live endpoint must resolve");
        assert_eq!(addr, target);
    }

    #[test]
    fn endpoint_by_token_misses_when_pinned_pod_removed() {
        // A token for an endpoint that is no longer pooled (scaled away) must miss so
        // the proxy can fall back to round-robin and re-establish affinity.
        let group = cookie_group(&["10.0.0.1:80", "10.0.0.2:80"]);
        let gone: SocketAddr = "10.0.0.9:80".parse().unwrap();
        assert!(group.endpoint_by_token(affinity_token(gone)).is_none());
    }

    #[test]
    fn endpoint_by_token_is_none_without_affinity() {
        let group = BackendGroup::new("ns/svc".to_string(), vec!["10.0.0.1:80".parse().unwrap()]);
        assert!(group.session_affinity().is_none());
        assert!(group.endpoint_by_token(0).is_none());
    }

    #[test]
    fn endpoint_by_hash_is_stable_and_minimally_disrupted_on_removal() {
        let header_group = |addrs: &[&str]| {
            let parsed: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
            BackendGroup::new("ns/svc".to_string(), parsed).with_session_affinity(Some(
                SessionAffinity::Header {
                    header: HeaderName::from_static("x-session-id"),
                },
            ))
        };
        let full = header_group(&["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"]);
        // Same key → same endpoint across repeated lookups (consistent selection).
        let key = 0x1234_5678_9abc_def0u64;
        let first = full.endpoint_by_hash(key).unwrap().0;
        assert_eq!(full.endpoint_by_hash(key).unwrap().0, first);

        // Rendezvous hashing: keys whose owner is still present keep their owner when
        // an *unrelated* endpoint is removed. Find a key owned by .1, then drop .3.
        let owner_one: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let reduced = header_group(&["10.0.0.1:80", "10.0.0.2:80"]);
        let mut checked = 0;
        for k in 0..2_000u64 {
            if full.endpoint_by_hash(k).unwrap().0 == owner_one {
                assert_eq!(
                    reduced.endpoint_by_hash(k).unwrap().0,
                    owner_one,
                    "removing an unrelated endpoint must not re-map key {k} away from .1"
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "expected some keys to be owned by .1");
    }

    #[test]
    fn affinity_lookup_recovers_per_backend_filters() {
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b: SocketAddr = "10.0.1.1:80".parse().unwrap();
        let filter = FilterAction::RequestHeaderModifier(HeaderMod {
            add: vec![],
            set: vec![(
                HeaderName::from_static("x-backend"),
                HeaderValue::from_static("b"),
            )],
            remove: vec![],
        });
        // Two weighted backends; only the second carries a per-backend filter.
        let group = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a], 1), (vec![b], 1)])
            .with_per_backend_filters(vec![vec![], vec![filter]])
            .with_session_affinity(Some(SessionAffinity::Cookie {
                cookie_name: Arc::from("__coxswain_session"),
            }));
        // Pinning to `b` must surface b's filter; pinning to `a` must surface none.
        let (_, b_filters) = group.endpoint_by_token(affinity_token(b)).unwrap();
        assert!(
            b_filters.is_some(),
            "endpoint b carries a per-backend filter"
        );
        let (_, a_filters) = group.endpoint_by_token(affinity_token(a)).unwrap();
        assert!(a_filters.is_none(), "endpoint a has no per-backend filter");
    }

    // ── with_keepalive_timeout ────────────────────────────────────────────────────

    #[test]
    fn keepalive_timeout_default_is_none() {
        let group = BackendGroup::new("ns/svc".to_string(), vec![]);
        assert!(
            group.keepalive_timeout().is_none(),
            "no annotation → None (Pingora default)"
        );
    }

    #[test]
    fn with_keepalive_timeout_round_trips() {
        let t = std::time::Duration::from_secs(60);
        let group = BackendGroup::new("ns/svc".to_string(), vec![]).with_keepalive_timeout(Some(t));
        assert_eq!(
            group.keepalive_timeout(),
            Some(t),
            "with_keepalive_timeout should store and return the duration"
        );
    }

    #[test]
    fn with_keepalive_timeout_none_leaves_none() {
        let group = BackendGroup::new("ns/svc".to_string(), vec![]).with_keepalive_timeout(None);
        assert!(
            group.keepalive_timeout().is_none(),
            "with_keepalive_timeout(None) must leave the field None"
        );
    }

    // ── with_connect_timeout (#354) ───────────────────────────────────────────────

    #[test]
    fn connect_timeout_default_is_none() {
        let group = BackendGroup::new("ns/svc".to_string(), vec![]);
        assert!(
            group.connect_timeout().is_none(),
            "no CoxswainBackendPolicy → None (route/backendRequest fallback)"
        );
    }

    #[test]
    fn with_connect_timeout_round_trips() {
        let t = std::time::Duration::from_millis(500);
        let group = BackendGroup::new("ns/svc".to_string(), vec![]).with_connect_timeout(Some(t));
        assert_eq!(
            group.connect_timeout(),
            Some(t),
            "with_connect_timeout should store and return the duration"
        );
    }

    #[test]
    fn with_connect_timeout_none_leaves_none() {
        let group = BackendGroup::new("ns/svc".to_string(), vec![]).with_connect_timeout(None);
        assert!(
            group.connect_timeout().is_none(),
            "with_connect_timeout(None) must leave the field None"
        );
    }

    // ── LoadBalance / select_upstream ─────────────────────────────────────────────

    fn addrs(n: usize, base_port: u16) -> Vec<SocketAddr> {
        (0..n)
            .map(|i| {
                format!("127.0.0.1:{}", base_port + i as u16)
                    .parse()
                    .expect("valid addr")
            })
            .collect()
    }

    #[test]
    fn with_load_balance_round_robin_leaves_lb_endpoints_none() {
        let group = BackendGroup::new("test/svc".to_string(), addrs(3, 8000))
            .with_load_balance(LoadBalance::RoundRobin);
        // RoundRobin: no lb_endpoints index (zero overhead).
        assert!(group.lb_endpoints.is_none());
    }

    #[test]
    fn with_load_balance_non_rr_builds_lb_endpoints() {
        let group = BackendGroup::new("test/svc".to_string(), addrs(2, 9000))
            .with_load_balance(LoadBalance::LeastConn);
        let eps = group
            .lb_endpoints
            .as_deref()
            .expect("lb_endpoints built for LeastConn");
        assert_eq!(eps.len(), 2, "one entry per pooled address");
    }

    #[test]
    fn select_upstream_round_robin_returns_none_on_empty() {
        let group = BackendGroup::new("test/empty".to_string(), vec![])
            .with_load_balance(LoadBalance::RoundRobin);
        assert!(group.select_upstream(None).is_none());
    }

    // ── Hash / consistent-hash ────────────────────────────────────────────────

    fn hash_group(n: usize, base_port: u16) -> BackendGroup {
        BackendGroup::new("test/svc".to_string(), addrs(n, base_port))
            .with_load_balance(LoadBalance::Hash(HashSource::SourceIp))
    }

    fn ip_key(ip: &str) -> u64 {
        let parsed: std::net::IpAddr = ip.parse().expect("valid IP");
        match parsed {
            std::net::IpAddr::V4(v4) => affinity_hash(&v4.octets()),
            std::net::IpAddr::V6(v6) => affinity_hash(&v6.octets()),
        }
    }

    #[test]
    fn select_upstream_hash_is_stable_for_same_key() {
        let group = hash_group(3, 7000);
        let key = ip_key("10.0.0.1");
        let first = group.select_upstream(Some(key)).expect("Some").addr;
        for _ in 0..20 {
            assert_eq!(
                group.select_upstream(Some(key)).expect("Some").addr,
                first,
                "same hash key must always select the same endpoint (rendezvous HRW)"
            );
        }
    }

    #[test]
    fn select_upstream_hash_varies_across_keys() {
        let group = hash_group(4, 6000);
        let seen: std::collections::HashSet<SocketAddr> = (0u8..64)
            .filter_map(|i| {
                let key = ip_key(&format!("10.0.1.{i}"));
                group.select_upstream(Some(key)).map(|s| s.addr)
            })
            .collect();
        assert!(
            seen.len() > 1,
            "hash must distribute across multiple endpoints"
        );
    }

    #[test]
    fn select_upstream_hash_none_key_falls_back_to_rr() {
        let group = hash_group(2, 5000);
        // No key → must not panic; falls back to round-robin.
        assert!(group.select_upstream(None).is_some());
    }

    #[test]
    fn select_upstream_hash_is_minimally_disrupted_on_endpoint_removal() {
        let full_group = hash_group(3, 4100);
        let reduced_group = BackendGroup::new("test/svc".to_string(), addrs(2, 4100))
            .with_load_balance(LoadBalance::Hash(HashSource::SourceIp));
        // Keys whose owner survives must still map to the same endpoint.
        let survivor: SocketAddr = "127.0.0.1:4100".parse().unwrap();
        let mut checked = 0;
        for i in 0u8..200 {
            let key = ip_key(&format!("10.0.2.{i}"));
            if full_group.select_upstream(Some(key)).expect("Some").addr == survivor {
                assert_eq!(
                    reduced_group.select_upstream(Some(key)).expect("Some").addr,
                    survivor,
                    "rendezvous must not remap key {i} away from survivor when an unrelated endpoint is removed"
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "expected some keys to map to the survivor");
    }

    #[test]
    fn select_upstream_hash_no_track() {
        let group = hash_group(2, 4300);
        let key = affinity_hash(b"test-uri");
        let sel = group.select_upstream(Some(key)).expect("Some");
        assert!(
            sel.track.is_none(),
            "Hash selection is stateless; track must be None"
        );
    }

    #[test]
    fn select_upstream_least_conn_picks_min_active() {
        let group = BackendGroup::new("test/svc".to_string(), addrs(3, 4000))
            .with_load_balance(LoadBalance::LeastConn);
        let eps = group.lb_endpoints.as_deref().expect("built");
        // Pre-load endpoints 0 and 1 with artificial active counts.
        eps[0].active.store(5, Ordering::Relaxed);
        eps[1].active.store(3, Ordering::Relaxed);
        eps[2].active.store(0, Ordering::Relaxed);
        let sel = group.select_upstream(None).expect("Some");
        // Endpoint 2 has minimum active (0) — must win.
        assert_eq!(
            sel.addr, eps[2].addr,
            "least_conn picks endpoint with fewest actives"
        );
        assert_eq!(sel.track, Some(2), "track index must be 2");
        // Counter was incremented.
        assert_eq!(
            eps[2].active.load(Ordering::Relaxed),
            1,
            "active count incremented on selection"
        );
    }

    #[test]
    fn release_decrements_least_conn_active() {
        let group = BackendGroup::new("test/svc".to_string(), addrs(2, 3000))
            .with_load_balance(LoadBalance::LeastConn);
        let sel = group.select_upstream(None).expect("Some");
        let idx = sel.track.expect("track for LeastConn");
        let eps = group.lb_endpoints.as_deref().expect("built");
        assert_eq!(eps[idx as usize].active.load(Ordering::Relaxed), 1);
        group.release(idx);
        assert_eq!(
            eps[idx as usize].active.load(Ordering::Relaxed),
            0,
            "release decrements active"
        );
    }

    #[test]
    fn complete_decrements_least_conn_active() {
        let group = BackendGroup::new("test/svc".to_string(), addrs(2, 2000))
            .with_load_balance(LoadBalance::LeastConn);
        let sel = group.select_upstream(None).expect("Some");
        let idx = sel.track.expect("track for LeastConn");
        group.complete(idx, Some(Duration::from_millis(10)));
        let eps = group.lb_endpoints.as_deref().expect("built");
        assert_eq!(
            eps[idx as usize].active.load(Ordering::Relaxed),
            0,
            "complete decrements active"
        );
    }

    #[test]
    fn ewma_starts_at_zero_and_folds_latency() {
        // Single-endpoint group so the same endpoint is always selected,
        // letting us verify the fold formula without endpoint-switching noise.
        let group = BackendGroup::new("test/svc".to_string(), addrs(1, 1000))
            .with_load_balance(LoadBalance::Ewma);
        let eps = group.lb_endpoints.as_deref().expect("built");
        assert_eq!(eps[0].ewma_ns.load(Ordering::Relaxed), 0, "starts at 0");

        // First sample is stored as-is (old == 0).
        let idx = group
            .select_upstream(None)
            .expect("Some")
            .track
            .expect("track");
        let sample_a = Duration::from_millis(100);
        group.complete(idx, Some(sample_a));
        assert_eq!(
            eps[0].ewma_ns.load(Ordering::Relaxed),
            sample_a.as_nanos() as u64,
            "first sample stored verbatim"
        );

        // Second sample on the same endpoint folds via alpha = 1/8.
        let old = eps[0].ewma_ns.load(Ordering::Relaxed);
        let idx2 = group
            .select_upstream(None)
            .expect("Some")
            .track
            .expect("track");
        let sample_b = Duration::from_millis(200);
        group.complete(idx2, Some(sample_b));
        let expected = old
            .saturating_sub(old / 8)
            .saturating_add(sample_b.as_nanos() as u64 / 8);
        assert_eq!(
            eps[0].ewma_ns.load(Ordering::Relaxed),
            expected,
            "EWMA folds via alpha=1/8"
        );
    }
}
