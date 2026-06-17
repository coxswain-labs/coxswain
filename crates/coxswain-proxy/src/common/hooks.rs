//! Shared bodies of Pingora `ProxyHttp` hooks, parameterised over the spec
//! kind. Both [`IngressProxy`][crate::ingress::IngressProxy] and
//! [`GatewayProxy`][crate::gateway::GatewayProxy] forward to these helpers so
//! their hook implementations remain a thin shim.
//!
//! ## Per-request allocation budget
//!
//! The hot path captures host/path/query once at [`request_filter`] entry
//! (3 small allocations: `Arc<str>` for host, `Arc<str>` for path, optional
//! `String` for query); everything downstream — routing lookup, upstream
//! selection, metric emission, and error counters — runs allocation-free.
//!
//! Metric label rendering used to allocate a `String` per `u16` port and
//! status code (regression introduced by #237/#239 access logging + metrics);
//! both labels now write into stack-only [`itoa::Buffer`]s. The optional
//! upstream `SocketAddr → String` render lives inside the access-log branch
//! so operators silencing the log via `--access-log=off` skip it entirely.
//!
//! Two unavoidable allocations remain inside [`upstream_peer`]: the SNI
//! hostname is cloned into a fresh `String` per outbound TLS connection
//! because Pingora's `HttpPeer` constructor takes ownership of it. These are
//! TLS-path allocations (once per upstream connection, not per request), and
//! cleartext upstream connections skip them entirely.

use super::ctx::{CONN_INFO, ProxyCtx, ResolvedRoute};
use super::engine::RoutingEngine;
use super::filter::TrafficFilter;
use super::outcome::{merge_timeouts, resolve_outcome, try_redirect};
use super::redirect::extract_host;
use crate::config::AccessLogPathMode;
use crate::upstream_ca::UpstreamCaCache;
use bytes::Bytes;
use coxswain_cache::ResponseCache;
use coxswain_core::routing::{RequestContext, RetryOn, RouteTimeouts, UpstreamCa};
use pingora_cache::key::{CacheKey, HashBinary};
use pingora_cache::{CacheMeta, RespCacheable, VarianceBuilder};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{
    ConnectTimedout, ConnectionClosed, Error, ErrorSource, HTTPStatus, ReadError, ReadTimedout,
    Result, WriteError, WriteTimedout,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, Session};
use std::sync::Arc;
use std::time::Instant;

/// Construct a fresh per-request context, seeding from the connection-local
/// `CONN_INFO` task-local when present (PROXY-protocol path).
#[must_use]
pub(crate) fn new_ctx() -> ProxyCtx {
    CONN_INFO
        .try_with(|info| ProxyCtx {
            real_client_addr: Some(info.real_addr),
            real_client_proto: Some(info.proto),
            local_port: Some(info.local_addr.port()),
            resolved: None,
            request_deadline: None,
            request_timeout_is_controlling: false,
            backend_request_timeout_active: false,
            selected_backend_filters: None,
            start: None,
            upstream_addr: None,
            retries_used: 0,
            last_retry_condition: None,
            max_body_size: None,
            body_bytes_seen: 0,
        })
        .unwrap_or_default()
}

/// Pingora `request_filter` body: looks up the route, applies any
/// `RequestRedirect` filter, and caches the resolved route on the `ProxyCtx`.
///
/// Returns `Ok(true)` when the request was fully handled (redirect or error
/// response written); `Ok(false)` when the request should continue to
/// `upstream_peer`.
///
/// # Errors
/// Propagates the same errors Pingora's hook contract specifies — typically
/// `Error::explain(404, ...)` when no route matches the host or path.
pub(crate) async fn request_filter<K>(
    engine: &RoutingEngine<K>,
    default_timeouts: &RouteTimeouts,
    session: &mut Session,
    ctx: &mut ProxyCtx,
) -> Result<bool> {
    // Capture start time as early as possible for accurate duration_ms in the access log.
    ctx.start.get_or_insert_with(Instant::now);

    let req = session.req_header();
    let mut host_buf = String::new();
    let host: Arc<str> = Arc::from(extract_host(req, &mut host_buf));
    let path: Arc<str> = Arc::from(req.uri.path());
    let query = req.uri.query().map(str::to_string);
    // PROXY-protocol path sets real_client_proto directly; standard Pingora TLS path
    // does not set CONN_INFO, so fall back to inspecting the session's TLS digest.
    let proto = ctx.real_client_proto.unwrap_or_else(|| {
        let is_tls = session
            .as_downstream()
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        if is_tls { "https" } else { "http" }
    });

    let port = ctx
        .local_port
        .or_else(|| {
            session
                .as_downstream()
                .server_addr()
                .and_then(|a| a.as_inet())
                .map(|a| a.port())
        })
        .unwrap_or(0);

    let outcome = {
        let route_ctx = RequestContext {
            method: &req.method,
            headers: &req.headers,
            query: query.as_deref(),
        };
        engine.find(port, &host, &path, &route_ctx)
    }; // route_ctx (and req borrow) drops here

    let Some(m) = resolve_outcome(session, &host, &path, outcome).await? else {
        return Ok(true);
    };

    // Per-route source-IP allow-list (ingress.coxswain-labs.dev/allow-source-range).
    // Access control runs first — ahead of redirect and body handling — so an
    // out-of-range client gets 403 and never receives a redirect (which would leak
    // the canonical host/URL) nor has its body read. Match the *real* client IP:
    // the PROXY-protocol peer when present, else the L4 downstream peer. Both are
    // `Copy`; the CIDR scan borrows the `Arc`'d set — no per-request allocation.
    if let Some(nets) = m.allow_source_range.as_deref() {
        let client_ip = ctx.real_client_addr.map(|a| a.ip()).or_else(|| {
            session
                .as_downstream()
                .client_addr()
                .and_then(|a| a.as_inet())
                .map(|a| a.ip())
        });
        if !ip_allowed(client_ip, nets) {
            return Err(pingora_core::Error::explain(
                HTTPStatus(403),
                "client IP not in allow-list",
            ));
        }
    }

    let timeouts = merge_timeouts(&m.timeouts, default_timeouts);
    ctx.request_deadline = timeouts.request.map(|d| Instant::now() + d);

    if try_redirect(
        session,
        &m.filters,
        proto,
        &host,
        port,
        &path,
        query.as_deref(),
    )
    .await?
    {
        return Ok(true);
    }

    // Per-route request-body limit (ingress.coxswain-labs.dev/max-body-size).
    // Up-front check: when `Content-Length` already exceeds the limit, reject with
    // 413 before opening any upstream connection. Streaming/chunked bodies that omit
    // `Content-Length` are capped mid-stream in `request_body_filter`. The limit is
    // stashed on the context for that later hook.
    ctx.max_body_size = m.max_body_size;
    if let Some(limit) = m.max_body_size
        && content_length(session).is_some_and(|len| len > limit)
    {
        return Err(pingora_core::Error::explain(
            HTTPStatus(413),
            "request body exceeds max-body-size",
        ));
    }

    ctx.resolved = Some(ResolvedRoute {
        backend_group: m.backend_group,
        filters: m.filters,
        timeouts,
        original_host: host,
        original_path: path,
        path_pattern: m.path_pattern,
        metric_route_id: m.metric_route_id,
        cache_enabled: m.cache_enabled,
    });
    Ok(false)
}

/// Returns `true` if `client_ip` is admitted by the CIDR allow-list `nets`.
///
/// Fail-closed: a `None` client IP (the peer could not be determined) is
/// rejected — an un-attributable request must not pass a security allow-list.
/// Matching is strict (no IPv4-mapped-IPv6 normalization), matching `ipnet`'s
/// default and the `TrustedSources` PROXY-protocol check.
#[must_use]
pub(crate) fn ip_allowed(client_ip: Option<std::net::IpAddr>, nets: &[ipnet::IpNet]) -> bool {
    client_ip.is_some_and(|ip| nets.iter().any(|n| n.contains(&ip)))
}

/// Read and parse the `Content-Length` request header, if present and valid.
///
/// Returns `None` when the header is absent, non-ASCII, or not a valid unsigned
/// integer — chunked/streaming uploads (no `Content-Length`) fall through to the
/// mid-stream cap in [`request_body_filter`].
fn content_length(session: &Session) -> Option<u64> {
    session
        .req_header()
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

// ── Response caching (#40) ──────────────────────────────────────────────────

/// Default cache freshness: never cache implicitly.
///
/// Returning `None` for every status means an object is admitted only when the
/// upstream gives it explicit freshness (`Cache-Control: max-age` / `Expires`),
/// matching the issue's explicit-freshness-only scope.
fn no_implicit_freshness(_status: http::StatusCode) -> Option<std::time::Duration> {
    None
}

/// Cache metadata defaults: no implicit TTL, no stale-while-revalidate, no
/// stale-if-error. Shared across all requests.
static CACHE_DEFAULTS: pingora_cache::CacheMetaDefaults =
    pingora_cache::CacheMetaDefaults::new(no_implicit_freshness, 0, 0);

/// Enable Pingora's response cache for this request when the matched route
/// opted in and the request is safely cacheable.
///
/// Caching is restricted to `GET`/`HEAD`, and bypassed for requests carrying
/// `Authorization` or `Cookie` (per-user state must never be shared between
/// clients). When this returns without enabling, the request proxies normally
/// with no caching. `cache` is `None` when the process started without a cache
/// (e.g. `--cache-max-size=0`).
pub(crate) fn request_cache_filter(
    cache: Option<ResponseCache>,
    session: &mut Session,
    ctx: &ProxyCtx,
) -> Result<()> {
    let Some(cache) = cache else { return Ok(()) };
    if !ctx.resolved.as_ref().is_some_and(|r| r.cache_enabled) {
        return Ok(());
    }
    let req = session.req_header();
    if !matches!(req.method, http::Method::GET | http::Method::HEAD) {
        return Ok(());
    }
    if req.headers.contains_key(http::header::AUTHORIZATION)
        || req.headers.contains_key(http::header::COOKIE)
    {
        return Ok(());
    }
    session
        .cache
        .enable(cache.storage(), Some(cache.eviction()), None, None, None);
    Ok(())
}

/// Build the cache key for this request: host namespace + `"{method} {path?query}"`.
///
/// Routes through [`coxswain_cache::cache_key`] so it derives identically to the
/// admin purge path; the host is taken from the resolved route's captured
/// `original_host` to match what was routed.
pub(crate) fn cache_key_callback(session: &Session, ctx: &ProxyCtx) -> CacheKey {
    let req = session.req_header();
    let method = req.method.as_str();
    let path_and_query = req
        .uri
        .path_and_query()
        .map_or_else(|| req.uri.path(), |pq| pq.as_str());
    let host = ctx
        .resolved
        .as_ref()
        .map_or("", |r| r.original_host.as_ref());
    coxswain_cache::cache_key(method, host, path_and_query)
}

/// Decide whether the upstream response is cacheable per RFC 7234.
///
/// Delegates to Pingora's `resp_cacheable`, which honors `Cache-Control`
/// (`no-store`/`no-cache`/`private`/`max-age`) and `Expires`. With
/// [`CACHE_DEFAULTS`] supplying no implicit TTL, only explicitly-fresh responses
/// are admitted.
pub(crate) fn response_cache_filter(resp: &ResponseHeader) -> RespCacheable {
    let cc = pingora_cache::cache_control::CacheControl::from_resp_headers(resp);
    pingora_cache::filters::resp_cacheable(cc.as_ref(), resp.clone(), false, &CACHE_DEFAULTS)
}

/// Build the `Vary` variance key from the cached response's `Vary` header and
/// the incoming request's matching header values.
///
/// Returns `None` when the response carries no `Vary` (the common case), so such
/// entries are keyed by URL alone.
pub(crate) fn cache_vary_filter(meta: &CacheMeta, req: &RequestHeader) -> Option<HashBinary> {
    let vary = meta.headers().get(http::header::VARY)?.to_str().ok()?;
    let names: Vec<&str> = vary
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut builder = VarianceBuilder::new();
    for name in &names {
        let value = req
            .headers
            .get(*name)
            .map_or_else(Vec::new, |v| v.as_bytes().to_vec());
        builder.add_owned_value(name, value);
    }
    builder.finalize()
}

/// The `route` metric label for the matched route, or `"none"` when unresolved.
fn route_label(ctx: &ProxyCtx) -> &str {
    ctx.resolved
        .as_ref()
        .map_or("none", |r| r.metric_route_id.as_ref())
}

/// Increment `coxswain_cache_hits_total` for the matched route.
pub(crate) fn record_cache_hit(ctx: &ProxyCtx) {
    coxswain_cache::cache_hits_total()
        .with_label_values(&[route_label(ctx)])
        .inc();
}

/// Increment `coxswain_cache_misses_total` for the matched route.
pub(crate) fn record_cache_miss(ctx: &ProxyCtx) {
    coxswain_cache::cache_misses_total()
        .with_label_values(&[route_label(ctx)])
        .inc();
}

/// Pingora `request_body_filter` body: enforce the per-route request-body size limit
/// on streaming/chunked uploads.
///
/// Called for every chunk of the request body. Accumulates the running byte count on
/// the [`ProxyCtx`] and, once it exceeds the route's `max-body-size`, returns
/// `Err(Error::explain(413, …))`. Pingora propagates that through `fail_to_proxy`,
/// which writes a clean `413 Payload Too Large` to the client. The body is never
/// buffered — the `u64` counter is the only state — so this stays within the hot-path
/// allocation budget. No-ops when the route carries no limit (every Gateway-API route,
/// and Ingress routes without the annotation).
///
/// # Errors
/// Returns `Error::explain(413, …)` once the cumulative body size exceeds the limit.
pub(crate) fn request_body_filter(body: Option<&Bytes>, ctx: &mut ProxyCtx) -> Result<()> {
    let Some(limit) = ctx.max_body_size else {
        return Ok(());
    };
    ctx.body_bytes_seen = ctx
        .body_bytes_seen
        .saturating_add(body.map_or(0, Bytes::len) as u64);
    if ctx.body_bytes_seen > limit {
        return Err(pingora_core::Error::explain(
            HTTPStatus(413),
            "request body exceeds max-body-size",
        ));
    }
    Ok(())
}

/// Pingora `upstream_peer` body: choose the backend address from the resolved
/// route, set up TLS / SNI, and translate per-route timeouts into Pingora
/// peer options.
///
/// # Errors
/// Returns `Error::explain(500/502/503/504, ...)` for upstream-selection
/// failures (no resolved route, no active endpoints, expired deadline, bad
/// `BackendTLSPolicy` CA bundle).
pub(crate) async fn upstream_peer(
    ca_cache: &UpstreamCaCache,
    ctx: &mut ProxyCtx,
) -> Result<Box<HttpPeer>> {
    let resolved = ctx.resolved.as_ref().ok_or_else(|| {
        pingora_core::Error::explain(HTTPStatus(500), "routing not resolved before upstream_peer")
    })?;

    // If a total request deadline has already passed, fail fast with 504.
    if let Some(deadline) = ctx.request_deadline
        && Instant::now() >= deadline
    {
        return Err(pingora_core::Error::explain(
            HTTPStatus(504),
            "request timeout exceeded before upstream connection",
        ));
    }

    let (addr, per_backend_filters) = resolved
        .backend_group
        .next_endpoint_with_filters()
        .ok_or_else(|| {
            pingora_core::Error::explain(HTTPStatus(503), "no active endpoints for backend group")
        })?;
    ctx.selected_backend_filters = per_backend_filters;
    ctx.upstream_addr = Some(addr);

    let protocol = resolved.backend_group.protocol();

    // BackendTLSPolicy overrides appProtocol-derived TLS decisions.
    let (is_tls, sni_host, group_key, ca_override) =
        if let Some(btls) = resolved.backend_group.upstream_tls() {
            let ca = match &btls.ca {
                UpstreamCa::System => None,
                UpstreamCa::Bundle(pem) => {
                    let parsed = ca_cache.get_or_parse(btls.group_key, pem);
                    if parsed.is_none() {
                        return Err(pingora_core::Error::explain(
                            HTTPStatus(502),
                            "BackendTLSPolicy CA bundle parse failed",
                        ));
                    }
                    parsed
                }
                _ => None, // non-exhaustive guard
            };
            (true, btls.sni.to_string(), btls.group_key, ca)
        } else if protocol.is_tls() {
            // appProtocol-driven TLS: use the request Host as SNI (existing behaviour).
            (true, resolved.original_host.to_string(), 0u64, None)
        } else {
            (false, String::new(), 0u64, None)
        };

    // Pass SocketAddr directly — avoids the per-request addr.to_string() allocation.
    let mut peer = HttpPeer::new(addr, is_tls, sni_host);
    peer.group_key = group_key;
    peer.options.verify_cert = is_tls;
    peer.options.verify_hostname = is_tls;
    if let Some(ca) = ca_override {
        peer.options.ca = Some(ca);
    }
    if protocol.is_h2() {
        peer.options.set_http_version(2, 2);
    }
    // Pingora's HttpPeer hash includes sni and group_key; pool isolation is automatic.

    // Apply per-route timeout settings.
    //
    // Priority order (highest wins):
    //   1. ingress connect/read/send timeouts (from ingress.coxswain-labs.dev/* annotations)
    //   2. backend_request timeout (from HTTPRoute.timeouts.backendRequest / merge_timeouts)
    //   3. request total-budget (remaining wall-clock from timeouts.request)
    //
    // connect: controls the TCP-connect phase → 502 on ConnectTimedout.
    // read:    controls the upstream response-read phase.
    // send:    controls the upstream request-send phase.
    // backend_request: used when explicit connect/read are absent (legacy behaviour).
    let remaining_request = ctx
        .request_deadline
        .and_then(|d| d.checked_duration_since(Instant::now()));
    let backend_timeout = resolved.timeouts.backend_request;

    // Ingress-annotation-derived timeouts (may be None for GW-API routes).
    let explicit_connect = resolved.timeouts.connect;
    let explicit_read = resolved.timeouts.read;
    let explicit_send = resolved.timeouts.send;

    // Connection timeout: annotation-specific connect wins; else backend_request legacy.
    let conn_timeout = explicit_connect.or(backend_timeout);
    if let Some(t) = conn_timeout {
        peer.options.connection_timeout = Some(t);
        ctx.backend_request_timeout_active = true;
    }

    // Write (send) timeout: annotation-specific send.
    if let Some(t) = explicit_send {
        peer.options.write_timeout = Some(t);
    }

    // Read timeout: annotation read wins; else min(backend_request, remaining request budget).
    let read_timeout = if let Some(read) = explicit_read {
        // Annotation-explicit read: clamp by remaining request budget if set.
        match remaining_request {
            Some(rem) => {
                ctx.request_timeout_is_controlling = rem <= read;
                Some(read.min(rem))
            }
            None => Some(read),
        }
    } else {
        // Legacy: min(backend_request, remaining request budget) — unchanged behaviour.
        match (backend_timeout, remaining_request) {
            (Some(bt), Some(rem)) => {
                ctx.request_timeout_is_controlling = rem <= bt;
                Some(bt.min(rem))
            }
            (Some(bt), None) => {
                ctx.request_timeout_is_controlling = false;
                Some(bt)
            }
            (None, Some(rem)) => {
                ctx.request_timeout_is_controlling = true;
                Some(rem)
            }
            (None, None) => None,
        }
    };
    if let Some(t) = read_timeout {
        peer.options.read_timeout = Some(t);
    }

    Ok(Box::new(peer))
}

/// Pingora `upstream_request_filter` body: apply rule-level filters then
/// per-backend filters (per GEP-1492 ordering).
///
/// # Errors
/// Propagates header-mutation errors from [`TrafficFilter::apply_request_filters`].
pub(crate) async fn upstream_request_filter(
    _session: &mut Session,
    upstream_request: &mut RequestHeader,
    ctx: &mut ProxyCtx,
) -> Result<()> {
    let (filters, original_host, original_path) = ctx
        .resolved
        .as_ref()
        .map(|r| (r.filters.as_ref(), &*r.original_host, &*r.original_path))
        .unwrap_or((&[], "", ""));
    TrafficFilter::apply_request_filters(
        upstream_request,
        filters,
        original_host,
        original_path,
        ctx,
    )?;
    // Per-backend `RequestHeaderModifier` filters from
    // `HTTPRoute.spec.rules[].backendRefs[].filters` apply AFTER rule-level
    // filters, per GEP-1492. Cloning the Arc here is cheap; we hold a separate
    // reference because `apply_request_filters` borrows `ctx` mutably.
    if let Some(per_backend) = ctx.selected_backend_filters.clone() {
        TrafficFilter::apply_request_filters(
            upstream_request,
            &per_backend,
            original_host,
            original_path,
            ctx,
        )?;
    }
    Ok(())
}

/// Pingora `upstream_response_filter` body: apply rule-level response filters and
/// trigger a retry when the upstream returns a 5xx status and the route allows it.
///
/// ## 5xx-response retries
///
/// When `retry-on` includes `5xx` and `max-retries` budget remains, this function
/// returns a retryable `Err` so Pingora re-enters the retry loop and calls
/// `upstream_peer` again.  On the **final** attempt (budget exhausted) the 5xx
/// passes through to the client unmodified.
///
/// **Replay guard**: retries are suppressed when `session.retry_buffer_truncated()`
/// is true — large or streaming request bodies cannot be replayed safely.
///
/// # Errors
/// Propagates header-mutation errors from [`TrafficFilter::apply_response_filters`]
/// and returns a retryable upstream error when a 5xx retry is triggered.
pub(crate) async fn upstream_response_filter(
    session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut ProxyCtx,
) -> Result<()> {
    if let Some(resolved) = &ctx.resolved {
        TrafficFilter::apply_response_filters(upstream_response, &resolved.filters);
    }
    let status = upstream_response.status.as_u16();
    if status >= 500 {
        inc_upstream_error(ctx, "5xx");

        // 5xx-response retry: check policy, budget, and replay safety.
        let retry_allowed = ctx.resolved.as_ref().is_some_and(|r| {
            r.backend_group
                .retry_policy()
                .on
                .contains(RetryOn::HTTP_5XX)
        });
        let budget_ok = ctx
            .resolved
            .as_ref()
            .is_some_and(|r| ctx.retries_used < r.backend_group.retry_policy().max_retries);
        if retry_allowed && budget_ok && !session.as_ref().retry_buffer_truncated() {
            ctx.retries_used += 1;
            ctx.last_retry_condition = Some(RetryOn::HTTP_5XX);
            inc_upstream_retry(ctx, "5xx");
            let mut e = Error::explain(
                HTTPStatus(status),
                format!(
                    "upstream returned {status}; retrying (attempt {})",
                    ctx.retries_used
                ),
            );
            e.retry = true.into();
            e.as_up();
            return Err(e);
        }
    }
    Ok(())
}

/// Pingora `fail_to_connect` body: retry upstream connection failures when the
/// route's `RetryPolicy` permits.
///
/// Called when establishing the TCP/TLS connection to the upstream fails **before**
/// any request bytes are sent, so replaying the request is always safe.
/// Marks the error retryable when:
/// - `retry-on` includes `connect-failure` (for `ErrorSource::Upstream` non-timeout
///   errors) or `timeout` (for `ConnectTimedout`); and
/// - the `max-retries` budget is not exhausted.
pub(crate) fn fail_to_connect(
    _session: &mut Session,
    _peer: &HttpPeer,
    ctx: &mut ProxyCtx,
    mut e: Box<pingora_core::Error>,
) -> Box<pingora_core::Error> {
    let Some(resolved) = ctx.resolved.as_ref() else {
        return e;
    };
    let policy = resolved.backend_group.retry_policy();
    if policy.is_disabled() || ctx.retries_used >= policy.max_retries {
        return e;
    }
    let is_timeout = matches!(e.etype(), ConnectTimedout);
    let condition = if is_timeout {
        RetryOn::TIMEOUT
    } else {
        RetryOn::CONNECT_FAILURE
    };
    if policy.on.contains(condition) {
        ctx.retries_used += 1;
        ctx.last_retry_condition = Some(condition);
        e.retry = true.into();
        let condition_label = if is_timeout {
            "timeout"
        } else {
            "connect-failure"
        };
        inc_upstream_retry(ctx, condition_label);
    }
    e
}

/// Pingora `error_while_proxy` body: preserve retry decisions made by
/// `upstream_response_filter`, and allow connect-level retries on fresh connections.
///
/// Pingora's default implementation gates retries on `client_reused &&
/// !retry_buffer_truncated()`.  We override it to:
/// - Keep the `retry = true` set by `fail_to_connect` (connect-failure path) or
///   `upstream_response_filter` (5xx-response path) unconditionally when those
///   hooks already bumped `retries_used`.
/// - Fall back to Pingora's default reuse-check for errors not triggered by our
///   own retry logic (e.g. mid-response I/O errors).
pub(crate) fn error_while_proxy(
    peer: &HttpPeer,
    session: &mut Session,
    mut e: Box<pingora_core::Error>,
    ctx: &mut ProxyCtx,
    client_reused: bool,
) -> Box<pingora_core::Error> {
    if ctx.last_retry_condition == Some(RetryOn::HTTP_5XX) {
        // 5xx-response retry was already set in upstream_response_filter; preserve it.
        // (Do NOT gate on client_reused — the connection held the response, not a reuse.)
        e.retry = true.into();
        return e;
    }
    // For connection-error retries (fail_to_connect already set retry=true) or
    // unrelated errors, apply Pingora's default reuse check.
    let mut e = e.more_context(format!("Peer: {peer}"));
    e.retry
        .decide_reuse(client_reused && !session.as_ref().retry_buffer_truncated());
    e
}

/// Pingora `fail_to_proxy` body: map upstream/downstream errors to HTTP
/// status codes and write a short plain-text body.
///
/// Mirrors Pingora's default code-selection logic but calls
/// `respond_error_with_body` so clients see "503 Service Unavailable\n"
/// rather than a zero-length body.
pub(crate) async fn fail_to_proxy(
    session: &mut Session,
    e: &pingora_core::Error,
    ctx: &mut ProxyCtx,
) -> FailToProxy {
    let code = match e.etype() {
        HTTPStatus(code) => *code,
        // request/backendRequest read timeouts → 504 (Gateway API spec, GEP-1742).
        // Connect failure while backendRequest active → 502 (upstream unreachable).
        // Flags set in upstream_peer avoid races with OS timer granularity.
        ReadTimedout | WriteTimedout
            if ctx.request_timeout_is_controlling || ctx.backend_request_timeout_active =>
        {
            504
        }
        ConnectTimedout if ctx.backend_request_timeout_active => 502,
        _ => match e.esource() {
            ErrorSource::Upstream => 502,
            ErrorSource::Downstream => match e.etype() {
                ConnectionClosed | ReadError | WriteError => 0,
                _ => 400,
            },
            _ => 500,
        },
    };
    let error_type = classify_upstream_error(e);
    inc_upstream_error(ctx, error_type);
    if code > 0 {
        let reason = http::StatusCode::from_u16(code)
            .ok()
            .and_then(|s| s.canonical_reason())
            .unwrap_or("Unknown");
        session
            .respond_error_with_body(code, Bytes::from(format!("{code} {reason}\n")))
            .await
            .unwrap_or_else(|err| tracing::error!("failed to send error response: {err}"));
    }
    FailToProxy {
        error_code: code,
        can_reuse_downstream: false,
    }
}

/// Bucket a Pingora `Error` into the `error_type` taxonomy carried on
/// `coxswain_proxy_upstream_errors_total`.
fn classify_upstream_error(e: &pingora_core::Error) -> &'static str {
    match e.etype() {
        ConnectTimedout | ReadTimedout | WriteTimedout => "timeout",
        _ => match e.esource() {
            ErrorSource::Upstream => "connect",
            _ => "other",
        },
    }
}

/// Increment `coxswain_proxy_upstream_retries_total{listener, route, upstream,
/// condition}` from a per-request `ProxyCtx`. Called once per retry attempt,
/// not per request. Best-effort: falls back to `"none"` labels when routing
/// has not yet resolved (should not occur in practice since retries require a
/// resolved route).
fn inc_upstream_retry(ctx: &ProxyCtx, condition: &'static str) {
    let mut port_buf = itoa::Buffer::new();
    let listener = port_buf.format(ctx.local_port.unwrap_or(0));
    let (route, upstream) = ctx.resolved.as_ref().map_or(("none", "none"), |r| {
        (r.metric_route_id.as_ref(), r.backend_group.name())
    });
    crate::metrics::upstream_retries_total()
        .with_label_values(&[listener, route, upstream, condition])
        .inc();
}

/// Increment `coxswain_proxy_upstream_errors_total{listener, route, upstream,
/// error_type}` from a per-request `ProxyCtx`. Best-effort: when the request
/// reached `fail_to_proxy` before routing resolved, `route`/`upstream` carry
/// the literal `"none"` fallback so the increment isn't dropped.
fn inc_upstream_error(ctx: &ProxyCtx, error_type: &'static str) {
    // `itoa::Buffer` writes into a stack-only buffer; no heap allocation for
    // the u16 → &str render. Re-issuing `p.to_string()` here would allocate
    // per request and is what #239's metric emission accidentally regressed.
    let mut port_buf = itoa::Buffer::new();
    let listener = port_buf.format(ctx.local_port.unwrap_or(0));
    let (route, upstream) = ctx.resolved.as_ref().map_or(("none", "none"), |r| {
        (r.metric_route_id.as_ref(), r.backend_group.name())
    });
    crate::metrics::upstream_errors_total()
        .with_label_values(&[listener, route, upstream, error_type])
        .inc();
}

/// Pingora `logging` body: emit one structured access-log event per request
/// *and* increment the per-request Prometheus counters.
///
/// Access-log emission is at `INFO` level on the `coxswain_proxy::access`
/// target so operators can filter it independently with
/// `--log=info,coxswain_proxy::access=off`. When `access_log_enabled` is
/// `false` the access-log emission is skipped but the metric emission still
/// runs — operators silencing logs must not lose request-rate signal.
pub(crate) async fn logging(
    access_log_enabled: bool,
    access_log_path_mode: AccessLogPathMode,
    session: &mut Session,
    e: Option<&pingora_core::Error>,
    ctx: &ProxyCtx,
) {
    let req = session.req_header();
    let method = req.method.as_str();
    let status = session.response_written().map(|h| h.status.as_u16());
    let bytes_sent = session.body_bytes_sent() as u64;
    let duration = ctx.start.map(|s| s.elapsed()).unwrap_or_default();
    let duration_ms = duration.as_millis() as u64;

    // Prefer the pre-resolved host from context; fall back to parsing the header.
    let mut host_buf = String::new();
    let host: &str = ctx
        .resolved
        .as_ref()
        .map(|r| r.original_host.as_ref())
        .unwrap_or_else(|| extract_host(req, &mut host_buf));

    let upstream = ctx.resolved.as_ref().map(|r| r.backend_group.name());
    let route_id = ctx.resolved.as_ref().map(|r| r.metric_route_id.as_ref());

    // --- Metric emission (always, independent of access-log toggle) ---
    // `itoa::Buffer` keeps the u16 → &str render stack-only; both buffers
    // sit on the request frame for the lifetime of this call.
    let mut listener_buf = itoa::Buffer::new();
    let listener_label = listener_buf.format(ctx.local_port.unwrap_or(0));
    let mut status_buf = itoa::Buffer::new();
    let status_label = status_buf.format(status.unwrap_or(0));
    let route_label = route_id.unwrap_or("none");
    crate::metrics::requests_total()
        .with_label_values(&[listener_label, route_label, method, status_label])
        .inc();
    crate::metrics::request_duration_seconds()
        .with_label_values(&[listener_label, route_label])
        .observe(duration.as_secs_f64());

    if !access_log_enabled {
        return;
    }

    // `SocketAddr::to_string` allocates — keep it inside the access-log branch
    // so operators silencing the log don't pay the alloc on every request.
    let upstream_addr_str = ctx.upstream_addr.map(|a| a.to_string());

    // path_str is Option<&str>: tracing's Value impl for Option silently omits
    // the field when None, giving us free conditional emission for `None` mode.
    let path_str: Option<&str> = match access_log_path_mode {
        AccessLogPathMode::Full => Some(
            ctx.resolved
                .as_ref()
                .map(|r| r.original_path.as_ref())
                .unwrap_or_else(|| req.uri.path()),
        ),
        AccessLogPathMode::Pattern => Some(
            ctx.resolved
                .as_ref()
                .map(|r| r.path_pattern.as_ref())
                .unwrap_or("/"),
        ),
        AccessLogPathMode::None => None,
    };

    let err_msg = e.map(|err| err.to_string());

    tracing::info!(
        target: "coxswain_proxy::access",
        host = %host,
        method = method,
        path = path_str,
        status = status,
        route_id = route_id,
        upstream = upstream,
        upstream_addr = upstream_addr_str.as_deref(),
        duration_ms = duration_ms,
        bytes_sent = bytes_sent,
        error = err_msg.as_deref(),
        "access",
    );
}

#[cfg(test)]
mod tests {
    use super::ip_allowed;
    use std::net::IpAddr;

    fn nets(cidrs: &[&str]) -> Vec<ipnet::IpNet> {
        cidrs
            .iter()
            .map(|c| c.parse().expect("valid CIDR"))
            .collect()
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().expect("valid IP"))
    }

    #[test]
    fn in_range_v4_allowed() {
        assert!(ip_allowed(ip("10.1.2.3"), &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn out_of_range_v4_rejected() {
        assert!(!ip_allowed(ip("192.168.0.1"), &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn in_range_v6_allowed() {
        assert!(ip_allowed(ip("2001:db8::1"), &nets(&["2001:db8::/32"])));
    }

    #[test]
    fn out_of_range_v6_rejected() {
        assert!(!ip_allowed(ip("2001:dead::1"), &nets(&["2001:db8::/32"])));
    }

    #[test]
    fn matches_second_cidr_in_list() {
        assert!(ip_allowed(
            ip("192.168.1.5"),
            &nets(&["10.0.0.0/8", "192.168.1.0/24"])
        ));
    }

    #[test]
    fn missing_client_ip_is_rejected_fail_closed() {
        // A peer we cannot attribute must never pass a security allow-list.
        assert!(!ip_allowed(None, &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn empty_allow_list_rejects_everything() {
        assert!(!ip_allowed(ip("10.0.0.1"), &[]));
    }

    #[test]
    fn v4_mapped_v6_does_not_match_v4_cidr() {
        // Strict matching: an IPv4-mapped IPv6 client does NOT satisfy an IPv4 CIDR.
        // Locks the documented behavior so leniency would be a deliberate change.
        assert!(!ip_allowed(ip("::ffff:10.0.0.1"), &nets(&["10.0.0.0/8"])));
    }
}
