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
//! Path normalization (#280) runs inside [`RoutingEngine::find`].  The
//! common case (path already canonical) costs one linear scan and zero
//! allocation; the slow path allocates exactly one `String` (and one
//! `Arc<str>` to box it) only when the path actually changes.  When the path
//! changed, [`upstream_request_filter`] rewrites the upstream request clone
//! before traffic filters run, so the normalized path is forwarded upstream.
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

use crate::config::AccessLogPathMode;
use crate::ctx::{CONN_INFO, ProxyCtx, ResolvedRoute};
use crate::edge::tls::ConnTlsInfo;
use crate::edge::upstream_ca::{
    BackendClientCertCache, SanCheckHookCache, UpstreamCaCache, UpstreamSanMismatch,
    apply_upstream_tls,
};
use crate::filters::TrafficFilter;
use crate::filters::cors::try_cors_preflight;
use crate::filters::redirect::{extract_host, try_redirect};
use crate::policy::access_control::{ip_allowed, ip_denied, resolve_client_ip};
use crate::policy::affinity;
use crate::retry::RetryTrigger;
use crate::routing::engine::RoutingEngine;
use crate::routing::outcome::{merge_timeouts, resolve_outcome};
use bytes::Bytes;
use coxswain_core::routing::{
    HashSource, RateLimitKey, RequestContext, SessionAffinity, affinity_hash, affinity_hash_parts,
};
use coxswain_core::tls::ClientCertConfigState;
use http::header;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, HTTPStatus, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
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
            last_retry_trigger: None,
            max_body_size: None,
            body_bytes_seen: 0,
            is_h2: false,
            affinity_pin: None,
            affinity_set_cookie: false,
            auth_response_headers: None,
            mirror_txs: Vec::new(),
            compression_encoder: None,
            client_cert_pem: None,
            client_ip: None,
            lb_track: None,
            hash_key: None,
            circuit_breaker_rejected: false,
            cors_origin: None,
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
    cfg: &crate::config::SharedProxyConfig,
    session: &mut Session,
    ctx: &mut ProxyCtx,
) -> Result<bool> {
    // Capture start time as early as possible for accurate duration_ms in the access log.
    ctx.start.get_or_insert_with(Instant::now);

    let req = session.req_header();
    let host: Arc<str> = Arc::from(extract_host(req));
    let path: Arc<str> = Arc::from(req.uri.path());
    let query = req.uri.query().map(str::to_string);
    // Capture the downstream protocol once: the mid-stream `max_body_size` cap in
    // `request_body_filter` must not fire on HTTP/2 (pingora deadlocks the client on a
    // body-filter error, #509). h2 size limits are enforced up-front via Content-Length.
    ctx.is_h2 = req.version == http::Version::HTTP_2;
    // Capture Origin early, before the session is mutably borrowed for response writing
    // (CORS preflight and response-header injection both need the value).
    ctx.cors_origin = req
        .headers
        .get(http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(Box::from);
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

    // ── GEP-3567 misdirected-request guard (#96) ────────────────────────────
    //
    // On HTTPS ports that carry named Gateway listeners, return 421 when the
    // request Host resolves to a different listener than the one selected by
    // the negotiated TLS SNI.  This blocks HTTP/2 connection coalescing from
    // sending a request for host B over a connection whose certificate and
    // listener were negotiated for a disjoint host A.
    //
    // The check is a no-op for: plain-HTTP requests, Ingress-only deployments,
    // and ports with no HTTPS Gateway listeners (`has_https_port` miss →
    // `listener_hostnames` default empty snapshot).
    if proto == "https" {
        let lh = cfg.listener_hostnames.load();
        if lh.has_https_port(port) {
            let sni = session
                .as_downstream()
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .and_then(|d| d.extension.get::<ConnTlsInfo>())
                .and_then(|t| t.sni.as_deref());
            if lh.resolve_sni(port, sni) != lh.resolve(port, &host) {
                return Err(pingora_core::Error::explain(
                    HTTPStatus(421),
                    "request host resolves to a different listener than the negotiated SNI",
                ));
            }
        }
    }

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

    // Adopt the normalized path (#280): the routing layer applies normalization
    // inside `find()` and surfaces the result in `m.normalized_path` when the
    // path actually changed.  Use it as the canonical path everywhere downstream
    // — redirect URL construction, consistent-hash key, and the `original_path`
    // forwarded upstream — so all handlers agree on the same form.  When
    // normalization is `none` or the path was already canonical, `normalized_path`
    // is `None` (zero allocation) and we fall back to the raw captured `path`.
    let effective_path = m
        .normalized_path
        .clone()
        .unwrap_or_else(|| Arc::clone(&path));

    // Resolve the effective client IP once per request (#271).  When the matched route
    // carries a ForwardedForConfig, the IP is extracted from the configured header
    // (subject to the trusted-CIDR anti-spoofing gate); otherwise the PROXY-protocol
    // addr or L4 peer is used directly.  All IP-based features below read ctx.client_ip.
    ctx.client_ip = resolve_client_ip(session, ctx.real_client_addr, m.forwarded_for.as_deref());

    // ── Per-Ingress client-certificate mTLS cross-SNI guard (#267) ──────────────
    //
    // If this Host requires mTLS, the connection MUST carry a verified client cert in the
    // `ConnTlsInfo` stored in the TLS digest extension. A TLS connection whose SNI matched
    // a different (non-mTLS) host will have no peer cert; return 421 Misdirected Request
    // so the client reconnects on the correct SNI, which will trigger the mTLS handshake.
    // Plain-HTTP connections (no ssl_digest) are exempt — the operator forces HTTPS via
    // `ssl-redirect`.
    //
    // GEP-91 AllowInsecureFallback (#86): when the host's frontend validation runs in
    // insecure-fallback mode, the client cert is requested but a missing/invalid cert is
    // NOT rejected here — authorization is delegated to the backend. The TLS layer already
    // allowed the handshake to complete without a cert (`set_verify_callback`), so this
    // HTTP-layer guard must mirror that and let the request through.
    {
        let cc_store = cfg.client_certs.load();
        if let Some(config_state) = cc_store.find_config(port, &host) {
            let ssl_digest = session
                .as_downstream()
                .digest()
                .and_then(|d| d.ssl_digest.as_ref());
            if let Some(ssl_digest) = ssl_digest {
                let cert_info = ssl_digest
                    .extension
                    .get::<ConnTlsInfo>()
                    .and_then(|t| t.client_cert.as_ref());
                let insecure_fallback = matches!(
                    config_state.as_ref(),
                    ClientCertConfigState::Config(cc) if cc.allow_insecure_fallback
                );
                if cert_info.is_none() && !insecure_fallback {
                    return Err(pingora_core::Error::explain(
                        HTTPStatus(421),
                        "client certificate required for this host",
                    ));
                }
                if let ClientCertConfigState::Config(cc_cfg) = config_state.as_ref()
                    && cc_cfg.pass_to_upstream
                    && let Some(ci) = cert_info
                {
                    ctx.client_cert_pem = Some(ci.cert_pem.clone());
                }
            }
        }
    }

    // Per-route source-IP block list (ingress.coxswain-labs.dev/deny-source-range).
    // Evaluated BEFORE the allow-list: a denied IP is blocked even when the allow-list
    // would admit it. A None client IP is fail-open (not denied) — a block list only
    // acts on IPs it can positively attribute to a listed range.
    //
    // Written explicitly via `session.write_response_header` (like the rate-limit
    // block below) rather than returned as `Err(Error::explain(...))`: Pingora's
    // generic `fail_to_proxy` error path does not reliably deliver a client-visible
    // response over HTTP/2 (confirmed via a gRPC client hanging instead of observing
    // 403 → PermissionDenied), while the explicit low-level write works on both
    // HTTP/1.1 and HTTP/2.
    if let Some(nets) = m.deny_source_range.as_deref() {
        let client_ip = ctx.client_ip;
        if ip_denied(client_ip, nets) {
            let resp = ResponseHeader::build(403, Some(0))?;
            session
                .write_response_header(Box::new(resp), true)
                .await
                .unwrap_or_else(|e| tracing::error!("failed to write deny-list response: {e}"));
            return Ok(true);
        }
    }

    // Per-route source-IP allow-list (ingress.coxswain-labs.dev/allow-source-range).
    // Access control runs ahead of redirect and body handling — so a denied client
    // never receives a redirect (which would leak the canonical host/URL) nor has
    // its body read. The real client IP is resolved once by resolve_client_ip (above)
    // and cached on ctx — no per-request allocation for the CIDR scan.
    //
    // Written explicitly for the same HTTP/2 reason as the deny-list block above.
    if let Some(nets) = m.allow_source_range.as_deref()
        && !ip_allowed(ctx.client_ip, nets)
    {
        let resp = ResponseHeader::build(403, Some(0))?;
        session
            .write_response_header(Box::new(resp), true)
            .await
            .unwrap_or_else(|e| tracing::error!("failed to write allow-list response: {e}"));
        return Ok(true);
    }

    // Per-route rate limiting. Enforcement runs after allow-list (denied clients
    // never consume a rate-limit slot) and before redirect (a rate-limited client
    // does not receive a redirect, preventing URL leakage). Fail-open on absent
    // client key (undeterminable IP or missing header) — matches nginx + Envoy.
    if let Some(rl_config) = m.rate_limit.as_deref() {
        let client_ip = ctx.client_ip;
        let client_key = {
            // Scope the immutable req borrow so it does not outlive the next mutable
            // session borrow (write_response_header below).
            let req = session.req_header();
            let header_val = if let RateLimitKey::Header(name) = &rl_config.key {
                req.headers.get(name.as_ref()).and_then(|v| v.to_str().ok())
            } else {
                None
            };
            crate::policy::rate_limit::extract_client_key(rl_config, client_ip, header_val)
        };
        if let Some(key) = client_key
            && let crate::policy::rate_limit::CheckOutcome::Limited { retry_after_secs } =
                cfg.rate_limiter.check(&m.metric_route_id, rl_config, key)
        {
            let mut resp = ResponseHeader::build(429, Some(1))?;
            // Render the u16 Retry-After into a stack buffer — matches the
            // file's itoa label discipline, no heap allocation (#397).
            let mut retry_after_buf = itoa::Buffer::new();
            resp.insert_header(
                header::RETRY_AFTER,
                retry_after_buf.format(retry_after_secs),
            )?;
            session
                .write_response_header(Box::new(resp), true)
                .await
                .unwrap_or_else(|e| tracing::error!("failed to write rate-limit response: {e}"));
            return Ok(true);
        }
    }

    // Per-route external auth (#24, #23). The additive chain runs in order — a
    // Gateway-attached policy check precedes a route-level check — and the first
    // hard-deny wins. Runs after the allow-list (denied clients never consume an
    // auth-service round-trip) and before redirect (an unauthenticated client
    // must not receive a redirect leaking the canonical URL). `enforce()` writes
    // a denial response and returns `Ok(true)`.
    for auth in m.auth.iter() {
        if crate::policy::auth::enforce(
            &cfg.auth_client,
            &cfg.grpc_auth_channels,
            auth,
            session,
            &mut ctx.auth_response_headers,
        )
        .await?
        {
            return Ok(true);
        }
    }

    let timeouts = merge_timeouts(&m.timeouts, &cfg.default_timeouts);
    ctx.request_deadline = timeouts.request.map(|d| Instant::now() + d);

    // CORS preflight short-circuit (GEP-1767, #41).
    // OPTIONS + Access-Control-Request-Method with a matched Origin → 204, no upstream.
    if try_cors_preflight(session, &m.filters, ctx.cors_origin.as_deref()).await? {
        return Ok(true);
    }

    // A `RequestRedirect` that preserves the incoming port must echo the
    // ADVERTISED listener port (what the client connected to), not the internal
    // port the proxy accepted on behind a per-Gateway VIP (#472). Recover it from
    // the accept port; a miss (Ingress / dedicated, advertised == accept) falls
    // back to `port`, which is correct. `port` itself stays the internal accept
    // port for the SNI-isolation and metric paths that key on it.
    let advertised_port = cfg
        .advertised_ports
        .load()
        .get(&port)
        .copied()
        .unwrap_or(port);
    if try_redirect(
        session,
        &m.filters,
        proto,
        &host,
        advertised_port,
        &effective_path,
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

    // Per-route session affinity (ingress.coxswain-labs.dev/session-*). Resolve the
    // pin from the request's cookie/header against the matched group's affinity index
    // now, while the request headers are in hand; `upstream_peer` honors it and
    // `upstream_response_filter` issues the cookie. No-op (and no allocation) for
    // groups without affinity configured.
    let affinity = affinity::resolve(session.req_header(), &m.backend_group);
    ctx.affinity_pin = affinity.pin;
    ctx.affinity_set_cookie = affinity.set_cookie;

    // Consistent-hash load balancing (#276): extract the key attribute once per request
    // while the headers are in hand, then hash it. No allocation for routes that don't
    // use hash:* — the `None` fast-path is a single branch on `hash_by()`.
    ctx.hash_key = extract_hash_key(
        session.req_header(),
        &m.backend_group,
        &effective_path,
        query.as_deref(),
        ctx.client_ip,
    );

    ctx.resolved = Some(ResolvedRoute {
        backend_group: m.backend_group,
        filters: m.filters,
        timeouts,
        original_host: host,
        original_path: effective_path,
        path_pattern: m.path_pattern,
        metric_route_id: m.metric_route_id,
        access_log_enabled: m.access_log_enabled,
        compression: m.compression,
        circuit_breaker: m.circuit_breaker,
    });

    // Mirror setup (#283, #261): sample Mirror filters, open per-backend channels,
    // and spawn fire-and-forget mirror tasks (delegated to the mirror module).
    crate::filters::mirror::setup(session, ctx, cfg, query.as_deref());

    Ok(false)
}

/// Extract and hash the configured `load-balance: hash:*` attribute value from the request.
///
/// Returns `None` when the group uses a non-`Hash` algorithm (zero-overhead fast path),
/// or when the attribute is absent/empty (caller falls back to round-robin). Every
/// variant is allocation-free: `Uri` streams FNV-1a over `path`, `b"?"`, and `query`
/// via [`affinity_hash_parts`] rather than building a joined `String` (#397).
fn extract_hash_key(
    req: &RequestHeader,
    group: &coxswain_core::routing::BackendGroup,
    path: &str,
    query: Option<&str>,
    client_ip: Option<std::net::IpAddr>,
) -> Option<u64> {
    match group.hash_by()? {
        HashSource::Uri => Some(match query {
            // Same byte sequence as `path ++ "?" ++ query`, hashed in place.
            Some(q) => affinity_hash_parts(&[path.as_bytes(), b"?", q.as_bytes()]),
            None => affinity_hash(path.as_bytes()),
        }),
        HashSource::SourceIp => client_ip.map(|ip| match ip {
            std::net::IpAddr::V4(v4) => affinity_hash(&v4.octets()),
            std::net::IpAddr::V6(v6) => affinity_hash(&v6.octets()),
        }),
        HashSource::Header(name) => req
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .map(|v| affinity_hash(v.as_bytes())),
        HashSource::Cookie(name) => affinity::cookie_value(req, name)
            .filter(|v| !v.is_empty())
            .map(|v| affinity_hash(v.as_bytes())),
        // `HashSource` is `#[non_exhaustive]`; a future variant degrades to round-robin.
        _ => None,
    }
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

/// Pingora `request_body_filter` body: enforce the per-route request-body size limit
/// on streaming/chunked **HTTP/1.x** uploads, and tees body chunks to any active mirror
/// tasks.
///
/// Called for every chunk of the request body (including a final call with
/// `end_of_stream = true` when the body is complete). On HTTP/1.x it accumulates the
/// running byte count on the [`ProxyCtx`] and, once it exceeds the route's
/// `max-body-size`, returns `Err(Error::explain(413, …))`. Pingora propagates that
/// through `fail_to_proxy`, which writes a clean `413 Payload Too Large` to the client.
/// The body is not buffered for size enforcement — the `u64` counter is the only state —
/// so this stays within the hot-path allocation budget. No-ops for size enforcement when
/// the route carries no limit (Ingress routes without the annotation) or the downstream
/// is **HTTP/2** ([`ProxyCtx::is_h2`]): returning `Err` here on an h2 session deadlocks
/// the client (#509), so h2/gRPC size limits are enforced only up-front via the
/// `Content-Length` check in `request_filter`.
///
/// When `mirror-target` is active, each chunk is also teed to all mirror tasks via
/// bounded mpsc senders ([`ProxyCtx::mirror_txs`]). Chunks are sent with
/// `try_send` (non-blocking): a slow mirror upstream causes the current chunk to be
/// dropped rather than stalling the primary path. On `end_of_stream` the sender vec is
/// cleared, dropping all senders and closing each mirror body stream. Mirroring is
/// independent of `max-body-size` (#360).
///
/// # Errors
/// On HTTP/1.x, returns `Error::explain(413, …)` once the cumulative body size exceeds
/// the limit. Never errors on HTTP/2 (see above).
pub(crate) fn request_body_filter(
    body: Option<&Bytes>,
    end_of_stream: bool,
    ctx: &mut ProxyCtx,
) -> Result<()> {
    // ── Body size enforcement ────────────────────────────────────────────────
    // HTTP/2 is deliberately excluded: returning `Err` from this hook on an h2
    // session deadlocks the client, because pingora's h2 proxy loop swallows the
    // error and never surfaces a response (#509). h2 requests that *declare* an
    // oversized body are already rejected up-front by the `Content-Length` check in
    // `request_filter`; a streaming h2 upload without `Content-Length` (notably gRPC)
    // is left to the backend's own limits until pingora supports request-body
    // buffering (pingora #816/#780). HTTP/1.x keeps full mid-stream enforcement.
    if let Some(limit) = ctx.max_body_size.filter(|_| !ctx.is_h2) {
        ctx.body_bytes_seen = ctx
            .body_bytes_seen
            .saturating_add(body.map_or(0, Bytes::len) as u64);
        if ctx.body_bytes_seen > limit {
            // Close mirror channels immediately so their tasks don't wait for
            // ProxyCtx to drop (which only happens after fail_to_proxy + logging).
            ctx.mirror_txs.clear();
            return Err(pingora_core::Error::explain(
                HTTPStatus(413),
                "request body exceeds max-body-size",
            ));
        }
    }

    // ── Mirror body tee (independent of max-body-size, #360) ────────────────
    if !ctx.mirror_txs.is_empty() {
        if let Some(chunk) = body
            && !chunk.is_empty()
        {
            for tx in &ctx.mirror_txs {
                // Bounded channel: drop the current chunk on backpressure rather
                // than stalling the primary path. Mirror is best-effort.
                let _ = tx.try_send(chunk.clone()); // Bytes clone = refcount bump, no data copy
            }
        }
        if end_of_stream {
            // Drop all senders → closes each receiver stream → signals EOF to
            // the reqwest body wrapping that stream.
            ctx.mirror_txs.clear();
        }
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
    backend_client_cert_cache: &BackendClientCertCache,
    san_hook_cache: &SanCheckHookCache,
    circuit_breakers: &crate::policy::circuit_breaker::CircuitBreakerRegistry,
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

    // Retry backoff (#445): on a retried attempt only, wait the `RetryPolicy` minimum
    // delay before re-connecting. Guarded on `retries_used > 0` so the initial attempt
    // never sleeps (keeps the zero-retry hot path allocation- and await-free here).
    if ctx.retries_used > 0
        && let Some(delay) = resolved.backend_group.retry_policy().backoff
    {
        tokio::time::sleep(delay).await;
    }

    // Session affinity: honor a pin resolved in `request_filter` (a live cookie/header
    // match), recovering that endpoint's per-backend filters; otherwise apply the
    // per-route load-balancing algorithm via `select_upstream`. A stale pin never
    // reaches here — it resolves to `None` and re-establishes via normal selection
    // + a fresh cookie.
    let (addr, per_backend_filters) = match ctx.affinity_pin {
        Some(pinned) => (pinned, resolved.backend_group.filters_for_endpoint(pinned)),
        None => {
            // On a retry: release the prior selection's accounting before re-selecting.
            if let Some(prev_track) = ctx.lb_track.take() {
                resolved.backend_group.release(prev_track);
            }
            // Clone the Arc to avoid holding a shared borrow on `resolved` while
            // mutating `ctx.lb_track` (borrow checker splits borrows).
            let group = Arc::clone(&resolved.backend_group);
            let sel = group.select_upstream(ctx.hash_key).ok_or_else(|| {
                pingora_core::Error::explain(
                    HTTPStatus(503),
                    "no active endpoints for backend group",
                )
            })?;
            ctx.lb_track = sel.track;
            (sel.addr, sel.filters)
        }
    };
    ctx.selected_backend_filters = per_backend_filters;
    ctx.upstream_addr = Some(addr);

    // ── Circuit-breaker gate (#282) ───────────────────────────────────────────
    // When the route carries a circuit-breaker config, check whether the selected
    // endpoint's breaker permits this request. An Open breaker returns 503
    // immediately (fail-fast). Routes without the annotation short-circuit on the
    // `None` check — zero overhead.
    if let Some(cfg) = resolved.circuit_breaker.as_deref() {
        let route_id = Arc::clone(&resolved.metric_route_id);
        if !circuit_breakers.is_call_permitted(&route_id, addr, cfg) {
            ctx.circuit_breaker_rejected = true;
            return Err(pingora_core::Error::explain(
                HTTPStatus(503),
                "circuit breaker open — endpoint temporarily unavailable",
            ));
        }
    }

    let protocol = resolved.backend_group.protocol();

    // Upstream TLS is originated solely by a BackendTLSPolicy (GEP-1897); the
    // `appProtocol`-derived protocol carries no TLS semantics.
    let btls_opt = resolved.backend_group.upstream_tls();
    let (is_tls, sni_host, group_key) = if let Some(btls) = btls_opt {
        // SNI must be an owned `String`: `HttpPeer::new` takes ownership, so a
        // fresh allocation is unavoidable here regardless of any cache (#397).
        // This is once per outbound TLS connection, not per request.
        (true, btls.sni.to_string(), btls.group_key)
    } else {
        (false, String::new(), 0u64)
    };

    // Pass SocketAddr directly — avoids the per-request addr.to_string() allocation.
    let mut peer = HttpPeer::new(addr, is_tls, sni_host);
    peer.group_key = group_key;
    peer.options.verify_cert = is_tls;
    peer.options.verify_hostname = is_tls;
    if let Some(btls) = btls_opt {
        apply_upstream_tls(
            &mut peer,
            btls,
            ca_cache,
            backend_client_cert_cache,
            san_hook_cache,
        )?;
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

    // Connection timeout precedence: an explicit per-route Ingress `connect-timeout`
    // wins; else the per-backend `CoxswainBackendPolicy` connect timeout (#354); else
    // the legacy `backend_request` budget.
    let conn_timeout = explicit_connect
        .or_else(|| resolved.backend_group.connect_timeout())
        .or(backend_timeout);
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

    // Apply per-backend upstream keepalive idle timeout: the Ingress
    // `upstream-keepalive-timeout` annotation, or for Gateway-API routes the
    // `CoxswainBackendPolicy` `spec.timeouts.idle` field (#354). `None` leaves
    // Pingora's LRU-eviction default unchanged.
    if let Some(t) = resolved.backend_group.keepalive_timeout() {
        peer.options.idle_timeout = Some(t);
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

    // Strip client-supplied forwarding headers before any operator filter or
    // proxy-generated header insertion runs (#409).  The proxy owns Forwarded,
    // X-Forwarded-For, X-Forwarded-Proto, and X-Real-IP: client-injected values
    // must never reach the backend.  When PROXY protocol is active,
    // apply_request_filters below re-inserts a proxy-generated Forwarded value
    // derived from the real client address.
    TrafficFilter::strip_client_forwarding_headers(upstream_request);

    // Forward the normalized path (#280): if path normalization changed the
    // downstream path (e.g. `merge-slashes` collapsed `//`), `original_path`
    // carries the normalized form while `upstream_request` still holds the raw
    // downstream bytes.  Rewrite the clone here so all traffic filters below
    // see the correct base path and the upstream receives the normalized form.
    if !original_path.is_empty() && upstream_request.uri.path() != original_path {
        let pq = match upstream_request.uri.query() {
            Some(q) => {
                let mut pq = String::with_capacity(original_path.len() + 1 + q.len());
                pq.push_str(original_path);
                pq.push('?');
                pq.push_str(q);
                pq
            }
            None => original_path.to_string(),
        };
        if let Ok(uri) = http::Uri::builder().path_and_query(pq.as_str()).build() {
            upstream_request.set_uri(uri);
        }
    }

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

    // Auth-response headers injected by an ext_authz `allowed_upstream_headers`
    // / `headersToUpstreamOnAllow` allow-list — applied last so auth-service
    // headers cannot be overwritten by upstream header modifiers.
    if let Some(hdrs) = ctx.auth_response_headers.take() {
        for (name, value) in hdrs {
            // Parse into typed `HeaderName`/`HeaderValue` — `insert_header`
            // accepts these without a `'static` requirement.
            if let Ok(hn) = http::HeaderName::from_bytes(name.as_bytes())
                && let Ok(hv) = http::HeaderValue::from_str(value.as_ref())
            {
                let _ = upstream_request.insert_header(hn, hv);
            }
        }
    }

    // Verified client-certificate forwarding (#267): when the Ingress annotation
    // `auth-tls-pass-certificate-to-upstream: "true"` is set and a client cert was
    // verified at the TLS handshake, forward its PEM as `X-SSL-Client-Cert`
    // (URL-encoded, per nginx-ingress convention). Applied after auth-response headers
    // so auth-service overrides cannot clobber it. `.take()` clears the field so the
    // header is never duplicated on retries.
    if let Some(pem) = ctx.client_cert_pem.take() {
        let encoded = utf8_percent_encode(&pem, NON_ALPHANUMERIC).to_string();
        if let Ok(hv) = http::HeaderValue::from_str(&encoded) {
            let _ = upstream_request.insert_header("x-ssl-client-cert", hv);
        }
    }

    Ok(())
}

/// Pingora `connected_to_upstream` body: enforce the GEP-1897 backend SAN check
/// and record keepalive state metrics.
///
/// **SAN mismatch rejection.** When `subjectAltNames` were configured, the
/// post-handshake [`HandshakeCompleteHook`] in `apply_upstream_tls` records an
/// [`UpstreamSanMismatch`] marker in the connection's `SslDigest.extension` on
/// failure.  This function reads that marker and returns a 502 before any request
/// bytes are sent upstream — the connection is returned as non-reusable and is
/// never pooled.  Matched connections carry no marker and are unaffected.
///
/// **Metric.** Increments [`crate::metrics::upstream_connections_total`] with
/// `state="reused"` or `state="new"` on success.
///
/// # Errors
///
/// Returns a `502` error when the peer leaf cert's SANs do not match the
/// `BackendTLSPolicy.spec.validation.subjectAltNames` constraints.
pub(crate) fn connected_to_upstream(
    reused: bool,
    digest: Option<&pingora_core::protocols::Digest>,
) -> Result<()> {
    // Check for a SAN mismatch recorded by the handshake hook.
    let mismatch = digest
        .and_then(|d| d.ssl_digest.as_ref())
        .and_then(|sd| sd.extension.get::<UpstreamSanMismatch>())
        .is_some();
    if mismatch {
        tracing::warn!(
            "upstream SAN mismatch: peer cert does not satisfy BackendTLSPolicy \
                         subjectAltNames — rejecting connection with 502"
        );
        crate::metrics::upstream_connections_total()
            .with_label_values(&["san_mismatch"])
            .inc();
        return Err(pingora_core::Error::explain(
            HTTPStatus(502),
            "backend cert SAN does not match BackendTLSPolicy subjectAltNames",
        ));
    }

    let state = if reused { "reused" } else { "new" };
    crate::metrics::upstream_connections_total()
        .with_label_values(&[state])
        .inc();
    Ok(())
}

/// Extract the `grpc-status` code from a **trailers-only** gRPC response.
///
/// Returns `Some(code)` only when the response is gRPC (`content-type:
/// application/grpc*`) AND carries a `grpc-status` header directly — a trailers-only
/// response (HEADERS frame with END_STREAM), the sole case where nothing has been
/// streamed to the client yet and a retry is safe. A `grpc-status` arriving as a real
/// trailer after a message body is not visible here (and is not retriable), matching
/// Envoy's gRPC retry limitation.
fn grpc_trailers_only_status(resp: &ResponseHeader) -> Option<u16> {
    let ct = resp.headers.get(header::CONTENT_TYPE)?;
    if !ct.as_bytes().starts_with(b"application/grpc") {
        return None;
    }
    let gs = resp.headers.get("grpc-status")?;
    std::str::from_utf8(gs.as_bytes()).ok()?.trim().parse().ok()
}

/// Pingora `upstream_response_filter` body: apply rule-level response filters and
/// trigger a retry when the upstream returns a retriable response and the route allows it.
///
/// ## Response-code retries (#445)
///
/// When the response status is in the route's `RetryPolicy.http_codes` (HTTP) or a
/// trailers-only `grpc-status` is in `grpc_codes` (gRPC) and the `attempts` budget
/// remains, this function returns a retryable `Err` so Pingora re-enters the retry loop
/// and calls `upstream_peer` again. On the **final** attempt (budget exhausted) the
/// response passes through to the client unmodified.
///
/// **Replay guard**: retries are suppressed when `session.retry_buffer_truncated()`
/// is true — large or streaming request bodies cannot be replayed safely.
///
/// # Errors
/// Propagates header-mutation errors from [`TrafficFilter::apply_response_filters`]
/// and returns a retryable upstream error when a response-code retry is triggered.
pub(crate) async fn upstream_response_filter(
    session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut ProxyCtx,
) -> Result<()> {
    if let Some(resolved) = &ctx.resolved {
        TrafficFilter::apply_response_filters(
            upstream_response,
            &resolved.filters,
            ctx.cors_origin.as_deref(),
        );
    }

    // Session affinity (cookie mode): when a fresh pin was established this request,
    // stamp the affinity cookie so the client returns to the same endpoint. Skipped
    // entirely for header mode and for requests that already carried a valid cookie.
    if ctx.affinity_set_cookie
        && let Some(addr) = ctx.upstream_addr
        && let Some(SessionAffinity::Cookie { cookie_name }) = ctx
            .resolved
            .as_ref()
            .and_then(|r| r.backend_group.session_affinity())
    {
        affinity::inject_set_cookie(upstream_response, cookie_name, addr)?;
    }

    let status = upstream_response.status.as_u16();
    if status >= 500 {
        crate::retry::inc_upstream_error(ctx, "5xx");
    }

    // Response-code retry (#445). Decide without holding a borrow of `ctx` across the
    // mutation below. Two mutually exclusive paths:
    //  - gRPC: a trailers-only response (status usually 200) whose `grpc-status` is in
    //    `RetryPolicy.grpc_codes`. Only trailers-only is retriable — nothing streamed yet.
    //  - HTTP: response status is in `RetryPolicy.http_codes`.
    let grpc_status = grpc_trailers_only_status(upstream_response);
    let decision: Option<(RetryTrigger, &'static str)> = ctx.resolved.as_ref().and_then(|r| {
        let policy = r.backend_group.retry_policy();
        if ctx.retries_used >= policy.attempts {
            return None;
        }
        match grpc_status {
            // gRPC application outcome: HTTP `codes` do not apply (status is 200).
            Some(code) if policy.retries_grpc(code) => Some((RetryTrigger::GrpcCode, "grpc-code")),
            Some(_) => None,
            None if policy.retries_http(status) => Some((RetryTrigger::HttpCode, "http-code")),
            None => None,
        }
    });

    if let Some((trigger, condition)) = decision
        && !session.as_ref().retry_buffer_truncated()
    {
        ctx.retries_used += 1;
        ctx.last_retry_trigger = Some(trigger);
        crate::retry::inc_upstream_retry(ctx, condition);
        let mut e = Error::explain(
            HTTPStatus(status),
            format!(
                "upstream returned a retriable response ({condition}); retrying (attempt {})",
                ctx.retries_used
            ),
        );
        e.retry = true.into();
        e.as_up();
        return Err(e);
    }

    // Response compression (#270): set up a streaming encoder when the route has
    // compression enabled and this response qualifies. Must run after the 5xx retry
    // check so we do not set up an encoder for a response we are about to discard.
    if let Some(cfg) = ctx.resolved.as_ref().and_then(|r| r.compression.clone()) {
        crate::policy::compression::maybe_setup_compression(
            session.req_header(),
            upstream_response,
            ctx,
            &cfg,
        );
    }

    Ok(())
}

/// Pingora `response_body_filter` body: stream each response body chunk
/// through the per-request compression encoder (if active).
///
/// Called once per body chunk and once more with `end_of_stream = true` (which
/// may carry an empty `body`).  When `ctx.compression_encoder` is `Some`, feeds
/// the chunk through `Encode::encode` and replaces `*body` with the compressed
/// output.  When encoding fails, the encoder is dropped and the failing chunk is
/// passed through uncompressed (partial compression is better than a broken
/// stream).
///
/// # Errors
///
/// Returns `Ok(())` always — encoding failures are logged and recovered by
/// disabling the encoder, not by aborting the request.
pub(crate) fn response_body_filter(
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut ProxyCtx,
) -> Result<()> {
    let Some(encoder) = ctx.compression_encoder.as_mut() else {
        return Ok(());
    };

    // Feed the chunk (or empty slice on EOS) through the encoder.
    // We must call encode even on an empty body when end_of_stream is true
    // so the encoder can flush its trailer bytes.
    let input: &[u8] = body.as_deref().map_or(&[], |b| b);
    match encoder.encode(input, end_of_stream) {
        Ok(compressed) => {
            *body = if compressed.is_empty() {
                // Encoder may buffer small chunks; emit nothing yet.
                None
            } else {
                Some(compressed)
            };
        }
        Err(e) => {
            tracing::warn!(error = %e, "compression encode error — disabling encoder for response");
            ctx.compression_encoder = None;
            // Pass the original chunk through unchanged.
        }
    }

    Ok(())
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
    circuit_breakers: &crate::policy::circuit_breaker::CircuitBreakerRegistry,
    session: &mut Session,
    e: Option<&pingora_core::Error>,
    ctx: &ProxyCtx,
) {
    let req = session.req_header();
    let method = req.method.as_str();
    let status = session.response_written().map(|h| h.status.as_u16());
    let bytes_sent = session.body_bytes_sent() as u64;
    let duration = ctx.start.map(|s| s.elapsed());
    let duration_ms = duration.unwrap_or_default().as_millis() as u64;

    // LB accounting: complete the in-flight tracking for LeastConn/Ewma (#275).
    // Always fires; `None` lb_track (RoundRobin, IpHash, GW-API routes) is a no-op.
    if let (Some(idx), Some(r)) = (ctx.lb_track, ctx.resolved.as_ref()) {
        r.backend_group.complete(idx, duration);
    }

    // Circuit-breaker outcome recording (#282).
    // Only record when: the route has a breaker config, an upstream address was
    // selected, and the request was not fail-fast rejected (no real upstream attempt
    // was made in that case, so there is no outcome to record).
    if !ctx.circuit_breaker_rejected
        && let (Some(cfg), Some(addr), Some(r)) = (
            ctx.resolved
                .as_ref()
                .and_then(|r| r.circuit_breaker.as_deref()),
            ctx.upstream_addr,
            ctx.resolved.as_ref(),
        )
    {
        let success = status.is_some_and(|s| s < 500);
        circuit_breakers.record(&r.metric_route_id, addr, cfg, success);
    }

    // Prefer the pre-resolved host from context; fall back to parsing the header.
    let host: &str = ctx
        .resolved
        .as_ref()
        .map(|r| r.original_host.as_ref())
        .unwrap_or_else(|| extract_host(req));

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
        .observe(duration.unwrap_or_default().as_secs_f64());

    // Suppress when the global flag is off, or when the matched class suppresses (#279).
    // Metrics above are always emitted; only the access-log line is gated here.
    let class_suppressed = ctx
        .resolved
        .as_ref()
        .is_some_and(|r| r.access_log_enabled == Some(false));
    if !access_log_enabled || class_suppressed {
        return;
    }

    // `SocketAddr::to_string` / `IpAddr::to_string` allocate — keep both inside the
    // access-log branch so operators silencing the log don't pay the alloc every request.
    let upstream_addr_str = ctx.upstream_addr.map(|a| a.to_string());
    let client_ip_str = ctx.client_ip.map(|ip| ip.to_string());

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
        client_ip = client_ip_str.as_deref(),
        duration_ms = duration_ms,
        bytes_sent = bytes_sent,
        error = err_msg.as_deref(),
        "access",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_limit(limit: u64, is_h2: bool) -> ProxyCtx {
        ProxyCtx {
            max_body_size: Some(limit),
            is_h2,
            ..Default::default()
        }
    }

    #[test]
    fn body_filter_rejects_oversized_on_h1() {
        let mut ctx = ctx_with_limit(10, false);
        let chunk = Bytes::from(vec![0u8; 20]);
        // Over the 10-byte cap on an HTTP/1.x session → 413.
        assert!(request_body_filter(Some(&chunk), true, &mut ctx).is_err());
    }

    #[test]
    fn body_filter_allows_underlimit_on_h1() {
        let mut ctx = ctx_with_limit(100, false);
        let chunk = Bytes::from(vec![0u8; 20]);
        assert!(request_body_filter(Some(&chunk), true, &mut ctx).is_ok());
    }

    #[test]
    fn body_filter_never_rejects_on_h2() {
        // #509: returning Err here on an h2 session deadlocks the client, so the
        // mid-stream cap must be skipped entirely regardless of body size.
        let mut ctx = ctx_with_limit(10, true);
        let chunk = Bytes::from(vec![0u8; 1_000]);
        assert!(request_body_filter(Some(&chunk), true, &mut ctx).is_ok());
        // Counter is not even advanced on h2 (enforcement is fully disabled).
        assert_eq!(ctx.body_bytes_seen, 0);
    }
}
