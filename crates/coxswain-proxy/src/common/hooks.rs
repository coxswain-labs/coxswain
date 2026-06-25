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

use super::affinity;
use super::ctx::{CONN_INFO, MirrorDispatch, ProxyCtx, ResolvedRoute};
use super::engine::RoutingEngine;
use super::filter::TrafficFilter;
use super::outcome::{merge_timeouts, resolve_outcome, try_cors_preflight, try_redirect};
use super::redirect::extract_host;
use crate::auth;
use crate::config::AccessLogPathMode;
use crate::tls::ConnTlsInfo;
use crate::upstream_ca::UpstreamCaCache;
use bytes::Bytes;
use coxswain_cache::ResponseCache;
use coxswain_core::routing::{
    BackendGroup, BackendProtocol, CompressionConfig, FilterAction, ForwardedForConfig, HashSource,
    MirrorFraction, RateLimitKey, RequestContext, RetryOn, SessionAffinity, UpstreamCa,
    affinity_hash, affinity_hash_parts,
};
use coxswain_core::tls::ClientCertConfigState;
use http::header;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use pingora_cache::key::{CacheKey, HashBinary};
use pingora_cache::{CacheMeta, NoCacheReason, RespCacheable, VarianceBuilder};
use pingora_core::protocols::http::compression::Algorithm;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{
    ConnectTimedout, ConnectionClosed, Error, ErrorSource, HTTPStatus, ReadError, ReadTimedout,
    Result, WriteError, WriteTimedout,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, Session};
use std::sync::Arc;
use std::time::Instant;

/// Headers stripped from mirror sub-requests beyond the standard hop-by-hop set.
///
/// `Authorization` and `Cookie` carry per-user credentials that must not be
/// forwarded to mirror (shadow) backends — those backends are secondary/test
/// endpoints that the Ingress author may not fully control.  Leaking them would
/// make the mirror a credential-harvesting surface.
///
/// `proxy-authorization` is already covered by [`crate::auth::HOP_BY_HOP`];
/// it is listed here for documentation clarity.
const MIRROR_CREDENTIAL_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

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
            affinity_pin: None,
            affinity_set_cookie: false,
            auth_response_headers: None,
            mirrors: Vec::new(),
            mirror_body: Vec::new(),
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
    {
        let cc_store = cfg.client_certs.load();
        if let Some(config_state) = cc_store.find_config(&host) {
            let ssl_digest = session
                .as_downstream()
                .digest()
                .and_then(|d| d.ssl_digest.as_ref());
            if let Some(ssl_digest) = ssl_digest {
                let cert_info = ssl_digest
                    .extension
                    .get::<ConnTlsInfo>()
                    .and_then(|t| t.client_cert.as_ref());
                if cert_info.is_none() {
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
    if let Some(nets) = m.deny_source_range.as_deref() {
        let client_ip = ctx.client_ip;
        if ip_denied(client_ip, nets) {
            return Err(pingora_core::Error::explain(
                HTTPStatus(403),
                "client IP in deny-list",
            ));
        }
    }

    // Per-route source-IP allow-list (ingress.coxswain-labs.dev/allow-source-range).
    // Access control runs ahead of redirect and body handling — so a denied client
    // never receives a redirect (which would leak the canonical host/URL) nor has
    // its body read. The real client IP is resolved once by resolve_client_ip (above)
    // and cached on ctx — no per-request allocation for the CIDR scan.
    if let Some(nets) = m.allow_source_range.as_deref()
        && !ip_allowed(ctx.client_ip, nets)
    {
        return Err(pingora_core::Error::explain(
            HTTPStatus(403),
            "client IP not in allow-list",
        ));
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
            crate::rate_limit::extract_client_key(rl_config, client_ip, header_val)
        };
        if let Some(key) = client_key
            && let crate::rate_limit::CheckOutcome::Limited { retry_after_secs } =
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

    // Per-route external auth (#24). Runs after the allow-list (denied clients
    // never consume an auth-service round-trip) and before redirect (an
    // unauthenticated client must not receive a redirect leaking the canonical
    // URL). `enforce()` writes a denial response and returns `Ok(true)`.
    if let Some(auth) = m.auth.as_deref()
        && crate::auth::enforce(
            &cfg.auth_client,
            auth,
            session,
            &mut ctx.auth_response_headers,
        )
        .await?
    {
        return Ok(true);
    }

    let timeouts = merge_timeouts(&m.timeouts, &cfg.default_timeouts);
    ctx.request_deadline = timeouts.request.map(|d| Instant::now() + d);

    // CORS preflight short-circuit (GEP-1767, #41).
    // OPTIONS + Access-Control-Request-Method with a matched Origin → 204, no upstream.
    if try_cors_preflight(session, &m.filters, ctx.cors_origin.as_deref()).await? {
        return Ok(true);
    }

    if try_redirect(
        session,
        &m.filters,
        proto,
        &host,
        port,
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
        cache_enabled: m.cache_enabled,
        access_log_enabled: m.access_log_enabled,
        compression: m.compression,
        circuit_breaker: m.circuit_breaker,
    });

    // ── Mirror setup (#283, #261) ───────────────────────────────────────────
    // Collect all Mirror filters, applying per-filter sampling gates (GEP-3171).
    // Non-mirror routes pay nothing — the filter() short-circuits immediately when
    // no Mirror variant is present and no Vec is allocated (the iterator is lazy).
    let mirror_backends: Vec<(Arc<BackendGroup>, Option<MirrorFraction>)> = ctx
        .resolved
        .as_ref()
        .map(|r| {
            r.filters
                .iter()
                .filter_map(|f| {
                    if let FilterAction::Mirror { backend, fraction } = f {
                        Some((Arc::clone(backend), *fraction))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if !mirror_backends.is_empty() {
        // Apply GEP-3171 sampling: draw one random u32 per mirror candidate and
        // discard candidates whose fraction gate rejects the draw.
        // `None` fraction == 100% — never filtered out.
        let surviving: Vec<Arc<BackendGroup>> = mirror_backends
            .into_iter()
            .filter(|(_, fraction)| {
                fraction.map_or(true, |f| f.should_sample(rand::random::<u32>()))
            })
            .map(|(b, _)| b)
            .collect();

        if !surviving.is_empty() {
            let method;
            let headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>;
            {
                // Re-borrow req_header to capture method + forwardable headers.
                // The mutable session borrows above (auth, rate-limit, redirect) have already
                // completed; this is a fresh immutable borrow, released before the ctx mutation.
                let req = session.req_header();
                method = req.method.clone();
                headers = req
                    .headers
                    .iter()
                    .filter_map(|(name, value)| {
                        let lower = name.as_str().to_ascii_lowercase();
                        if lower == "host"
                            || auth::HOP_BY_HOP.contains(&lower.as_str())
                            || MIRROR_CREDENTIAL_HEADERS.contains(&lower.as_str())
                        {
                            return None;
                        }
                        Some((name.clone(), value.clone()))
                    })
                    .collect();
            } // req borrow released

            let resolved = ctx
                .resolved
                .as_ref()
                .unwrap_or_else(|| panic!("invariant: resolved is Some after assignment above"));
            let host = resolved.original_host.clone();
            let original_path = resolved.original_path.clone();
            let metric_route_id = Arc::clone(&resolved.metric_route_id);
            // Reuse the captured `Arc<str>` when there is no query to append — only the
            // query arm allocates (#397).
            let path_and_query: Arc<str> = match query.as_deref() {
                Some(q) => {
                    let mut pq = String::with_capacity(original_path.len() + 1 + q.len());
                    pq.push_str(&original_path);
                    pq.push('?');
                    pq.push_str(q);
                    Arc::from(pq)
                }
                None => Arc::clone(&original_path),
            };

            // Build one MirrorDispatch per surviving backend, sharing immutable
            // captures via Arc clone (no data copy).
            let dispatches: Vec<MirrorDispatch> = surviving
                .into_iter()
                .map(|backend| MirrorDispatch {
                    backend,
                    method: method.clone(),
                    host: Arc::clone(&host),
                    path_and_query: Arc::clone(&path_and_query),
                    headers: headers.clone(),
                    metric_route_id: Arc::clone(&metric_route_id),
                })
                .collect();

            if ctx.max_body_size.is_none() {
                // Header-only mode: no body will be buffered; dispatch all now.
                // Covers bodyless methods (GET, HEAD) and routes without max-body-size.
                for dispatch in dispatches {
                    spawn_mirror_dispatch(
                        dispatch,
                        cfg.auth_client.clone(),
                        Bytes::new(),
                        &cfg.mirror_tracker,
                    );
                }
            } else {
                // Body-buffering mode: stash dispatches; request_body_filter accumulates
                // chunks and dispatches all on end_of_stream.
                ctx.mirrors = dispatches;
            }
        }
    }

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

/// Private and reserved IP ranges that are never treated as a real client IP when
/// extracting from a forwarded header.  Includes RFC 1918 private ranges, loopback,
/// link-local, ULA (fc00::/7), and the unspecified address.
static PRIVATE_NETS: std::sync::LazyLock<[ipnet::IpNet; 9]> = std::sync::LazyLock::new(|| {
    [
        "10.0.0.0/8"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "172.16.0.0/12"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "192.168.0.0/16"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "127.0.0.0/8"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "169.254.0.0/16"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "::1/128"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "fe80::/10"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "fc00::/7"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
        "::/128"
            .parse()
            .unwrap_or_else(|e| panic!("invariant: {e}")),
    ]
});

/// Scan a comma-separated header value for the first non-private, non-loopback
/// IP address.  Returns `None` when every token is private, unparseable, or the
/// value is empty.
///
/// "First" is left-to-right per the XFF convention: the leftmost value is the
/// one closest to the original client and furthest from potential LB injection.
fn first_non_private_ip(header_value: &str) -> Option<std::net::IpAddr> {
    header_value
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse::<std::net::IpAddr>().ok())
        .find(|ip| !PRIVATE_NETS.iter().any(|n| n.contains(ip)))
}

/// Resolve the effective client IP for the current request.
///
/// Resolution order (per `ForwardedForConfig` doc):
/// 1. If no config → L4 IP (current behavior).
/// 2. If `trusted_cidrs` non-empty AND L4 IP ∉ any CIDR → L4 IP (anti-spoofing).
/// 3. Else extract the first non-private IP from the configured header; fall back
///    to L4 IP when absent or all entries are private.
fn resolve_client_ip(
    session: &Session,
    real_client_addr: Option<std::net::SocketAddr>,
    fwd: Option<&ForwardedForConfig>,
) -> Option<std::net::IpAddr> {
    let l4_ip = real_client_addr.map(|a| a.ip()).or_else(|| {
        session
            .as_downstream()
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip())
    });

    let Some(cfg) = fwd else {
        return l4_ip;
    };

    // Anti-spoofing gate: if trusted CIDRs are configured, only trust the header
    // when the L4 peer is within one of those CIDRs.
    if !cfg.trusted_cidrs.is_empty()
        && !l4_ip.is_some_and(|ip| cfg.trusted_cidrs.iter().any(|n| n.contains(&ip)))
    {
        return l4_ip;
    }

    // Trust the header: grab the forwarded-IP value and find the first public IP.
    let header_ip = session
        .req_header()
        .headers
        .get(cfg.header.as_ref())
        .and_then(|v| v.to_str().ok())
        .and_then(first_non_private_ip);

    header_ip.or(l4_ip)
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

/// Returns `true` if `client_ip` falls inside any CIDR in the deny-list `nets`.
///
/// Inverse-fail-open on identity: a `None` client IP (peer could not be determined)
/// is **not** considered to match any CIDR and is therefore **not** denied — a block
/// list only blocks IPs it can positively attribute to a listed range. This is the
/// inverse of [`ip_allowed`]'s fail-closed semantics.
/// Matching is strict (no IPv4-mapped-IPv6 normalization).
#[must_use]
pub(crate) fn ip_denied(client_ip: Option<std::net::IpAddr>, nets: &[ipnet::IpNet]) -> bool {
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
///
/// A response carrying `Set-Cookie` is refused outright: `resp_cacheable` would
/// otherwise store and replay the cookie verbatim to every client (it only
/// strips it when the origin uses the qualified `Cache-Control: no-cache=
/// "set-cookie"` form), which is session leakage / cache poisoning on a shared
/// cache. RFC 7234 §3 permits caching `Set-Cookie` responses only with explicit
/// authorization; we take the conservative stance and never do.
pub(crate) fn response_cache_filter(resp: &ResponseHeader) -> RespCacheable {
    if resp.headers.contains_key(http::header::SET_COOKIE) {
        return RespCacheable::Uncacheable(NoCacheReason::OriginNotCache);
    }
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
/// on streaming/chunked uploads and buffer body chunks for fire-and-forget mirroring.
///
/// Called for every chunk of the request body (including a final call with
/// `end_of_stream = true` when the body is complete). Accumulates the running byte
/// count on the [`ProxyCtx`] and, once it exceeds the route's `max-body-size`, returns
/// `Err(Error::explain(413, …))`. Pingora propagates that through `fail_to_proxy`,
/// which writes a clean `413 Payload Too Large` to the client. The body is not buffered
/// for size enforcement — the `u64` counter is the only state — so this stays within the
/// hot-path allocation budget. No-ops for size enforcement when the route carries no
/// limit (every Gateway-API route, and Ingress routes without the annotation).
///
/// When `mirror-target` is active and `max-body-size` is set, each chunk is also teed
/// into [`ProxyCtx::mirror_body`] (a [`Bytes`] refcount clone — no data copy). On
/// `end_of_stream` the mirror dispatch fires fire-and-forget via [`spawn_mirror_dispatch`].
/// The `auth_client` is only cloned when a mirror dispatch is triggered (i.e., when
/// `ctx.mirrors.is_empty()` is false and `end_of_stream` is true).
///
/// # Errors
/// Returns `Error::explain(413, …)` once the cumulative body size exceeds the limit.
pub(crate) fn request_body_filter(
    body: Option<&Bytes>,
    end_of_stream: bool,
    cfg: &crate::config::SharedProxyConfig,
    ctx: &mut ProxyCtx,
) -> Result<()> {
    // ── Body size enforcement (unchanged) ────────────────────────────────────
    if let Some(limit) = ctx.max_body_size {
        ctx.body_bytes_seen = ctx
            .body_bytes_seen
            .saturating_add(body.map_or(0, Bytes::len) as u64);
        if ctx.body_bytes_seen > limit {
            return Err(pingora_core::Error::explain(
                HTTPStatus(413),
                "request body exceeds max-body-size",
            ));
        }

        // ── Mirror body tee ──────────────────────────────────────────────────
        // Only active when mirror dispatches are pending and body buffering is configured
        // (max-body-size implies a bounded buffer; #263 rejects over-cap bodies above,
        // so the mirror buffer is inherently bounded at the same cap).
        if !ctx.mirrors.is_empty() {
            if let Some(chunk) = body
                && !chunk.is_empty()
            {
                ctx.mirror_body.push(chunk.clone()); // refcount bump, no data copy
            }
            if end_of_stream {
                let body_bytes: Bytes = if ctx.mirror_body.is_empty() {
                    Bytes::new()
                } else {
                    let total: usize = ctx.mirror_body.iter().map(Bytes::len).sum();
                    let mut buf = bytes::BytesMut::with_capacity(total);
                    for chunk in ctx.mirror_body.drain(..) {
                        buf.extend_from_slice(&chunk);
                    }
                    buf.freeze()
                };
                // Dispatch all pending mirrors, sharing the assembled body via
                // Bytes refcount clone (no extra data copy per mirror).
                for dispatch in ctx.mirrors.drain(..) {
                    spawn_mirror_dispatch(
                        dispatch,
                        cfg.auth_client.clone(),
                        body_bytes.clone(),
                        &cfg.mirror_tracker,
                    );
                }
            }
        }
    }
    Ok(())
}

/// Dispatch a fire-and-forget mirror request, discarding the response.
///
/// Spawns a Tokio task that:
/// 1. Selects one endpoint from `dispatch.backend` via weighted round-robin.
/// 2. Builds a `reqwest` request with the original method, forwarded headers, and
///    the assembled body (empty for header-only mirrors).
/// 3. Sends with a bounded 5-second timeout (mirror latency must not stall the caller).
/// 4. Discards the response entirely.
/// 5. Emits a `coxswain_proxy::access` log row tagged `mirror = true` carrying
///    `host`, `path`, `upstream`, and `status` (the primary observability signal
///    for mirroring and the e2e side channel for asserting mirror receipt).
/// 6. Emits `WARN` on connect/send errors or timeout and drops the mirror.
///
/// The spawned task owns all its data; no session or primary-path state is borrowed.
fn spawn_mirror_dispatch(
    dispatch: MirrorDispatch,
    client: reqwest::Client,
    body: Bytes,
    tracker: &tokio_util::task::TaskTracker,
) {
    // Bump synchronously before spawning so the counter is updated by the time
    // the primary request returns — enables deterministic negative assertions in
    // tests without requiring an async poll.  The upstream label uses the backend
    // group name (ns/service) rather than the resolved addr because addr
    // selection is round-robin inside the spawned task.
    crate::metrics::mirror_requests_total()
        .with_label_values(&[dispatch.metric_route_id.as_ref(), dispatch.backend.name()])
        .inc();

    tracker.spawn(async move {
        let Some((addr, _)) = dispatch.backend.next_endpoint_with_filters() else {
            tracing::warn!(
                host = %dispatch.host,
                "mirror-target has no active endpoints — dropping mirror"
            );
            return;
        };

        let scheme = match dispatch.backend.protocol() {
            BackendProtocol::Https => "https",
            _ => "http",
        };

        use std::fmt::Write;
        let mut url = String::with_capacity(scheme.len() + 3 + 45 + dispatch.path_and_query.len());
        let _ = write!(&mut url, "{}://{}{}", scheme, addr, dispatch.path_and_query);

        let mut builder = client.request(dispatch.method.clone(), &url).body(body);

        // Re-inject the original Host first (reqwest strips it by default).
        builder = builder.header(reqwest::header::HOST, dispatch.host.as_ref());

        for (name, value) in &dispatch.headers {
            builder = builder.header(name, value);
        }

        const MIRROR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        let status = match tokio::time::timeout(MIRROR_TIMEOUT, builder.send()).await {
            Ok(Ok(resp)) => {
                let s = resp.status().as_u16();
                // Discard the response body (no await on body, just drop the response).
                s
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    host = %dispatch.host,
                    upstream = %addr,
                    error = %e,
                    "mirror dispatch failed — dropping mirror"
                );
                return;
            }
            Err(_elapsed) => {
                tracing::warn!(
                    host = %dispatch.host,
                    upstream = %addr,
                    timeout_ms = MIRROR_TIMEOUT.as_millis(),
                    "mirror dispatch timed out — dropping mirror"
                );
                return;
            }
        };

        // Emit an access-log row for the mirror sub-request so operators can
        // observe mirror traffic and e2e tests can assert mirror receipt.
        tracing::info!(
            target: "coxswain_proxy::access",
            mirror = true,
            host = %dispatch.host,
            path = %dispatch.path_and_query,
            upstream = %addr,
            status = status,
            "mirror",
        );
    });
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
    circuit_breakers: &crate::circuit_breaker::CircuitBreakerRegistry,
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
            // SNI must be an owned `String`: `HttpPeer::new` takes ownership, so a
            // fresh allocation is unavoidable here regardless of any cache (#397).
            // This is once per outbound TLS connection, not per request.
            (true, btls.sni.to_string(), btls.group_key, ca)
        } else if protocol.is_tls() {
            // appProtocol-driven TLS: use the request Host as SNI (existing behaviour).
            // Owned for the same `HttpPeer::new` reason as the BackendTLSPolicy arm.
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

    // Apply per-route upstream keepalive idle timeout (Ingress-only; Gateway-API routes
    // leave this None and Pingora uses its LRU-eviction default).
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

/// Pingora `connected_to_upstream` body: record whether the connection to the
/// upstream was freshly established or reused from the keepalive pool.
///
/// Increments [`crate::metrics::upstream_connections_total`] with
/// `state="reused"` or `state="new"` — the only labels that make this metric
/// meaningful for keepalive observability. No allocation: the label values are
/// `'static` string literals.
pub(crate) fn connected_to_upstream(reused: bool) {
    let state = if reused { "reused" } else { "new" };
    crate::metrics::upstream_connections_total()
        .with_label_values(&[state])
        .inc();
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

    // Response compression (#270): set up a streaming encoder when the route has
    // compression enabled and this response qualifies. Must run after the 5xx retry
    // check so we do not set up an encoder for a response we are about to discard.
    if let Some(cfg) = ctx.resolved.as_ref().and_then(|r| r.compression.clone()) {
        maybe_setup_compression(session.req_header(), upstream_response, ctx, &cfg);
    }

    Ok(())
}

/// Decide whether to compress this response and, if so, initialise a streaming
/// encoder on `ctx.compression_encoder`.
///
/// Called from [`upstream_response_filter`] when the matched route carries a
/// [`CompressionConfig`].  The decision is a conjunction of five guards:
///
/// 1. The response status is a normal body-bearing code (not 1xx/204/304).
/// 2. The response does not already have a `Content-Encoding` header.
/// 3. The response `Content-Type` (media type before `;`) is in the allow-list.
/// 4. The response `Content-Length` is either absent or ≥ `min_size`.
/// 5. The client's `Accept-Encoding` advertises at least one enabled codec.
///    Brotli is preferred when both are enabled and `br` is offered.
///
/// On a positive decision, the encoder is stored in `ctx.compression_encoder`;
/// the response headers are adjusted (add `Content-Encoding`, add/extend `Vary`,
/// remove `Content-Length` and `Accept-Ranges`) so that downstream sees a chunked
/// compressed body. On any negative branch the function returns without touching
/// `ctx` or the headers.
fn maybe_setup_compression(
    req: &RequestHeader,
    resp: &mut ResponseHeader,
    ctx: &mut ProxyCtx,
    cfg: &CompressionConfig,
) {
    use http::header::{
        ACCEPT_RANGES, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING, VARY,
    };

    // Guard 1: skip 1xx, 204 (no content), 304 (not modified) — no body.
    let status = resp.status.as_u16();
    if status < 200 || status == 204 || status == 304 {
        return;
    }

    // Guard 2: already compressed — pass through untouched.
    if resp.headers.contains_key(CONTENT_ENCODING) {
        return;
    }

    // Guard 3: Content-Type must be in the allow-list.
    let ct = resp
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .unwrap_or("");
    if !cfg.allows_type(ct) {
        return;
    }

    // Guard 4: Content-Length, when present, must be >= min_size.
    // Absent Content-Length (chunked upstream) is allowed — we cannot know the
    // size in advance, so we compress optimistically.
    if let Some(cl_val) = resp.headers.get(CONTENT_LENGTH) {
        let cl: u64 = std::str::from_utf8(cl_val.as_bytes())
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if cl < cfg.min_size {
            return;
        }
    }

    // Guard 5: client Accept-Encoding — pick algorithm (brotli preferred).
    let ae = req
        .headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .unwrap_or("");

    let algorithm = choose_algorithm(ae, cfg);
    let Some(algorithm) = algorithm else {
        return;
    };

    // Build the encoder. `Algorithm::compressor` may return None for unknown
    // algorithms, but Gzip and Brotli always return Some.
    let Some(encoder) = algorithm.compressor(cfg.level) else {
        return;
    };

    ctx.compression_encoder = Some(encoder);

    // Adjust response headers: set Content-Encoding, extend Vary, remove
    // Content-Length (body length changes) and Accept-Ranges (ranges are
    // meaningless on a compressed stream).
    let ce_value = match algorithm {
        Algorithm::Gzip => "gzip",
        Algorithm::Brotli => "br",
        // Safety: choose_algorithm only returns Gzip or Brotli.
        _ => return,
    };

    // Vary: extend the existing value rather than clobber it.
    let vary = resp
        .headers
        .get(VARY)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let new_vary = match vary {
        Some(existing) if existing.to_ascii_lowercase().contains("accept-encoding") => existing,
        Some(existing) => format!("{existing}, Accept-Encoding"),
        None => "Accept-Encoding".to_string(),
    };

    // Use Pingora's safe header API so both `base.headers` and `header_name_map`
    // stay in sync.  Direct `resp.headers.insert/remove` (via DerefMut) only
    // touches `base.headers`; `write_response_header` later zips the two maps
    // via `case_header_iter` and asserts key-order parity — a mismatch panics,
    // aborting the proxy process (`panic = "abort"` in release profile).
    let _ = resp.insert_header(CONTENT_ENCODING, ce_value);
    let _ = resp.insert_header(VARY, new_vary.as_str());
    resp.remove_header(&CONTENT_LENGTH);
    resp.remove_header(&ACCEPT_RANGES);
    // Pingora's H1 handler decides whether to add Transfer-Encoding: chunked
    // *before* calling upstream_response_filter, based on the upstream's
    // Content-Length.  Because we remove Content-Length here, we must set
    // chunked ourselves so the downstream has a valid body framing.
    let _ = resp.insert_header(TRANSFER_ENCODING, "chunked");
}

/// Choose a compression algorithm from the client's `Accept-Encoding` string,
/// respecting the route's `gzip` / `brotli` flags. Brotli is preferred when both
/// are enabled and the client advertises `br`.
///
/// Returns `None` when no enabled algorithm is offered by the client.
fn choose_algorithm(accept_encoding: &str, cfg: &CompressionConfig) -> Option<Algorithm> {
    let brotli_offered = accept_encoding
        .split(',')
        .map(|t| t.trim().split(';').next().unwrap_or("").trim())
        .any(|t| t.eq_ignore_ascii_case("br"));
    let gzip_offered = accept_encoding
        .split(',')
        .map(|t| t.trim().split(';').next().unwrap_or("").trim())
        .any(|t| t.eq_ignore_ascii_case("gzip"));

    if cfg.brotli && brotli_offered {
        Some(Algorithm::Brotli)
    } else if cfg.gzip && gzip_offered {
        Some(Algorithm::Gzip)
    } else {
        None
    }
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

/// Select the HTTP status for a failed proxy attempt from the Pingora error and
/// the per-request timeout-attribution flags.
///
/// Extracted from [`fail_to_proxy`] so the mapping is unit-testable without
/// constructing a live [`Session`].
///
/// # Status rules
///
/// - `HTTPStatus(code)` — passthrough (Pingora-level overrides).
/// - `ReadTimedout | WriteTimedout` while a request or backend-request budget is
///   controlling → 504 (Gateway API spec, GEP-1742).
/// - `ConnectTimedout` while a backend-request budget is active → 502.
/// - Everything else: 502 for upstream sources, 0 (no response written) for
///   downstream connection-level errors, 400 for other downstream errors, 500
///   for internal faults.
fn select_failure_status(
    etype: &pingora_core::ErrorType,
    esource: &ErrorSource,
    request_timeout_is_controlling: bool,
    backend_request_timeout_active: bool,
) -> u16 {
    match etype {
        HTTPStatus(code) => *code,
        // request/backendRequest read/write timeouts → 504 (Gateway API spec, GEP-1742).
        // Connect failure while backendRequest active → 502 (upstream unreachable).
        // Flags set in upstream_peer avoid races with OS timer granularity.
        ReadTimedout | WriteTimedout
            if request_timeout_is_controlling || backend_request_timeout_active =>
        {
            504
        }
        ConnectTimedout if backend_request_timeout_active => 502,
        _ => match esource {
            ErrorSource::Upstream => 502,
            ErrorSource::Downstream => match etype {
                ConnectionClosed | ReadError | WriteError => 0,
                _ => 400,
            },
            _ => 500,
        },
    }
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
    let code = select_failure_status(
        e.etype(),
        e.esource(),
        ctx.request_timeout_is_controlling,
        ctx.backend_request_timeout_active,
    );
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
    circuit_breakers: &crate::circuit_breaker::CircuitBreakerRegistry,
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
    use super::{ip_allowed, ip_denied};
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

    // ── ip_denied ─────────────────────────────────────────────────────────────

    #[test]
    fn in_range_v4_denied() {
        assert!(ip_denied(ip("10.1.2.3"), &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn out_of_range_v4_not_denied() {
        assert!(!ip_denied(ip("192.168.0.1"), &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn in_range_v6_denied() {
        assert!(ip_denied(ip("2001:db8::1"), &nets(&["2001:db8::/32"])));
    }

    #[test]
    fn out_of_range_v6_not_denied() {
        assert!(!ip_denied(ip("2001:dead::1"), &nets(&["2001:db8::/32"])));
    }

    #[test]
    fn missing_client_ip_is_not_denied_fail_open() {
        // A peer we cannot attribute must NOT be auto-denied — a block list only
        // blocks IPs it can positively attribute to a listed range.
        assert!(!ip_denied(None, &nets(&["10.0.0.0/8"])));
    }

    #[test]
    fn empty_deny_list_denies_nothing() {
        assert!(!ip_denied(ip("10.0.0.1"), &[]));
    }

    #[test]
    fn v4_mapped_v6_does_not_match_deny_v4_cidr() {
        // Strict matching: an IPv4-mapped IPv6 client does NOT match an IPv4 deny CIDR.
        assert!(!ip_denied(ip("::ffff:10.0.0.1"), &nets(&["10.0.0.0/8"])));
    }

    // ── first_non_private_ip ──────────────────────────────────────────────────

    #[test]
    fn first_non_private_ip_skips_private_finds_public() {
        let result = super::first_non_private_ip("10.0.0.1, 203.0.113.5, 198.51.100.1");
        assert_eq!(result, "203.0.113.5".parse::<IpAddr>().ok());
    }

    #[test]
    fn first_non_private_ip_single_public() {
        let result = super::first_non_private_ip("1.2.3.4");
        assert_eq!(result, "1.2.3.4".parse::<IpAddr>().ok());
    }

    #[test]
    fn first_non_private_ip_all_private_is_none() {
        let result = super::first_non_private_ip("10.0.0.1, 192.168.0.1, 172.16.0.1");
        assert!(result.is_none());
    }

    #[test]
    fn first_non_private_ip_empty_is_none() {
        assert!(super::first_non_private_ip("").is_none());
        assert!(super::first_non_private_ip("  ,  ").is_none());
    }

    #[test]
    fn first_non_private_ip_loopback_is_private() {
        assert!(super::first_non_private_ip("127.0.0.1").is_none());
        assert!(super::first_non_private_ip("::1").is_none());
    }

    // ── resolve_client_ip: unit tests (no Session available; tested via integration) ─
    // The per-request happy/sad path is covered by the e2e security-plane tests.

    #[test]
    fn cacheable_response_without_set_cookie_is_admitted() {
        use super::response_cache_filter;
        use pingora_cache::RespCacheable;
        use pingora_http::ResponseHeader;

        let mut resp = ResponseHeader::build(200, None).expect("build response");
        resp.insert_header("Cache-Control", "max-age=300")
            .expect("insert cache-control");
        assert!(
            matches!(response_cache_filter(&resp), RespCacheable::Cacheable(_)),
            "an explicitly-fresh response with no Set-Cookie must be cacheable"
        );
    }

    #[test]
    fn response_with_set_cookie_is_never_cached() {
        use super::response_cache_filter;
        use pingora_cache::RespCacheable;
        use pingora_http::ResponseHeader;

        // A Set-Cookie response that is otherwise fresh must be refused: caching it
        // would replay one client's cookie to every other client (session leakage).
        let mut resp = ResponseHeader::build(200, None).expect("build response");
        resp.insert_header("Cache-Control", "max-age=300")
            .expect("insert cache-control");
        resp.insert_header("Set-Cookie", "session=secret")
            .expect("insert set-cookie");
        assert!(
            matches!(response_cache_filter(&resp), RespCacheable::Uncacheable(_)),
            "a Set-Cookie response must never be admitted to the shared cache"
        );
    }

    // ── maybe_setup_compression / choose_algorithm ────────────────────────────

    use super::{choose_algorithm, maybe_setup_compression};
    use crate::common::ctx::ProxyCtx;
    use coxswain_core::routing::CompressionConfig;
    use pingora_http::{RequestHeader, ResponseHeader};

    fn gzip_cfg() -> CompressionConfig {
        CompressionConfig::new(
            true,
            false,
            6,
            1024,
            vec!["application/json".into(), "text/html".into()].into_boxed_slice(),
        )
    }

    fn both_cfg() -> CompressionConfig {
        CompressionConfig::new(
            true,
            true,
            6,
            1024,
            vec!["application/json".into()].into_boxed_slice(),
        )
    }

    fn req_with_ae(accept_encoding: &str) -> RequestHeader {
        let mut r = RequestHeader::build("GET", b"/", None).expect("build request");
        r.insert_header("accept-encoding", accept_encoding)
            .expect("insert ae");
        r
    }

    fn resp_200(ct: &str, cl: Option<u64>) -> ResponseHeader {
        let mut r = ResponseHeader::build(200, None).expect("build response");
        r.insert_header("content-type", ct).expect("insert ct");
        if let Some(n) = cl {
            r.insert_header("content-length", n.to_string())
                .expect("insert cl");
        }
        r
    }

    #[test]
    fn choose_algorithm_prefers_brotli_when_both_enabled_and_br_offered() {
        use pingora_core::protocols::http::compression::Algorithm;
        let cfg = both_cfg();
        assert_eq!(
            choose_algorithm("gzip, br", &cfg),
            Some(Algorithm::Brotli),
            "brotli must be preferred when both enabled and br advertised"
        );
    }

    #[test]
    fn choose_algorithm_falls_back_to_gzip() {
        use pingora_core::protocols::http::compression::Algorithm;
        let cfg = both_cfg();
        assert_eq!(
            choose_algorithm("gzip", &cfg),
            Some(Algorithm::Gzip),
            "should fall back to gzip when br not offered"
        );
    }

    #[test]
    fn choose_algorithm_none_when_no_match() {
        let cfg = gzip_cfg();
        assert!(
            choose_algorithm("br", &cfg).is_none(),
            "gzip-only config must not match br"
        );
    }

    #[test]
    fn choose_algorithm_none_when_ae_empty() {
        let cfg = gzip_cfg();
        assert!(choose_algorithm("", &cfg).is_none());
    }

    #[test]
    fn setup_compression_sets_content_encoding_and_vary() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", Some(2048));
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(ctx.compression_encoder.is_some(), "encoder must be set");
        assert_eq!(
            resp.headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("gzip")
        );
        assert!(
            resp.headers
                .get("vary")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("accept-encoding"),
            "Vary must include Accept-Encoding"
        );
        assert!(
            resp.headers.get("content-length").is_none(),
            "Content-Length must be removed"
        );
    }

    #[test]
    fn setup_compression_passes_through_already_compressed() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", Some(2048));
        resp.insert_header("content-encoding", "gzip")
            .expect("insert ce");
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_none(),
            "must not re-compress an already-compressed response"
        );
    }

    #[test]
    fn setup_compression_skips_disallowed_content_type() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("image/png", Some(4096));
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_none(),
            "image/png must not be compressed"
        );
    }

    #[test]
    fn setup_compression_skips_below_min_size() {
        let cfg = gzip_cfg(); // min_size = 1024
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", Some(100));
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_none(),
            "response below min_size must not be compressed"
        );
    }

    #[test]
    fn setup_compression_allows_chunked_without_content_length() {
        // No Content-Length (chunked) → always compress regardless of min_size.
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", None); // no Content-Length
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_some(),
            "chunked response without Content-Length must be compressed"
        );
    }

    #[test]
    fn setup_compression_skips_204_no_content() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = ResponseHeader::build(204, None).expect("build 204");
        resp.insert_header("content-type", "application/json")
            .expect("insert ct");
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(ctx.compression_encoder.is_none(), "204 must be skipped");
    }

    #[test]
    fn setup_compression_vary_extends_existing() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", None);
        resp.insert_header("vary", "Cookie").expect("insert vary");
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        let vary = resp
            .headers
            .get("vary")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            vary.to_ascii_lowercase().contains("cookie"),
            "original Vary value must be preserved"
        );
        assert!(
            vary.to_ascii_lowercase().contains("accept-encoding"),
            "Accept-Encoding must be appended to Vary"
        );
    }

    // ── select_failure_status / classify_upstream_error ──────────────────────
    //
    // `fail_to_proxy` is async and writes to a live Session, so the status-
    // selection logic is extracted into `select_failure_status` and tested here.

    use super::{classify_upstream_error, select_failure_status};
    use pingora_core::{
        ConnectTimedout, ConnectionClosed, ErrorSource, HTTPStatus, ReadError, ReadTimedout,
        WriteError, WriteTimedout,
    };

    // ── WriteTimedout (the `send-timeout` annotation, #341) ───────────────────

    #[test]
    fn write_timeout_maps_to_502_upstream() {
        // `ingress.coxswain-labs.dev/send-timeout` fires a WriteTimedout with
        // ErrorSource::Upstream.  No request/backend budget is active, so the
        // generic upstream arm applies: 502.
        assert_eq!(
            select_failure_status(&WriteTimedout, &ErrorSource::Upstream, false, false),
            502,
            "WriteTimedout from upstream without an active budget must map to 502"
        );
    }

    #[test]
    fn write_timeout_with_request_budget_maps_to_504() {
        // When the *request* timeout (GEP-1742) is the controlling deadline a
        // WriteTimedout is reclassified to 504.
        assert_eq!(
            select_failure_status(&WriteTimedout, &ErrorSource::Upstream, true, false),
            504,
            "WriteTimedout while request timeout is controlling must map to 504"
        );
    }

    #[test]
    fn write_timeout_with_backend_budget_maps_to_504() {
        // Same reclassification when the *backendRequest* budget is active.
        assert_eq!(
            select_failure_status(&WriteTimedout, &ErrorSource::Upstream, false, true),
            504,
            "WriteTimedout while backend-request budget active must map to 504"
        );
    }

    // ── ReadTimedout (`read-timeout` annotation) ──────────────────────────────

    #[test]
    fn read_timeout_maps_to_502_upstream() {
        assert_eq!(
            select_failure_status(&ReadTimedout, &ErrorSource::Upstream, false, false),
            502,
            "ReadTimedout from upstream without an active budget must map to 502"
        );
    }

    #[test]
    fn read_timeout_with_request_budget_maps_to_504() {
        assert_eq!(
            select_failure_status(&ReadTimedout, &ErrorSource::Upstream, true, false),
            504,
        );
    }

    // ── ConnectTimedout (`connect-timeout` annotation) ────────────────────────

    #[test]
    fn connect_timeout_without_backend_budget_maps_to_502_via_upstream_source() {
        // ConnectTimedout without a backend budget falls through to the
        // ErrorSource::Upstream => 502 arm (connect is always upstream-sourced).
        assert_eq!(
            select_failure_status(&ConnectTimedout, &ErrorSource::Upstream, false, false),
            502,
        );
    }

    #[test]
    fn connect_timeout_with_backend_budget_maps_to_502() {
        assert_eq!(
            select_failure_status(&ConnectTimedout, &ErrorSource::Upstream, false, true),
            502,
        );
    }

    // ── HTTPStatus passthrough ────────────────────────────────────────────────

    #[test]
    fn http_status_passthrough() {
        // A Pingora-level HTTPStatus override is forwarded verbatim regardless of
        // source or budget flags.
        assert_eq!(
            select_failure_status(&HTTPStatus(503), &ErrorSource::Upstream, false, false),
            503,
        );
        assert_eq!(
            select_failure_status(&HTTPStatus(429), &ErrorSource::Internal, true, true),
            429,
        );
    }

    // ── Downstream errors ─────────────────────────────────────────────────────

    #[test]
    fn downstream_connection_closed_maps_to_zero() {
        // 0 means "don't write a response" (client already gone).
        assert_eq!(
            select_failure_status(&ConnectionClosed, &ErrorSource::Downstream, false, false),
            0,
        );
    }

    #[test]
    fn downstream_read_write_error_maps_to_zero() {
        assert_eq!(
            select_failure_status(&ReadError, &ErrorSource::Downstream, false, false),
            0,
        );
        assert_eq!(
            select_failure_status(&WriteError, &ErrorSource::Downstream, false, false),
            0,
        );
    }

    #[test]
    fn downstream_other_error_maps_to_400() {
        // Any downstream error that isn't a connection-level close maps to 400.
        assert_eq!(
            select_failure_status(&ConnectTimedout, &ErrorSource::Downstream, false, false),
            400,
        );
    }

    #[test]
    fn internal_error_maps_to_500() {
        assert_eq!(
            select_failure_status(&ReadTimedout, &ErrorSource::Internal, false, false),
            500,
        );
    }

    // ── classify_upstream_error ───────────────────────────────────────────────

    #[test]
    fn classify_upstream_error_timeout_bucket() {
        // ConnectTimedout, ReadTimedout, and WriteTimedout all map to "timeout"
        // for the upstream-error Prometheus label.
        assert_eq!(
            classify_upstream_error(pingora_core::Error::new(ConnectTimedout).as_ref()),
            "timeout",
            "ConnectTimedout must bucket as 'timeout'"
        );
        assert_eq!(
            classify_upstream_error(pingora_core::Error::new(ReadTimedout).as_ref()),
            "timeout",
            "ReadTimedout must bucket as 'timeout'"
        );
        assert_eq!(
            classify_upstream_error(pingora_core::Error::new(WriteTimedout).as_ref()),
            "timeout",
            "WriteTimedout must bucket as 'timeout'"
        );
    }
}
