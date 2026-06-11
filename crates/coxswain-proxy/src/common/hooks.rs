//! Shared bodies of Pingora `ProxyHttp` hooks, parameterised over the spec
//! kind. Both [`IngressProxy`][crate::ingress::IngressProxy] and
//! [`GatewayProxy`][crate::gateway::GatewayProxy] forward to these helpers so
//! their hook implementations remain a thin shim.

use super::ctx::{CONN_INFO, ProxyCtx, ResolvedRoute};
use super::engine::RoutingEngine;
use super::filter::TrafficFilter;
use super::outcome::{merge_timeouts, resolve_outcome, try_redirect};
use super::redirect::extract_host;
use crate::config::AccessLogPathMode;
use crate::upstream_ca::UpstreamCaCache;
use bytes::Bytes;
use coxswain_core::routing::{RequestContext, RouteTimeouts, UpstreamCa};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{
    ConnectTimedout, ConnectionClosed, ErrorSource, HTTPStatus, ReadError, ReadTimedout, Result,
    WriteError, WriteTimedout,
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

    let Some((backend_group, filters, route_timeouts, path_pattern)) =
        resolve_outcome(session, &host, &path, outcome).await?
    else {
        return Ok(true);
    };

    let timeouts = merge_timeouts(&route_timeouts, default_timeouts);
    ctx.request_deadline = timeouts.request.map(|d| Instant::now() + d);

    if try_redirect(
        session,
        &filters,
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

    ctx.resolved = Some(ResolvedRoute {
        backend_group,
        filters,
        timeouts,
        original_host: host,
        original_path: path,
        path_pattern,
    });
    Ok(false)
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
    // backendRequest controls the upstream read (and connect) phase → 502 on expiry.
    // request controls the total budget; we use the remaining time as read_timeout so
    // that an expiry can be detected in fail_to_proxy and mapped to 504.
    let remaining_request = ctx
        .request_deadline
        .and_then(|d| d.checked_duration_since(Instant::now()));
    let backend_timeout = resolved.timeouts.backend_request;

    let read_timeout = match (backend_timeout, remaining_request) {
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
    };
    if let Some(t) = read_timeout {
        peer.options.read_timeout = Some(t);
    }
    if let Some(t) = backend_timeout {
        peer.options.connection_timeout = Some(t);
        ctx.backend_request_timeout_active = true;
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

/// Pingora `upstream_response_filter` body: apply rule-level response filters.
///
/// # Errors
/// None today; signature is `Result` for forward-compatibility with future
/// response-side validation.
pub(crate) async fn upstream_response_filter(
    _session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut ProxyCtx,
) -> Result<()> {
    if let Some(resolved) = &ctx.resolved {
        TrafficFilter::apply_response_filters(upstream_response, &resolved.filters);
    }
    Ok(())
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

/// Pingora `logging` body: emit one structured access-log event per request.
///
/// Emits at `INFO` level on the `coxswain_proxy::access` target so operators
/// can filter it independently with `--log=info,coxswain_proxy::access=off`.
/// When `access_log_enabled` is `false` this is a no-op (zero cost).
pub(crate) async fn logging(
    access_log_enabled: bool,
    access_log_path_mode: AccessLogPathMode,
    session: &mut Session,
    e: Option<&pingora_core::Error>,
    ctx: &ProxyCtx,
) {
    if !access_log_enabled {
        return;
    }

    let req = session.req_header();
    let method = req.method.as_str();
    let status = session.response_written().map(|h| h.status.as_u16());
    let bytes_sent = session.body_bytes_sent() as u64;
    let duration_ms = ctx
        .start
        .map(|s| s.elapsed().as_millis() as u64)
        .unwrap_or(0);

    // Prefer the pre-resolved host from context; fall back to parsing the header.
    let mut host_buf = String::new();
    let host: &str = ctx
        .resolved
        .as_ref()
        .map(|r| r.original_host.as_ref())
        .unwrap_or_else(|| extract_host(req, &mut host_buf));

    let upstream = ctx.resolved.as_ref().map(|r| r.backend_group.name());
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
        upstream = upstream,
        upstream_addr = upstream_addr_str.as_deref(),
        duration_ms = duration_ms,
        bytes_sent = bytes_sent,
        error = err_msg.as_deref(),
        "access",
    );
}
