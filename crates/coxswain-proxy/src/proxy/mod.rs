//! Pingora `ProxyHttp` implementation: routing, filter application, upstream selection,
//! and error-code mapping.

use async_trait::async_trait;
use bytes::Bytes;
use coxswain_core::routing::{
    FilterAction, RequestContext, RouteOutcome, RouteTimeouts, UpstreamCa,
};
use http::header;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{
    ConnectTimedout, ConnectionClosed, ErrorSource, HTTPStatus, ReadError, ReadTimedout, Result,
    WriteError, WriteTimedout,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::sync::Arc;
use std::time::Instant;

use crate::filter::TrafficFilter;
use crate::upstream_ca::UpstreamCaCache;

mod ctx;
mod engine;
mod redirect;

pub(crate) use ctx::{CONN_INFO, ConnectionInfo};
pub use ctx::{ProxyCtx, ResolvedRoute};
pub use engine::RoutingEngine;

use redirect::{RedirectOrigin, build_redirect_location, extract_host};

#[cfg(test)]
mod tests;

/// Pingora `ProxyHttp` implementation that routes requests through [`RoutingEngine`].
pub struct Proxy {
    /// Lock-free routing engine shared across all worker threads.
    pub engine: Arc<RoutingEngine>,
    /// Global fallback timeouts used when a matched route has no per-rule timeouts set.
    pub default_timeouts: RouteTimeouts,
    /// Parse cache for upstream CA bundles from `BackendTLSPolicy` attachments.
    ///
    /// Shared across all requests; `get_or_parse` holds the lock only briefly and
    /// never across an `.await`.
    pub ca_cache: Arc<UpstreamCaCache>,
}

/// Merge per-route timeouts with global defaults; per-route wins when set.
fn merge_timeouts(route: &RouteTimeouts, default: &RouteTimeouts) -> RouteTimeouts {
    RouteTimeouts {
        request: route.request.or(default.request),
        backend_request: route.backend_request.or(default.backend_request),
    }
}

/// Resolves a pre-computed `RouteOutcome` into its components.
///
/// Returns `Some(...)` on success, or `None` when `RouteOutcome::Error` was
/// handled by writing an error response directly to `session`.
async fn resolve_outcome(
    session: &mut Session,
    host: &str,
    path: &str,
    outcome: RouteOutcome,
) -> Result<
    Option<(
        Arc<coxswain_core::routing::BackendGroup>,
        Arc<[FilterAction]>,
        RouteTimeouts,
    )>,
> {
    match outcome {
        RouteOutcome::Found(u, f, t) => Ok(Some((u, f, t))),
        RouteOutcome::Error(status) => {
            let resp = ResponseHeader::build(status, Some(0))?;
            session
                .write_response_header(Box::new(resp), true)
                .await
                .unwrap_or_else(|e| tracing::error!("failed to write error response: {e}"));
            Ok(None)
        }
        RouteOutcome::NoHost => Err(pingora_core::Error::explain(
            HTTPStatus(404),
            format!("no route for host {host}"),
        )),
        RouteOutcome::NoPath => Err(pingora_core::Error::explain(
            HTTPStatus(404),
            format!("no route for path {path} on host {host}"),
        )),
        _ => unreachable!("unhandled RouteOutcome variant"),
    }
}

/// If `filters` contains a `RequestRedirect`, build the `Location` header,
/// write the 3xx response, and return `true`. Returns `false` otherwise.
async fn try_redirect(
    session: &mut Session,
    filters: &[FilterAction],
    proto: &str,
    host: &str,
    incoming_port: u16,
    path: &str,
    query: Option<&str>,
) -> Result<bool> {
    for f in filters {
        if let FilterAction::RequestRedirect {
            scheme,
            hostname,
            port,
            status_code,
            path: path_mod,
        } = f
        {
            let origin = RedirectOrigin {
                scheme: proto,
                host,
                port: incoming_port,
                path,
                query,
            };
            let location = build_redirect_location(
                scheme.as_deref(),
                hostname.as_deref(),
                *port,
                path_mod.as_ref(),
                &origin,
            );
            let mut resp = ResponseHeader::build(*status_code, Some(2))?;
            resp.insert_header(header::LOCATION, location)?;
            session
                .write_response_header(Box::new(resp), true)
                .await
                .unwrap_or_else(|e| tracing::error!("failed to write redirect response: {e}"));
            return Ok(true);
        }
    }
    Ok(false)
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
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
            })
            .unwrap_or_default()
    }

    /// Perform routing early so `RequestRedirect` filters can short-circuit
    /// before an upstream connection is attempted.
    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyCtx) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
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
            self.engine.find(port, &host, &path, &route_ctx)
        }; // route_ctx (and req borrow) drops here

        let Some((backend_group, filters, route_timeouts)) =
            resolve_outcome(session, &host, &path, outcome).await?
        else {
            return Ok(true);
        };

        let timeouts = merge_timeouts(&route_timeouts, &self.default_timeouts);
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
        });
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut ProxyCtx,
    ) -> Result<Box<HttpPeer>> {
        let resolved = ctx.resolved.as_ref().ok_or_else(|| {
            pingora_core::Error::explain(
                HTTPStatus(500),
                "routing not resolved before upstream_peer",
            )
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
                pingora_core::Error::explain(
                    HTTPStatus(503),
                    "no active endpoints for backend group",
                )
            })?;
        ctx.selected_backend_filters = per_backend_filters;

        let protocol = resolved.backend_group.protocol();

        // BackendTLSPolicy overrides appProtocol-derived TLS decisions.
        let (is_tls, sni_host, group_key, ca_override) =
            if let Some(btls) = resolved.backend_group.upstream_tls() {
                let ca = match &btls.ca {
                    UpstreamCa::System => None,
                    UpstreamCa::Bundle(pem) => {
                        let parsed = self.ca_cache.get_or_parse(btls.group_key, pem);
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

        // Determine which timeout is the binding constraint and set the flag that
        // fail_to_proxy will use to pick 504 vs 502.  Doing this here (at peer-creation
        // time) avoids a racy Instant::now() >= deadline comparison in fail_to_proxy,
        // which can yield the wrong answer when the OS timer fires a few µs early.
        let read_timeout = match (backend_timeout, remaining_request) {
            (Some(bt), Some(rem)) => {
                // Whichever is smaller fires; record which one controls.
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

    async fn upstream_request_filter(
        &self,
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

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(resolved) = &ctx.resolved {
            TrafficFilter::apply_response_filters(upstream_response, &resolved.filters);
        }
        Ok(())
    }

    /// Send a plain-text error body instead of Pingora's default empty response.
    ///
    /// Mirrors the default code-selection logic but calls `respond_error_with_body`
    /// so clients see "503 Service Unavailable\n" rather than a zero-length body.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut ProxyCtx,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
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
}
