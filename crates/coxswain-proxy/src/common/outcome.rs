//! Routing-outcome resolution and redirect filter handling — the steps that
//! sit between the lock-free table lookup and the upstream connection.

use super::redirect::{RedirectOrigin, build_redirect_location};
use coxswain_core::routing::{FilterAction, RouteMatch, RouteOutcome, RouteTimeouts};
use http::header;
use pingora_core::{HTTPStatus, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

/// Merge per-route timeouts with global defaults; per-route wins when set.
pub(crate) fn merge_timeouts(route: &RouteTimeouts, default: &RouteTimeouts) -> RouteTimeouts {
    RouteTimeouts {
        request: route.request.or(default.request),
        backend_request: route.backend_request.or(default.backend_request),
        connect: route.connect.or(default.connect),
        read: route.read.or(default.read),
        send: route.send.or(default.send),
    }
}

/// Resolves a pre-computed [`RouteOutcome`] into the matched [`RouteMatch`].
///
/// Returns `Some(route_match)` on a successful match, or `None` when an explicit
/// [`RouteOutcome::Error`] was handled by writing an error response directly
/// to `session`.
///
/// # Errors
/// Propagates Pingora I/O errors from response-header construction. The
/// `NoHost` / `NoPath` variants are surfaced as `Err(Error::explain(404, ...))`
/// so the caller can short-circuit through Pingora's standard error path.
pub(crate) async fn resolve_outcome(
    session: &mut Session,
    host: &str,
    path: &str,
    outcome: RouteOutcome,
) -> Result<Option<RouteMatch>> {
    match outcome {
        RouteOutcome::Found(m) => Ok(Some(m)),
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
        _ => unreachable!("invariant: RouteOutcome is non-exhaustive but only four variants exist"),
    }
}

/// If `filters` contains a `RequestRedirect`, build the `Location` header,
/// write the 3xx response, and return `true`. Returns `false` otherwise.
///
/// # Errors
/// Propagates Pingora I/O errors from response-header construction.
pub(crate) async fn try_redirect(
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

/// If `filters` contains a `Cors` filter AND the request is a preflight `OPTIONS`
/// (identified by the presence of `Access-Control-Request-Method`) AND the request
/// origin matches the allow-list, write a `204 No Content` with the CORS allow-headers
/// and return `true`. Returns `false` in every other case (no CORS filter, wrong
/// method, no `Origin`, origin not allowed).
///
/// Must be called after routing is resolved but before forwarding to the upstream,
/// so that the upstream backend is never contacted for preflight requests.
///
/// # Errors
/// Propagates Pingora I/O errors from response-header construction.
pub(crate) async fn try_cors_preflight(
    session: &mut Session,
    filters: &[FilterAction],
    cors_origin: Option<&str>,
) -> Result<bool> {
    let Some(origin_str) = cors_origin else {
        return Ok(false);
    };
    {
        let req = session.req_header();
        if req.method != http::Method::OPTIONS {
            return Ok(false);
        }
        if req
            .headers
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .is_none()
        {
            // Not a real preflight (OPTIONS without ACRM is a regular request).
            return Ok(false);
        }
    }
    for f in filters {
        if let FilterAction::Cors(cfg) = f {
            let Some(allow_origin) = cfg.resolve_origin(origin_str) else {
                // Origin present but not in the allow-list — let the request proceed;
                // the browser enforces the CORS policy based on the absent response header.
                return Ok(false);
            };
            let mut resp = ResponseHeader::build(204, Some(4))?;
            resp.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin)?;
            if cfg.allow_credentials {
                resp.insert_header(
                    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    http::HeaderValue::from_static("true"),
                )?;
            }
            if let Some(methods) = &cfg.allow_methods {
                resp.insert_header(header::ACCESS_CONTROL_ALLOW_METHODS, methods.clone())?;
            }
            if let Some(headers) = &cfg.allow_headers {
                resp.insert_header(header::ACCESS_CONTROL_ALLOW_HEADERS, headers.clone())?;
            }
            resp.insert_header(header::ACCESS_CONTROL_MAX_AGE, cfg.max_age.clone())?;
            session
                .write_response_header(Box::new(resp), true)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("failed to write CORS preflight response: {e}")
                });
            return Ok(true);
        }
    }
    Ok(false)
}
