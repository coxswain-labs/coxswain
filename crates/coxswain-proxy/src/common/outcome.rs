//! Routing-outcome resolution and redirect filter handling — the steps that
//! sit between the lock-free table lookup and the upstream connection.

use super::redirect::{RedirectOrigin, build_redirect_location};
use coxswain_core::routing::{BackendGroup, FilterAction, RouteOutcome, RouteTimeouts};
use http::header;
use pingora_core::{HTTPStatus, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::sync::Arc;

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

/// Resolves a pre-computed [`RouteOutcome`] into its components.
///
/// Returns `Some(...)` on a successful match, or `None` when an explicit
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
) -> Result<
    Option<(
        Arc<BackendGroup>,
        Arc<[FilterAction]>,
        RouteTimeouts,
        Arc<str>,
        Arc<str>,
    )>,
> {
    match outcome {
        RouteOutcome::Found(u, f, t, p, m) => Ok(Some((u, f, t, p, m))),
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
