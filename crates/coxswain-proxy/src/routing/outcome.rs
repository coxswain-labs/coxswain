//! Routing-outcome resolution — the step between the lock-free table lookup and
//! the upstream connection. Resolves a [`RouteOutcome`] into a concrete match
//! (writing error responses for the miss variants) and merges per-route timeouts.
//!
//! The filter-driven early exits that may short-circuit a resolved request
//! before the upstream (redirect, CORS preflight) live in [`crate::filters`].

use coxswain_core::routing::{RouteMatch, RouteOutcome, RouteTimeouts};
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
