//! Upstream failure handling and retry policy: the Pingora `fail_to_connect`,
//! `error_while_proxy`, and `fail_to_proxy` hook bodies, the error→status mapping
//! they share, and the upstream retry/error metric emitters.
//!
//! These are wired into both proxies' `ProxyHttp` impls and invoked by the
//! lifecycle in [`crate::hooks`]; keeping them here keeps the orchestration
//! module focused on the happy-path request flow.

use crate::ctx::ProxyCtx;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{
    ConnectTimedout, ConnectionClosed, ErrorSource, HTTPStatus, ReadError, ReadTimedout,
    WriteError, WriteTimedout,
};
use pingora_proxy::{FailToProxy, Session};

/// Why the last retry was triggered.
///
/// Drives [`error_while_proxy`]: a response-based retry (`HttpCode`/`GrpcCode`, set in
/// `upstream_response_filter` after the connection already delivered a response) must be
/// preserved unconditionally, whereas a connection-error retry re-runs Pingora's reuse
/// check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryTrigger {
    /// Upstream TCP/TLS connection failure on a fresh connection — always replay-safe.
    ConnectError,
    /// Upstream connect timeout.
    Timeout,
    /// Retriable HTTP response status matched against `RetryPolicy.http_codes`.
    HttpCode,
    /// Retriable trailers-only gRPC `grpc-status` matched against `RetryPolicy.grpc_codes`.
    GrpcCode,
}

/// Pingora `fail_to_connect` body: retry upstream connection failures when the
/// route's `RetryPolicy` permits.
///
/// Called when establishing the TCP/TLS connection to the upstream fails **before**
/// any request bytes are sent, so replaying the request is always safe. Under the
/// exact-native-mirror model, connection failures and connect-timeouts are retried
/// whenever `attempts >= 1` and the budget is not exhausted — there is no per-condition
/// opt-in (GEP-1731 has no connection-error field; it is implicit).
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
    if policy.is_disabled() || ctx.retries_used >= policy.attempts {
        return e;
    }
    let is_timeout = matches!(e.etype(), ConnectTimedout);
    ctx.retries_used += 1;
    ctx.last_retry_trigger = Some(if is_timeout {
        RetryTrigger::Timeout
    } else {
        RetryTrigger::ConnectError
    });
    e.retry = true.into();
    let condition_label = if is_timeout {
        "timeout"
    } else {
        "connect-failure"
    };
    inc_upstream_retry(ctx, condition_label);
    e
}

/// Pingora `error_while_proxy` body: preserve retry decisions made by
/// `upstream_response_filter`, and allow connect-level retries on fresh connections.
///
/// Pingora's default implementation gates retries on `client_reused &&
/// !retry_buffer_truncated()`.  We override it to:
/// - Keep the `retry = true` set by `fail_to_connect` (connection path) or
///   `upstream_response_filter` (response-code path) unconditionally when those
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
    if matches!(
        ctx.last_retry_trigger,
        Some(RetryTrigger::HttpCode | RetryTrigger::GrpcCode)
    ) {
        // A response-code retry was already decided in upstream_response_filter; preserve
        // it. (Do NOT gate on client_reused — the connection held the response, not a reuse.)
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
pub(crate) fn inc_upstream_retry(ctx: &ProxyCtx, condition: &'static str) {
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
pub(crate) fn inc_upstream_error(ctx: &ProxyCtx, error_type: &'static str) {
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

#[cfg(test)]
mod tests {
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
