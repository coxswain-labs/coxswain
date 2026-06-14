//! Pod-log relay powering the Operator UI Logs view (`GET /api/v1/pods/{name}/logs`).
//!
//! The browser (reached via `kubectl port-forward`) can only talk to the
//! controller admin port, never pod IPs, so — like every other surface in the
//! UI — logs are aggregated through the controller. This module relays the
//! Kubernetes pod-logs subresource (`…/pods/{name}/log?follow&tailLines=N`) to
//! the client as a chunked body, byte-for-byte. coxswain logs newline-delimited
//! JSON, so the relayed body is NDJSON the UI parses per line.
//!
//! ## Why a hand-rolled stream
//!
//! Like the `/api/v1/events` SSE stream, a follow stream is long-lived and
//! cannot be driven by Pingora's buffered [`ServeHttp`](pingora_core::apps::http_app::ServeHttp)
//! trait. [`crate::AdminServer`] dispatches the logs path directly out of
//! [`HttpServerApp::process_new_http`](pingora_core::apps::HttpServerApp) into
//! [`run_until_shutdown`], which writes chunked frames as the upstream produces
//! them.
//!
//! ## Liveness
//!
//! `log_stream` blocks on the upstream, so a client that closes its tab while
//! the pod is idle would otherwise pin a [`Semaphore`](tokio::sync::Semaphore)
//! permit until the next log line. A `KEEPALIVE_INTERVAL` idle timeout therefore
//! writes a single newline (an empty NDJSON line the UI skips) whenever the
//! stream sits at a line boundary; the failed write on a vanished client tears
//! the stream down promptly. The newline is only ever emitted at a line
//! boundary, so it never splits a log record.

use std::time::Duration;

use bytes::Bytes;
use futures::AsyncReadExt;
use http::{StatusCode, header};
use k8s_openapi::api::core::v1::Pod;
use kube::api::LogParams;
use kube::{Api, Client};
use pingora_core::protocols::http::ServerSession;
use pingora_core::server::ShutdownWatch;
use pingora_http::ResponseHeader;

/// Default number of trailing lines when the client omits `tail`.
const DEFAULT_TAIL: i64 = 1000;

/// Hard cap on `tail` — protects the controller and kubelet from an operator
/// requesting an unbounded backlog.
const MAX_TAIL: i64 = 5000;

/// Read buffer for the upstream→downstream pump. Sized to amortise syscalls
/// without holding a large allocation in the per-connection future state.
const READ_BUF_BYTES: usize = 16 * 1024;

/// Idle-liveness probe cadence — mirrors the events stream's keepalive. On an
/// idle follow stream this is the worst-case delay before a vanished client is
/// detected (via the failed write) and its permit released.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

// ── Query parsing ─────────────────────────────────────────────────────────────

/// Parsed `?tail=&follow=` parameters for a logs request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogQuery {
    /// Whether to keep streaming new lines (`true`) or return a snapshot and
    /// close at EOF (`false`).
    follow: bool,
    /// Number of trailing lines to seed the stream with, clamped to
    /// `[1, MAX_TAIL]`.
    tail: i64,
}

impl LogQuery {
    /// Parse the raw query string (the part after `?`, or `""` when absent).
    ///
    /// Unknown keys are ignored; an unparseable `tail` falls back to the
    /// default; `follow` is `false` only for the explicit `false`/`0` values so
    /// the common `?follow=true` and a bare `?follow` both tail.
    pub(crate) fn parse(query: &str) -> Self {
        let mut q = LogQuery {
            follow: true,
            tail: DEFAULT_TAIL,
        };
        for pair in query.split('&').filter(|s| !s.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            match key {
                "tail" => {
                    if let Ok(n) = value.parse::<i64>() {
                        q.tail = n.clamp(1, MAX_TAIL);
                    }
                }
                "follow" => q.follow = !matches!(value, "false" | "0"),
                _ => {}
            }
        }
        q
    }

    /// Render the Kubernetes [`LogParams`] this query selects.
    fn to_params(self) -> LogParams {
        LogParams {
            follow: self.follow,
            tail_lines: Some(self.tail),
            ..LogParams::default()
        }
    }
}

// ── Stream driver ─────────────────────────────────────────────────────────────

/// Relay a pod's logs until the upstream ends, the client disconnects, or the
/// server shuts down.
///
/// `namespace` is resolved by the caller from the trusted fleet snapshot (never
/// from the request URL), so this never tails a pod coxswain doesn't track.
pub(crate) async fn run_until_shutdown(
    kube: &Client,
    namespace: &str,
    pod_name: &str,
    query: &LogQuery,
    session: &mut ServerSession,
    shutdown: &ShutdownWatch,
) {
    let mut shutdown = shutdown.clone();
    if *shutdown.borrow() {
        return;
    }
    tokio::select! {
        () = run(kube, namespace, pod_name, query, session) => {}
        _ = shutdown.changed() => {}
    }
}

/// Open the upstream log stream and pump it to the client.
async fn run(
    kube: &Client,
    namespace: &str,
    pod_name: &str,
    query: &LogQuery,
    session: &mut ServerSession,
) {
    // Log streams are single-use and long-lived; never offer keepalive reuse.
    session.set_keepalive(None);

    let api: Api<Pod> = Api::namespaced(kube.clone(), namespace);
    let reader = match api.log_stream(pod_name, &query.to_params()).await {
        Ok(r) => r,
        Err(kube::Error::Api(e)) if e.code == StatusCode::NOT_FOUND.as_u16() => {
            // The fleet snapshot is eventually consistent — a pod can vanish
            // between resolution and the log request.
            write_status(session, StatusCode::NOT_FOUND, "pod not found").await;
            return;
        }
        Err(e) => {
            tracing::warn!(error = %e, namespace, pod = pod_name, "pod log stream failed to open");
            write_status(
                session,
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to open log stream",
            )
            .await;
            return;
        }
    };
    // `Pin<Box<_>>` is `Unpin` and implements `AsyncRead`, so `read` works
    // regardless of whether the upstream reader is itself `Unpin`.
    let mut reader = Box::pin(reader);

    if write_header(session).await.is_err() {
        return;
    }

    let mut buf = [0u8; READ_BUF_BYTES];
    // Whether the last byte written was a newline. The idle keepalive only
    // fires at a line boundary so it never splits a log record.
    let mut at_line_start = true;
    loop {
        match tokio::time::timeout(KEEPALIVE_INTERVAL, reader.read(&mut buf)).await {
            Ok(Ok(0)) => break, // upstream EOF (snapshot end, or pod gone)
            Ok(Ok(n)) => {
                at_line_start = buf[n - 1] == b'\n';
                if write_body(session, &buf[..n]).await.is_err() {
                    break; // client gone
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, pod = pod_name, "pod log upstream read error");
                break;
            }
            Err(_elapsed) => {
                // Idle: probe the client only at a line boundary.
                if at_line_start && write_body(session, b"\n").await.is_err() {
                    break;
                }
            }
        }
    }

    // Terminate the chunked stream; the client is likely gone, so ignore errors.
    let _ = session.write_response_body(Bytes::new(), true).await;
}

// ── Session writers ───────────────────────────────────────────────────────────

/// Write the 200 streaming header: `text/plain` NDJSON over explicit chunked
/// framing (Pingora otherwise close-delimits an unknown-length body).
async fn write_header(session: &mut ServerSession) -> pingora_core::Result<()> {
    let mut header = ResponseHeader::build(StatusCode::OK, Some(4))?;
    header.insert_header(header::CONTENT_TYPE, "text/plain; charset=utf-8")?;
    header.insert_header(header::CACHE_CONTROL, "no-cache")?;
    header.insert_header(header::CONNECTION, "keep-alive")?;
    header.insert_header(header::TRANSFER_ENCODING, "chunked")?;
    session.write_response_header(Box::new(header)).await
}

/// Write a non-terminal body chunk (`end = false` keeps the stream open).
async fn write_body(session: &mut ServerSession, bytes: &[u8]) -> pingora_core::Result<()> {
    session
        .write_response_body(Bytes::copy_from_slice(bytes), false)
        .await
}

/// Write a small buffered error response directly on the session.
///
/// Used for the pre-stream failure cases (429/404/503/500). The logs path is
/// dispatched out of the streaming arm of `process_new_http`, past the buffered
/// pipeline, so these are written by hand rather than returned as a
/// `Response<Vec<u8>>`. Errors are ignored — there is nothing to recover.
pub(crate) async fn write_status(session: &mut ServerSession, status: StatusCode, msg: &str) {
    let mut body = msg.to_string();
    body.push('\n');
    let header = match ResponseHeader::build(status, Some(2)) {
        Ok(mut h) => {
            let _ = h.insert_header(header::CONTENT_TYPE, "text/plain; charset=utf-8");
            let _ = h.insert_header(header::CONTENT_LENGTH, body.len().to_string());
            h
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to build logs error header");
            return;
        }
    };
    if session
        .write_response_header(Box::new(header))
        .await
        .is_err()
    {
        return;
    }
    let _ = session
        .write_response_body(Bytes::from(body.into_bytes()), true)
        .await;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults_when_query_empty() {
        let q = LogQuery::parse("");
        assert_eq!(
            q,
            LogQuery {
                follow: true,
                tail: DEFAULT_TAIL
            }
        );
    }

    #[test]
    fn parse_reads_tail_and_follow() {
        let q = LogQuery::parse("tail=250&follow=false");
        assert_eq!(
            q,
            LogQuery {
                follow: false,
                tail: 250
            }
        );
    }

    #[test]
    fn parse_clamps_tail_to_max() {
        assert_eq!(LogQuery::parse("tail=100000").tail, MAX_TAIL);
    }

    #[test]
    fn parse_clamps_tail_to_min() {
        assert_eq!(LogQuery::parse("tail=0").tail, 1);
        assert_eq!(LogQuery::parse("tail=-5").tail, 1);
    }

    #[test]
    fn parse_unparseable_tail_falls_back_to_default() {
        assert_eq!(LogQuery::parse("tail=abc").tail, DEFAULT_TAIL);
    }

    #[test]
    fn parse_follow_truthy_variants_all_tail() {
        assert!(LogQuery::parse("follow=true").follow);
        assert!(LogQuery::parse("follow").follow); // bare key
        assert!(LogQuery::parse("follow=1").follow);
        assert!(!LogQuery::parse("follow=false").follow);
        assert!(!LogQuery::parse("follow=0").follow);
    }

    #[test]
    fn parse_ignores_unknown_keys() {
        let q = LogQuery::parse("foo=bar&tail=42&baz");
        assert_eq!(
            q,
            LogQuery {
                follow: true,
                tail: 42
            }
        );
    }

    #[test]
    fn to_params_maps_fields() {
        let lp = LogQuery {
            follow: false,
            tail: 7,
        }
        .to_params();
        assert!(!lp.follow);
        assert_eq!(lp.tail_lines, Some(7));
    }
}
