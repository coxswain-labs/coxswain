//! `RequestMirror` dispatch (GEP-3171): the fire-and-forget mirror sub-request.
//!
//! [`setup`] samples `FilterAction::Mirror` filters, opens the per-backend mpsc
//! channels, and spawns the mirror tasks; `request_body_filter` tees arriving chunks
//! to the channel senders; this module also owns the terminal step ([`spawn_mirror_dispatch`]):
//! the spawned task that streams the body to the mirror backend and discards its response.

use crate::config::SharedProxyConfig;
use crate::ctx::{MirrorDispatch, ProxyCtx};
use bytes::Bytes;
use coxswain_core::routing::{BackendGroup, FilterAction, MirrorFraction};
use pingora_proxy::Session;
use std::sync::Arc;
use tokio_stream::StreamExt as _;

/// Bounded capacity for the per-mirror mpsc channel (#360).
///
/// A full channel causes the current chunk to be dropped rather than stalling
/// the primary request path (`try_send` is used, never `send`). 64 chunks provides
/// enough headroom for any realistic mirror consumer lag while keeping per-request
/// memory cost negligible (mirror is best-effort fire-and-forget).
pub(crate) const MIRROR_CHANNEL_CAP: usize = 64;

/// Headers stripped from mirror sub-requests beyond the standard hop-by-hop set.
///
/// `Authorization` and `Cookie` carry per-user credentials that must not be
/// forwarded to mirror (shadow) backends — those backends are secondary/test
/// endpoints that the Ingress author may not fully control. Leaking them would
/// make the mirror a credential-harvesting surface. `proxy-authorization` is
/// already covered by [`crate::policy::auth::HOP_BY_HOP`]; listed for clarity.
const MIRROR_CREDENTIAL_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

/// Set up request mirroring for the resolved route: sample the `Mirror` filters
/// (GEP-3171), capture forwardable request headers, and spawn one fire-and-forget
/// mirror task per surviving backend, storing the body-tee senders on `ctx.mirror_txs`.
///
/// Non-mirror routes pay almost nothing — the filter scan short-circuits and no Vec
/// is allocated. Called from [`crate::hooks::request_filter`] after the route is
/// resolved; `query` is the captured request query string (without `?`).
pub(crate) fn setup(
    session: &Session,
    ctx: &mut ProxyCtx,
    cfg: &SharedProxyConfig,
    query: Option<&str>,
) {
    // Collect all Mirror filters, applying per-filter sampling gates (GEP-3171).
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

    if mirror_backends.is_empty() {
        return;
    }

    // Apply GEP-3171 sampling: draw one random u32 per mirror candidate and discard
    // candidates whose fraction gate rejects the draw. `None` fraction == 100%.
    let surviving: Vec<Arc<BackendGroup>> = mirror_backends
        .into_iter()
        .filter(|(_, fraction)| fraction.is_none_or(|f| f.should_sample(rand::random::<u32>())))
        .map(|(b, _)| b)
        .collect();

    if surviving.is_empty() {
        return;
    }

    let method;
    let headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>;
    {
        // Re-borrow req_header to capture method + forwardable headers. The mutable
        // session borrows above (auth, rate-limit, redirect) have completed; this is a
        // fresh immutable borrow, released before the ctx mutation.
        let req = session.req_header();
        method = req.method.clone();
        headers = req
            .headers
            .iter()
            .filter_map(|(name, value)| {
                // `HeaderName::as_str()` is contractually lowercase, so compare
                // it directly — no per-header owned lowercase copy.
                let name_str = name.as_str();
                if name_str == "host"
                    // content-length is stripped because the streaming mirror body uses
                    // Transfer-Encoding: chunked; forwarding the original CL alongside
                    // chunked TE violates RFC 9112 §6.1 and confuses strict backends.
                    || name_str == "content-length"
                    || crate::policy::auth::HOP_BY_HOP.contains(&name_str)
                    || MIRROR_CREDENTIAL_HEADERS.contains(&name_str)
                {
                    return None;
                }
                Some((name.clone(), value.clone()))
            })
            .collect();
    } // req borrow released

    // `ctx.resolved` was set to `Some` before this call with no intervening
    // reassignment, so this always binds; degrade to skipping the (best-effort)
    // mirror rather than panicking on the data plane if that ever changes.
    let Some(resolved) = ctx.resolved.as_ref() else {
        return;
    };
    let host = resolved.original_host.clone();
    let original_path = resolved.original_path.clone();
    let metric_route_id = Arc::clone(&resolved.metric_route_id);
    // Reuse the captured `Arc<str>` when there is no query to append — only the
    // query arm allocates (#397).
    let path_and_query: Arc<str> = match query {
        Some(q) => {
            let mut pq = String::with_capacity(original_path.len() + 1 + q.len());
            pq.push_str(&original_path);
            pq.push('?');
            pq.push_str(q);
            Arc::from(pq)
        }
        None => Arc::clone(&original_path),
    };

    // Dispatch mirror tasks per surviving backend.
    //
    // Methods that cannot carry a request body (GET, HEAD, OPTIONS, CONNECT, TRACE)
    // are dispatched immediately with an empty body — no channel needed. This also
    // avoids the H2 bodyless edge case where Pingora never calls `request_body_filter`
    // for methods with no DATA frames.
    //
    // All other methods (POST, PUT, PATCH, DELETE, …) open a bounded mpsc channel per
    // backend and wrap its receiver as a streaming reqwest::Body so the body is
    // forwarded chunk-by-chunk in `request_body_filter`, concurrent with primary
    // forwarding — no buffering and no max-body-size dependency (#360).
    let method_has_body = !matches!(
        method,
        http::Method::GET
            | http::Method::HEAD
            | http::Method::OPTIONS
            | http::Method::CONNECT
            | http::Method::TRACE
    );
    let mut txs = Vec::with_capacity(surviving.len());
    for backend in surviving {
        let dispatch = MirrorDispatch {
            backend,
            method: method.clone(),
            host: Arc::clone(&host),
            path_and_query: Arc::clone(&path_and_query),
            headers: headers.clone(),
            metric_route_id: Arc::clone(&metric_route_id),
        };
        let body = if method_has_body {
            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(MIRROR_CHANNEL_CAP);
            let body = reqwest::Body::wrap_stream(
                tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok::<Bytes, std::io::Error>),
            );
            txs.push(tx);
            body
        } else {
            reqwest::Body::default()
        };
        spawn_mirror_dispatch(dispatch, cfg.auth_client.clone(), body, &cfg.mirror_tracker);
    }
    ctx.mirror_txs = txs;
}

/// Dispatch a fire-and-forget mirror request, discarding the response.
///
/// Spawns a Tokio task that:
/// 1. Selects one endpoint from `dispatch.backend` via weighted round-robin.
/// 2. Builds a `reqwest` request with the original method, forwarded headers, and
///    the streaming body (chunked transfer-encoded; the sender side is fed
///    chunk-by-chunk by `request_body_filter`, concurrent with primary forwarding).
/// 3. Sends with a bounded 5-second timeout (mirror latency must not stall the caller).
/// 4. Discards the response entirely.
/// 5. Emits a `coxswain_proxy::access` log row tagged `mirror = true` carrying
///    `host`, `path`, `upstream`, and `status` (the primary observability signal
///    for mirroring and the e2e side channel for asserting mirror receipt).
/// 6. Emits `WARN` on connect/send errors or timeout and drops the mirror.
///
/// The spawned task owns all its data; no session or primary-path state is borrowed.
pub(crate) fn spawn_mirror_dispatch(
    dispatch: MirrorDispatch,
    client: reqwest::Client,
    body: reqwest::Body,
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

        // TLS is originated solely by a BackendTLSPolicy (GEP-1897); the mirror
        // URL scheme follows the upstream TLS context, not the wire protocol.
        let scheme = if dispatch.backend.upstream_tls().is_some() {
            "https"
        } else {
            "http"
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
