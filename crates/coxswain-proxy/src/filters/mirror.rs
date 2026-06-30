//! `RequestMirror` dispatch (GEP-3171): the fire-and-forget mirror sub-request.
//!
//! Mirror setup (sampling `FilterAction::Mirror` filters, opening per-backend mpsc
//! channels, and spawning mirror tasks) happens in [`crate::hooks::request_filter`].
//! `request_body_filter` tees arriving chunks to the channel senders; this module
//! owns only the terminal step: the spawned task that streams the body to the mirror
//! backend and discards its response.

use crate::ctx::MirrorDispatch;

/// Bounded capacity for the per-mirror mpsc channel (#360).
///
/// A full channel causes the current chunk to be dropped rather than stalling
/// the primary request path (`try_send` is used, never `send`). 64 chunks provides
/// enough headroom for any realistic mirror consumer lag while keeping per-request
/// memory cost negligible (mirror is best-effort fire-and-forget).
pub(crate) const MIRROR_CHANNEL_CAP: usize = 64;

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
