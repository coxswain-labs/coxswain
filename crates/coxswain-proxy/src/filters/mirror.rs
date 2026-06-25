//! `RequestMirror` dispatch (GEP-3171): the fire-and-forget mirror sub-request.
//!
//! The mirror *setup* (sampling each `FilterAction::Mirror`, building one
//! [`MirrorDispatch`] per backend, and buffering the request body when a
//! max-body-size is configured) stays inline in [`crate::hooks`] because it is
//! interleaved with the `request_filter` / `request_body_filter` lifecycle. This
//! module owns only the terminal step: spawning the detached task that actually
//! sends the mirror and discards its response.

use crate::ctx::MirrorDispatch;
use bytes::Bytes;
use coxswain_core::routing::BackendProtocol;

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
pub(crate) fn spawn_mirror_dispatch(
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
