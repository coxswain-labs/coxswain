//! Health HTTP endpoints: `/healthz` (always 200) and `/readyz` (gated on the
//! aggregate of every subsystem registered in the shared [`HealthRegistry`]).

use async_trait::async_trait;
use coxswain_core::health::{HealthRegistry, LivenessGate};
use http::{HeaderValue, Response, StatusCode, header};
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;

/// Pingora HTTP app serving `/healthz` (liveness) and `/readyz` (readiness).
///
/// `/readyz` returns 200 iff every registered subsystem is `Ready` or
/// `Degraded`; otherwise 503. A `Degraded` subsystem keeps the pod in
/// kubelet's endpoints because the data plane is still functional — only
/// `Pending` and `Failed` subsystems flip the probe to 503.
///
/// `/healthz` returns 200 unless a [`LivenessGate`] is wired and has tripped.
/// The gate is the #573 relist-wedge backstop: the controller trips it after a
/// reflector relist stays incomplete past the window, so kubelet restarts the
/// otherwise-`Ready`-but-functionally-dead pod. Roles without a gate (the
/// proxy) keep the historical always-200 liveness semantics.
// intentionally open: field-literal constructed in crates/coxswain-bin/src/lib.rs.
pub struct HealthServer {
    /// Shared health registry inspected on every `/readyz` request.
    pub registry: HealthRegistry,
    /// Liveness backstop consulted on every `/healthz` request. `None` = always
    /// live (the historical behaviour); `Some` gate that has tripped = 503.
    pub liveness: Option<LivenessGate>,
}

fn text_response(status: StatusCode, body: &'static [u8]) -> Response<Vec<u8>> {
    let mut r = Response::new(body.to_vec());
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    r
}

#[async_trait]
impl ServeHttp for HealthServer {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        match session.req_header().uri.path() {
            "/healthz" => {
                let live = self.liveness.as_ref().map_or(true, LivenessGate::is_alive);
                if live {
                    text_response(StatusCode::OK, b"ok\n")
                } else {
                    text_response(StatusCode::SERVICE_UNAVAILABLE, b"not live\n")
                }
            }
            "/readyz" => {
                if self.registry.is_ready() {
                    text_response(StatusCode::OK, b"ok\n")
                } else {
                    text_response(StatusCode::SERVICE_UNAVAILABLE, b"not ready\n")
                }
            }
            _ => {
                let mut r = Response::new(Vec::new());
                *r.status_mut() = StatusCode::NOT_FOUND;
                r
            }
        }
    }
}
