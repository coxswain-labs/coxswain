//! Health HTTP endpoints: `/healthz` (always 200) and `/readyz` (gated on the
//! aggregate of every subsystem registered in the shared [`HealthRegistry`]).

use async_trait::async_trait;
use coxswain_core::health::HealthRegistry;
use http::{HeaderValue, Response, StatusCode, header};
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;

/// Pingora HTTP app serving `/healthz` (always 200) and `/readyz`.
///
/// `/readyz` returns 200 iff every registered subsystem is `Ready` or
/// `Degraded`; otherwise 503. A `Degraded` subsystem keeps the pod in
/// kubelet's endpoints because the data plane is still functional — only
/// `Pending` and `Failed` subsystems flip the probe to 503.
// intentionally open: field-literal constructed in crates/coxswain-bin/src/main.rs.
pub struct HealthServer {
    /// Shared health registry inspected on every `/readyz` request.
    pub registry: HealthRegistry,
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
            "/healthz" => text_response(StatusCode::OK, b"ok\n"),
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
