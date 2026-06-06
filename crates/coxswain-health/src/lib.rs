use async_trait::async_trait;
use http::{HeaderValue, Response, StatusCode, header};
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct HealthServer {
    pub synced: Arc<AtomicBool>,
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
                if self.synced.load(Ordering::Acquire) {
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
