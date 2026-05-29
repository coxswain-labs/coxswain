use async_trait::async_trait;
use http::Response;
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct HealthService {
    pub synced: Arc<AtomicBool>,
}

#[async_trait]
impl ServeHttp for HealthService {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        match session.req_header().uri.path() {
            "/healthz" => Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(b"ok\n".to_vec())
                .expect("infallible: static response headers are valid"),
            "/readyz" => {
                if self.synced.load(Ordering::Acquire) {
                    Response::builder()
                        .status(200)
                        .header("content-type", "text/plain")
                        .body(b"ok\n".to_vec())
                        .expect("infallible: static response headers are valid")
                } else {
                    Response::builder()
                        .status(503)
                        .header("content-type", "text/plain")
                        .body(b"not ready\n".to_vec())
                        .expect("infallible: static response headers are valid")
                }
            }
            _ => Response::builder()
                .status(404)
                .body(Vec::new())
                .expect("infallible: static response headers are valid"),
        }
    }
}
