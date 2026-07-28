//! Telemetry endpoints: `/metrics` (Prometheus) and `/statusz` (this pod's own
//! subsystem detail).
//!
//! # Why this is its own listener
//!
//! Three audiences want three different reachability guarantees, and a port is
//! the only thing that can express them:
//!
//! - **kubelet** probes `/healthz` and `/readyz` ([`super::HealthServer`]).
//!   That traffic is node-sourced, which most CNIs cannot select in a
//!   `NetworkPolicy`, so its port can never be fenced.
//! - **Prometheus and peer pods** read this port. It carries cluster data (the
//!   metric labels enumerate routes and backends), so it *should* be fenceable —
//!   but it can never be authenticated, because `PodMonitor` has no credential
//!   knob and a probing pod holds only the bcrypt hash of the operator
//!   credential. It is open by default and fenceable on request.
//! - **Humans and the UI** use the operator port, which is authenticated with no
//!   exemptions and reachable only via the leader-selecting Service.
//!
//! Collapsing this into the kubelet port would make `/metrics` permanently
//! unfenceable; collapsing it into the operator port is what forced the
//! Basic-auth carve-outs that this split removes.
//!
//! # Why `/statusz` and not `/api/v1/health`
//!
//! `/api/v1/*` denotes the versioned, authenticated, cluster-scoped operator
//! API. This endpoint is none of those: it is unauthenticated by necessity and
//! reports only the serving pod's own state. It sits in the probe family with
//! `/healthz` and `/readyz`, and is deliberately thinner than the operator
//! port's `/api/v1/health` — no `api_surfaces` (the UI reads that from its own
//! pod) and no leader flag (leadership comes from the Lease, which is
//! authoritative and resolves even for an unreachable pod).

use async_trait::async_trait;
use coxswain_core::health::{HealthRegistry, SubsystemSnapshot};
use http::{HeaderValue, Response, StatusCode, header};
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Pingora HTTP app serving `/metrics` and `/statusz`.
pub struct TelemetryServer {
    /// Shared health registry rendered by `/statusz`.
    pub registry: HealthRegistry,
}

/// `/statusz` response body.
///
/// Deliberately narrower than the operator port's `/api/v1/health`: it answers
/// "what is wrong with *this* pod", which is the only question a peer can't
/// answer from its own state or from the Kubernetes API.
#[derive(Serialize)]
struct StatusResponse {
    /// Coxswain build version of the serving pod.
    version: &'static str,
    /// Per-subsystem check states, keyed by subsystem name.
    subsystems: BTreeMap<Arc<str>, SubsystemSnapshot>,
}

impl TelemetryServer {
    /// Resolve a request path to its response.
    ///
    /// Split out from [`ServeHttp::response`] so both endpoints are testable
    /// without a `ServerSession` (which needs a real socket).
    fn route(&self, path: &str) -> Response<Vec<u8>> {
        match path {
            "/metrics" => metrics_response(),
            "/statusz" => self.statusz_response(),
            _ => {
                let mut r = Response::new(Vec::new());
                *r.status_mut() = StatusCode::NOT_FOUND;
                r
            }
        }
    }

    fn statusz_response(&self) -> Response<Vec<u8>> {
        let body = StatusResponse {
            version: env!("CARGO_PKG_VERSION"),
            subsystems: self.registry.snapshot().subsystems,
        };
        match serde_json::to_vec(&body) {
            Ok(bytes) => {
                let mut r = Response::new(bytes);
                *r.status_mut() = StatusCode::OK;
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                r
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to encode /statusz response");
                let mut r = Response::new(Vec::new());
                *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                r
            }
        }
    }
}

/// Encode the process-wide Prometheus registry as a scrape response.
///
/// An encode failure degrades to 500 rather than panicking: a scrape is not
/// worth taking a data-plane pod down for.
fn metrics_response() -> Response<Vec<u8>> {
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = prometheus::Encoder::encode(&encoder, &prometheus::gather(), &mut buffer) {
        tracing::warn!(error = %e, "failed to encode Prometheus metrics");
        let mut r = Response::new(Vec::new());
        *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return r;
    }
    let content_type = HeaderValue::from_str(prometheus::Encoder::format_type(&encoder))
        .unwrap_or_else(|_| HeaderValue::from_static("text/plain"));
    let mut r = Response::new(buffer);
    *r.status_mut() = StatusCode::OK;
    r.headers_mut().insert(header::CONTENT_TYPE, content_type);
    r
}

#[async_trait]
impl ServeHttp for TelemetryServer {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        self.route(session.req_header().uri.path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> TelemetryServer {
        TelemetryServer {
            registry: HealthRegistry::new(),
        }
    }

    #[test]
    fn statusz_reports_version_and_subsystems() {
        let registry = HealthRegistry::new();
        let handle = registry.register("reflector", &["initial-list"]);
        handle.failed("initial-list", "watch wedged");
        let r = TelemetryServer { registry }.route("/statusz");

        assert_eq!(r.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(r.body()).unwrap_or_default();
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            body["subsystems"]["reflector"]["checks"]["initial-list"]["state"], "failed",
            "the per-check detail is the whole reason a peer probes this instead of /readyz"
        );
    }

    #[test]
    fn statusz_omits_leadership_and_api_surfaces() {
        // Leadership comes from the Lease, which is authoritative and resolves
        // even when the pod is unreachable; `api_surfaces` is read by the UI
        // from its own pod. Carrying either here would re-create the coupling
        // the port split exists to remove.
        let body: serde_json::Value =
            serde_json::from_slice(server().route("/statusz").body()).unwrap_or_default();
        assert!(
            body.get("leader").is_none(),
            "leadership is the Lease's job"
        );
        assert!(body.get("api_surfaces").is_none());
    }

    #[test]
    fn metrics_is_served_in_the_prometheus_text_format() {
        let r = server().route("/metrics");
        assert_eq!(r.status(), StatusCode::OK);
        let ct = r
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.starts_with("text/plain"),
            "Prometheus expects the text exposition format, got {ct:?}"
        );
    }

    #[test]
    fn unknown_paths_are_404() {
        // Notably `/api/v1/health` and `/healthz`: this listener is not the
        // operator port and not the kubelet port.
        for path in ["/", "/api/v1/health", "/healthz", "/readyz"] {
            assert_eq!(
                server().route(path).status(),
                StatusCode::NOT_FOUND,
                "{path} must not be served on the telemetry port"
            );
        }
    }
}
