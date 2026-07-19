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

impl HealthServer {
    /// Resolve a request path to its probe response.
    ///
    /// Split out from [`ServeHttp::response`] so the probe semantics are
    /// testable without a `ServerSession` (which needs a real socket): the
    /// trait impl below is a one-line delegation that only reads the path.
    /// `/readyz` is what holds a pod in kubelet's endpoint set, so its
    /// behaviour is worth asserting directly.
    fn route(&self, path: &str) -> Response<Vec<u8>> {
        match path {
            "/healthz" => {
                let live = self.liveness.as_ref().is_none_or(LivenessGate::is_alive);
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

#[async_trait]
impl ServeHttp for HealthServer {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        self.route(session.req_header().uri.path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::health::HealthRegistry;

    fn server(registry: HealthRegistry, liveness: Option<LivenessGate>) -> HealthServer {
        HealthServer { registry, liveness }
    }

    fn body_of(r: &Response<Vec<u8>>) -> &str {
        std::str::from_utf8(r.body()).unwrap_or("<non-utf8>")
    }

    #[test]
    fn healthz_is_ok_when_no_liveness_gate_is_wired() {
        let r = server(HealthRegistry::new(), None).route("/healthz");
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_of(&r), "ok\n");
    }

    #[test]
    fn healthz_is_ok_while_the_gate_is_untripped() {
        let r = server(HealthRegistry::new(), Some(LivenessGate::new())).route("/healthz");
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn healthz_is_503_once_the_gate_trips() {
        let gate = LivenessGate::new();
        gate.trip();
        let r = server(HealthRegistry::new(), Some(gate)).route("/healthz");
        assert_eq!(
            r.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a tripped liveness gate must fail /healthz so kubelet restarts the pod"
        );
        assert_eq!(body_of(&r), "not live\n");
    }

    #[test]
    fn readyz_is_ok_with_no_registered_subsystems() {
        let r = server(HealthRegistry::new(), None).route("/readyz");
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn readyz_is_503_while_a_subsystem_is_still_pending() {
        let registry = HealthRegistry::new();
        let _handle = registry.register("reflector", &["initial-list"]);
        let r = server(registry, None).route("/readyz");
        assert_eq!(
            r.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a registered-but-Pending subsystem must keep the pod out of endpoints"
        );
        assert_eq!(body_of(&r), "not ready\n");
    }

    #[test]
    fn readyz_is_ok_once_every_check_reports_ready() {
        let registry = HealthRegistry::new();
        let handle = registry.register("reflector", &["initial-list"]);
        handle.ready("initial-list");
        let r = server(registry, None).route("/readyz");
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn readyz_stays_ok_when_a_subsystem_is_only_degraded() {
        let registry = HealthRegistry::new();
        let handle = registry.register("reflector", &["initial-list"]);
        handle.degraded("initial-list", "stale but serving");
        let r = server(registry, None).route("/readyz");
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "Degraded means the data plane still serves — the pod must stay in endpoints"
        );
    }

    #[test]
    fn readyz_is_503_when_a_subsystem_failed() {
        let registry = HealthRegistry::new();
        let handle = registry.register("reflector", &["initial-list"]);
        handle.failed("initial-list", "watch wedged");
        let r = server(registry, None).route("/readyz");
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn liveness_and_readiness_are_independent() {
        // A wedged reflector fails /readyz but must not fail /healthz unless the
        // gate is explicitly tripped — otherwise kubelet restarts a pod that is
        // merely not-yet-ready.
        let registry = HealthRegistry::new();
        let handle = registry.register("reflector", &["initial-list"]);
        handle.failed("initial-list", "watch wedged");
        let s = server(registry, Some(LivenessGate::new()));
        assert_eq!(s.route("/readyz").status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(s.route("/healthz").status(), StatusCode::OK);
    }

    #[test]
    fn unknown_paths_are_404_with_an_empty_body() {
        let r = server(HealthRegistry::new(), None).route("/metrics");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert!(r.body().is_empty(), "404 must not carry a probe body");
    }

    #[test]
    fn probe_responses_are_labelled_text_plain() {
        let r = server(HealthRegistry::new(), None).route("/healthz");
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).map(|h| h.as_bytes()),
            Some(&b"text/plain"[..])
        );
    }
}
