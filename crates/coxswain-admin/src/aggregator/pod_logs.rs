//! `/api/v1/pods/{name}/logs` — chunked NDJSON log-stream relay for a coxswain pod.

use http::StatusCode;
use pingora_core::protocols::http::ServerSession;
use pingora_core::server::ShutdownWatch;
use std::sync::Arc;

use super::{OperatorAggregator, find_entry};
use crate::logs::{self, LogQuery};

impl OperatorAggregator {
    /// Relay a coxswain pod's logs to the client as a chunked NDJSON stream.
    ///
    /// Unlike the buffered endpoints, this writes its full response (header and
    /// body, including error statuses) directly on `session` — it is dispatched
    /// out of the streaming arm of `process_new_http`, past the buffered
    /// pipeline. The flow is: acquire a concurrency permit (→ 429 when the cap
    /// is saturated); resolve `pod_name` to its namespace from the trusted fleet
    /// snapshot (→ 404 when unknown — never the request URL, so an arbitrary
    /// cluster pod can't be tailed); obtain the kube client (→ 503 on failure);
    /// then delegate the byte pump to [`logs::run_until_shutdown`]. The permit is
    /// released by RAII when the stream ends.
    pub(crate) async fn stream_logs(
        &self,
        pod_name: &str,
        query: &str,
        session: &mut ServerSession,
        shutdown: &ShutdownWatch,
    ) {
        let Ok(_permit) = Arc::clone(&self.log_permits).try_acquire_owned() else {
            logs::write_status(
                session,
                StatusCode::TOO_MANY_REQUESTS,
                "too many concurrent log streams",
            )
            .await;
            return;
        };

        // Resolve namespace from the fleet, not the URL — this is what scopes
        // the endpoint to pods coxswain already tracks.
        let namespace = {
            let snapshot = self.fleet.load();
            match find_entry(&snapshot, pod_name) {
                Some(entry) => entry.pod_namespace.clone(),
                None => {
                    logs::write_status(session, StatusCode::NOT_FOUND, "pod not found").await;
                    return;
                }
            }
        };

        let kube = match self.kube().await {
            Ok(c) => c.clone(),
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/pods/.../logs");
                logs::write_status(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "kubernetes client not available",
                )
                .await;
                return;
            }
        };

        let query = LogQuery::parse(query);
        logs::run_until_shutdown(&kube, &namespace, pod_name, &query, session, shutdown).await;
    }
}
