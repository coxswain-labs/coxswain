//! `/api/v1/controllers` endpoints — controller pods with liveness + leadership.
//!
//! Two different questions with two different sources, deliberately:
//!
//! - **"is this pod alive, and what is broken on it?"** — only that pod can
//!   answer, so it is probed over HTTP at `/statusz`. There is no alternative:
//!   controllers are not discovery clients (they never dial each other over
//!   gRPC, and standbys accept no streams), so no existing channel carries it.
//! - **"which pod is the leader?"** — the `coxswain-leader-lock` Lease answers
//!   authoritatively. Reading it beats believing each pod's self-report on two
//!   counts: it resolves even for an unreachable pod, and a pod's flag is a
//!   cached value refreshed on its own renewal tick, so it lags across failover.

use http::Response;

use coxswain_core::fleet::FleetEntry;
use futures::future::join_all;
use std::sync::Arc;

use super::{OperatorAggregator, attach_health_rollup, json_response, not_found, pod_statusz_url};

impl OperatorAggregator {
    /// The current lease holder's pod name, or `None` when leadership is
    /// unknown.
    ///
    /// A lock-free read of the cell the controller's lease loop publishes into —
    /// no apiserver call on the request path. `None` covers a genuinely
    /// leaderless window and a not-yet-observed lease alike; both render as no
    /// pod being leader rather than a guess.
    pub(super) fn lease_holder(&self) -> Option<Arc<str>> {
        self.leader_identity
            .as_ref()
            .and_then(|cell| cell.load().as_ref().clone())
    }

    /// `GET /api/v1/controllers` — all controller pods with liveness + leadership.
    ///
    /// Probes each controller's `/statusz` for reachability and subsystem state,
    /// and resolves `is_leader` from the Lease — see the module header for why
    /// those come from different places.
    pub(crate) async fn list_controllers(&self) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot.controllers.to_vec();
        let probes = join_all(entries.iter().map(|e| async move {
            let mut v = Self::entry_json(e);
            match self.fetch_json(&pod_statusz_url(e)).await {
                Some(body) => {
                    v["reachable"] = serde_json::Value::Bool(true);
                    attach_health_rollup(&mut v, &body);
                }
                // Keep the full entry (namespace, …) on the unreachable path
                // too, so the card still renders its identity.
                None => v["reachable"] = serde_json::Value::Bool(false),
            }
            v
        }));
        let mut results = probes.await;
        let holder = self.lease_holder();
        for v in &mut results {
            let is_leader = holder.as_deref() == v["pod_name"].as_str();
            v["is_leader"] = serde_json::Value::Bool(is_leader);
        }
        json_response(serde_json::json!({ "controllers": results }).to_string())
    }

    /// `GET /api/v1/controllers/{pod-name}` — single controller pod info.
    ///
    /// Probes `/statusz` for liveness and resolves leadership from the Lease,
    /// mirroring [`Self::list_controllers`].
    ///
    /// Leadership is reported even when the pod itself is unreachable — the
    /// Lease knows who holds it regardless, and "unreachable but still the
    /// lease holder" is exactly the state an operator needs to see.
    pub(crate) async fn get_controller(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let Some(entry) = snapshot.controllers.iter().find(|e| e.pod_name == pod_name) else {
            return not_found();
        };
        let probe = self.fetch_json(&pod_statusz_url(entry)).await;
        let is_leader = self.lease_holder().as_deref() == Some(pod_name);
        let mut v = Self::entry_json(entry);
        v["reachable"] = serde_json::Value::Bool(probe.is_some());
        v["is_leader"] = serde_json::Value::Bool(is_leader);
        json_response(v.to_string())
    }

    /// `GET /api/v1/controllers/{pod-name}/health` — fan-out to that pod's
    /// `/statusz`.
    pub(crate) async fn get_controller_health(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let Some(entry) = snapshot.controllers.iter().find(|e| e.pod_name == pod_name) else {
            return not_found();
        };
        self.fetch_pod_health(pod_name, entry).await
    }

    /// Shared implementation for `/{pod}/health` detail endpoints.
    pub(super) async fn fetch_pod_health(
        &self,
        pod_name: &str,
        entry: &FleetEntry,
    ) -> Response<Vec<u8>> {
        let url = pod_statusz_url(entry);
        match self.fetch_json(&url).await {
            Some(health) => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": true, "health": health })
                    .to_string(),
            ),
            None => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": false }).to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::tests::*;
    use coxswain_core::cluster::SharedClusterSummary;
    use coxswain_core::fleet::SharedFleet;
    use http::StatusCode;

    // ── fleet-miss 404 ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_controller_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_controller("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn get_controller_health_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_controller_health("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    // ── fan-out: list_controllers ─────────────────────────────────────────────

    #[tokio::test]
    async fn list_controllers_marks_reachable_and_unreachable_pods() {
        let live_port = start_mock_http(r#"{"ok":true}"#).await;
        let dead_port = refused_port();
        let pods = [
            make_pod(
                "ctrl-live",
                "controller",
                "127.0.0.1",
                &live_port.to_string(),
                None,
            ),
            make_pod(
                "ctrl-dead",
                "controller",
                "127.0.0.1",
                &dead_port.to_string(),
                None,
            ),
        ];
        let agg = make_agg(fleet_with(pods), SharedClusterSummary::default());

        let resp = agg.list_controllers().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let controllers = body["controllers"].as_array().unwrap();
        assert_eq!(controllers.len(), 2);
        let live = controllers
            .iter()
            .find(|c| c["pod_name"] == "ctrl-live")
            .unwrap();
        assert_eq!(live["reachable"], true);
        // No leader-identity cell wired in this fixture, so leadership is
        // unknown and no pod may be labelled leader.
        assert_eq!(live["is_leader"], false);
        let dead = controllers
            .iter()
            .find(|c| c["pod_name"] == "ctrl-dead")
            .unwrap();
        assert_eq!(dead["reachable"], false);
    }

    #[tokio::test]
    async fn list_controllers_ignores_a_pod_claiming_leadership_in_its_own_body() {
        // Regression guard for #676: `is_leader` used to be read straight out of
        // the probed pod's response body. It now comes from the Lease, which is
        // authoritative — a pod's self-report is a cached flag that lags a
        // failover, so believing it can label two pods leader at once (the old
        // leader still says `true` until its next renewal tick observes the
        // demotion). Here the pod insists it leads and must not be believed.
        let port = start_mock_http(r#"{"version":"0.0.0","leader":true,"subsystems":{}}"#).await;
        let pods = [make_pod(
            "ctrl-liar",
            "controller",
            "127.0.0.1",
            &port.to_string(),
            None,
        )];
        let agg = make_agg(fleet_with(pods), SharedClusterSummary::default());

        let resp = agg.list_controllers().await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let entry = body["controllers"][0].clone();

        assert_eq!(entry["reachable"], true, "the probe itself still works");
        assert_eq!(
            entry["is_leader"], false,
            "leadership must come from the Lease, not the pod's own claim"
        );
    }
}
