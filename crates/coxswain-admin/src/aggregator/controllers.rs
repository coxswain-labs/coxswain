//! `/api/v1/controllers` endpoints — controller pods with liveness + leadership.

use http::Response;

use coxswain_core::fleet::FleetEntry;
use futures::future::join_all;

use super::{OperatorAggregator, attach_health_rollup, json_response, not_found, pod_base_url};

impl OperatorAggregator {
    /// `GET /api/v1/controllers` — all controller pods with liveness + leadership.
    ///
    /// Probes each controller's `/api/v1/health`: it doubles as a liveness check
    /// (200 ⇒ reachable) and carries that pod's live `leader` flag and subsystem
    /// state in one hop, so the response reports `is_leader` per pod. (This
    /// replaced the retired `/api/v1/cluster` leader probe.)
    pub(crate) async fn list_controllers(&self) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot.controllers.to_vec();
        let probes: Vec<_> = entries
            .iter()
            .map(|e| async move {
                let health_url = format!("{}/api/v1/health", pod_base_url(e));
                match self.fetch_json(&health_url).await {
                    Some(body) => {
                        let is_leader = body["leader"].as_bool().unwrap_or(false);
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(true);
                        v["is_leader"] = serde_json::Value::Bool(is_leader);
                        attach_health_rollup(&mut v, &body);
                        v
                    }
                    // Keep the full entry (namespace, …) on the unreachable
                    // path too, so the card still renders its identity.
                    None => {
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(false);
                        v
                    }
                }
            })
            .collect();
        let results = join_all(probes).await;
        json_response(serde_json::json!({ "controllers": results }).to_string())
    }

    /// `GET /api/v1/controllers/{pod-name}` — single controller pod info.
    ///
    /// Probes `/api/v1/health`: it doubles as a liveness check and carries this
    /// pod's live `leader` flag, so the controller detail page can show
    /// leader/standby without a second call — mirroring [`Self::list_controllers`].
    pub(crate) async fn get_controller(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let Some(entry) = snapshot.controllers.iter().find(|e| e.pod_name == pod_name) else {
            return not_found();
        };
        let url = format!("{}/api/v1/health", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(body) => {
                let is_leader = body["leader"].as_bool().unwrap_or(false);
                let mut v = Self::entry_json(entry);
                v["reachable"] = serde_json::Value::Bool(true);
                v["is_leader"] = serde_json::Value::Bool(is_leader);
                json_response(v.to_string())
            }
            None => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": false }).to_string(),
            ),
        }
    }

    /// `GET /api/v1/controllers/{pod-name}/health` — fan-out to that pod's
    /// `/api/v1/health`.
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
        let url = format!("{}/api/v1/health", pod_base_url(entry));
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
        // /cluster body had no controller.leader → defaults to false.
        assert_eq!(live["is_leader"], false);
        let dead = controllers
            .iter()
            .find(|c| c["pod_name"] == "ctrl-dead")
            .unwrap();
        assert_eq!(dead["reachable"], false);
    }

    #[tokio::test]
    async fn list_controllers_reports_is_leader_from_health_endpoint() {
        // The /api/v1/health probe carries the top-level `leader` flag; the
        // reachable entry must surface it as is_leader so the UI doesn't misread a
        // healthy single-leader cluster as having no elected leader.
        let port = start_mock_http(r#"{"version":"0.0.0","leader":true,"subsystems":{}}"#).await;
        let pods = [make_pod(
            "ctrl-leader",
            "controller",
            "127.0.0.1",
            &port.to_string(),
            None,
        )];
        let agg = make_agg(fleet_with(pods), SharedClusterSummary::default());

        let resp = agg.list_controllers().await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let leader = body["controllers"][0].clone();
        assert_eq!(leader["reachable"], true);
        assert_eq!(leader["is_leader"], true);
    }
}
