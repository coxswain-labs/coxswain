//! `/api/v1/proxies` endpoints — shared + dedicated proxy pods with liveness.

use http::Response;

use coxswain_core::fleet::FleetEntry;
use futures::future::join_all;

use super::{OperatorAggregator, attach_health_rollup, json_response, not_found, pod_base_url};
use crate::page::ListParams;

impl OperatorAggregator {
    /// `GET /api/v1/proxies` — all shared + dedicated proxy pods with liveness.
    pub(crate) async fn list_proxies(&self) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .cloned()
            .collect();
        let probes: Vec<_> = entries
            .iter()
            .map(|e| async move {
                // The liveness probe already returns the pod's full health body;
                // parse it (rather than discard it) so the entry carries a health
                // rollup without a second per-pod round-trip.
                let url = format!("{}/api/v1/health", pod_base_url(e));
                match self.fetch_json(&url).await {
                    Some(body) => {
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(true);
                        attach_health_rollup(&mut v, &body);
                        v
                    }
                    // Carry the full entry (component, namespace, …) even when
                    // unreachable so the UI can still bucket the pod by component
                    // and label it; "unreachable" is a probe outcome, not a loss
                    // of fleet-snapshot identity.
                    None => {
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(false);
                        v
                    }
                }
            })
            .collect();
        let results = join_all(probes).await;
        json_response(serde_json::json!({ "proxies": results }).to_string())
    }

    /// `GET /api/v1/proxies/{pod-name}` — single proxy pod info + liveness.
    pub(crate) async fn get_proxy(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let url = format!("{}/api/v1/health", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(_) => {
                let mut v = Self::entry_json(entry);
                v["reachable"] = serde_json::Value::Bool(true);
                json_response(v.to_string())
            }
            None => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": false }).to_string(),
            ),
        }
    }

    /// `GET /api/v1/fleet/proxies/{pod-name}/routes` — fan-out to the pod's
    /// `/api/v1/routes`, relaying the filter/pagination `params` so the **proxy** does
    /// the filtering at the source (the typed routing table lives there, #286).
    /// The controller is a transparent relay: it never receives non-matching rows.
    pub(crate) async fn get_proxy_routes(
        &self,
        pod_name: &str,
        params: &ListParams,
    ) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let base = pod_base_url(entry);
        let url = if params.is_empty() {
            format!("{base}/api/v1/routes")
        } else {
            format!("{base}/api/v1/routes?{}", params.to_query())
        };
        match self.fetch_json(&url).await {
            Some(routes) => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": true, "routes": routes })
                    .to_string(),
            ),
            None => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": false }).to_string(),
            ),
        }
    }

    /// `GET /api/v1/fleet/proxies/{pod-name}/facets` — relay the proxy's distinct
    /// hosts + route namespaces (the route table's filter-dropdown options). On an
    /// unreachable pod the lists come back empty, so the UI's combos just offer
    /// "All …".
    pub(crate) async fn get_proxy_facets(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let url = format!("{}/api/v1/facets", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(facets) => json_response(facets.to_string()),
            None => json_response(serde_json::json!({ "hosts": [], "namespaces": [] }).to_string()),
        }
    }

    /// `GET /api/v1/proxies/{pod-name}/health` — fan-out to the pod's
    /// `/api/v1/health`.
    pub(crate) async fn get_proxy_health(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        self.fetch_pod_health(pod_name, entry).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::tests::*;
    use coxswain_core::cluster::SharedClusterSummary;
    use coxswain_core::fleet::SharedFleet;
    use http::StatusCode;

    // ── fleet-miss 404 ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_proxy_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_proxy("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn get_proxy_routes_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_proxy_routes("missing", &ListParams::default())
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn get_proxy_health_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_proxy_health("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    // ── fan-out: list_proxies ─────────────────────────────────────────────────

    #[tokio::test]
    async fn list_proxies_empty_fleet_returns_empty_array() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        let resp = agg.list_proxies().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["proxies"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn list_proxies_marks_reachable_and_unreachable_pods() {
        let live_port = start_mock_http(r#"{"ok":true}"#).await;
        let dead_port = refused_port();
        let pods = [
            make_pod(
                "proxy-live",
                "shared-proxy",
                "127.0.0.1",
                &live_port.to_string(),
                None,
            ),
            make_pod(
                "proxy-dead",
                "shared-proxy",
                "127.0.0.1",
                &dead_port.to_string(),
                None,
            ),
        ];
        let agg = make_agg(fleet_with(pods), SharedClusterSummary::default());

        let resp = agg.list_proxies().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let proxies = body["proxies"].as_array().unwrap();
        assert_eq!(proxies.len(), 2);
        let live = proxies
            .iter()
            .find(|p| p["pod_name"] == "proxy-live")
            .unwrap();
        assert_eq!(live["reachable"], true);
        let dead = proxies
            .iter()
            .find(|p| p["pod_name"] == "proxy-dead")
            .unwrap();
        assert_eq!(dead["reachable"], false);
    }

    // ── fan-out: get_proxy ────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_proxy_reachable_returns_pod_info_with_reachable_true() {
        let port = start_mock_http(r#"{"ok":true}"#).await;
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["reachable"], true);
        assert_eq!(body["component"], "shared-proxy");
    }

    #[tokio::test]
    async fn get_proxy_unreachable_returns_reachable_false() {
        let port = refused_port();
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["reachable"], false);
    }

    // ── fan-out: get_proxy_routes ─────────────────────────────────────────────

    #[tokio::test]
    async fn get_proxy_routes_reachable_returns_routes_key() {
        let routes_body =
            r#"{"ingress":{"hosts":[],"conflicts":[]},"gateway":{"hosts":[],"conflicts":[]}}"#;
        let port = start_mock_http(routes_body).await;
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg
            .get_proxy_routes("proxy-0", &ListParams::default())
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["reachable"], true);
        assert!(body.get("routes").is_some());
    }

    #[tokio::test]
    async fn get_proxy_routes_unreachable_omits_routes_key() {
        let port = refused_port();
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg
            .get_proxy_routes("proxy-0", &ListParams::default())
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["reachable"], false);
        assert!(body.get("routes").is_none());
    }

    // ── fan-out: get_proxy_health ─────────────────────────────────────────────

    #[tokio::test]
    async fn get_proxy_health_reachable_returns_health_key() {
        let health_body = r#"{"version":"0.0.1","subsystems":{"reflector":"ok"}}"#;
        let port = start_mock_http(health_body).await;
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy_health("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["reachable"], true);
        assert!(body.get("health").is_some());
    }
}
