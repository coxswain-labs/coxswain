//! `/api/v1/routing/{ingresses,httproutes}` + `/api/v1/ingresses/{ns}/{name}` —
//! ingress + HTTPRoute lists from the cluster summary, ingress detail enriched
//! with a live load-balancer address.

use http::Response;

use k8s_openapi::api::networking::v1::Ingress;
use kube::Api;

use super::{OperatorAggregator, json_response, not_found};
use crate::page::{ListParams, Page, page_response};

impl OperatorAggregator {
    /// `GET /api/v1/routing/ingresses` — ingress list from the cluster summary
    /// (no fan-out), with the shared filter/pagination envelope.
    pub(crate) fn list_ingresses(&self, params: &ListParams) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let filtered: Vec<serde_json::Value> = snapshot
            .ingresses
            .iter()
            .filter(|i| !params.problems_only || i.status.is_problem())
            .filter(|i| params.namespace_matches(&i.namespace))
            .filter(|i| params.name_matches(&i.name))
            .map(|i| serde_json::to_value(i).unwrap_or(serde_json::Value::Null))
            .collect();
        page_response("ingresses", Page::paginate(filtered, params))
    }

    /// `GET /api/v1/routing/httproutes` — HTTPRoute list from the cluster summary
    /// (no fan-out, #293), with the shared filter/pagination envelope. The `name`
    /// filter matches the route's object name (name-only, like the other routing
    /// lists); declared hostnames are not part of the free-text search.
    pub(crate) fn list_httproutes(&self, params: &ListParams) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let filtered: Vec<serde_json::Value> = snapshot
            .httproutes
            .iter()
            .filter(|r| !params.problems_only || r.status.is_problem())
            .filter(|r| params.namespace_matches(&r.namespace))
            .filter(|r| params.name_matches(&r.name))
            .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
            .collect();
        page_response("httproutes", Page::paginate(filtered, params))
    }

    /// `GET /api/v1/ingresses/{namespace}/{name}` — cluster-summary entry
    /// enriched with a live load-balancer address from the Kubernetes API.
    pub(crate) async fn get_ingress(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let summary = match snapshot
            .ingresses
            .iter()
            .find(|i| i.name == name && i.namespace == namespace)
        {
            Some(s) => s,
            None => return not_found(),
        };

        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/ingresses detail");
                return json_response(ingress_summary_json(summary, None).to_string());
            }
        };

        let api: Api<Ingress> = Api::namespaced(kube.clone(), namespace);
        let live_lb = match api.get(name).await {
            Ok(ing) => ing
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_deref())
                .and_then(|items| items.first())
                .and_then(|i| i.ip.as_deref().or(i.hostname.as_deref()))
                .map(str::to_owned),
            Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET Ingress failed; using summary data");
                None
            }
        };

        json_response(ingress_summary_json(summary, live_lb.as_deref()).to_string())
    }
}

fn ingress_summary_json(
    summary: &coxswain_core::cluster::IngressSummary,
    live_lb: Option<&str>,
) -> serde_json::Value {
    let lb = live_lb.unwrap_or(summary.load_balancer.as_str());
    let mut v = serde_json::json!({
        "name": summary.name,
        "namespace": summary.namespace,
        "route_count": summary.route_count,
    });
    if !lb.is_empty() {
        v["load_balancer"] = serde_json::Value::String(lb.to_owned());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::tests::*;
    use coxswain_core::cluster::{
        ClusterSummary, ControllerSummary, IngressSummary, SharedClusterSummary,
    };
    use coxswain_core::fleet::SharedFleet;
    use http::StatusCode;

    // ── ingress list ──────────────────────────────────────────────────────────

    #[test]
    fn ingress_list_derived_from_cluster_summary() {
        let summary = ClusterSummary::new(
            vec![],
            vec![
                IngressSummary::new("ing-a", "default").with_route_count(2),
                IngressSummary::new("ing-b", "other").with_load_balancer("10.0.0.5"),
            ],
            vec![],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));

        let snapshot = cluster.load();
        let body = serde_json::json!({ "ingresses": snapshot.ingresses });
        let ingresses = body["ingresses"].as_array().expect("array");
        assert_eq!(ingresses.len(), 2);
        assert_eq!(ingresses[0]["name"], "ing-a");
        assert_eq!(ingresses[1]["load_balancer"], "10.0.0.5");
    }

    // ── list_ingresses handler ────────────────────────────────────────────────

    #[test]
    fn list_ingresses_handler_returns_200_with_ingresses_key() {
        let summary = ClusterSummary::new(
            vec![],
            vec![
                IngressSummary::new("ing-a", "default")
                    .with_route_count(1)
                    .with_load_balancer("10.0.0.5"),
            ],
            vec![],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));
        let agg = make_agg(SharedFleet::default(), cluster);

        let resp = agg.list_ingresses(&ListParams::default());
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["ingresses"][0]["name"], "ing-a");
        assert_eq!(body["ingresses"][0]["load_balancer"], "10.0.0.5");
    }
}
