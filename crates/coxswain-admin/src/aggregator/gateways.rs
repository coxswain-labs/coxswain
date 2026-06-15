//! `/api/v1/routing/{summary,gateways}` + `/api/v1/gateways/{ns}/{name}` —
//! gateway list and detail derived from the cluster summary, enriched with live
//! Kubernetes status conditions.

use http::Response;

use coxswain_core::cluster::{ClusterSummary, GatewayCondition, Severity};
use kube::{Api, Client};

use super::{OperatorAggregator, internal_error, json_response, not_found};
use crate::gw_types;
use crate::page::{ListParams, Page, page_response};

impl OperatorAggregator {
    /// `GET /api/v1/routing/summary` — compact per-category counts + worst
    /// severity (Gateways/HTTPRoutes/Ingresses) from the cluster summary, plus the
    /// cluster-wide `namespaces` set. Backs the routing-tab badges + warning icons
    /// and the namespace dropdown without shipping the full lists.
    pub(crate) fn routing_summary(&self) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let mut v = match serde_json::to_value(snapshot.routing_summary()) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "failed to serialise /api/v1/routing/summary");
                return internal_error();
            }
        };
        // Every namespace holding a routing resource — the namespace dropdown must
        // list them all regardless of the active page/filter, so it can't be
        // derived from a single (paginated) list response.
        let mut namespaces: Vec<&str> = snapshot
            .gateways
            .iter()
            .map(|g| g.namespace.as_str())
            .chain(snapshot.httproutes.iter().map(|r| r.namespace.as_str()))
            .chain(snapshot.ingresses.iter().map(|i| i.namespace.as_str()))
            .collect();
        namespaces.sort_unstable();
        namespaces.dedup();
        v["namespaces"] = serde_json::json!(namespaces);
        json_response(v.to_string())
    }

    /// `GET /api/v1/routing/gateways` — gateway list from the cluster summary (no
    /// fan-out), with the shared filter/pagination envelope.
    pub(crate) fn list_gateways(&self, params: &ListParams) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let filtered: Vec<serde_json::Value> = snapshot
            .gateways
            .iter()
            .filter(|g| !params.problems_only || g.status.is_problem())
            .filter(|g| params.namespace_matches(&g.namespace))
            .filter(|g| params.name_matches(&g.name))
            .map(|g| serde_json::to_value(g).unwrap_or(serde_json::Value::Null))
            .collect();
        page_response("gateways", Page::paginate(filtered, params))
    }

    /// `GET /api/v1/gateways/{namespace}/{name}` — cluster-summary entry
    /// enriched with live status conditions from the Kubernetes API.
    pub(crate) async fn get_gateway(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        // Find the entry in the cluster summary (fast path).
        let snapshot = self.cluster.load();
        let summary = match snapshot
            .gateways
            .iter()
            .find(|g| g.name == name && g.namespace == namespace)
        {
            Some(s) => s,
            None => return not_found(),
        };

        // Enrich with live K8s conditions.
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/gateways detail");
                return json_response(gateway_summary_json(summary, &snapshot).to_string());
            }
        };

        let api: Api<gw_types::v::gateways::Gateway> = Api::namespaced(kube.clone(), namespace);
        // Fetch the live Gateway object once; use it for both conditions and
        // listener detail so we only make one K8s call.
        let (conditions, listeners) = match api.get(name).await {
            Ok(gw) => {
                let conds = gw
                    .status
                    .as_ref()
                    .and_then(|s| s.conditions.as_deref())
                    .unwrap_or_default()
                    .iter()
                    .map(GatewayCondition::from_kube)
                    .collect::<Vec<_>>();

                // Join spec listeners with per-listener status (attached-route
                // count + conditions for TLS health). Status may be absent before
                // the first reconcile.
                let status_by_name: std::collections::HashMap<&str, &_> = gw
                    .status
                    .as_ref()
                    .and_then(|s| s.listeners.as_deref())
                    .unwrap_or_default()
                    .iter()
                    .map(|l| (l.name.as_str(), l))
                    .collect();

                let lsnrs: Vec<serde_json::Value> = gw
                    .spec
                    .listeners
                    .iter()
                    .map(|l| {
                        let st = status_by_name.get(l.name.as_str()).copied();
                        let attached = st.map(|s| s.attached_routes).unwrap_or(0);
                        // Listener-precise TLS health: a configured listener's
                        // badge reflects whether its certificate refs resolved and
                        // it programmed — not merely that a TLS block exists.
                        let (tls_status, tls_reason) = if l.tls.is_some() {
                            let (sev, why) =
                                listener_tls_health(st.map(|s| s.conditions.as_slice()));
                            (
                                serde_json::to_value(sev).unwrap_or(serde_json::Value::Null),
                                why,
                            )
                        } else {
                            (serde_json::Value::Null, None)
                        };
                        serde_json::json!({
                            "name": l.name,
                            "port": l.port,
                            "protocol": l.protocol,
                            "tls_enabled": l.tls.is_some(),
                            "tls_status": tls_status,
                            "tls_reason": tls_reason,
                            "attached_routes": attached,
                        })
                    })
                    .collect();

                (conds, lsnrs)
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                // Deleted since the last cluster-summary rebuild.
                return not_found();
            }
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET Gateway failed; using summary conditions");
                (summary.conditions.clone(), Vec::new())
            }
        };

        let attached_routes_list = self
            .list_attached_httproutes(kube, &snapshot, namespace, name)
            .await;

        let mut v = gateway_summary_json(summary, &snapshot);
        v["conditions"] = serde_json::to_value(&conditions).unwrap_or(serde_json::Value::Null);
        v["listeners"] = serde_json::Value::Array(listeners);
        v["attached_routes_list"] = serde_json::Value::Array(attached_routes_list);
        json_response(v.to_string())
    }

    /// List all HTTPRoutes cluster-wide and return those whose `parentRefs`
    /// reference the given Gateway (`gw_namespace/gw_name`).
    ///
    /// A `parentRef` is considered to target the Gateway when its `name`
    /// matches `gw_name` and its effective namespace (the `namespace` field
    /// if present, otherwise the route's own namespace) matches `gw_namespace`.
    /// An absent `kind` or `group` is treated as `Gateway` /
    /// `gateway.networking.k8s.io` per the Gateway API spec.
    ///
    /// On any Kubernetes error the list degrades gracefully to an empty slice.
    async fn list_attached_httproutes(
        &self,
        kube: &Client,
        snapshot: &ClusterSummary,
        gw_namespace: &str,
        gw_name: &str,
    ) -> Vec<serde_json::Value> {
        let api: Api<gw_types::HttpRoute> = Api::all(kube.clone());
        let routes = match api.list(&kube::api::ListParams::default()).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    gw_namespace,
                    gw_name,
                    "K8s list HTTPRoutes failed; attached_routes_list will be empty"
                );
                return Vec::new();
            }
        };

        // De-dup: a route can have multiple parentRefs targeting the same
        // Gateway (different sections); count the route once, not once per ref.
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();

        for route in &routes {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or_default();
            let route_name = match route.metadata.name.as_deref() {
                Some(n) => n,
                None => continue,
            };

            // Skip if we've already recorded this route (multiple matching parentRefs).
            if !seen.insert((route_ns, route_name)) {
                continue;
            }

            let refs = route.spec.parent_refs.as_deref().unwrap_or_default();

            let attaches = refs.iter().any(|p| {
                // Absent `kind` defaults to "Gateway"; absent `group` defaults to
                // "gateway.networking.k8s.io" — both are implicitly our target.
                let kind_ok = p.kind.as_deref().is_none_or(|k| k == "Gateway");
                let effective_ns = p.namespace.as_deref().unwrap_or(route_ns);
                kind_ok && p.name == gw_name && effective_ns == gw_namespace
            });

            if attaches {
                // Enrich with hostnames + rule count straight from the route spec
                // so the Gateway-detail table mirrors the routing HTTPRoutes table
                // (Parent is implicit here — it's this Gateway).
                let hostnames = route.spec.hostnames.as_deref().unwrap_or(&[]).to_vec();
                let rule_count = route.spec.rules.as_deref().map(<[_]>::len).unwrap_or(0);
                // Reflector-computed traffic-served status (same field the routing
                // HTTPRoutes table shows). The UI overlays /problems on top, so
                // dead/conflict routes on a dedicated gateway still surface.
                let status = snapshot
                    .httproutes
                    .iter()
                    .find(|h| h.namespace == route_ns && h.name == route_name)
                    .map(|h| h.status);
                result.push(serde_json::json!({
                    "kind": "HTTPRoute",
                    "namespace": route_ns,
                    "name": route_name,
                    "hostnames": hostnames,
                    "rule_count": rule_count,
                    "status": status,
                }));
            }
        }

        result
    }
}

/// Build a JSON object from a `GatewaySummary` (dropping its own `conditions`
/// so the caller can inject live ones).
fn gateway_summary_json(
    summary: &coxswain_core::cluster::GatewaySummary,
    _snapshot: &ClusterSummary,
) -> serde_json::Value {
    serde_json::json!({
        "name": summary.name,
        "namespace": summary.namespace,
        "proxy": summary.proxy,
        "route_count": summary.route_count,
        "addresses": summary.addresses,
        "conditions": summary.conditions,
        "status": summary.status,
    })
}

/// Listener-precise TLS health from a listener's Gateway API status conditions.
///
/// `ResolvedRefs=False` (its `certificateRefs` didn't resolve — missing/invalid
/// Secret or a cross-namespace ref not permitted) means no TLS traffic serves on
/// this listener → [`Severity::Error`]. `Programmed=False` means it isn't yet
/// realized in the data plane → [`Severity::Warn`]. Both `True` → [`Severity::Ok`].
/// Absent status (pre-reconcile) is reported as `Warn`, never a confident lock —
/// the badge must not claim a certificate is good when we don't yet know.
fn listener_tls_health(
    conditions: Option<&[k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition]>,
) -> (Severity, Option<String>) {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
    let Some(conds) = conditions else {
        return (
            Severity::Warn,
            Some("listener status not reported yet".to_string()),
        );
    };
    let why = |c: &Condition| {
        if c.message.is_empty() {
            c.reason.clone()
        } else {
            c.message.clone()
        }
    };
    if let Some(c) = conds.iter().find(|c| c.type_ == "ResolvedRefs")
        && c.status != "True"
    {
        return (Severity::Error, Some(why(c)));
    }
    if let Some(c) = conds.iter().find(|c| c.type_ == "Programmed")
        && c.status != "True"
    {
        return (Severity::Warn, Some(why(c)));
    }
    (Severity::Ok, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::tests::*;
    use coxswain_core::cluster::{
        ControllerSummary, GatewaySummary, ProxyAssignment, SharedClusterSummary,
    };
    use coxswain_core::fleet::SharedFleet;
    use http::StatusCode;

    #[test]
    fn listener_tls_health_maps_conditions_to_severity() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
        let cond = |t: &str, s: &str| Condition {
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
            message: String::new(),
            observed_generation: None,
            reason: format!("{t}Reason"),
            status: s.to_string(),
            type_: t.to_string(),
        };
        // Both conditions True → genuinely good.
        let (sev, why) = listener_tls_health(Some(&[
            cond("ResolvedRefs", "True"),
            cond("Programmed", "True"),
        ]));
        assert_eq!(sev, Severity::Ok);
        assert!(why.is_none());
        // Cert ref unresolved → serves no TLS traffic → error, with the reason.
        let (sev, why) = listener_tls_health(Some(&[
            cond("ResolvedRefs", "False"),
            cond("Programmed", "True"),
        ]));
        assert_eq!(sev, Severity::Error);
        assert_eq!(why.as_deref(), Some("ResolvedRefsReason"));
        // Resolved but not yet programmed → warn.
        let (sev, _) = listener_tls_health(Some(&[
            cond("ResolvedRefs", "True"),
            cond("Programmed", "False"),
        ]));
        assert_eq!(sev, Severity::Warn);
        // No status reported yet → warn, never a confident ok.
        let (sev, _) = listener_tls_health(None);
        assert_eq!(sev, Severity::Warn);
    }

    // ── gateway list ──────────────────────────────────────────────────────────

    #[test]
    fn gateway_list_derived_from_cluster_summary() {
        let summary = ClusterSummary::new(
            vec![
                GatewaySummary::new("gw-a", "default")
                    .with_proxy(ProxyAssignment::dedicated())
                    .with_route_count(3),
                GatewaySummary::new("gw-b", "infra").with_route_count(1),
            ],
            vec![],
            vec![],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));

        let snapshot = cluster.load();
        let body = serde_json::json!({ "gateways": snapshot.gateways });
        let gateways = body["gateways"].as_array().expect("array");
        assert_eq!(gateways.len(), 2);
        assert_eq!(gateways[0]["name"], "gw-a");
        assert_eq!(gateways[0]["proxy"]["pool"], "dedicated");
        assert_eq!(gateways[1]["name"], "gw-b");
    }

    // ── list_gateways handler ─────────────────────────────────────────────────

    #[test]
    fn list_gateways_handler_returns_200_with_gateways_key() {
        let summary = ClusterSummary::new(
            vec![GatewaySummary::new("gw-a", "default").with_route_count(2)],
            vec![],
            vec![],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));
        let agg = make_agg(SharedFleet::default(), cluster);

        let resp = agg.list_gateways(&ListParams::default());
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["gateways"][0]["name"], "gw-a");
        assert_eq!(body["gateways"][0]["route_count"], 2);
    }
}
