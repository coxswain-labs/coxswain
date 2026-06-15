//! `/api/v1/routing/routes/{kind}/{ns}/{name}` route detail + its `/check`
//! data-plane consistency endpoint, plus the effective-config serialization
//! helpers that render the route detail bodies.

use http::Response;

use coxswain_core::cluster::GatewayCondition;
use coxswain_core::fleet::FleetEntry;
use futures::future::join_all;
use k8s_openapi::api::networking::v1::Ingress;
use kube::Api;

use super::route_check::{route_kind_key, route_rows_for, row_key, serving_proxies_for_parents};
use super::{
    OperatorAggregator, internal_error, json_response, not_found, pod_base_url, service_unavailable,
};
use crate::gw_types::{self, HttpRoute};

impl OperatorAggregator {
    /// `GET /api/v1/routing/routes/{kind}/{namespace}/{name}` — kind-dispatching
    /// route detail. `kind` is `httproute` or `ingress`; anything else is 404
    /// (mirrors `get_manifest`'s kind validation).
    pub(crate) async fn get_route(
        &self,
        kind: &str,
        namespace: &str,
        name: &str,
    ) -> Response<Vec<u8>> {
        match kind {
            "httproute" => self.get_httproute(namespace, name).await,
            "ingress" => self.get_ingress_route(namespace, name).await,
            _ => not_found(),
        }
    }

    /// Live HTTPRoute status conditions from Kubernetes + parallel `/api/v1/routes`
    /// fan-out to all proxy pods.
    pub(crate) async fn get_httproute(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/routing/routes/httproute");
                return service_unavailable("kubernetes client not available");
            }
        };

        let api: Api<HttpRoute> = Api::namespaced(kube.clone(), namespace);
        let route = match api.get(name).await {
            Ok(route) => route,
            Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET HTTPRoute failed");
                return internal_error();
            }
        };

        // Per-parentRef conditions — the richest Gateway-API troubleshooting
        // surface, rendered as the route's conditions table.
        let parent_statuses = route
            .status
            .as_ref()
            .map(|s| s.parents.as_slice())
            .unwrap_or_default()
            .iter()
            .map(|p| {
                let conditions: Vec<GatewayCondition> = p
                    .conditions
                    .iter()
                    .map(GatewayCondition::from_kube)
                    .collect();
                serde_json::json!({
                    "parent_ref": {
                        "name": p.parent_ref.name,
                        "namespace": p.parent_ref.namespace,
                    },
                    "conditions": conditions,
                })
            })
            .collect::<Vec<_>>();

        // Effective config (the route's declared intent, interpreted) for the
        // detail body — sourced from the object we just fetched, no extra calls.
        let hostnames = route.spec.hostnames.clone().unwrap_or_default();
        let rules = httproute_rules_json(&route.spec);

        // Reflector traffic-served status (same field the routing table shows);
        // the UI overlays /problems on top for the header status badge.
        let status = self
            .cluster
            .load()
            .httproutes
            .iter()
            .find(|h| h.namespace == namespace && h.name == name)
            .map(|h| h.status);

        json_response(
            serde_json::json!({
                "namespace": namespace,
                "name": name,
                "status": status,
                "hostnames": hostnames,
                "parent_statuses": parent_statuses,
                "rules": rules,
            })
            .to_string(),
        )
    }

    /// `GET /api/v1/routing/routes/ingress/{namespace}/{name}` — live Ingress
    /// load-balancer status from Kubernetes + parallel `/api/v1/routes` fan-out to
    /// all proxy pods.
    pub(crate) async fn get_ingress_route(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/routing/routes/ingress");
                return service_unavailable("kubernetes client not available");
            }
        };

        let api: Api<Ingress> = Api::namespaced(kube.clone(), namespace);
        let ing = match api.get(name).await {
            Ok(ing) => ing,
            Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET Ingress (routes) failed");
                return internal_error();
            }
        };

        let load_balancer = ing
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_deref())
            .and_then(|items| items.first())
            .and_then(|i| i.ip.as_deref().or(i.hostname.as_deref()))
            .map(str::to_owned)
            .unwrap_or_default();

        // Effective config (class, TLS blocks, host/path → backend rules) from
        // the object we just fetched — Ingress is flat, so this is most of what
        // the resource *is*.
        let empty_spec = k8s_openapi::api::networking::v1::IngressSpec::default();
        let spec = ing.spec.as_ref().unwrap_or(&empty_spec);
        let class = spec.ingress_class_name.clone().unwrap_or_default();
        let tls = ingress_tls_json(spec);
        let default_backend = spec.default_backend.as_ref().map(ingress_backend_json);
        let rules = ingress_rules_json(spec);

        let status = self
            .cluster
            .load()
            .ingresses
            .iter()
            .find(|i| i.namespace == namespace && i.name == name)
            .map(|i| i.status);

        let mut v = serde_json::json!({
            "namespace": namespace,
            "name": name,
            "status": status,
            "class": class,
            "tls": tls,
            "default_backend": default_backend,
            "rules": rules,
        });
        if !load_balancer.is_empty() {
            v["load_balancer"] = serde_json::Value::String(load_balancer);
        }
        json_response(v.to_string())
    }

    /// `GET …/routes/{kind}/{ns}/{name}/check` — on-demand data-plane
    /// consistency check against the controller for a single route.
    ///
    /// Everything else on the route detail page reflects the *controller's*
    /// view (status, conditions, `/problems`). This is the one check that asks
    /// each proxy directly. It targets only the proxies that *should* serve the
    /// route — the shared pool, or the dedicated proxies of the route's parent
    /// Gateways (matched by the `gateway-name` label) — fans out to their
    /// `/api/v1/routes`, and diffs the route-tagged rows across them: a proxy missing a
    /// row its peers have is drift.
    ///
    /// # Errors
    ///
    /// 400 for an unknown kind, 404 when the route does not exist, 503 when the
    /// Kubernetes client is unavailable, 500 for other Kubernetes errors.
    pub(crate) async fn check_route(
        &self,
        kind: &str,
        namespace: &str,
        name: &str,
    ) -> Response<Vec<u8>> {
        let Some(spec_key) = route_kind_key(kind) else {
            return not_found();
        };

        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for route check");
                return service_unavailable("kubernetes client not available");
            }
        };

        // Resolve which proxies should serve this route. HTTPRoute follows its
        // parent Gateways (dedicated → those pods, otherwise the shared pool);
        // Ingress is always served by the shared pool.
        let snapshot = self.fleet.load();
        let serving: Vec<FleetEntry> = match kind {
            "httproute" => {
                let api: Api<HttpRoute> = Api::namespaced(kube.clone(), namespace);
                let route = match api.get(name).await {
                    Ok(r) => r,
                    Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET HTTPRoute (check) failed");
                        return internal_error();
                    }
                };
                let parents = route.spec.parent_refs.as_deref().unwrap_or_default();
                serving_proxies_for_parents(&snapshot, namespace, parents)
            }
            "ingress" => {
                let api: Api<Ingress> = Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(_) => {}
                    Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET Ingress (check) failed");
                        return internal_error();
                    }
                }
                snapshot.shared_proxies.clone()
            }
            _ => return not_found(),
        };

        let pod_results = self.fan_out_routes_to(&serving).await;

        // Pass 1: per-pod route-tagged rows + the union of (host, path, backend)
        // keys seen across all reachable serving proxies — the expected set.
        let mut union: Vec<(String, String, String)> = Vec::new();
        let mut union_seen: std::collections::HashSet<(String, String, String)> =
            std::collections::HashSet::new();
        let mut pod_rows: Vec<(String, bool, Vec<serde_json::Value>)> = Vec::new();
        for pr in &pod_results {
            let pod_name = pr
                .get("pod_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let reachable = pr
                .get("reachable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !reachable {
                pod_rows.push((pod_name, false, Vec::new()));
                continue;
            }
            let routes = pr.get("routes").cloned().unwrap_or(serde_json::Value::Null);
            let rows = route_rows_for(&routes, spec_key, namespace, name);
            for r in &rows {
                let key = row_key(r);
                if union_seen.insert(key.clone()) {
                    union.push(key);
                }
            }
            pod_rows.push((pod_name, true, rows));
        }

        // Pass 2: per-pod present rows (flagging dead backends) + the union keys
        // each pod is missing. Any unreachable pod, any missing key, or a route
        // absent from every proxy means the data plane disagrees.
        let mut consistent = !union.is_empty();
        let mut proxies_json: Vec<serde_json::Value> = Vec::new();
        for (pod_name, reachable, rows) in &pod_rows {
            if !reachable {
                consistent = false;
                proxies_json.push(serde_json::json!({ "pod_name": pod_name, "reachable": false }));
                continue;
            }
            let present: std::collections::HashSet<(String, String, String)> =
                rows.iter().map(row_key).collect();
            let missing: Vec<serde_json::Value> = union
                .iter()
                .filter(|k| !present.contains(*k))
                .map(|(host, path, backend_group)| {
                    serde_json::json!({ "host": host, "path": path, "backend_group": backend_group })
                })
                .collect();
            if !missing.is_empty() {
                consistent = false;
            }
            let rows_json: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let dead = r
                        .get("endpoints")
                        .and_then(|e| e.as_array())
                        .is_none_or(|a| a.is_empty());
                    let mut rr = r.clone();
                    rr["dead"] = serde_json::Value::Bool(dead);
                    rr
                })
                .collect();
            proxies_json.push(serde_json::json!({
                "pod_name": pod_name,
                "reachable": true,
                "rows": rows_json,
                "missing": missing,
            }));
        }

        let expected: Vec<serde_json::Value> = union
            .iter()
            .map(|(host, path, backend_group)| {
                serde_json::json!({ "host": host, "path": path, "backend_group": backend_group })
            })
            .collect();

        json_response(
            serde_json::json!({
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "consistent": consistent,
                "expected": expected,
                "proxies": proxies_json,
            })
            .to_string(),
        )
    }

    /// Fan out `GET /api/v1/routes` to all proxy pods in parallel.
    ///
    /// Returns one entry per pod: `{pod_name, reachable: true, routes: {...}}`
    /// when the pod responds, or `{pod_name, reachable: false}` on timeout or
    /// error.
    pub(super) async fn fan_out_routes(&self) -> Vec<serde_json::Value> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .cloned()
            .collect();
        self.fan_out_routes_to(&entries).await
    }

    /// Fan out `GET /api/v1/routes` to a specific set of proxy pods in parallel —
    /// the check path targets only the proxies that should serve a given route,
    /// not the whole fleet.
    async fn fan_out_routes_to(&self, entries: &[FleetEntry]) -> Vec<serde_json::Value> {
        let http = &self.http;
        let futures: Vec<_> = entries
            .iter()
            .map(|e| {
                let url = format!("{}/api/v1/routes", pod_base_url(e));
                let pod_name = e.pod_name.clone();
                async move {
                    match http
                        .get(&url)
                        .send()
                        .await
                        .ok()
                        .filter(|r| r.status().is_success())
                    {
                        Some(resp) => match resp.json::<serde_json::Value>().await.ok() {
                            Some(routes) => serde_json::json!({
                                "pod_name": pod_name,
                                "reachable": true,
                                "routes": routes,
                            }),
                            None => serde_json::json!({ "pod_name": pod_name, "reachable": false }),
                        },
                        None => serde_json::json!({ "pod_name": pod_name, "reachable": false }),
                    }
                }
            })
            .collect();
        join_all(futures).await
    }
}

// ── Effective-config serialization (route detail bodies) ──────────────────────

/// Gateway-API spelling for a path-match type. Absent ⇒ the spec default of a
/// `PathPrefix` match on `/`.
fn path_match_str(
    t: Option<&gw_types::v::httproutes::HttpRouteRulesMatchesPathType>,
) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesMatchesPathType as T;
    match t {
        Some(T::Exact) => "Exact",
        Some(T::PathPrefix) | None => "PathPrefix",
        Some(T::RegularExpression) => "RegularExpression",
    }
}

/// Gateway-API spelling for an HTTP method matcher.
fn method_match_str(m: &gw_types::v::httproutes::HttpRouteRulesMatchesMethod) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesMatchesMethod as M;
    match m {
        M::Get => "GET",
        M::Head => "HEAD",
        M::Post => "POST",
        M::Put => "PUT",
        M::Delete => "DELETE",
        M::Connect => "CONNECT",
        M::Options => "OPTIONS",
        M::Trace => "TRACE",
        M::Patch => "PATCH",
    }
}

/// Gateway-API spelling for a header match type. Absent ⇒ `Exact` (the spec
/// default).
fn header_match_str(
    t: Option<&gw_types::v::httproutes::HttpRouteRulesMatchesHeadersType>,
) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesMatchesHeadersType as T;
    match t {
        Some(T::RegularExpression) => "RegularExpression",
        Some(T::Exact) | None => "Exact",
    }
}

/// Gateway-API spelling for a query-param match type. Absent ⇒ `Exact`.
fn query_match_str(
    t: Option<&gw_types::v::httproutes::HttpRouteRulesMatchesQueryParamsType>,
) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesMatchesQueryParamsType as T;
    match t {
        Some(T::RegularExpression) => "RegularExpression",
        Some(T::Exact) | None => "Exact",
    }
}

/// Gateway-API spelling for a filter kind (the `type` discriminant only — the
/// effective-config table lists which filters are in play, not their bodies).
fn filter_kind_str(t: &gw_types::v::httproutes::HttpRouteRulesFiltersType) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesFiltersType as F;
    match t {
        F::RequestHeaderModifier => "RequestHeaderModifier",
        F::ResponseHeaderModifier => "ResponseHeaderModifier",
        F::RequestMirror => "RequestMirror",
        F::RequestRedirect => "RequestRedirect",
        F::UrlRewrite => "URLRewrite",
        F::ExtensionRef => "ExtensionRef",
        F::Cors => "CORS",
    }
}

/// Interpreted HTTPRoute spec rules for the detail screen's effective-config
/// table.
///
/// Flattens each rule to the fields an operator reads — match predicates
/// (path/method/headers/query), weighted backends, and the filter kinds in
/// play. Sourced from the already-fetched object, so it costs no extra API
/// call. Empty inner collections are emitted as empty arrays for a stable shape.
fn httproute_rules_json(spec: &gw_types::v::httproutes::HttpRouteSpec) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = spec
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|rule| {
            let matches: Vec<serde_json::Value> = rule
                .matches
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|m| {
                    let headers: Vec<serde_json::Value> = m
                        .headers
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|h| {
                            serde_json::json!({
                                "name": h.name,
                                "type": header_match_str(h.r#type.as_ref()),
                                "value": h.value,
                            })
                        })
                        .collect();
                    let query_params: Vec<serde_json::Value> = m
                        .query_params
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|q| {
                            serde_json::json!({
                                "name": q.name,
                                "type": query_match_str(q.r#type.as_ref()),
                                "value": q.value,
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "path": {
                            "type": path_match_str(m.path.as_ref().and_then(|p| p.r#type.as_ref())),
                            "value": m.path.as_ref().and_then(|p| p.value.clone()).unwrap_or_else(|| "/".to_owned()),
                        },
                        "method": m.method.as_ref().map(method_match_str),
                        "headers": headers,
                        "query_params": query_params,
                    })
                })
                .collect();
            let backends: Vec<serde_json::Value> = rule
                .backend_refs
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|b| {
                    serde_json::json!({
                        "name": b.name,
                        "namespace": b.namespace,
                        "port": b.port,
                        "weight": b.weight,
                    })
                })
                .collect();
            let filters: Vec<&str> = rule
                .filters
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|f| filter_kind_str(&f.r#type))
                .collect();
            serde_json::json!({
                "matches": matches,
                "backends": backends,
                "filters": filters,
            })
        })
        .collect();
    serde_json::Value::Array(rules)
}

/// Render an [`IngressBackend`] to `{service, port}` (the common case) or
/// `{resource}` for a resource backend. Port renders as the number, falling
/// back to the named port.
fn ingress_backend_json(b: &k8s_openapi::api::networking::v1::IngressBackend) -> serde_json::Value {
    if let Some(s) = &b.service {
        let port = s
            .port
            .as_ref()
            .and_then(|p| p.number.map(|n| n.to_string()).or_else(|| p.name.clone()));
        serde_json::json!({ "service": s.name, "port": port })
    } else if let Some(r) = &b.resource {
        serde_json::json!({ "resource": format!("{}/{}", r.kind, r.name) })
    } else {
        serde_json::Value::Null
    }
}

/// TLS blocks (`{hosts, secret}`) declared inline on the Ingress.
fn ingress_tls_json(spec: &k8s_openapi::api::networking::v1::IngressSpec) -> serde_json::Value {
    let tls: Vec<serde_json::Value> = spec
        .tls
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|t| {
            serde_json::json!({
                "hosts": t.hosts.clone().unwrap_or_default(),
                "secret": t.secret_name,
            })
        })
        .collect();
    serde_json::Value::Array(tls)
}

/// Interpreted Ingress spec rules: `host` → `[{path, path_type, backend}]`.
fn ingress_rules_json(spec: &k8s_openapi::api::networking::v1::IngressSpec) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = spec
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|r| {
            let paths: Vec<serde_json::Value> = r
                .http
                .as_ref()
                .map(|h| h.paths.as_slice())
                .unwrap_or_default()
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "path": p.path.clone().unwrap_or_else(|| "/".to_owned()),
                        "path_type": p.path_type,
                        "backend": ingress_backend_json(&p.backend),
                    })
                })
                .collect();
            serde_json::json!({
                "host": r.host,
                "paths": paths,
            })
        })
        .collect();
    serde_json::Value::Array(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── routes JSON parse ─────────────────────────────────────────────────────

    #[test]
    fn routes_response_parses_proxy_routes_shape() {
        // Simulates the body returned by a proxy pod's GET /api/v1/routes.
        let raw = serde_json::json!({
            "ingress": {
                "hosts": [
                    {
                        "port": 80,
                        "host": "example.com",
                        "routes": [
                            {
                                "type": "prefix",
                                "path": "/",
                                "backend_group": "default/svc:80",
                                "endpoints": ["10.0.1.1:8080"]
                            }
                        ]
                    }
                ],
                "conflicts": []
            },
            "gateway": { "hosts": [], "conflicts": [] }
        });

        // The aggregator stores the parsed value as-is inside the per-pod entry.
        let entry = serde_json::json!({
            "pod_name": "proxy-0",
            "reachable": true,
            "routes": raw,
        });
        assert_eq!(
            entry["routes"]["ingress"]["hosts"][0]["host"],
            "example.com"
        );
        assert_eq!(
            entry["routes"]["ingress"]["hosts"][0]["routes"][0]["type"],
            "prefix"
        );
        assert_eq!(entry["routes"]["gateway"]["hosts"], serde_json::json!([]));
    }

    #[test]
    fn httproute_rules_json_flattens_matches_backends_filters() {
        let spec: gw_types::v::httproutes::HttpRouteSpec =
            serde_json::from_value(serde_json::json!({
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "GET",
                        "headers": [{"name": "x-env", "value": "prod"}],
                        "queryParams": [{"name": "v", "value": "2"}]
                    }],
                    "backendRefs": [
                        {"name": "api", "port": 8080, "weight": 90},
                        {"name": "api-canary", "port": 8080, "weight": 10}
                    ],
                    "filters": [{"type": "RequestRedirect", "requestRedirect": {}}]
                }]
            }))
            .expect("valid HTTPRoute spec");
        let v = httproute_rules_json(&spec);
        let rule = &v[0];
        assert_eq!(rule["matches"][0]["path"]["type"], "PathPrefix");
        assert_eq!(rule["matches"][0]["path"]["value"], "/api");
        assert_eq!(rule["matches"][0]["method"], "GET");
        assert_eq!(rule["matches"][0]["headers"][0]["name"], "x-env");
        assert_eq!(rule["matches"][0]["headers"][0]["type"], "Exact");
        assert_eq!(rule["matches"][0]["query_params"][0]["value"], "2");
        assert_eq!(rule["backends"][0]["weight"], 90);
        assert_eq!(rule["backends"][1]["name"], "api-canary");
        assert_eq!(rule["filters"][0], "RequestRedirect");
    }

    #[test]
    fn httproute_rules_json_defaults_path_when_match_omits_it() {
        // A rule with no `matches` still renders its backends; a match with no
        // path defaults to a PathPrefix on "/".
        let spec: gw_types::v::httproutes::HttpRouteSpec =
            serde_json::from_value(serde_json::json!({
                "rules": [
                    { "backendRefs": [{"name": "web", "port": 80}] },
                    { "matches": [{"method": "POST"}] }
                ]
            }))
            .expect("valid HTTPRoute spec");
        let v = httproute_rules_json(&spec);
        assert_eq!(
            v[0]["matches"].as_array().expect("matches is array").len(),
            0
        );
        assert_eq!(v[0]["backends"][0]["name"], "web");
        assert_eq!(v[1]["matches"][0]["path"]["type"], "PathPrefix");
        assert_eq!(v[1]["matches"][0]["path"]["value"], "/");
    }

    #[test]
    fn filter_kind_str_uses_gateway_api_spelling() {
        use gw_types::v::httproutes::HttpRouteRulesFiltersType as F;
        assert_eq!(filter_kind_str(&F::UrlRewrite), "URLRewrite");
        assert_eq!(filter_kind_str(&F::Cors), "CORS");
        assert_eq!(
            filter_kind_str(&F::RequestHeaderModifier),
            "RequestHeaderModifier"
        );
    }

    #[test]
    fn ingress_rules_json_maps_host_paths_backend_and_tls() {
        let spec: k8s_openapi::api::networking::v1::IngressSpec =
            serde_json::from_value(serde_json::json!({
                "ingressClassName": "coxswain",
                "tls": [{"hosts": ["demo.local"], "secretName": "demo-tls"}],
                "rules": [{
                    "host": "demo.local",
                    "http": {"paths": [
                        {"path": "/", "pathType": "Prefix",
                         "backend": {"service": {"name": "web", "port": {"number": 80}}}}
                    ]}
                }]
            }))
            .expect("valid Ingress spec");
        let rules = ingress_rules_json(&spec);
        assert_eq!(rules[0]["host"], "demo.local");
        assert_eq!(rules[0]["paths"][0]["path"], "/");
        assert_eq!(rules[0]["paths"][0]["path_type"], "Prefix");
        assert_eq!(rules[0]["paths"][0]["backend"]["service"], "web");
        assert_eq!(rules[0]["paths"][0]["backend"]["port"], "80");

        let tls = ingress_tls_json(&spec);
        assert_eq!(tls[0]["hosts"][0], "demo.local");
        assert_eq!(tls[0]["secret"], "demo-tls");
    }
}
