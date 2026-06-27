//! Build a [`ClusterSummary`] from reflector-store snapshots and the per-Gateway
//! listener status map produced by the reconciler.
//!
//! Called from the reconciler's rebuild loop after the routing tables and TLS
//! store have already been published. The summary is then `store()`d into a
//! [`SharedClusterSummary`] for the admin server to read lock-free.
//!
//! Gateways and Ingresses are emitted sorted by (namespace, name) so successive
//! snapshots are stable when nothing has changed — keeps polling diffs minimal
//! and tests deterministic.

use crate::gw_types::HttpRoute;
use crate::gw_types::v::gateways::Gateway;
use crate::ingress::claimed_ingress_class;
use crate::keys::RouteParentKey;
use crate::status::{GatewayListenerStatus, RouteStatusMap};
use coxswain_core::cluster::{
    ClusterSummary, ControllerSummary, GatewayCondition, GatewaySummary, HttpRouteSummary,
    IngressSummary, PARAMETERS_REF_GROUP, PARAMETERS_REF_KIND, ProxyAssignment, Severity,
};
use coxswain_core::ownership::ObjectKey;
use k8s_openapi::api::networking::v1::Ingress;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

/// Gateway condition type set by the dedicated-mode operator once the per-Gateway
/// proxy has at least one Ready pod. `False` means traffic cannot flow through
/// the Gateway yet even when the Gateway is otherwise `Accepted`.
const DEDICATED_PROXY_READY: &str = "gateway.coxswain-labs.dev/DedicatedProxyReady";

/// Inputs required to build a [`ClusterSummary`].
///
/// Grouped to keep [`build_cluster_summary`] below the
/// `clippy::too_many_arguments` threshold and to let unit tests construct
/// fixtures in one place. Borrowed from the reconciler's already-materialised
/// rebuild state — no kube API calls.
#[non_exhaustive]
pub struct ClusterSummaryInputs<'a> {
    /// Snapshot of all Gateways in scope (from `Store<Gateway>::state()`).
    pub gateways: &'a [Arc<Gateway>],
    /// Snapshot of all Ingresses in scope (from `Store<Ingress>::state()`).
    pub ingresses: &'a [Arc<Ingress>],
    /// Set of Gateways owned by this controller — filter for the gateway list.
    pub owned_gateways: &'a HashSet<ObjectKey>,
    /// Set of GatewayClass names that have a `CoxswainGatewayParameters`
    /// `parametersRef` (i.e. are dedicated-mode classes). Used to classify
    /// Gateways whose dedicated-mode opt-in comes via the class, not the
    /// per-Gateway `infrastructure.parametersRef` (#229).
    pub dedicated_gateway_class_names: &'a HashSet<String>,
    /// Set of IngressClass names owned by this controller.
    pub owned_ingress_classes: &'a HashSet<String>,
    /// Name of the default IngressClass owned by this controller (if any) — claims
    /// Ingresses that don't set an explicit class.
    pub default_ingress_class: Option<&'a str>,
    /// Per-Gateway listener status, used to sum `attached_routes` for route counts
    /// and (via each listener's TLS outcome) to compute listener-precise health.
    pub gateway_listener_status: &'a HashMap<ObjectKey, GatewayListenerStatus>,
    /// Snapshot of all HTTPRoutes in scope (from `Store<HttpRoute>::state()`).
    pub routes: &'a [Arc<HttpRoute>],
    /// Per-(route, parent) health produced by `compute_route_health` — supplies
    /// each route's own `Accepted`/`ResolvedRefs` for the traffic-served status.
    pub route_status: &'a RouteStatusMap,
    /// Whether this controller pod currently holds the leader-election lease.
    pub leader: bool,
}

/// Build a [`ClusterSummary`] from in-memory reflector state.
///
/// Sorted by `(namespace, name)` for stable output across rebuilds.
#[must_use]
pub fn build_cluster_summary(inputs: &ClusterSummaryInputs<'_>) -> ClusterSummary {
    // Per-Gateway severity, keyed by ObjectKey — computed once so HTTPRoutes can
    // inherit their parent Gateway's health without recomputing it per route.
    let gateway_severity = gateway_severity_map(inputs);

    let mut gateways = build_gateways(inputs, &gateway_severity);
    let mut ingresses = build_ingresses(inputs);
    let mut httproutes = build_httproutes(inputs, &gateway_severity);
    gateways.sort_by(cmp_ns_name_gateway);
    ingresses.sort_by(cmp_ns_name_ingress);
    httproutes.sort_by(cmp_ns_name_httproute);
    ClusterSummary::new(
        gateways,
        ingresses,
        httproutes,
        ControllerSummary::new(inputs.leader),
    )
}

/// Compute the traffic-served [`Severity`] for every owned Gateway, keyed by
/// [`ObjectKey`].
fn gateway_severity_map(inputs: &ClusterSummaryInputs<'_>) -> HashMap<ObjectKey, Severity> {
    inputs
        .gateways
        .iter()
        .filter_map(|gw| {
            let ns = gw.metadata.namespace.as_deref()?;
            let name = gw.metadata.name.as_deref()?;
            let key = ObjectKey::new(ns, name);
            if !inputs.owned_gateways.contains(&key) {
                return None;
            }
            let sev = gateway_severity(gw, inputs.gateway_listener_status.get(&key));
            Some((key, sev))
        })
        .collect()
}

fn build_gateways(
    inputs: &ClusterSummaryInputs<'_>,
    gateway_severity: &HashMap<ObjectKey, Severity>,
) -> Vec<GatewaySummary> {
    inputs
        .gateways
        .iter()
        .filter_map(|gw| {
            let ns = gw.metadata.namespace.as_deref()?;
            let name = gw.metadata.name.as_deref()?;
            let key = ObjectKey::new(ns, name);
            if !inputs.owned_gateways.contains(&key) {
                return None;
            }
            let proxy = if has_dedicated_parameters_ref(gw)
                || inputs
                    .dedicated_gateway_class_names
                    .contains(&gw.spec.gateway_class_name)
            {
                ProxyAssignment::dedicated()
            } else {
                ProxyAssignment::shared()
            };
            let route_count = inputs
                .gateway_listener_status
                .get(&key)
                .map(|h| {
                    h.listeners
                        .values()
                        .map(|li| usize::try_from(li.attached_routes.max(0)).unwrap_or(0))
                        .sum()
                })
                .unwrap_or(0);
            let addresses = gw
                .status
                .as_ref()
                .and_then(|s| s.addresses.as_ref())
                .map(|addrs| addrs.iter().map(|a| a.value.clone()).collect())
                .unwrap_or_default();
            let conditions = gw
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .map(|conds| conds.iter().map(GatewayCondition::from_kube).collect())
                .unwrap_or_default();
            let status = gateway_severity.get(&key).copied().unwrap_or_default();
            Some(
                GatewaySummary::new(name, ns)
                    .with_proxy(proxy)
                    .with_route_count(route_count)
                    .with_addresses(addresses)
                    .with_conditions(conditions)
                    .with_status(status),
            )
        })
        .collect()
}

/// Traffic-served health of a Gateway as a binding (upstream-only propagation —
/// route conflicts under it never flip the Gateway itself).
///
/// `Error` when the binding can't serve at all (`Accepted=False`,
/// `Programmed=False`, or `DedicatedProxyReady=False`); `Warn` when the binding
/// is up but at least one listener's TLS is unresolved (partial); else `Ok`.
fn gateway_severity(gw: &Gateway, listener_status: Option<&GatewayListenerStatus>) -> Severity {
    let conditions = gw.status.as_ref().and_then(|s| s.conditions.as_ref());
    let condition_false = |type_: &str| {
        conditions.is_some_and(|cs| cs.iter().any(|c| c.type_ == type_ && c.status == "False"))
    };
    if condition_false("Accepted")
        || condition_false("Programmed")
        || condition_false(DEDICATED_PROXY_READY)
    {
        return Severity::Error;
    }
    let any_listener_unhealthy = listener_status
        .is_some_and(|h| h.listeners.values().any(|li| !li.tls_outcome.is_healthy()));
    if any_listener_unhealthy {
        Severity::Warn
    } else {
        Severity::Ok
    }
}

/// Build the HTTPRoute summaries, listing only routes that attach to at least
/// one owned Gateway (routes targeting foreign Gateways are not ours to report).
fn build_httproutes(
    inputs: &ClusterSummaryInputs<'_>,
    gateway_severity: &HashMap<ObjectKey, Severity>,
) -> Vec<HttpRouteSummary> {
    inputs
        .routes
        .iter()
        .filter_map(|route| {
            let route_ns = route.metadata.namespace.as_deref()?;
            let route_name = route.metadata.name.as_deref()?;

            // Owned parent Gateways, deduplicated as `namespace/name`.
            let mut parent_gateways: Vec<String> = Vec::new();
            for pr in route.spec.parent_refs.as_deref().unwrap_or(&[]) {
                let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
                let gw_key = ObjectKey::new(gw_ns, pr.name.as_str());
                if !inputs.owned_gateways.contains(&gw_key) {
                    continue;
                }
                let label = format!("{gw_ns}/{}", pr.name);
                if !parent_gateways.contains(&label) {
                    parent_gateways.push(label);
                }
            }
            // Not attached to any owned Gateway → not in our purview.
            if parent_gateways.is_empty() {
                return None;
            }
            parent_gateways.sort();

            let hostnames = route.spec.hostnames.as_deref().unwrap_or(&[]).to_vec();
            let rule_count = route.spec.rules.as_deref().map(<[_]>::len).unwrap_or(0);
            // Binding/acceptance health. Routing-table conflicts/dead-routes are
            // overlaid from the cross-proxy `/api/v1/problems` aggregate in the UI
            // (the controller's table excludes cut-over dedicated gateways, #301).
            let status = httproute_severity(route, route_ns, route_name, inputs, gateway_severity);

            Some(
                HttpRouteSummary::new(route_name, route_ns)
                    .with_hostnames(hostnames)
                    .with_parent_gateways(parent_gateways)
                    .with_rule_count(rule_count)
                    .with_status(status),
            )
        })
        .collect()
}

/// Traffic-served health of one HTTPRoute, reduced across the (owned) parent
/// paths it binds.
///
/// Per parent path, "serves" requires the route's own `Accepted`+`ResolvedRefs`
/// (from `compute_route_health`), the parent Gateway binding being up, and the
/// **specific listener(s)** the route binds being TLS-healthy (listener-precise).
/// Reduction: all paths serve → `Ok`; none → `Error`; mixed → `Warn`.
fn httproute_severity(
    route: &HttpRoute,
    route_ns: &str,
    route_name: &str,
    inputs: &ClusterSummaryInputs<'_>,
    gateway_severity: &HashMap<ObjectKey, Severity>,
) -> Severity {
    let mut path_severities: Vec<Severity> = Vec::new();

    for pr in route.spec.parent_refs.as_deref().unwrap_or(&[]) {
        let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
        let gw_name = pr.name.as_str();
        let gw_key = ObjectKey::new(gw_ns, gw_name);
        let Some(&gw_sev) = gateway_severity.get(&gw_key) else {
            continue; // foreign / unowned parent — not counted
        };
        let section = pr.section_name.as_deref().unwrap_or("");

        // The route's own acceptance + backend resolution against this parent.
        // `compute_route_health` only populates entries for shared-pool owned
        // Gateways; a dedicated/cut-over Gateway has no entry, so an absent entry
        // defers to the Gateway's binding health rather than counting as dark.
        let own_ok = inputs
            .route_status
            .get(&RouteParentKey::new(
                route_ns, route_name, gw_ns, gw_name, section,
            ))
            .is_none_or(|h| h.accepted && h.resolved_refs);

        let path = if !own_ok || gw_sev == Severity::Error {
            // Route rejected/unresolved, or the binding itself is dark.
            Severity::Error
        } else {
            // Binding is up and the route is accepted: the path's health is the
            // health of the listener(s) it binds (listener-precise).
            listener_path_severity(inputs.gateway_listener_status.get(&gw_key), section)
        };
        path_severities.push(path);
    }

    reduce_paths(&path_severities)
}

/// Severity of the listener(s) a parent path binds. With a `sectionName`, the
/// single named listener; without one, the route binds every listener, so the
/// path is `Ok` only when all are healthy, `Error` when none are, else `Warn`.
fn listener_path_severity(
    listener_status: Option<&GatewayListenerStatus>,
    section: &str,
) -> Severity {
    let Some(health) = listener_status else {
        return Severity::Ok; // no TLS detail (e.g. cleartext) — treat as healthy
    };
    if !section.is_empty() {
        // The listener name is unique only within a source (GEP-1713), but this is
        // an observability heuristic, not routing: match by name across sources.
        return match health
            .listeners
            .iter()
            .find(|(k, _)| k.name == section)
            .map(|(_, li)| li)
        {
            Some(li) if li.tls_outcome.is_healthy() => Severity::Ok,
            Some(_) => Severity::Error,
            None => Severity::Ok, // unmatched section is reflected in own_ok, not here
        };
    }
    if health.listeners.is_empty() {
        return Severity::Ok;
    }
    let healthy = health
        .listeners
        .values()
        .filter(|li| li.tls_outcome.is_healthy())
        .count();
    if healthy == health.listeners.len() {
        Severity::Ok
    } else if healthy == 0 {
        Severity::Error
    } else {
        Severity::Warn
    }
}

/// Reduce per-path severities to the resource severity on the traffic-served
/// principle: all serve → `Ok`; none serve → `Error`; mixed → `Warn`. A route
/// with no owned parent paths is `Error` (it attaches nowhere we serve).
fn reduce_paths(paths: &[Severity]) -> Severity {
    if paths.is_empty() {
        return Severity::Error;
    }
    let dark = paths.iter().filter(|s| **s == Severity::Error).count();
    if dark == 0 && paths.iter().all(|s| *s == Severity::Ok) {
        Severity::Ok
    } else if dark == paths.len() {
        Severity::Error
    } else {
        Severity::Warn
    }
}

fn build_ingresses(inputs: &ClusterSummaryInputs<'_>) -> Vec<IngressSummary> {
    inputs
        .ingresses
        .iter()
        .filter_map(|ing| {
            if !ingress_is_owned(
                ing,
                inputs.owned_ingress_classes,
                inputs.default_ingress_class,
            ) {
                return None;
            }
            let ns = ing.metadata.namespace.as_deref()?;
            let name = ing.metadata.name.as_deref()?;
            let route_count = ing
                .spec
                .as_ref()
                .and_then(|s| s.rules.as_deref())
                .map(|rules| {
                    rules
                        .iter()
                        .map(|r| r.http.as_ref().map(|h| h.paths.len()).unwrap_or(0))
                        .sum()
                })
                .unwrap_or(0);
            let load_balancer = ing
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_ref())
                .and_then(|entries| entries.first())
                .and_then(|entry| {
                    entry
                        .ip
                        .clone()
                        .filter(|s| !s.is_empty())
                        .or_else(|| entry.hostname.clone().filter(|s| !s.is_empty()))
                })
                .unwrap_or_default();
            // Empty when claimed via the default-class fallback; the UI shows `—`.
            let ingress_class = claimed_ingress_class(ing).unwrap_or_default().to_string();
            // Ingress is self-contained (no parent Gateway) and carries no
            // binding conditions in the summary, so its server-side status stays
            // `ok`; routing-table conflicts/dead-routes are overlaid in the UI
            // from `/api/v1/problems` (#301).
            Some(
                IngressSummary::new(name, ns)
                    .with_route_count(route_count)
                    .with_load_balancer(load_balancer)
                    .with_ingress_class(ingress_class),
            )
        })
        .collect()
}

fn ingress_is_owned(
    ing: &Ingress,
    owned_classes: &HashSet<String>,
    default_class: Option<&str>,
) -> bool {
    match claimed_ingress_class(ing) {
        Some(class) => owned_classes.contains(class),
        None => default_class.is_some(),
    }
}

fn has_dedicated_parameters_ref(gw: &Gateway) -> bool {
    gw.spec
        .infrastructure
        .as_ref()
        .and_then(|i| i.parameters_ref.as_ref())
        .is_some_and(|pr| pr.group == PARAMETERS_REF_GROUP && pr.kind == PARAMETERS_REF_KIND)
}

fn cmp_ns_name_gateway(a: &GatewaySummary, b: &GatewaySummary) -> std::cmp::Ordering {
    (a.namespace.as_str(), a.name.as_str()).cmp(&(b.namespace.as_str(), b.name.as_str()))
}

fn cmp_ns_name_ingress(a: &IngressSummary, b: &IngressSummary) -> std::cmp::Ordering {
    (a.namespace.as_str(), a.name.as_str()).cmp(&(b.namespace.as_str(), b.name.as_str()))
}

fn cmp_ns_name_httproute(a: &HttpRouteSummary, b: &HttpRouteSummary) -> std::cmp::Ordering {
    (a.namespace.as_str(), a.name.as_str()).cmp(&(b.namespace.as_str(), b.name.as_str()))
}

#[cfg(test)]
mod tests {
    use crate::cluster::{ClusterSummaryInputs, build_cluster_summary};
    use crate::gw_types::v::gateways::{
        Gateway, GatewayInfrastructure, GatewayInfrastructureParametersRef, GatewaySpec,
        GatewayStatus, GatewayStatusAddresses,
    };
    use crate::status::{GatewayListenerStatus, ListenerInfo, ListenerStatusKey, RouteStatusMap};
    use coxswain_core::cluster::{PARAMETERS_REF_GROUP, PARAMETERS_REF_KIND, ProxyPool};
    use coxswain_core::ownership::ObjectKey;
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressLoadBalancerIngress,
        IngressLoadBalancerStatus, IngressRule, IngressServiceBackend, IngressSpec, IngressStatus,
        ServiceBackendPort,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
    use kube::api::ObjectMeta;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::Arc;

    fn gateway(
        ns: &str,
        name: &str,
        class: &str,
        with_parameters_ref: bool,
        addresses: Vec<&str>,
        conditions: Vec<(&str, &str)>,
    ) -> Arc<Gateway> {
        Arc::new(Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: class.to_string(),
                listeners: vec![],
                infrastructure: with_parameters_ref.then(|| GatewayInfrastructure {
                    parameters_ref: Some(GatewayInfrastructureParametersRef {
                        group: PARAMETERS_REF_GROUP.to_string(),
                        kind: PARAMETERS_REF_KIND.to_string(),
                        name: format!("{name}-params"),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: Some(GatewayStatus {
                addresses: Some(
                    addresses
                        .into_iter()
                        .map(|a| GatewayStatusAddresses {
                            r#type: Some("IPAddress".to_string()),
                            value: a.to_string(),
                        })
                        .collect(),
                ),
                conditions: Some(
                    conditions
                        .into_iter()
                        .map(|(t, s)| Condition {
                            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
                            message: String::new(),
                            observed_generation: None,
                            reason: String::new(),
                            status: s.to_string(),
                            type_: t.to_string(),
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
        })
    }

    fn listener_health_with_routes(routes: i32) -> GatewayListenerStatus {
        let mut listeners = BTreeMap::new();
        let mut li = ListenerInfo::default();
        li.attached_routes = routes;
        li.hostname = String::new();
        li.allows_all_namespaces = true;
        li.port = 80;
        listeners.insert(ListenerStatusKey::gateway("default"), li);
        let mut glh = GatewayListenerStatus::default();
        glh.listeners = listeners;
        glh
    }

    fn ingress(
        ns: &str,
        name: &str,
        class: Option<&str>,
        path_count_per_rule: &[usize],
        load_balancer_ip: Option<&str>,
    ) -> Arc<Ingress> {
        let rules: Vec<IngressRule> = path_count_per_rule
            .iter()
            .enumerate()
            .map(|(i, n)| IngressRule {
                host: Some(format!("rule-{i}.example.com")),
                http: Some(HTTPIngressRuleValue {
                    paths: (0..*n)
                        .map(|p| HTTPIngressPath {
                            path: Some(format!("/p{p}")),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "svc".to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        ..Default::default()
                                    }),
                                }),
                                ..Default::default()
                            },
                        })
                        .collect(),
                }),
            })
            .collect();
        Arc::new(Ingress {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: class.map(String::from),
                rules: Some(rules),
                ..Default::default()
            }),
            status: load_balancer_ip.map(|ip| IngressStatus {
                load_balancer: Some(IngressLoadBalancerStatus {
                    ingress: Some(vec![IngressLoadBalancerIngress {
                        ip: Some(ip.to_string()),
                        ..Default::default()
                    }]),
                }),
            }),
        })
    }

    fn owned_set(items: &[(&str, &str)]) -> HashSet<ObjectKey> {
        items
            .iter()
            .map(|(ns, n)| ObjectKey::new(*ns, *n))
            .collect()
    }

    fn empty_status() -> HashMap<ObjectKey, GatewayListenerStatus> {
        HashMap::new()
    }

    #[test]
    fn shared_mode_only() {
        let gw = gateway(
            "default",
            "gw1",
            "coxswain",
            false,
            vec!["10.0.0.5"],
            vec![("Programmed", "True")],
        );
        let owned = owned_set(&[("default", "gw1")]);
        let mut health = empty_status();
        health.insert(
            ObjectKey::new("default", "gw1"),
            listener_health_with_routes(3),
        );

        let gateways = vec![gw];
        let ingresses: Vec<Arc<Ingress>> = vec![];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_listener_status: &health,
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: false,
        });

        assert_eq!(summary.gateways.len(), 1);
        assert_eq!(summary.gateways[0].proxy.pool, ProxyPool::Shared);
        assert_eq!(summary.gateways[0].route_count, 3);
        assert_eq!(summary.gateways[0].addresses, vec!["10.0.0.5"]);
        assert_eq!(summary.gateways[0].conditions.len(), 1);
        assert_eq!(summary.gateways[0].conditions[0].kind, "Programmed");
        assert_eq!(summary.ingresses.len(), 0);
    }

    #[test]
    fn dedicated_mode_only() {
        let gw = gateway(
            "tenant-a",
            "public",
            "coxswain",
            true,
            vec!["10.0.0.7"],
            vec![],
        );
        let owned = owned_set(&[("tenant-a", "public")]);
        let mut health = empty_status();
        health.insert(
            ObjectKey::new("tenant-a", "public"),
            listener_health_with_routes(12),
        );

        let gateways = vec![gw];
        let ingresses: Vec<Arc<Ingress>> = vec![];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_listener_status: &health,
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: false,
        });

        assert_eq!(summary.gateways.len(), 1);
        assert_eq!(summary.gateways[0].proxy.pool, ProxyPool::Dedicated);
        assert_eq!(summary.gateways[0].route_count, 12);
    }

    #[test]
    fn ingress_only_cluster() {
        let ing = ingress("default", "foo", Some("coxswain"), &[2], Some("10.0.0.4"));
        let mut owned_classes = HashSet::new();
        owned_classes.insert("coxswain".to_string());

        let gateways: Vec<Arc<Gateway>> = vec![];
        let ingresses = vec![ing];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &HashSet::new(),
            owned_ingress_classes: &owned_classes,
            default_ingress_class: None,
            gateway_listener_status: &empty_status(),
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: true,
        });

        assert_eq!(summary.gateways.len(), 0);
        assert_eq!(summary.ingresses.len(), 1);
        assert_eq!(summary.ingresses[0].name, "foo");
        assert_eq!(summary.ingresses[0].route_count, 2);
        assert_eq!(summary.ingresses[0].load_balancer, "10.0.0.4");
        assert!(summary.controller.leader);
    }

    #[test]
    fn mixed_cluster_sorts_by_ns_then_name() {
        let gw_a = gateway("ns-z", "alpha", "coxswain", false, vec![], vec![]);
        let gw_b = gateway("ns-a", "beta", "coxswain", true, vec![], vec![]);
        let gw_c = gateway("ns-a", "alpha", "coxswain", false, vec![], vec![]);
        let owned = owned_set(&[("ns-z", "alpha"), ("ns-a", "beta"), ("ns-a", "alpha")]);
        let mut health = empty_status();
        health.insert(
            ObjectKey::new("ns-a", "alpha"),
            listener_health_with_routes(1),
        );
        health.insert(
            ObjectKey::new("ns-a", "beta"),
            listener_health_with_routes(2),
        );
        health.insert(
            ObjectKey::new("ns-z", "alpha"),
            listener_health_with_routes(3),
        );

        let ing_a = ingress("default", "foo", Some("coxswain"), &[1, 2], None);
        let ing_b = ingress("apps", "bar", Some("coxswain"), &[1], Some("10.0.0.20"));
        let mut owned_classes = HashSet::new();
        owned_classes.insert("coxswain".to_string());

        let gateways = vec![gw_a, gw_b, gw_c];
        let ingresses = vec![ing_a, ing_b];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &owned_classes,
            default_ingress_class: None,
            gateway_listener_status: &health,
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: false,
        });

        let order: Vec<(&str, &str)> = summary
            .gateways
            .iter()
            .map(|g| (g.namespace.as_str(), g.name.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![("ns-a", "alpha"), ("ns-a", "beta"), ("ns-z", "alpha")]
        );
        let pools: Vec<ProxyPool> = summary.gateways.iter().map(|g| g.proxy.pool).collect();
        assert_eq!(
            pools,
            vec![ProxyPool::Shared, ProxyPool::Dedicated, ProxyPool::Shared]
        );

        let ing_order: Vec<&str> = summary
            .ingresses
            .iter()
            .map(|i| i.namespace.as_str())
            .collect();
        assert_eq!(ing_order, vec!["apps", "default"]);
        assert_eq!(summary.ingresses[0].load_balancer, "10.0.0.20");
        assert_eq!(summary.ingresses[1].route_count, 3); // 1 + 2 paths
        assert_eq!(summary.ingresses[1].load_balancer, "");
    }

    #[test]
    fn unowned_gateway_is_skipped() {
        let gw = gateway("ns", "foreign", "other-class", false, vec![], vec![]);
        let owned = owned_set(&[]); // empty — not ours
        let gateways = vec![gw];
        let ingresses: Vec<Arc<Ingress>> = vec![];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_listener_status: &empty_status(),
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: false,
        });
        assert_eq!(summary.gateways.len(), 0);
    }

    #[test]
    fn unclassified_ingress_skipped_without_default_class() {
        let ing = ingress("default", "unclassed", None, &[1], None);
        let gateways: Vec<Arc<Gateway>> = vec![];
        let ingresses = vec![ing];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &HashSet::new(),
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_listener_status: &empty_status(),
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: false,
        });
        assert_eq!(summary.ingresses.len(), 0);
    }

    #[test]
    fn unclassified_ingress_claimed_by_default_class() {
        let ing = ingress("default", "unclassed", None, &[3], None);
        let gateways: Vec<Arc<Gateway>> = vec![];
        let ingresses = vec![ing];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &HashSet::new(),
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: Some("coxswain"),
            gateway_listener_status: &empty_status(),
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: false,
        });
        assert_eq!(summary.ingresses.len(), 1);
        assert_eq!(summary.ingresses[0].route_count, 3);
    }

    #[test]
    fn ingress_load_balancer_falls_back_to_hostname() {
        let ing = Arc::new(Ingress {
            metadata: ObjectMeta {
                name: Some("foo".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![]),
                ..Default::default()
            }),
            status: Some(IngressStatus {
                load_balancer: Some(IngressLoadBalancerStatus {
                    ingress: Some(vec![IngressLoadBalancerIngress {
                        hostname: Some("lb.example.com".to_string()),
                        ..Default::default()
                    }]),
                }),
            }),
        });
        let mut owned_classes = HashSet::new();
        owned_classes.insert("coxswain".to_string());

        let gateways: Vec<Arc<Gateway>> = vec![];
        let ingresses = vec![ing];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &HashSet::new(),
            owned_ingress_classes: &owned_classes,
            default_ingress_class: None,
            gateway_listener_status: &empty_status(),
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: false,
        });
        assert_eq!(summary.ingresses[0].load_balancer, "lb.example.com");
        assert_eq!(summary.ingresses[0].ingress_class, "coxswain");
    }

    #[test]
    fn gateway_with_other_parameters_ref_kind_is_shared() {
        // A parametersRef pointing at some other CRD must NOT trigger dedicated mode.
        let gw = Arc::new(Gateway {
            metadata: ObjectMeta {
                name: Some("gw".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners: vec![],
                infrastructure: Some(GatewayInfrastructure {
                    parameters_ref: Some(GatewayInfrastructureParametersRef {
                        group: "other.example.com".to_string(),
                        kind: "OtherParams".to_string(),
                        name: "x".to_string(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        });
        let owned = owned_set(&[("default", "gw")]);
        let gateways = vec![gw];
        let ingresses: Vec<Arc<Ingress>> = vec![];
        let empty_dedicated_classes = HashSet::new();
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            dedicated_gateway_class_names: &empty_dedicated_classes,
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_listener_status: &empty_status(),
            routes: &[],
            route_status: &RouteStatusMap::new(),
            leader: false,
        });
        assert_eq!(summary.gateways[0].proxy.pool, ProxyPool::Shared);
    }

    // ── traffic-served health (#301) ───────────────────────────────────────────

    use crate::cluster::{gateway_severity, listener_path_severity, reduce_paths};
    use crate::status::ListenerTlsOutcome;
    use coxswain_core::cluster::Severity;

    fn listener(name: &str, outcome: ListenerTlsOutcome) -> (ListenerStatusKey, ListenerInfo) {
        let mut li = ListenerInfo::default();
        li.tls_outcome = outcome;
        (ListenerStatusKey::gateway(name), li)
    }

    fn health_with(listeners: Vec<(ListenerStatusKey, ListenerInfo)>) -> GatewayListenerStatus {
        let mut glh = GatewayListenerStatus::default();
        glh.listeners = listeners.into_iter().collect();
        glh
    }

    #[test]
    fn reduce_paths_follows_traffic_served_principle() {
        // No owned parent path → attaches nowhere → dark.
        assert_eq!(reduce_paths(&[]), Severity::Error);
        // Every path serves.
        assert_eq!(reduce_paths(&[Severity::Ok, Severity::Ok]), Severity::Ok);
        // No path serves.
        assert_eq!(
            reduce_paths(&[Severity::Error, Severity::Error]),
            Severity::Error
        );
        // Some serve, some don't → degraded.
        assert_eq!(
            reduce_paths(&[Severity::Ok, Severity::Error]),
            Severity::Warn
        );
        assert_eq!(reduce_paths(&[Severity::Warn]), Severity::Warn);
    }

    #[test]
    fn listener_path_severity_is_listener_precise() {
        let health = health_with(vec![
            listener("web", ListenerTlsOutcome::Resolved),
            listener(
                "secure",
                ListenerTlsOutcome::Invalid {
                    message: "bad cert".to_string(),
                },
            ),
        ]);
        // Bound to the healthy listener → unaffected by the sibling's bad cert.
        assert_eq!(listener_path_severity(Some(&health), "web"), Severity::Ok);
        // Bound to the broken listener → dark.
        assert_eq!(
            listener_path_severity(Some(&health), "secure"),
            Severity::Error
        );
        // No sectionName → binds every listener; mixed health → partial.
        assert_eq!(listener_path_severity(Some(&health), ""), Severity::Warn);
        // No TLS detail (cleartext) → healthy.
        assert_eq!(listener_path_severity(None, ""), Severity::Ok);
    }

    #[test]
    fn gateway_severity_error_on_dedicated_proxy_not_ready() {
        let gw = gateway(
            "tenant",
            "gw",
            "coxswain",
            true,
            vec![],
            vec![
                ("Programmed", "True"),
                ("gateway.coxswain-labs.dev/DedicatedProxyReady", "False"),
            ],
        );
        assert_eq!(gateway_severity(&gw, None), Severity::Error);
    }

    #[test]
    fn gateway_severity_error_when_not_programmed() {
        let gw = gateway(
            "ns",
            "gw",
            "coxswain",
            false,
            vec![],
            vec![("Programmed", "False")],
        );
        assert_eq!(gateway_severity(&gw, None), Severity::Error);
    }

    #[test]
    fn gateway_severity_warn_on_unhealthy_listener_else_ok() {
        let gw = gateway(
            "ns",
            "gw",
            "coxswain",
            false,
            vec![],
            vec![("Accepted", "True"), ("Programmed", "True")],
        );
        // Healthy conditions, no listener detail → ok.
        assert_eq!(gateway_severity(&gw, None), Severity::Ok);
        // Healthy conditions but a listener with a bad cert → warn (binding up, partial).
        let bad = health_with(vec![listener(
            "l",
            ListenerTlsOutcome::Invalid {
                message: "x".to_string(),
            },
        )]);
        assert_eq!(gateway_severity(&gw, Some(&bad)), Severity::Warn);
    }
}
