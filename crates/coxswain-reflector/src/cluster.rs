//! Build a [`ClusterSummary`] from reflector-store snapshots and the per-Gateway
//! listener health map produced by the reconciler.
//!
//! Called from the reconciler's rebuild loop after the routing tables and TLS
//! store have already been published. The summary is then `store()`d into a
//! [`SharedClusterSummary`] for the admin server to read lock-free.
//!
//! Gateways and Ingresses are emitted sorted by (namespace, name) so successive
//! snapshots are stable when nothing has changed — keeps polling diffs minimal
//! and tests deterministic.

use crate::gw_types::v::gateways::Gateway;
use crate::ingress::claimed_ingress_class;
use crate::tls::GatewayListenerHealth;
use coxswain_core::cluster::{
    ClusterSummary, ControllerSummary, GatewayCondition, GatewaySummary, IngressSummary,
    PARAMETERS_REF_GROUP, PARAMETERS_REF_KIND, ProxyAssignment,
};
use coxswain_core::ownership::ObjectKey;
use k8s_openapi::api::networking::v1::Ingress;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

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
    /// Set of IngressClass names owned by this controller.
    pub owned_ingress_classes: &'a HashSet<String>,
    /// Name of the default IngressClass owned by this controller (if any) — claims
    /// Ingresses that don't set an explicit class.
    pub default_ingress_class: Option<&'a str>,
    /// Per-Gateway listener health, used to sum `attached_routes` for route counts.
    pub gateway_tls_health: &'a HashMap<ObjectKey, GatewayListenerHealth>,
    /// Whether this controller pod currently holds the leader-election lease.
    pub leader: bool,
}

/// Build a [`ClusterSummary`] from in-memory reflector state.
///
/// Sorted by `(namespace, name)` for stable output across rebuilds.
#[must_use]
pub fn build_cluster_summary(inputs: &ClusterSummaryInputs<'_>) -> ClusterSummary {
    let mut gateways = build_gateways(inputs);
    let mut ingresses = build_ingresses(inputs);
    gateways.sort_by(cmp_ns_name_gateway);
    ingresses.sort_by(cmp_ns_name_ingress);
    ClusterSummary::new(gateways, ingresses, ControllerSummary::new(inputs.leader))
}

fn build_gateways(inputs: &ClusterSummaryInputs<'_>) -> Vec<GatewaySummary> {
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
            let proxy = if has_dedicated_parameters_ref(gw) {
                ProxyAssignment::dedicated()
            } else {
                ProxyAssignment::shared()
            };
            let route_count = inputs
                .gateway_tls_health
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
            Some(
                GatewaySummary::new(name, ns)
                    .with_proxy(proxy)
                    .with_route_count(route_count)
                    .with_addresses(addresses)
                    .with_conditions(conditions),
            )
        })
        .collect()
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
            Some(
                IngressSummary::new(name, ns)
                    .with_route_count(route_count)
                    .with_load_balancer(load_balancer),
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

#[cfg(test)]
mod tests {
    use crate::cluster::{ClusterSummaryInputs, build_cluster_summary};
    use crate::gw_types::v::gateways::{
        Gateway, GatewayInfrastructure, GatewayInfrastructureParametersRef, GatewaySpec,
        GatewayStatus, GatewayStatusAddresses,
    };
    use crate::tls::{GatewayListenerHealth, ListenerInfo};
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

    fn listener_health_with_routes(routes: i32) -> GatewayListenerHealth {
        let mut listeners = BTreeMap::new();
        listeners.insert(
            "default".to_string(),
            ListenerInfo {
                attached_routes: routes,
                hostname: String::new(),
                allows_all_namespaces: true,
                port: 80,
                ..Default::default()
            },
        );
        GatewayListenerHealth { listeners }
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

    fn empty_health() -> HashMap<ObjectKey, GatewayListenerHealth> {
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
        let mut health = empty_health();
        health.insert(
            ObjectKey::new("default", "gw1"),
            listener_health_with_routes(3),
        );

        let gateways = vec![gw];
        let ingresses: Vec<Arc<Ingress>> = vec![];
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_tls_health: &health,
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
        let mut health = empty_health();
        health.insert(
            ObjectKey::new("tenant-a", "public"),
            listener_health_with_routes(12),
        );

        let gateways = vec![gw];
        let ingresses: Vec<Arc<Ingress>> = vec![];
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_tls_health: &health,
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
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &HashSet::new(),
            owned_ingress_classes: &owned_classes,
            default_ingress_class: None,
            gateway_tls_health: &empty_health(),
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
        let mut health = empty_health();
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
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &owned_classes,
            default_ingress_class: None,
            gateway_tls_health: &health,
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
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_tls_health: &empty_health(),
            leader: false,
        });
        assert_eq!(summary.gateways.len(), 0);
    }

    #[test]
    fn unclassified_ingress_skipped_without_default_class() {
        let ing = ingress("default", "unclassed", None, &[1], None);
        let gateways: Vec<Arc<Gateway>> = vec![];
        let ingresses = vec![ing];
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &HashSet::new(),
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_tls_health: &empty_health(),
            leader: false,
        });
        assert_eq!(summary.ingresses.len(), 0);
    }

    #[test]
    fn unclassified_ingress_claimed_by_default_class() {
        let ing = ingress("default", "unclassed", None, &[3], None);
        let gateways: Vec<Arc<Gateway>> = vec![];
        let ingresses = vec![ing];
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &HashSet::new(),
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: Some("coxswain"),
            gateway_tls_health: &empty_health(),
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
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &HashSet::new(),
            owned_ingress_classes: &owned_classes,
            default_ingress_class: None,
            gateway_tls_health: &empty_health(),
            leader: false,
        });
        assert_eq!(summary.ingresses[0].load_balancer, "lb.example.com");
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
        let summary = build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned,
            owned_ingress_classes: &HashSet::new(),
            default_ingress_class: None,
            gateway_tls_health: &empty_health(),
            leader: false,
        });
        assert_eq!(summary.gateways[0].proxy.pool, ProxyPool::Shared);
    }
}
