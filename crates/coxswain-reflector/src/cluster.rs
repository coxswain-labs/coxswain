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
