//! Aggregate cluster summary the reflector publishes for the controller's admin API.
//!
//! The reflector publishes a fresh [`ClusterSummary`] into a [`SharedClusterSummary`]
//! at the end of each rebuild cycle; the admin server reads the latest snapshot
//! atomically. This is the controller's cluster-wide, read-only view of every
//! routing resource it owns. It is **not** served directly as one HTTP dump
//! (the former `/cluster` endpoint was retired in #301): instead it backs the
//! paginated `routing/{gateways,httproutes,ingresses}` list endpoints and the
//! compact `routing/summary` aggregate.
//!
//! Each resource carries a [`Severity`] `status` computed at rebuild on the
//! **traffic-served** principle — `error` = serves no traffic, `warn` = partial,
//! `ok` = all paths serve (issue #301). For HTTPRoutes the status propagates the
//! health of the specific listener(s) the route binds, plus the Gateway-wide
//! dedicated-proxy readiness.

use crate::shared::Shared;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use serde::Serialize;

/// Per-resource health severity, computed at rebuild on the traffic-served
/// principle: how much of the resource's configured traffic actually serves.
///
/// Drives the operator UI's per-row status badge, the `?status=problem` list
/// filter, and (aggregated per category) the routing-tab warning icon and the
/// Dashboard tiles. Ordered so `worst` reductions take the max variant.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Every path the resource configures serves traffic.
    #[default]
    Ok,
    /// Some paths serve, some don't (partial/degraded).
    Warn,
    /// The resource serves no traffic at all.
    Error,
}

impl Severity {
    /// Reduce two severities to the worse (higher) of the pair.
    #[must_use]
    pub fn worse(self, other: Self) -> Self {
        self.max(other)
    }

    /// `true` when the resource is anything other than fully healthy — the
    /// predicate behind the `?status=problem` list filter.
    #[must_use]
    pub fn is_problem(self) -> bool {
        self != Severity::Ok
    }
}

/// Compact per-category aggregate: how many resources of a kind exist and the
/// worst severity among them.
///
/// Returned by the `fleet/summary` and `routing/summary` endpoints so the
/// operator UI can render tab counts + a warning icon without fetching the full
/// (potentially huge) resource lists.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CategorySummary {
    /// Total resources in this category.
    pub total: usize,
    /// Worst severity across the category (`ok` when empty or all healthy).
    pub worst: Severity,
}

impl CategorySummary {
    /// Aggregate a category from an iterator of per-resource severities.
    #[must_use]
    pub fn from_severities(severities: impl IntoIterator<Item = Severity>) -> Self {
        let mut total = 0;
        let mut worst = Severity::Ok;
        for s in severities {
            total += 1;
            worst = worst.worse(s);
        }
        Self { total, worst }
    }
}

/// Per-category aggregate for the routing axis (`GET /api/v1/routing/summary`).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RoutingSummary {
    /// Gateway resources.
    pub gateways: CategorySummary,
    /// HTTPRoute resources.
    pub httproutes: CategorySummary,
    /// Ingress resources.
    pub ingresses: CategorySummary,
}

/// CRD group that identifies a `parametersRef` pointing at `CoxswainGatewayParameters`.
///
/// Used by the cluster-summary builder to classify a Gateway as
/// [`ProxyPool::Dedicated`] when its `spec.infrastructure.parametersRef` targets
/// a `coxswain-labs.dev` `CoxswainGatewayParameters` resource.
pub const PARAMETERS_REF_GROUP: &str = "gateway.coxswain-labs.dev";

/// CRD kind that identifies a `parametersRef` pointing at `CoxswainGatewayParameters`.
///
/// See [`PARAMETERS_REF_GROUP`].
pub const PARAMETERS_REF_KIND: &str = "CoxswainGatewayParameters";

/// Aggregate view of the controller's cluster-wide state.
///
/// Built once per reconcile cycle and published into a [`SharedClusterSummary`]
/// for the admin server to read. Serialises as the `/cluster` JSON response.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ClusterSummary {
    /// All Gateways owned by this controller (filtered by `GatewayClass.controllerName`).
    pub gateways: Vec<GatewaySummary>,
    /// All Ingresses owned by this controller (filtered by `IngressClass.controller`
    /// plus the default-class fallback).
    pub ingresses: Vec<IngressSummary>,
    /// All HTTPRoutes in the controller's route store (#293).
    pub httproutes: Vec<HttpRouteSummary>,
    /// Per-instance controller state (leader flag today; `lease_holder` deferred to #221).
    pub controller: ControllerSummary,
}

impl ClusterSummary {
    /// Assemble a summary from its components.
    ///
    /// External-crate constructor for the `#[non_exhaustive]` struct.
    #[must_use]
    pub fn new(
        gateways: Vec<GatewaySummary>,
        ingresses: Vec<IngressSummary>,
        httproutes: Vec<HttpRouteSummary>,
        controller: ControllerSummary,
    ) -> Self {
        Self {
            gateways,
            ingresses,
            httproutes,
            controller,
        }
    }

    /// Reduce the routing resources to the compact per-category aggregate the
    /// `routing/summary` endpoint serves (counts + worst severity per kind).
    #[must_use]
    pub fn routing_summary(&self) -> RoutingSummary {
        RoutingSummary {
            gateways: CategorySummary::from_severities(self.gateways.iter().map(|g| g.status)),
            httproutes: CategorySummary::from_severities(self.httproutes.iter().map(|r| r.status)),
            ingresses: CategorySummary::from_severities(self.ingresses.iter().map(|i| i.status)),
        }
    }
}

/// Per-Gateway summary entry.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct GatewaySummary {
    /// Gateway object name.
    pub name: String,
    /// Gateway object namespace.
    pub namespace: String,
    /// Which proxy serves this Gateway. Nested so #221 can add `deployment`,
    /// `replicas`, `ready` siblings additively.
    pub proxy: ProxyAssignment,
    /// Total HTTPRoutes attached across all listeners
    /// (sum of `ListenerInfo::attached_routes`, matching Gateway API's
    /// AttachedRoutes counter semantics).
    pub route_count: usize,
    /// Network addresses assigned to the Gateway, from `status.addresses[].value`.
    pub addresses: Vec<String>,
    /// Top-level Gateway conditions (`Accepted`, `Programmed`, …) reduced to
    /// `type`/`status`/`reason`/`message`. Per-listener conditions are omitted
    /// from this summary; consumers wanting detail should read the Gateway
    /// object directly.
    pub conditions: Vec<GatewayCondition>,
    /// Traffic-served health of this Gateway as a binding. Derived from its own
    /// `Accepted`/`Programmed`/`DedicatedProxyReady` conditions — propagation is
    /// upstream-only, so a route conflict under this Gateway does not flip it.
    pub status: Severity,
}

impl GatewaySummary {
    /// Start a new entry with the required identifiers; chain `with_*` for the
    /// rest.
    #[must_use]
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            proxy: ProxyAssignment::shared(),
            route_count: 0,
            addresses: Vec::new(),
            conditions: Vec::new(),
            status: Severity::Ok,
        }
    }

    /// Set the proxy assignment that serves this Gateway.
    #[must_use]
    pub fn with_proxy(mut self, proxy: ProxyAssignment) -> Self {
        self.proxy = proxy;
        self
    }

    /// Set the computed traffic-served health.
    #[must_use]
    pub fn with_status(mut self, status: Severity) -> Self {
        self.status = status;
        self
    }

    /// Set the attached-routes count.
    #[must_use]
    pub fn with_route_count(mut self, count: usize) -> Self {
        self.route_count = count;
        self
    }

    /// Set the addresses bound to this Gateway.
    #[must_use]
    pub fn with_addresses(mut self, addresses: Vec<String>) -> Self {
        self.addresses = addresses;
        self
    }

    /// Set the top-level conditions reported on this Gateway.
    #[must_use]
    pub fn with_conditions(mut self, conditions: Vec<GatewayCondition>) -> Self {
        self.conditions = conditions;
        self
    }
}

/// Which proxy serves a given Gateway.
///
/// In v0 the only populated field is [`Self::pool`]; #221 will add
/// `deployment`, `replicas`, and `ready` siblings as proxy provisioning lands.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ProxyAssignment {
    /// Which proxy pool this Gateway is served by.
    pub pool: ProxyPool,
}

impl ProxyAssignment {
    /// Shared-pool assignment (no `parametersRef`, served by the shared-proxy fleet).
    #[must_use]
    pub fn shared() -> Self {
        Self {
            pool: ProxyPool::Shared,
        }
    }

    /// Dedicated-pool assignment (`parametersRef` targets `CoxswainGatewayParameters`).
    #[must_use]
    pub fn dedicated() -> Self {
        Self {
            pool: ProxyPool::Dedicated,
        }
    }
}

/// Whether a Gateway is served by the shared-proxy fleet or by a dedicated per-Gateway proxy.
///
/// Resolved from `Gateway.spec.infrastructure.parametersRef`: absent → shared;
/// present and pointing at [`PARAMETERS_REF_GROUP`] / [`PARAMETERS_REF_KIND`] →
/// dedicated. Any other `parametersRef` group/kind is treated as shared (not
/// our CRD).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyPool {
    /// Shared-proxy fleet (default).
    #[default]
    Shared,
    /// Dedicated per-Gateway proxy (opted in via `parametersRef`).
    Dedicated,
}

/// One top-level Gateway condition reduced to a compact JSON shape.
///
/// Mirrors `k8s_openapi`'s `Condition` but drops `lastTransitionTime` and
/// `observedGeneration` from the summary view to keep responses small. Reason
/// and message are empty-skipped to avoid noisy `""` values when a controller
/// hasn't set them.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct GatewayCondition {
    /// Condition type (e.g. `Accepted`, `Programmed`). Serialised as `"type"`
    /// to match Kubernetes convention.
    #[serde(rename = "type")]
    pub kind: String,
    /// `"True"` / `"False"` / `"Unknown"`.
    pub status: String,
    /// Short machine-readable reason; empty when not set by the writer.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Free-form message; empty when not set by the writer.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
}

impl GatewayCondition {
    /// Build a summary condition from a Kubernetes [`Condition`] object.
    #[must_use]
    pub fn from_kube(c: &Condition) -> Self {
        Self {
            kind: c.type_.clone(),
            status: c.status.clone(),
            reason: c.reason.clone(),
            message: c.message.clone(),
        }
    }
}

/// Per-Ingress summary entry.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IngressSummary {
    /// Ingress object name.
    pub name: String,
    /// Ingress object namespace.
    pub namespace: String,
    /// Number of paths configured across all rules
    /// (`sum(ingress.spec.rules[].http.paths.len())`). Intent-level: matches
    /// what the user configured, not what's actively serving healthy backends.
    pub route_count: usize,
    /// First `ip` or `hostname` from `status.loadBalancer.ingress[]`; empty
    /// when the address has not been assigned.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub load_balancer: String,
    /// The IngressClass this object is claimed by (`spec.ingressClassName` or the
    /// legacy annotation). Empty when claimed only via the default-class fallback;
    /// the operator UI shows `—` then.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ingress_class: String,
    /// Traffic-served health. Derived from the Ingress's own status (address
    /// assigned) plus any `ingress`-kind conflicts/dead-routes attributed to it.
    pub status: Severity,
}

impl IngressSummary {
    /// Start a new entry with the required identifiers; chain `with_*` for the rest.
    #[must_use]
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            route_count: 0,
            load_balancer: String::new(),
            ingress_class: String::new(),
            status: Severity::Ok,
        }
    }

    /// Set the configured-paths count.
    #[must_use]
    pub fn with_route_count(mut self, count: usize) -> Self {
        self.route_count = count;
        self
    }

    /// Set the resolved load-balancer address.
    #[must_use]
    pub fn with_load_balancer(mut self, address: impl Into<String>) -> Self {
        self.load_balancer = address.into();
        self
    }

    /// Set the claimed IngressClass name.
    #[must_use]
    pub fn with_ingress_class(mut self, class: impl Into<String>) -> Self {
        self.ingress_class = class.into();
        self
    }

    /// Set the computed traffic-served health.
    #[must_use]
    pub fn with_status(mut self, status: Severity) -> Self {
        self.status = status;
        self
    }
}

/// Per-HTTPRoute summary entry.
///
/// HTTPRoute is a first-class routing resource (#293): listed alongside Gateways
/// and Ingresses. Its [`status`](Self::status) is the traffic-served health with
/// listener-precise parent propagation — a route bound to a listener whose
/// `Programmed=False`, or attached to a Gateway whose dedicated proxy isn't
/// ready, is surfaced as degraded/dark here even when its own `Accepted` is true.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HttpRouteSummary {
    /// HTTPRoute object name.
    pub name: String,
    /// HTTPRoute object namespace.
    pub namespace: String,
    /// Hostnames declared in `spec.hostnames` (may be empty — inherits the
    /// listener's hostname then).
    pub hostnames: Vec<String>,
    /// Parent Gateways this route attaches to, as `namespace/name`, deduplicated
    /// across `parentRefs`. The operator UI links each back to its Gateway.
    pub parent_gateways: Vec<String>,
    /// Number of rules configured (`spec.rules.len()`).
    pub rule_count: usize,
    /// Traffic-served health (see the struct docs).
    pub status: Severity,
}

impl HttpRouteSummary {
    /// Start a new entry with the required identifiers; chain `with_*` for the rest.
    #[must_use]
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            hostnames: Vec::new(),
            parent_gateways: Vec::new(),
            rule_count: 0,
            status: Severity::Ok,
        }
    }

    /// Set the declared hostnames.
    #[must_use]
    pub fn with_hostnames(mut self, hostnames: Vec<String>) -> Self {
        self.hostnames = hostnames;
        self
    }

    /// Set the parent Gateways (`namespace/name`).
    #[must_use]
    pub fn with_parent_gateways(mut self, parents: Vec<String>) -> Self {
        self.parent_gateways = parents;
        self
    }

    /// Set the configured-rules count.
    #[must_use]
    pub fn with_rule_count(mut self, count: usize) -> Self {
        self.rule_count = count;
        self
    }

    /// Set the computed traffic-served health.
    #[must_use]
    pub fn with_status(mut self, status: Severity) -> Self {
        self.status = status;
        self
    }
}

/// Per-instance controller state.
///
/// Today carries just the leader flag; #221 adds `lease_holder` once
/// `kube-leader-election`'s holder identity is plumbed through.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ControllerSummary {
    /// `true` when this pod currently holds the leader-election lease.
    pub leader: bool,
}

impl ControllerSummary {
    /// Build a controller summary with the leader flag.
    #[must_use]
    pub fn new(leader: bool) -> Self {
        Self { leader }
    }
}

/// Atomic-snapshot handle for the controller's cluster summary.
///
/// Symmetric with [`crate::tls::SharedTlsStore`] and the routing-table
/// aliases — the reflector writes a fresh snapshot at the end of every rebuild,
/// readers (admin server) `load()` lock-free.
pub type SharedClusterSummary = Shared<ClusterSummary>;

#[cfg(test)]
mod tests {
    use crate::cluster::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

    #[test]
    fn empty_cluster_summary_serialises() {
        let s = ClusterSummary::default();
        let v: serde_json::Value = serde_json::to_value(&s).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "gateways": [],
                "ingresses": [],
                "httproutes": [],
                "controller": { "leader": false }
            })
        );
    }

    #[test]
    fn gateway_summary_round_trips_required_and_optional_fields() {
        let g = GatewaySummary::new("public-gw", "tenant-a")
            .with_proxy(ProxyAssignment::dedicated())
            .with_route_count(12)
            .with_addresses(vec!["10.0.0.5".to_string()])
            .with_conditions(vec![GatewayCondition {
                kind: "Programmed".to_string(),
                status: "True".to_string(),
                reason: "Programmed".to_string(),
                message: "Gateway is programmed".to_string(),
            }]);
        let v: serde_json::Value = serde_json::to_value(&g).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "name": "public-gw",
                "namespace": "tenant-a",
                "proxy": { "pool": "dedicated" },
                "route_count": 12,
                "addresses": ["10.0.0.5"],
                "conditions": [{
                    "type": "Programmed",
                    "status": "True",
                    "reason": "Programmed",
                    "message": "Gateway is programmed"
                }],
                "status": "ok"
            })
        );
    }

    #[test]
    fn gateway_summary_defaults_to_shared_pool_with_zero_routes() {
        let g = GatewaySummary::new("plain", "default");
        let v: serde_json::Value = serde_json::to_value(&g).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "name": "plain",
                "namespace": "default",
                "proxy": { "pool": "shared" },
                "route_count": 0,
                "addresses": [],
                "conditions": [],
                "status": "ok"
            })
        );
    }

    #[test]
    fn ingress_summary_omits_empty_load_balancer() {
        let i = IngressSummary::new("foo", "default").with_route_count(2);
        let v: serde_json::Value = serde_json::to_value(&i).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "name": "foo",
                "namespace": "default",
                "route_count": 2,
                "status": "ok"
            })
        );
    }

    #[test]
    fn ingress_summary_includes_load_balancer_when_set() {
        let i = IngressSummary::new("foo", "default")
            .with_route_count(2)
            .with_load_balancer("10.0.0.4");
        let v: serde_json::Value = serde_json::to_value(&i).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "name": "foo",
                "namespace": "default",
                "route_count": 2,
                "load_balancer": "10.0.0.4",
                "status": "ok"
            })
        );
    }

    #[test]
    fn ingress_summary_includes_ingress_class_when_set() {
        let i = IngressSummary::new("foo", "default")
            .with_route_count(1)
            .with_ingress_class("coxswain");
        let v: serde_json::Value = serde_json::to_value(&i).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "name": "foo",
                "namespace": "default",
                "route_count": 1,
                "ingress_class": "coxswain",
                "status": "ok"
            })
        );
    }

    #[test]
    fn gateway_condition_from_kube_strips_timestamp_and_observed_generation() {
        let kube = Condition {
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
            message: "ok".to_string(),
            observed_generation: Some(42),
            reason: "Programmed".to_string(),
            status: "True".to_string(),
            type_: "Programmed".to_string(),
        };
        let c = GatewayCondition::from_kube(&kube);
        let v: serde_json::Value = serde_json::to_value(&c).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "type": "Programmed",
                "status": "True",
                "reason": "Programmed",
                "message": "ok"
            })
        );
    }

    #[test]
    fn gateway_condition_skips_empty_reason_and_message() {
        let c = GatewayCondition {
            kind: "Accepted".to_string(),
            status: "Unknown".to_string(),
            reason: String::new(),
            message: String::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&c).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "type": "Accepted",
                "status": "Unknown"
            })
        );
    }

    #[test]
    fn shared_cluster_summary_default_is_empty() {
        let s: SharedClusterSummary = SharedClusterSummary::default();
        let snapshot = s.load();
        assert_eq!(snapshot.gateways.len(), 0);
        assert_eq!(snapshot.ingresses.len(), 0);
        assert!(!snapshot.controller.leader);
    }

    #[test]
    fn severity_worse_takes_the_higher_variant_and_serialises_lowercase() {
        assert_eq!(Severity::Ok.worse(Severity::Warn), Severity::Warn);
        assert_eq!(Severity::Error.worse(Severity::Warn), Severity::Error);
        assert_eq!(Severity::Ok.worse(Severity::Ok), Severity::Ok);
        assert!(Severity::Warn.is_problem());
        assert!(Severity::Error.is_problem());
        assert!(!Severity::Ok.is_problem());
        assert_eq!(
            serde_json::to_value(Severity::Error).expect("serialise"),
            serde_json::json!("error")
        );
    }

    #[test]
    fn category_summary_counts_and_takes_worst() {
        let c = CategorySummary::from_severities([Severity::Ok, Severity::Warn, Severity::Ok]);
        assert_eq!(c.total, 3);
        assert_eq!(c.worst, Severity::Warn);
        let empty = CategorySummary::from_severities([]);
        assert_eq!(empty.total, 0);
        assert_eq!(empty.worst, Severity::Ok);
    }

    #[test]
    fn routing_summary_aggregates_each_category_independently() {
        let summary = ClusterSummary::new(
            vec![
                GatewaySummary::new("gw", "ns").with_status(Severity::Ok),
                GatewaySummary::new("gw2", "ns").with_status(Severity::Error),
            ],
            vec![IngressSummary::new("ing", "ns").with_status(Severity::Warn)],
            vec![HttpRouteSummary::new("r", "ns").with_status(Severity::Ok)],
            ControllerSummary::new(true),
        );
        let rs = summary.routing_summary();
        assert_eq!(
            rs.gateways,
            CategorySummary {
                total: 2,
                worst: Severity::Error
            }
        );
        assert_eq!(
            rs.ingresses,
            CategorySummary {
                total: 1,
                worst: Severity::Warn
            }
        );
        assert_eq!(
            rs.httproutes,
            CategorySummary {
                total: 1,
                worst: Severity::Ok
            }
        );
        let v: serde_json::Value = serde_json::to_value(rs).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "gateways": { "total": 2, "worst": "error" },
                "httproutes": { "total": 1, "worst": "ok" },
                "ingresses": { "total": 1, "worst": "warn" }
            })
        );
    }

    #[test]
    fn httproute_summary_round_trips() {
        let r = HttpRouteSummary::new("api", "demo")
            .with_hostnames(vec!["api.example.com".to_string()])
            .with_parent_gateways(vec!["demo/demo-gw".to_string()])
            .with_rule_count(3)
            .with_status(Severity::Warn);
        let v: serde_json::Value = serde_json::to_value(&r).expect("serialise");
        assert_eq!(
            v,
            serde_json::json!({
                "name": "api",
                "namespace": "demo",
                "hostnames": ["api.example.com"],
                "parent_gateways": ["demo/demo-gw"],
                "rule_count": 3,
                "status": "warn"
            })
        );
    }

    #[test]
    fn parameters_ref_constants_match_crd_metadata() {
        // If anyone changes the CRD group/kind, this should fail so the cluster
        // builder's classification logic doesn't silently drift.
        assert_eq!(PARAMETERS_REF_GROUP, "gateway.coxswain-labs.dev");
        assert_eq!(PARAMETERS_REF_KIND, "CoxswainGatewayParameters");
    }
}
