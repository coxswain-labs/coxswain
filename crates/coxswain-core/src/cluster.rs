//! Aggregate cluster summary surfaced on the controller's admin `/cluster` endpoint.
//!
//! The reflector publishes a fresh [`ClusterSummary`] into a [`SharedClusterSummary`]
//! at the end of each rebuild cycle; the admin server reads the latest snapshot
//! atomically to serialise the response. Compared to the per-pod `/routes`
//! endpoint, this view is cluster-wide and intentionally read-only.
//!
//! Field shape is the **minimal honest v0** agreed in issue #205: every field is
//! backed by state the controller already watches. Per-Gateway `proxy.deployment`
//! / `proxy.replicas` / `proxy.ready`, the `shared_proxy` block, and
//! `controller.lease_holder` are tracked under #221 and slot in additively as
//! siblings under the existing nested objects.

use crate::shared::Shared;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use serde::Serialize;

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
    /// Per-instance controller state (leader flag today; `lease_holder` deferred to #221).
    pub controller: ControllerSummary,
}

impl ClusterSummary {
    /// Assemble a summary from its three components.
    ///
    /// External-crate constructor for the `#[non_exhaustive]` struct.
    #[must_use]
    pub fn new(
        gateways: Vec<GatewaySummary>,
        ingresses: Vec<IngressSummary>,
        controller: ControllerSummary,
    ) -> Self {
        Self {
            gateways,
            ingresses,
            controller,
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
        }
    }

    /// Set the proxy assignment that serves this Gateway.
    #[must_use]
    pub fn with_proxy(mut self, proxy: ProxyAssignment) -> Self {
        self.proxy = proxy;
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
