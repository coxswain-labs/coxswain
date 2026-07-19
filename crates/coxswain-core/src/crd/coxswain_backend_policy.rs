//! `CoxswainBackendPolicy` CRD — per-backend connection policy for a `Service`.
//!
//! Attaches to a Kubernetes `Service` (GEP-713 direct-policy attachment, the same
//! pattern as [`ClientTrafficPolicy`](super::client_traffic_policy)) and applies
//! per-upstream-connection settings to every route — Gateway API or Ingress —
//! whose backend resolves to that Service (#554). It is the canonical, sole
//! home for per-backend connection policy: `spec.timeouts` (connect/idle,
//! #354), `spec.loadBalancer` (#389), `spec.circuitBreaker` (#478), and
//! `spec.sessionPersistence` (#554). None of these has a stable Gateway API
//! field to converge with — as of Gateway API v1.6.0 the closest upstream
//! concept, `BackendLBPolicy`, was removed and folded into the experimental
//! `XBackendTrafficPolicy` (GEP-3388), which covers only retry budgets and
//! session persistence, not LB algorithm or circuit breaking. `loadBalancer`
//! and `circuitBreaker` are therefore deliberately proprietary, anchored to
//! Envoy's native LB policies and outlier detection / Istio's `DestinationRule`
//! respectively — not "Gateway API parity" fields. `sessionPersistence` mirrors
//! the shape of Gateway API's (experimental) `SessionPersistence` type as
//! closely as our stateless affinity machinery supports.
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/coxswainbackendpolicies.yaml` and
//! `charts/coxswain/crds/coxswainbackendpolicies.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Per-backend connection policy attached to one or more `Service` objects.
///
/// A `CoxswainBackendPolicy` in namespace `ns` targets the `Service` objects in
/// `targetRefs` (each in the same namespace). Its settings apply to every
/// route whose backend resolves to a targeted Service — Gateway API
/// (`HTTPRoute`, `GRPCRoute`) and Ingress alike (#554) — automatically; no
/// route needs to reference the policy by name.
///
/// When two policies target the same Service, the older one (by
/// `creationTimestamp`, ties broken by name) wins and the loser receives
/// `Accepted=False, reason=Conflicted` in its status.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "CoxswainBackendPolicy",
    plural = "coxswainbackendpolicies",
    namespaced,
    status = "CoxswainBackendPolicyStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct CoxswainBackendPolicySpec {
    /// Services this policy targets.
    ///
    /// Each entry must reference a core `Service` in the same namespace as this
    /// policy. The policy's `timeouts` apply to upstream connections to that
    /// Service's endpoints.
    pub target_refs: Vec<BackendPolicyTargetRef>,

    /// Per-upstream-connection timeouts.
    ///
    /// When `None` the policy is a no-op (valid and immediately accepted with no
    /// effect on connection behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<BackendTimeouts>,

    /// Upstream load-balancing algorithm for routes backed by the targeted
    /// Service (#389). Deliberately proprietary — anchored to Envoy's native LB
    /// policies, not a Gateway API standard (see the module docs). When `None`
    /// the route keeps the default weighted round-robin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<BackendLoadBalancer>,

    /// Upstream circuit-breaker for routes backed by the targeted Service
    /// (#478). Deliberately proprietary — anchored to Istio
    /// `DestinationRule.trafficPolicy.outlierDetection` / Envoy outlier
    /// detection, not a Gateway API standard (see the module docs). When
    /// `None` the breaker is disabled (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<BackendCircuitBreaker>,

    /// Session persistence for routes backed by the targeted Service (#554).
    /// Mirrors Gateway API's experimental `SessionPersistence` shape as
    /// closely as our stateless affinity machinery supports. When `None`, no
    /// session persistence is applied (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_persistence: Option<BackendSessionPersistence>,
}

/// A reference to a `Service` this policy targets.
///
/// Mirrors the Gateway API `LocalPolicyTargetReference` shape without importing
/// the generated types, so we control the schema. Section-name (per-port)
/// targeting is intentionally omitted for #354 — a policy applies to the whole
/// Service.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendPolicyTargetRef {
    /// API group of the target. Use `""` (the core group) for a `Service`.
    #[serde(default)]
    pub group: String,
    /// Kind of the target resource. Must be `Service`.
    pub kind: String,
    /// Name of the target Service in the same namespace as this policy.
    pub name: String,
}

/// Per-upstream-connection timeout settings.
///
/// Both fields are free-form GEP-2257 duration strings (e.g. `"500ms"`, `"5s"`,
/// `"1m"`). They are intentionally **not** schema-pattern-validated: an
/// unparseable value reaches the reflector, which WARNs and falls back to the
/// default connection behaviour rather than the apiserver rejecting the resource.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendTimeouts {
    /// Upstream TCP-connect timeout. Bounds how long the proxy waits to establish
    /// a connection to a backend endpoint before failing the request (`502`).
    ///
    /// When unset or unparseable, the proxy falls back to the Gateway API
    /// `backendRequest` budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<String>,

    /// Upstream keepalive idle timeout. How long an idle pooled connection to a
    /// backend endpoint is retained before eviction.
    ///
    /// When unset or unparseable, Pingora's built-in pool behaviour is unchanged
    /// (connections stay until LRU capacity forces eviction).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<String>,
}

/// Upstream load-balancing algorithm selector (#389).
///
/// `algorithm` is a free-form string, parsed by the shared
/// [`LoadBalance::parse_lenient`](crate::routing::LoadBalance::parse_lenient) parser
/// used by every surface that selects an LB algorithm. Deliberately
/// proprietary — Gateway API has no LB-algorithm-selection standard (upstream
/// closed kubernetes-sigs/gateway-api#1778 "not planned"); this anchors to
/// Envoy's native LB policies instead. It is intentionally **not**
/// schema-enum-validated: an unrecognised value reaches the reflector, which
/// WARNs and falls back to weighted round-robin rather than the apiserver
/// rejecting the resource (matching [`BackendTimeouts`]).
///
/// Accepted values: `round_robin` (default), `least_conn`, `ewma`, `ip_hash`,
/// `hash:uri`, `hash:source-ip`, `hash:header=<name>`, `hash:cookie=<name>`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendLoadBalancer {
    /// Algorithm selector string. See the type-level docs for the vocabulary.
    pub algorithm: String,
}

/// Upstream circuit-breaker settings (#478).
///
/// `threshold` is the gate: absent or out of the `1..=100` range disables the
/// breaker (WARN + default). Durations are free-form GEP-2257 strings, **not**
/// schema-pattern-validated — an unparseable value WARNs and falls back to the
/// per-field default at the reflector (matching [`BackendTimeouts`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendCircuitBreaker {
    /// Error rate (%) that trips the breaker (`1..=100`). The gate: absent or out
    /// of range → breaker disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u8>,

    /// Rolling window over which the EWMA error rate is computed. Default `10s`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,

    /// How long the breaker stays open before allowing a probe. Default `5s`.
    /// Starting duration when `maxOpenDuration` enables exponential backoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_duration: Option<String>,

    /// Minimum requests in the window before the breaker can trip. Default `10`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_requests: Option<u32>,

    /// Maximum open-duration cap. When set, the breaker uses exponential backoff
    /// from `openDuration` up to this cap; when unset, the open duration is
    /// constant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_open_duration: Option<String>,
}

/// Session-persistence settings for routes backed by the targeted Service
/// (#554).
///
/// Mirrors the shape of Gateway API's experimental `SessionPersistence` type
/// (`type` + `sessionName`) as closely as our stateless affinity machinery
/// supports. `absoluteTimeout` / `cookieConfig` are intentionally omitted —
/// coxswain's affinity is stateless (a deterministic token derived from the
/// endpoint address, or a rendezvous hash), so there is no session store to
/// expire early; accepting those fields without enforcing them would be
/// dishonest. `idleTimeout` is also omitted: Gateway API itself removed it
/// from `SessionPersistence` in v1.6.0.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendSessionPersistence {
    /// Persistence mechanism: `Cookie` (the proxy injects a sticky cookie) or
    /// `Header` (a request header is rendezvous-hashed to select the
    /// endpoint). Free-form and **not** schema-enum-validated: an
    /// unrecognised value reaches the reflector, which WARNs and disables
    /// persistence (matching [`BackendLoadBalancer::algorithm`]).
    #[serde(rename = "type")]
    pub session_type: String,

    /// Cookie name (`Cookie` mode, default `__coxswain_session` when unset) or
    /// header name (`Header` mode, required — absent or invalid disables
    /// persistence).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
}

/// Status written back to the `CoxswainBackendPolicy` by the controller.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoxswainBackendPolicyStatus {
    /// Per-ancestor (targeted Service) policy conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<BackendPolicyAncestorStatus>,
}

/// Status of this policy with respect to one ancestor (a targeted `Service`).
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendPolicyAncestorStatus {
    /// Reference to the `Service` this ancestor entry describes.
    pub ancestor_ref: BackendPolicyAncestorRef,
    /// The controller that wrote this entry.
    pub controller_name: String,
    /// Conditions for this ancestor (e.g. `Accepted`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition>,
}

/// Identifies the ancestor (targeted `Service`) a [`BackendPolicyAncestorStatus`]
/// entry corresponds to.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendPolicyAncestorRef {
    /// API group of the ancestor (`""` for a core `Service`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind of the ancestor (`Service`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Namespace of the ancestor Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Name of the ancestor Service.
    pub name: String,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/coxswainbackendpolicies.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/coxswainbackendpolicies.yaml");

    fn parse_cr(spec_fragment: &str) -> CoxswainBackendPolicy {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: CoxswainBackendPolicy\n\
             metadata:\n  name: t\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("parse failed: {e}\n--- yaml ---\n{yaml}"))
    }

    #[test]
    fn committed_manifest_crd_matches_generator() {
        let on_disk: CustomResourceDefinition = serde_yaml::from_str(MANIFEST_CRD_YAML)
            .unwrap_or_else(|e| panic!("committed CRD YAML must deserialize: {e}"));
        let generated = CoxswainBackendPolicy::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/coxswainbackendpolicies.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- CoxswainBackendPolicy \
             > deploy/manifests/crds/coxswainbackendpolicies.yaml \
             && cp deploy/manifests/crds/coxswainbackendpolicies.yaml \
             charts/coxswain/crds/coxswainbackendpolicies.yaml",
        );
    }

    #[test]
    fn chart_crd_is_byte_identical_to_manifest_crd() {
        assert_eq!(
            MANIFEST_CRD_YAML, CHART_CRD_YAML,
            "deploy/manifests/crds and charts/coxswain/crds CRDs diverged; \
             copy the manifest CRD over the chart CRD",
        );
    }

    #[test]
    fn minimal_spec_deserializes() {
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- group: \"\"\n",
            "  kind: Service\n",
            "  name: my-svc",
        ));
        assert_eq!(cr.spec.target_refs.len(), 1);
        assert_eq!(cr.spec.target_refs[0].kind, "Service");
        assert!(cr.spec.timeouts.is_none());
    }

    #[test]
    fn full_spec_round_trips() {
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- group: \"\"\n",
            "  kind: Service\n",
            "  name: my-svc\n",
            "timeouts:\n",
            "  connect: 500ms\n",
            "  idle: 60s",
        ));
        let t = cr.spec.timeouts.as_ref().expect("timeouts present");
        assert_eq!(t.connect.as_deref(), Some("500ms"));
        assert_eq!(t.idle.as_deref(), Some("60s"));
    }

    #[test]
    fn load_balancer_algorithm_round_trips() {
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- kind: Service\n",
            "  name: my-svc\n",
            "loadBalancer:\n",
            "  algorithm: least_conn",
        ));
        let lb = cr
            .spec
            .load_balancer
            .as_ref()
            .expect("loadBalancer present");
        assert_eq!(lb.algorithm, "least_conn");
        assert!(cr.spec.circuit_breaker.is_none());
    }

    #[test]
    fn circuit_breaker_round_trips() {
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- kind: Service\n",
            "  name: my-svc\n",
            "circuitBreaker:\n",
            "  threshold: 50\n",
            "  window: 10s\n",
            "  openDuration: 5s\n",
            "  minRequests: 20\n",
            "  maxOpenDuration: 1m",
        ));
        let cb = cr
            .spec
            .circuit_breaker
            .as_ref()
            .expect("circuitBreaker present");
        assert_eq!(cb.threshold, Some(50));
        assert_eq!(cb.window.as_deref(), Some("10s"));
        assert_eq!(cb.open_duration.as_deref(), Some("5s"));
        assert_eq!(cb.min_requests, Some(20));
        assert_eq!(cb.max_open_duration.as_deref(), Some("1m"));
    }

    #[test]
    fn session_persistence_round_trips() {
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- kind: Service\n",
            "  name: my-svc\n",
            "sessionPersistence:\n",
            "  type: Cookie\n",
            "  sessionName: my-session",
        ));
        let sp = cr
            .spec
            .session_persistence
            .as_ref()
            .expect("sessionPersistence present");
        assert_eq!(sp.session_type, "Cookie");
        assert_eq!(sp.session_name.as_deref(), Some("my-session"));
    }

    #[test]
    fn session_persistence_name_is_optional() {
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- kind: Service\n",
            "  name: my-svc\n",
            "sessionPersistence:\n",
            "  type: Header",
        ));
        let sp = cr
            .spec
            .session_persistence
            .as_ref()
            .expect("sessionPersistence present");
        assert_eq!(sp.session_type, "Header");
        assert!(sp.session_name.is_none());
    }

    #[test]
    fn group_defaults_to_core() {
        // `group` omitted → core group "" (a Service reference).
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- kind: Service\n",
            "  name: my-svc",
        ));
        assert_eq!(cr.spec.target_refs[0].group, "");
    }
}
