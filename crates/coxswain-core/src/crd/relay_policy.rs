//! `CoxswainRelayPolicy` CRD — per-namespace control for the controller-provisioned
//! dedicated **relay** tier (#589, follow-up to the relay-tier epic #384 / slice C #584).
//!
//! #584 shipped namespace-relay provisioning with **global** operator control only
//! (the `--relay-*` controller flags): every provisioned relay across every namespace
//! is identical. This **namespaced** CRD overlays per-namespace structured control —
//! resources, scheduling, HA, and opt-in autoscaling — on top of those global defaults,
//! keyed by the object's own namespace exactly like the [`super::gateway_parameters`]
//! precedent for dedicated-**proxy** provisioning. Structured defaults are per namespace;
//! the only cluster-wide default is the flat `--relay-*` flags.
//!
//! ## Enablement is override, not activation
//!
//! Relays stay *automatic* whenever `--relay-enabled` is on: the controller provisions a
//! namespace relay where it reduces leader fan-out (the #584 break-even threshold +
//! hysteresis, kept as the silent default). A policy's [`CoxswainRelayPolicySpec::enabled`]
//! is a tri-state **override** of that automatic decision — the operator never has to opt a
//! namespace in for the optimization to apply.
//!
//! ## Autoscaling is controller-driven — no Kubernetes HPA
//!
//! [`RelayAutoscaling`] does not provision an `HorizontalPodAutoscaler`. The relay is
//! I/O/fan-out-bound, so CPU (an HPA's default signal) mistracks load; and each relay
//! replica opens its own upstream `Namespace` stream to the leader, so uncapped scaling
//! would regrow the exact fan-out the tier caps. Instead the **controller** re-implements the
//! standard autoscaler loop internally (#602): it sizes `Deployment.spec.replicas` from the
//! namespace's **live** dedicated-proxy subscriber count (the fan-out the relay actually
//! serves), `clamp(ceil(signal / target_proxies_per_replica), minReplicas, maxReplicas)`,
//! damped by a relative [`RelayAutoscaling::tolerance`] deadband and an asymmetric
//! [`RelayAutoscaling::scale_down_stabilization_seconds`] window (scale up fast, scale down
//! slow). The controller is the sole writer of `replicas` (no HPA/SSA tug-of-war).
//! `maxReplicas` is the mandatory cap on leader-fan-out regrowth.
//!
//! On/off (scale-to-zero) is a KEDA-style activation/cooldown: the relay is provisioned once
//! the signal reaches the break-even threshold (`--relay-min-proxy-replicas`) and torn down
//! after the signal holds below it for [`RelayAutoscaling::cooldown_seconds`] — replacing the
//! old keep-until-fully-drained hysteresis.
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/coxswainrelaypolicies.yaml` and
//! `charts/coxswain/crds/coxswainrelaypolicies.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.

use k8s_openapi::api::core::v1::ResourceRequirements;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::preserve_unknown_fields_schema;

/// Per-namespace parameters for the controller-provisioned dedicated relay.
///
/// Namespaced: the `CoxswainRelayPolicy` in a namespace governs that namespace's relay,
/// keyed by the object's own namespace (the `CoxswainGatewayParameters` model). Every
/// field is `Option` so a policy overlays only the fields it sets, falling through to the
/// #584 global controller-flag defaults (`--relay-*`) for the rest. At most one policy per
/// namespace is expected; if several exist the resolver in `coxswain-controller`'s
/// `operator::relay_params` picks the lexically-first by name and warn-logs the ambiguity.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "CoxswainRelayPolicy",
    plural = "coxswainrelaypolicies",
    namespaced
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
#[derive(Default)]
pub struct CoxswainRelayPolicySpec {
    /// Tri-state override of the controller's automatic provisioning decision:
    /// - `None` (unset) — the controller decides automatically (the #584 break-even
    ///   threshold + hysteresis); the operator does nothing.
    /// - `Some(true)` — force the relay on whenever the namespace holds ≥1 active dedicated
    ///   Gateway, bypassing the threshold. Still garbage-collected when the namespace drains
    ///   to zero dedicated Gateways.
    /// - `Some(false)` — force the relay off unconditionally; the namespace's proxies stay
    ///   direct-to-controller. Overrides hysteresis (an explicit operator intent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Static replica count for the provisioned relay Deployment. When omitted, falls back
    /// to the controller's `--relay-replicas` (default 2, HA). Ignored while
    /// [`RelayAutoscaling::enabled`] is `true` and capped, in which case the controller
    /// computes the count. Must be ≥ 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub replicas: Option<u32>,

    /// Resource requests/limits for the relay container. Supersedes the flat
    /// `--relay-cpu-request` / `--relay-memory-request` / `--relay-memory-limit` flags for
    /// matched namespaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Raw partial `PodTemplateSpec` strategic-merged onto the controller-rendered relay
    /// pod — the scheduling escape hatch (`nodeSelector`, `tolerations`, `affinity`,
    /// `topologySpreadConstraints`, `priorityClassName`, …). Opaque to the CRD validator
    /// (`x-kubernetes-preserve-unknown-fields`); the controller merges and validates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preserve_unknown_fields_schema")]
    pub pod_template: Option<serde_json::Value>,

    /// Opt-in, capped, controller-driven autoscaling for the relay. See [`RelayAutoscaling`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoscaling: Option<RelayAutoscaling>,
}

/// Controller-driven relay autoscaling — **no** Kubernetes `HorizontalPodAutoscaler`.
///
/// When `enabled` is `true` and [`Self::max_replicas`] is set, the controller sizes the
/// relay Deployment to `clamp(ceil(live_subscriber_count / target_proxies_per_replica),
/// min_replicas, max_replicas)`, where `live_subscriber_count` is the namespace's live
/// dedicated-proxy fan-out read from the node registry (#602) — damped by [`Self::tolerance`]
/// and [`Self::scale_down_stabilization_seconds`]. `max_replicas` is mandatory: it caps the
/// leader-fan-out regrowth each additional relay replica costs. When `enabled` is `true` but
/// `max_replicas` is unset, the controller refuses to autoscale (warn-logged) and falls
/// back to the static [`CoxswainRelayPolicySpec::replicas`] — an uncapped relay never runs.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RelayAutoscaling {
    /// When `true`, the controller sizes the relay to downstream fan-out (subject to a set
    /// `max_replicas`). Must be set explicitly; the `Default` is `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Minimum replicas the controller will scale the relay down to. When omitted, the
    /// effective static replica count (policy `replicas` or `--relay-replicas`, default 2)
    /// is the floor. Keep ≥ 2 for HA. Must be ≥ 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub min_replicas: Option<u32>,

    /// Maximum replicas the controller will scale the relay up to — the **mandatory** cap on
    /// the upstream streams the relay tier opens against the leader. Autoscaling is inert
    /// (falls back to static replicas) when this is unset. Must be ≥ 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub max_replicas: Option<u32>,

    /// Target number of downstream dedicated proxies each relay replica should front — the
    /// **capacity ratio**, decoupled from the break-even gate (#602). The controller adds a
    /// replica per this many proxies of live namespace fan-out. When omitted, falls back to
    /// `--relay-target-proxies-per-replica` (default 50): a relay is a fan-out cache (one
    /// upstream stream in, broadcast to N subscribers), so real per-replica capacity is
    /// O(100s), bounded by egress/serialization and failover blast radius — **not** the
    /// break-even `--relay-min-proxy-replicas` number this once inherited. Keep `max_replicas`
    /// well below the namespace's downstream fan-out divided by this, or the relay's own
    /// upstream streams approach the count it is meant to collapse. Must be ≥ 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub target_proxies_per_replica: Option<u32>,

    /// Scale-down stabilization window, in seconds (#602). When scaling **down**, the
    /// controller sizes on the **maximum** signal observed over this trailing window, so a
    /// brief dip does not immediately shed a replica (scale-up is not damped — a relay grows
    /// promptly under load). When omitted, falls back to `--relay-scale-down-stabilization`
    /// (default 300). `0` disables the window (size on the instantaneous signal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_down_stabilization_seconds: Option<u32>,

    /// Deactivation cooldown, in seconds (#602). Once the live signal falls below the
    /// break-even activation threshold (`--relay-min-proxy-replicas`), the relay is torn down
    /// only after the signal has stayed below it continuously for this long — the KEDA-style
    /// hysteresis that replaces the old keep-until-fully-drained rule. A namespace that
    /// genuinely drains (no dedicated Gateways left) tears down at once; a transient `0` while
    /// Gateways remain (relay restart / control-stream reconnect) waits the cooldown, so a
    /// blip never deletes a live relay. When omitted, falls back to `--relay-cooldown`
    /// (default 300).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u32>,

    /// Relative sizing deadband (#602). The controller changes the replica count only when the
    /// newly-computed desired count differs from the current count by more than this fraction
    /// of the current — a `0.10` tolerance ignores deviations under 10%, so small signal
    /// jitter does not churn the Deployment. When omitted, falls back to `--relay-tolerance`
    /// (default 0.10). Must be ≥ 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0.0))]
    pub tolerance: Option<f64>,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use crate::crd::{CoxswainRelayPolicy, CoxswainRelayPolicySpec, RelayAutoscaling};
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/coxswainrelaypolicies.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/coxswainrelaypolicies.yaml");
    const SAMPLE_FIXTURE_YAML: &str =
        include_str!("../../../../deploy/dev/sample-relay-policy.yaml");

    fn parse_cr(spec_fragment: &str) -> CoxswainRelayPolicy {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: CoxswainRelayPolicy\n\
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
        let generated = CoxswainRelayPolicy::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/coxswainrelaypolicies.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- CoxswainRelayPolicy \
             > deploy/manifests/crds/coxswainrelaypolicies.yaml \
             && cp deploy/manifests/crds/coxswainrelaypolicies.yaml \
             charts/coxswain/crds/coxswainrelaypolicies.yaml",
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
    fn crd_is_namespaced() {
        let crd = CoxswainRelayPolicy::crd();
        assert_eq!(
            crd.spec.scope, "Namespaced",
            "CoxswainRelayPolicy is namespaced — the policy in a namespace governs that namespace"
        );
    }

    #[test]
    fn empty_spec_leaves_all_fields_unset() {
        let cr = parse_cr("{}");
        assert!(cr.spec.enabled.is_none());
        assert!(cr.spec.replicas.is_none());
        assert!(cr.spec.resources.is_none());
        assert!(cr.spec.pod_template.is_none());
        assert!(cr.spec.autoscaling.is_none());
    }

    #[test]
    fn enabled_tri_state_round_trips() {
        assert_eq!(parse_cr("enabled: true").spec.enabled, Some(true));
        assert_eq!(parse_cr("enabled: false").spec.enabled, Some(false));
        assert_eq!(parse_cr("{}").spec.enabled, None);
    }

    #[test]
    fn partial_specs_leave_unmentioned_fields_unset() {
        let cases: &[(&str, &str, CoxswainRelayPolicySpec)] = &[
            (
                "replicas only",
                "replicas: 4",
                CoxswainRelayPolicySpec {
                    replicas: Some(4),
                    ..Default::default()
                },
            ),
            (
                "enabled false only",
                "enabled: false",
                CoxswainRelayPolicySpec {
                    enabled: Some(false),
                    ..Default::default()
                },
            ),
        ];
        for (name, fragment, expected) in cases {
            let parsed = parse_cr(fragment).spec;
            assert_eq!(&parsed, expected, "case: {name}");
        }
    }

    #[test]
    fn autoscaling_round_trips() {
        let cr = parse_cr(
            "autoscaling:\n  enabled: true\n  \
             minReplicas: 2\n  maxReplicas: 12\n  targetProxiesPerReplica: 10",
        );
        let a = cr.spec.autoscaling.as_ref().expect("autoscaling present");
        assert!(a.enabled);
        assert_eq!(a.min_replicas, Some(2));
        assert_eq!(a.max_replicas, Some(12));
        assert_eq!(a.target_proxies_per_replica, Some(10));
    }

    #[test]
    fn autoscaling_control_loop_overrides_round_trip() {
        let cr = parse_cr(
            "autoscaling:\n  enabled: true\n  maxReplicas: 12\n  \
             targetProxiesPerReplica: 50\n  scaleDownStabilizationSeconds: 120\n  \
             cooldownSeconds: 90\n  tolerance: 0.2",
        );
        let a = cr.spec.autoscaling.as_ref().expect("autoscaling present");
        assert_eq!(a.target_proxies_per_replica, Some(50));
        assert_eq!(a.scale_down_stabilization_seconds, Some(120));
        assert_eq!(a.cooldown_seconds, Some(90));
        assert_eq!(a.tolerance, Some(0.2));
    }

    #[test]
    fn autoscaling_control_loop_overrides_default_none() {
        // Unset control-loop overrides fall through to the --relay-* flag defaults.
        let a = parse_cr("autoscaling:\n  enabled: true\n  maxReplicas: 4")
            .spec
            .autoscaling
            .expect("autoscaling present");
        assert!(a.scale_down_stabilization_seconds.is_none());
        assert!(a.cooldown_seconds.is_none());
        assert!(a.tolerance.is_none());
        assert!(a.target_proxies_per_replica.is_none());
    }

    #[test]
    fn autoscaling_enabled_without_cap_parses_but_leaves_max_unset() {
        // The "uncapped" case is legal to parse; the controller refuses to autoscale it.
        let a = parse_cr("autoscaling:\n  enabled: true")
            .spec
            .autoscaling
            .expect("autoscaling present");
        assert!(a.enabled);
        assert!(
            a.max_replicas.is_none(),
            "max_replicas absent — controller falls back to static replicas + warns"
        );
    }

    #[test]
    fn resources_and_pod_template_preserved() {
        let cr = parse_cr(
            "resources:\n  requests:\n    cpu: 100m\n    memory: 128Mi\n\
             podTemplate:\n  spec:\n    nodeSelector:\n      zone: us-east-1",
        );
        let req = cr
            .spec
            .resources
            .as_ref()
            .and_then(|r| r.requests.as_ref())
            .expect("requests present");
        assert_eq!(req.get("cpu").map(|q| q.0.as_str()), Some("100m"));
        let pt = cr.spec.pod_template.as_ref().expect("podTemplate present");
        assert_eq!(pt["spec"]["nodeSelector"]["zone"], "us-east-1");
    }

    #[test]
    fn default_autoscaling_is_disabled() {
        assert!(!RelayAutoscaling::default().enabled);
    }

    #[test]
    fn sample_dev_fixture_deserializes() {
        let parsed: CoxswainRelayPolicy = serde_yaml::from_str(SAMPLE_FIXTURE_YAML)
            .unwrap_or_else(|e| panic!("dev sample fixture must deserialize: {e}"));
        assert!(
            parsed.metadata.namespace.is_some(),
            "sample is a namespaced policy governing its own namespace"
        );
        assert_eq!(parsed.spec.enabled, Some(true));
    }
}
