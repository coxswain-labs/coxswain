//! Resolution of `CoxswainRelayPolicy` for one namespace (#589).
//!
//! `CoxswainRelayPolicy` is **namespaced**: the policy in a namespace governs that
//! namespace's relay, keyed by the object's own namespace (the `CoxswainGatewayParameters`
//! model). The effective policy for a namespace is simply that namespace's policy, if any;
//! the resulting [`EffectiveRelayPolicy`] holds `Option`s so the reconciler applies the #584
//! global controller-flag defaults (`--relay-replicas`, `--relay-*-request`) as the base
//! wherever a field is unset — exactly like [`super::params`] does for
//! `CoxswainGatewayParameters`. There is no cluster-default *policy* and no
//! `namespaceSelector`: the sole cluster-wide default is the flat `--relay-*` flags.
//!
//! At most one policy per namespace is expected; if several exist it's a misconfiguration —
//! the lexically-first by name is used and the ambiguity is warn-logged (the controller is
//! the sole diagnostic emitter; a log is sufficient, no K8s Event).

use coxswain_core::crd::{CoxswainRelayPolicy, RelayAutoscaling};
use k8s_openapi::api::core::v1::ResourceRequirements;
use std::sync::Arc;

/// Effective per-namespace relay policy — the fields of the `CoxswainRelayPolicy` in the
/// namespace, if one exists.
///
/// Every field stays optional: the reconciler applies the #584 global defaults when a field
/// is `None`. `enabled` is tri-state — `None` means "controller decides automatically"
/// (the break-even threshold), not "off".
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct EffectiveRelayPolicy {
    pub(super) enabled: Option<bool>,
    pub(super) replicas: Option<u32>,
    pub(super) resources: Option<ResourceRequirements>,
    pub(super) pod_template: Option<serde_json::Value>,
    pub(super) autoscaling: Option<RelayAutoscaling>,
}

/// Resolve the effective relay policy for `namespace` from the full policy set (the reflector
/// store snapshot). Returns the policy that lives *in* `namespace`, converted to an
/// [`EffectiveRelayPolicy`]; an all-`None` policy when the namespace has none — falling back
/// entirely to the global controller-flag defaults.
pub(super) fn resolve(
    namespace: &str,
    policies: &[Arc<CoxswainRelayPolicy>],
) -> EffectiveRelayPolicy {
    let Some(policy) = namespace_policy(namespace, policies) else {
        return EffectiveRelayPolicy::default();
    };
    let spec = &policy.spec;
    EffectiveRelayPolicy {
        enabled: spec.enabled,
        replicas: spec.replicas,
        resources: spec.resources.clone(),
        pod_template: spec.pod_template.clone(),
        autoscaling: spec.autoscaling.clone(),
    }
}

/// The `CoxswainRelayPolicy` governing `namespace` — the policy whose object namespace equals
/// `namespace`. At most one is expected; if several exist it's a misconfiguration, so the
/// lexically-first by name is chosen and the ambiguity is warn-logged.
fn namespace_policy<'a>(
    namespace: &str,
    policies: &'a [Arc<CoxswainRelayPolicy>],
) -> Option<&'a CoxswainRelayPolicy> {
    let mut in_namespace: Vec<&CoxswainRelayPolicy> = policies
        .iter()
        .map(Arc::as_ref)
        .filter(|p| p.metadata.namespace.as_deref() == Some(namespace))
        .collect();
    in_namespace.sort_by(|a, b| policy_name(a).cmp(policy_name(b)));
    if in_namespace.len() > 1 {
        tracing::warn!(
            namespace = %namespace,
            policies = ?in_namespace.iter().map(|p| policy_name(p)).collect::<Vec<_>>(),
            "relay policy: multiple CoxswainRelayPolicies in one namespace; using the \
             lexically-first by name — keep at most one per namespace"
        );
    }
    in_namespace.into_iter().next()
}

fn policy_name(p: &CoxswainRelayPolicy) -> &str {
    p.metadata.name.as_deref().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;

    fn policy(
        name: &str,
        namespace: &str,
        spec_json: serde_json::Value,
    ) -> Arc<CoxswainRelayPolicy> {
        let spec: coxswain_core::crd::CoxswainRelayPolicySpec =
            serde_json::from_value(spec_json).expect("valid spec");
        Arc::new(CoxswainRelayPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec,
        })
    }

    #[test]
    fn no_policies_yields_all_none() {
        assert_eq!(resolve("team-a", &[]), EffectiveRelayPolicy::default());
    }

    #[test]
    fn policy_in_its_namespace_applies() {
        let policies = vec![policy(
            "p",
            "team-a",
            serde_json::json!({"enabled": true, "replicas": 5}),
        )];
        let eff = resolve("team-a", &policies);
        assert_eq!(eff.enabled, Some(true));
        assert_eq!(eff.replicas, Some(5));
    }

    #[test]
    fn policy_does_not_affect_other_namespaces() {
        let policies = vec![policy("p", "team-a", serde_json::json!({"replicas": 5}))];
        assert_eq!(
            resolve("team-b", &policies),
            EffectiveRelayPolicy::default(),
            "a policy in team-a must not govern team-b"
        );
    }

    #[test]
    fn all_fields_pass_through_from_the_namespace_policy() {
        let policies = vec![policy(
            "p",
            "team-a",
            serde_json::json!({
                "enabled": false,
                "replicas": 3,
                "resources": {"requests": {"cpu": "100m"}},
                "podTemplate": {"spec": {"nodeSelector": {"zone": "eu"}}},
                "autoscaling": {"enabled": true, "minReplicas": 2, "maxReplicas": 8},
            }),
        )];
        let eff = resolve("team-a", &policies);
        assert_eq!(eff.enabled, Some(false));
        assert_eq!(eff.replicas, Some(3));
        assert!(eff.resources.is_some());
        assert_eq!(
            eff.pod_template.expect("pod_template")["spec"]["nodeSelector"],
            serde_json::json!({"zone": "eu"})
        );
        assert!(eff.autoscaling.is_some_and(|a| a.enabled));
    }

    #[test]
    fn unset_fields_stay_none_for_the_global_flag_fallback() {
        let policies = vec![policy("p", "team-a", serde_json::json!({"replicas": 4}))];
        let eff = resolve("team-a", &policies);
        assert_eq!(eff.replicas, Some(4));
        assert_eq!(eff.enabled, None, "unset → controller decides");
        assert_eq!(eff.resources, None, "unset → --relay-* flag defaults");
        assert_eq!(eff.autoscaling, None);
    }

    #[test]
    fn multiple_policies_in_one_namespace_lexically_first_wins() {
        // Misconfiguration: two policies in the same namespace. Deterministic, warn-logged.
        let policies = vec![
            policy("bbb", "team-a", serde_json::json!({"replicas": 2})),
            policy("aaa", "team-a", serde_json::json!({"replicas": 7})),
        ];
        assert_eq!(
            resolve("team-a", &policies).replicas,
            Some(7),
            "lexically-first name 'aaa' wins"
        );
    }
}
