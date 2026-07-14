//! Resolution + per-field overlay of `CoxswainRelayPolicy` for one namespace (#589).
//!
//! `CoxswainRelayPolicy` is cluster-scoped with an optional `namespaceSelector`. The
//! effective policy for a namespace is a two-layer overlay:
//!
//! - **Layer 1 — cluster default:** the policy with *no* `namespaceSelector`, applied to
//!   every relay-fronted namespace.
//! - **Layer 2 — namespace match:** the most-specific policy whose `namespaceSelector`
//!   matches the namespace's labels.
//!
//! Layer 2 overlays per-field onto Layer 1; `podTemplate` strategic-merges across layers.
//! The resulting [`EffectiveRelayPolicy`] still holds `Option`s — the reconciler applies the
//! #584 global controller-flag defaults (`--relay-replicas`, `--relay-*-request`) as the base
//! at the last moment, exactly like [`super::params`] does for `CoxswainGatewayParameters`.
//!
//! "Most-specific" tiebreak: more selector terms (`matchLabels` + `matchExpressions`) wins;
//! remaining ties break lexically by policy name. Ambiguous same-specificity matches — and
//! multiple no-selector defaults — are resolved deterministically and warn-logged (the
//! controller is the sole diagnostic emitter; a log is sufficient, no K8s Event).

use super::merge::strategic_merge_pod_template;
use coxswain_core::crd::{CoxswainRelayPolicy, RelayAutoscaling};
use k8s_openapi::api::core::v1::ResourceRequirements;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Effective per-namespace relay policy after the cluster-default → namespace-match overlay.
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

/// Resolve the effective relay policy for a namespace given its labels and the full policy
/// set (the reflector store snapshot). Returns an all-`None` policy when nothing matches —
/// the namespace falls back entirely to the global controller-flag defaults.
pub(super) fn resolve(
    namespace: &str,
    namespace_labels: &BTreeMap<String, String>,
    policies: &[Arc<CoxswainRelayPolicy>],
) -> EffectiveRelayPolicy {
    let default_layer = cluster_default_policy(policies);
    let match_layer = best_matching_policy(namespace, namespace_labels, policies);
    overlay(default_layer, match_layer)
}

/// The single cluster-default policy (no `namespaceSelector`). If more than one exists it's a
/// misconfiguration: pick the lexically-first by name and warn.
fn cluster_default_policy(policies: &[Arc<CoxswainRelayPolicy>]) -> Option<&CoxswainRelayPolicy> {
    let mut defaults: Vec<&CoxswainRelayPolicy> = policies
        .iter()
        .map(Arc::as_ref)
        .filter(|p| p.spec.namespace_selector.is_none())
        .collect();
    defaults.sort_by(|a, b| policy_name(a).cmp(policy_name(b)));
    if defaults.len() > 1 {
        tracing::warn!(
            policies = ?defaults.iter().map(|p| policy_name(p)).collect::<Vec<_>>(),
            "relay policy: multiple cluster-default CoxswainRelayPolicies (no namespaceSelector); \
             using the lexically-first — remove the duplicates"
        );
    }
    defaults.into_iter().next()
}

/// The most-specific policy whose `namespaceSelector` matches the namespace. Specificity =
/// selector term count; ties break lexically by name. A same-specificity tie is warn-logged.
fn best_matching_policy<'a>(
    namespace: &str,
    namespace_labels: &BTreeMap<String, String>,
    policies: &'a [Arc<CoxswainRelayPolicy>],
) -> Option<&'a CoxswainRelayPolicy> {
    let mut matches: Vec<(usize, &CoxswainRelayPolicy)> = policies
        .iter()
        .map(Arc::as_ref)
        .filter_map(|p| {
            let selector = p.spec.namespace_selector.as_ref()?;
            selector_matches(selector, namespace_labels).then(|| (selector_term_count(selector), p))
        })
        .collect();
    // Sort by specificity desc, then name asc — the first element is the winner.
    matches.sort_by(|(sa, a), (sb, b)| sb.cmp(sa).then_with(|| policy_name(a).cmp(policy_name(b))));
    if let (Some((top_terms, top)), Some((next_terms, _))) = (matches.first(), matches.get(1))
        && top_terms == next_terms
    {
        tracing::warn!(
            namespace = %namespace,
            winner = %policy_name(top),
            "relay policy: multiple equally-specific CoxswainRelayPolicies match this namespace; \
             using the lexically-first — disambiguate their namespaceSelectors"
        );
    }
    matches.into_iter().next().map(|(_, p)| p)
}

/// Per-field overlay: `match_layer` (namespace-specific) wins over `default_layer`
/// (cluster default); each falls through to `None` (→ global default) when unset.
/// `pod_template` strategic-merges across the two layers.
fn overlay(
    default_layer: Option<&CoxswainRelayPolicy>,
    match_layer: Option<&CoxswainRelayPolicy>,
) -> EffectiveRelayPolicy {
    let d = default_layer.map(|p| &p.spec);
    let m = match_layer.map(|p| &p.spec);
    EffectiveRelayPolicy {
        enabled: m
            .and_then(|s| s.enabled)
            .or_else(|| d.and_then(|s| s.enabled)),
        replicas: m
            .and_then(|s| s.replicas)
            .or_else(|| d.and_then(|s| s.replicas)),
        resources: m
            .and_then(|s| s.resources.clone())
            .or_else(|| d.and_then(|s| s.resources.clone())),
        pod_template: merge_pod_templates(
            d.and_then(|s| s.pod_template.as_ref()),
            m.and_then(|s| s.pod_template.as_ref()),
        ),
        // Whole-block override: match layer wins if set, else the cluster default.
        autoscaling: m
            .and_then(|s| s.autoscaling.clone())
            .or_else(|| d.and_then(|s| s.autoscaling.clone())),
    }
}

fn merge_pod_templates(
    default_layer: Option<&serde_json::Value>,
    match_layer: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    match (default_layer, match_layer) {
        (None, None) => None,
        (Some(d), None) => Some(d.clone()),
        (None, Some(m)) => Some(m.clone()),
        (Some(d), Some(m)) => Some(strategic_merge_pod_template(d, m)),
    }
}

fn policy_name(p: &CoxswainRelayPolicy) -> &str {
    p.metadata.name.as_deref().unwrap_or_default()
}

/// Number of terms in a selector — `matchLabels` entries plus `matchExpressions`. Used as the
/// specificity score for precedence.
fn selector_term_count(selector: &LabelSelector) -> usize {
    selector.match_labels.as_ref().map_or(0, BTreeMap::len)
        + selector.match_expressions.as_ref().map_or(0, Vec::len)
}

/// Evaluate a Kubernetes `LabelSelector` against a label set (`matchLabels` ANDed with
/// `matchExpressions`). An empty selector matches everything; an unknown operator fails
/// closed (does not match), so a malformed selector never silently widens scope.
fn selector_matches(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    if let Some(ml) = selector.match_labels.as_ref() {
        for (k, v) in ml {
            if labels.get(k) != Some(v) {
                return false;
            }
        }
    }
    for req in selector.match_expressions.iter().flatten() {
        let present = labels.get(&req.key);
        let values = req.values.as_deref().unwrap_or(&[]);
        let ok = match req.operator.as_str() {
            "In" => present.is_some_and(|v| values.iter().any(|x| x == v)),
            "NotIn" => present.is_none_or(|v| !values.iter().any(|x| x == v)),
            "Exists" => present.is_some(),
            "DoesNotExist" => present.is_none(),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;
    use kube::api::ObjectMeta;

    fn policy(
        name: &str,
        selector: Option<LabelSelector>,
        spec_json: serde_json::Value,
    ) -> Arc<CoxswainRelayPolicy> {
        let mut spec: coxswain_core::crd::CoxswainRelayPolicySpec =
            serde_json::from_value(spec_json).expect("valid spec");
        spec.namespace_selector = selector;
        Arc::new(CoxswainRelayPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec,
        })
    }

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn match_labels(pairs: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: Some(labels(pairs)),
            match_expressions: None,
        }
    }

    #[test]
    fn no_policies_yields_all_none() {
        let eff = resolve("team-a", &labels(&[]), &[]);
        assert_eq!(eff, EffectiveRelayPolicy::default());
    }

    #[test]
    fn cluster_default_applies_without_selector() {
        let policies = vec![policy("default", None, serde_json::json!({"replicas": 3}))];
        let eff = resolve("team-a", &labels(&[]), &policies);
        assert_eq!(eff.replicas, Some(3));
    }

    #[test]
    fn selectored_policy_matches_only_labelled_namespace() {
        let policies = vec![policy(
            "hs",
            Some(match_labels(&[("tier", "high")])),
            serde_json::json!({"enabled": true, "replicas": 5}),
        )];
        // Matches.
        let eff = resolve("big", &labels(&[("tier", "high")]), &policies);
        assert_eq!(eff.enabled, Some(true));
        assert_eq!(eff.replicas, Some(5));
        // Doesn't match → all None.
        let eff = resolve("small", &labels(&[("tier", "low")]), &policies);
        assert_eq!(eff, EffectiveRelayPolicy::default());
    }

    #[test]
    fn match_layer_overlays_cluster_default_per_field() {
        let policies = vec![
            policy(
                "default",
                None,
                serde_json::json!({"replicas": 2, "enabled": false}),
            ),
            policy(
                "hs",
                Some(match_labels(&[("tier", "high")])),
                serde_json::json!({"replicas": 6}),
            ),
        ];
        let eff = resolve("big", &labels(&[("tier", "high")]), &policies);
        assert_eq!(eff.replicas, Some(6), "match layer wins");
        assert_eq!(
            eff.enabled,
            Some(false),
            "cluster default fills unset field"
        );
    }

    #[test]
    fn most_specific_wins_by_term_count() {
        let policies = vec![
            policy(
                "one-term",
                Some(match_labels(&[("tier", "high")])),
                serde_json::json!({"replicas": 3}),
            ),
            policy(
                "two-term",
                Some(match_labels(&[("tier", "high"), ("zone", "eu")])),
                serde_json::json!({"replicas": 9}),
            ),
        ];
        let eff = resolve(
            "big",
            &labels(&[("tier", "high"), ("zone", "eu")]),
            &policies,
        );
        assert_eq!(
            eff.replicas,
            Some(9),
            "the two-term selector is more specific"
        );
    }

    #[test]
    fn equal_specificity_breaks_lexically() {
        let policies = vec![
            policy(
                "bbb",
                Some(match_labels(&[("zone", "eu")])),
                serde_json::json!({"replicas": 2}),
            ),
            policy(
                "aaa",
                Some(match_labels(&[("tier", "high")])),
                serde_json::json!({"replicas": 7}),
            ),
        ];
        let eff = resolve(
            "big",
            &labels(&[("tier", "high"), ("zone", "eu")]),
            &policies,
        );
        assert_eq!(
            eff.replicas,
            Some(7),
            "lexically-first name 'aaa' wins the tie"
        );
    }

    #[test]
    fn match_expression_operators() {
        let sel = LabelSelector {
            match_labels: None,
            match_expressions: Some(vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "In".to_string(),
                values: Some(vec!["prod".to_string(), "staging".to_string()]),
            }]),
        };
        let policies = vec![policy("p", Some(sel), serde_json::json!({"enabled": true}))];
        assert_eq!(
            resolve("a", &labels(&[("env", "prod")]), &policies).enabled,
            Some(true)
        );
        assert_eq!(
            resolve("b", &labels(&[("env", "dev")]), &policies),
            EffectiveRelayPolicy::default(),
            "env=dev not In [prod,staging]"
        );
    }

    #[test]
    fn tri_state_enabled_match_wins_over_default() {
        let policies = vec![
            policy("default", None, serde_json::json!({"enabled": true})),
            policy(
                "off",
                Some(match_labels(&[("relay", "off")])),
                serde_json::json!({"enabled": false}),
            ),
        ];
        // Matched namespace: force-off wins.
        assert_eq!(
            resolve("x", &labels(&[("relay", "off")]), &policies).enabled,
            Some(false)
        );
        // Unmatched namespace: cluster default on.
        assert_eq!(resolve("y", &labels(&[]), &policies).enabled, Some(true));
    }

    #[test]
    fn pod_template_strategic_merges_across_layers() {
        let policies = vec![
            policy(
                "default",
                None,
                serde_json::json!({"podTemplate": {"spec": {"nodeSelector": {"tier": "edge"}}}}),
            ),
            policy(
                "hs",
                Some(match_labels(&[("z", "1")])),
                serde_json::json!({"podTemplate": {"spec": {"nodeSelector": {"zone": "eu"}}}}),
            ),
        ];
        let eff = resolve("big", &labels(&[("z", "1")]), &policies);
        let pt = eff.pod_template.expect("pod_template");
        assert_eq!(
            pt["spec"]["nodeSelector"],
            serde_json::json!({"tier": "edge", "zone": "eu"})
        );
    }
}
