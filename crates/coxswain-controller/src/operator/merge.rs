//! Strategic merge for `PodTemplateSpec`.
//!
//! The `CoxswainGatewayParameters` CRD's `spec.podTemplate` field is an escape
//! hatch — operators paste in a partial [`PodTemplateSpec`] and the controller
//! merges it onto the controller-rendered base. Plain JSON merge patch (RFC
//! 7396) does the wrong thing for the most common cases: a `containers: [sidecar]`
//! overlay would *replace* the coxswain container instead of appending. We want
//! the `kubectl apply` mental model — arrays merge by their well-known key
//! (`name` for `containers`, `(key, operator)` for `tolerations`, etc.).
//!
//! This module hand-codes that strategy for the subset of `PodTemplateSpec`
//! fields operators actually reach for. The merge runs over [`serde_json::Value`]
//! so the CRD's `pod_template` (typed as `serde_json::Value` with
//! `x-kubernetes-preserve-unknown-fields`) and the K8s-openapi-typed base
//! (serialised to JSON for the merge, then deserialised back) share the same
//! representation during the merge step.
//!
//! ## Merge keys
//!
//! Paths are the sequence of JSON object keys descended into so far, starting
//! from the root `PodTemplateSpec`. Array indices are *not* on the path — when
//! we recurse into an array element, we keep the same path because the
//! schema-level field name (e.g. `containers`) already names the array.
//!
//! | Path | Key(s) | Source |
//! |---|---|---|
//! | `spec.containers` | `name` | K8s strategic merge convention |
//! | `spec.initContainers` | `name` | K8s strategic merge convention |
//! | `spec.volumes` | `name` | K8s strategic merge convention |
//! | `spec.imagePullSecrets` | `name` | K8s strategic merge convention |
//! | `spec.tolerations` | `key`, `operator` | K8s strategic merge convention |
//! | `spec.containers.env` | `name` | K8s strategic merge convention |
//! | `spec.containers.volumeMounts` | `name` | K8s strategic merge convention |
//! | `spec.containers.ports` | `containerPort` | K8s strategic merge convention |
//! | `spec.initContainers.env` | `name` | (mirrors `spec.containers.env`) |
//! | `spec.initContainers.volumeMounts` | `name` | (mirrors `spec.containers.volumeMounts`) |
//! | `spec.initContainers.ports` | `containerPort` | (mirrors `spec.containers.ports`) |
//!
//! Arrays whose path is not in the table fall back to replace-semantics; this
//! is the same behaviour as `kubectl apply` for arrays without a registered
//! merge key.
//!
//! Strategic-merge directives like `$patch: delete` are not implemented in this
//! version — they're rarely useful for the escape-hatch case and add real
//! complexity. Document if a user ever needs them.

use serde_json::{Map, Value};

/// Merge `patch` onto `base` using K8s strategic-merge semantics for
/// `PodTemplateSpec`.
///
/// Objects deep-merge: keys present in `patch` overlay onto `base`; keys
/// present only in `base` survive. Arrays merge by their registered key (see
/// the module-level table) — patch elements with a matching key on a base
/// element merge into that element; patch elements with no match in `base`
/// are appended. Arrays at paths without a registered key replace `base`'s
/// array entirely. Primitive scalars and type-mismatches: `patch` wins.
///
/// Both inputs are expected to be JSON serialisations of `PodTemplateSpec`s
/// (or partial ones). The caller is responsible for converting between
/// [`k8s_openapi::api::core::v1::PodTemplateSpec`] and [`Value`] at the
/// boundary; this function is schema-blind beyond the merge-key table.
#[must_use]
pub(super) fn strategic_merge_pod_template(base: &Value, patch: &Value) -> Value {
    let mut path = Vec::new();
    merge_value(base, patch, &mut path)
}

fn merge_value(base: &Value, patch: &Value, path: &mut Vec<String>) -> Value {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => Value::Object(merge_objects(b, p, path)),
        (Value::Array(b), Value::Array(p)) => match merge_keys_for_path(path) {
            Some(keys) => Value::Array(merge_arrays_by_keys(b, p, keys, path)),
            None => Value::Array(p.clone()),
        },
        // Type mismatches and primitives: patch wins. This includes the case
        // where `patch` is `null`, which RFC 7396 uses as a "delete" sentinel —
        // we don't honour delete here (it would conflict with the controller's
        // own-set defaults), but documenting that null overlays the base value.
        (_, _) => patch.clone(),
    }
}

fn merge_objects(
    base: &Map<String, Value>,
    patch: &Map<String, Value>,
    path: &mut Vec<String>,
) -> Map<String, Value> {
    let mut out = base.clone();
    for (k, v_patch) in patch {
        path.push(k.clone());
        let merged = match base.get(k) {
            Some(v_base) => merge_value(v_base, v_patch, path),
            None => v_patch.clone(),
        };
        out.insert(k.clone(), merged);
        path.pop();
    }
    out
}

/// Merge two arrays by matching elements that share the values at `keys`.
/// Matched pairs recurse through [`merge_value`]; unmatched patch elements
/// append in their original order to preserve operator intent.
fn merge_arrays_by_keys(
    base: &[Value],
    patch: &[Value],
    keys: &[&str],
    path: &mut Vec<String>,
) -> Vec<Value> {
    let mut out: Vec<Value> = base.to_vec();

    for v_patch in patch {
        let patch_keys = extract_key_tuple(v_patch, keys);
        let matched_idx = patch_keys.as_ref().and_then(|pk| {
            out.iter()
                .position(|v_base| extract_key_tuple(v_base, keys).as_ref() == Some(pk))
        });
        if let Some(idx) = matched_idx {
            let merged = merge_value(&out[idx], v_patch, path);
            out[idx] = merged;
        } else {
            out.push(v_patch.clone());
        }
    }
    out
}

/// Read the values of `keys` from a JSON object element; returns `None` if
/// any key is missing or the element isn't an object. Elements with missing
/// keys fall through to the append branch (they won't match any base element).
fn extract_key_tuple(v: &Value, keys: &[&str]) -> Option<Vec<Value>> {
    let obj = v.as_object()?;
    keys.iter()
        .map(|k| obj.get(*k).cloned())
        .collect::<Option<Vec<_>>>()
}

/// Look up the merge-key field names for a given object-key path. Returns
/// `None` for paths without a registered strategy, which signals "this array
/// replaces base on overlay" to [`merge_value`].
fn merge_keys_for_path(path: &[String]) -> Option<&'static [&'static str]> {
    let segments: Vec<&str> = path.iter().map(String::as_str).collect();
    match segments.as_slice() {
        ["spec", "containers"]
        | ["spec", "initContainers"]
        | ["spec", "volumes"]
        | ["spec", "imagePullSecrets"] => Some(&["name"]),
        ["spec", "tolerations"] => Some(&["key", "operator"]),
        ["spec", "containers", "env"]
        | ["spec", "initContainers", "env"]
        | ["spec", "containers", "volumeMounts"]
        | ["spec", "initContainers", "volumeMounts"] => Some(&["name"]),
        ["spec", "containers", "ports"] | ["spec", "initContainers", "ports"] => {
            Some(&["containerPort"])
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Sanity: plain primitive replace.
    #[test]
    fn primitive_patch_wins() {
        let base = json!({"replicas": 2});
        let patch = json!({"replicas": 5});
        assert_eq!(strategic_merge_pod_template(&base, &patch), patch);
    }

    /// Sanity: deep merge for nested objects.
    #[test]
    fn deep_merge_objects() {
        let base = json!({"spec": {"nodeSelector": {"tier": "edge"}}});
        let patch = json!({"spec": {"nodeSelector": {"zone": "us-west-1"}}});
        let expected = json!({"spec": {"nodeSelector": {"tier": "edge", "zone": "us-west-1"}}});
        assert_eq!(strategic_merge_pod_template(&base, &patch), expected);
    }

    /// Containers merge by `name`: an overlay sidecar appends without wiping
    /// the base's coxswain container. This is the headline footgun avoided
    /// vs. plain JSON merge patch.
    #[test]
    fn containers_merge_by_name_appends_sidecar() {
        let base = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "image": "coxswain:v0.2"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "sidecar", "image": "my-sidecar:v1"}
                ]
            }
        });
        let result = strategic_merge_pod_template(&base, &patch);
        let containers = result["spec"]["containers"]
            .as_array()
            .expect("containers array");
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0]["name"], "coxswain");
        assert_eq!(containers[1]["name"], "sidecar");
    }

    /// Containers merge by `name`: overlay on the same name merges per-field,
    /// not replace.
    #[test]
    fn containers_merge_by_name_overlays_same_name() {
        let base = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "image": "coxswain:v0.2", "args": ["serve", "proxy"]}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "resources": {"limits": {"memory": "512Mi"}}}
                ]
            }
        });
        let result = strategic_merge_pod_template(&base, &patch);
        let c = &result["spec"]["containers"][0];
        assert_eq!(c["name"], "coxswain");
        assert_eq!(c["image"], "coxswain:v0.2");
        assert_eq!(c["args"], json!(["serve", "proxy"]));
        assert_eq!(c["resources"]["limits"]["memory"], "512Mi");
    }

    /// Container-level `env` is merged by `name` — overlaying an existing env
    /// var's value replaces only that one.
    #[test]
    fn container_env_merges_by_name() {
        let base = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "env": [
                        {"name": "RUST_LOG", "value": "info"},
                        {"name": "POD_NAMESPACE", "value": "coxswain-system"}
                    ]}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "env": [
                        {"name": "RUST_LOG", "value": "debug"},
                        {"name": "EXTRA", "value": "yes"}
                    ]}
                ]
            }
        });
        let result = strategic_merge_pod_template(&base, &patch);
        let env = result["spec"]["containers"][0]["env"]
            .as_array()
            .expect("env array");
        assert_eq!(env.len(), 3);
        let by_name: std::collections::HashMap<&str, &str> = env
            .iter()
            .map(|e| (e["name"].as_str().unwrap(), e["value"].as_str().unwrap()))
            .collect();
        assert_eq!(by_name["RUST_LOG"], "debug");
        assert_eq!(by_name["POD_NAMESPACE"], "coxswain-system");
        assert_eq!(by_name["EXTRA"], "yes");
    }

    /// Tolerations merge by `(key, operator)` — a patch with the same pair
    /// overlays, different pair appends.
    #[test]
    fn tolerations_merge_by_key_and_operator() {
        let base = json!({
            "spec": {
                "tolerations": [
                    {"key": "dedicated", "operator": "Equal", "value": "gateway"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "tolerations": [
                    {"key": "dedicated", "operator": "Equal", "value": "gateway-v2"},
                    {"key": "infra", "operator": "Exists"}
                ]
            }
        });
        let result = strategic_merge_pod_template(&base, &patch);
        let t = result["spec"]["tolerations"]
            .as_array()
            .expect("tolerations array");
        assert_eq!(t.len(), 2);
        assert_eq!(t[0]["value"], "gateway-v2");
        assert_eq!(t[1]["key"], "infra");
    }

    /// volumeMounts merge by `name`.
    #[test]
    fn volume_mounts_merge_by_name() {
        let base = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "volumeMounts": [
                        {"name": "config", "mountPath": "/etc/coxswain"}
                    ]}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "volumeMounts": [
                        {"name": "config", "mountPath": "/etc/coxswain", "readOnly": true},
                        {"name": "extra", "mountPath": "/data"}
                    ]}
                ]
            }
        });
        let result = strategic_merge_pod_template(&base, &patch);
        let vms = result["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts array");
        assert_eq!(vms.len(), 2);
        assert_eq!(vms[0]["readOnly"], true);
        assert_eq!(vms[1]["name"], "extra");
    }

    /// Container ports merge by `containerPort`.
    #[test]
    fn container_ports_merge_by_container_port() {
        let base = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "ports": [
                        {"containerPort": 80, "name": "http"}
                    ]}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "coxswain", "ports": [
                        {"containerPort": 80, "protocol": "TCP"},
                        {"containerPort": 443, "name": "https"}
                    ]}
                ]
            }
        });
        let result = strategic_merge_pod_template(&base, &patch);
        let ports = result["spec"]["containers"][0]["ports"]
            .as_array()
            .expect("ports array");
        assert_eq!(ports.len(), 2);
        // The :80 entry should retain its original name + gain the new protocol.
        assert_eq!(ports[0]["containerPort"], 80);
        assert_eq!(ports[0]["name"], "http");
        assert_eq!(ports[0]["protocol"], "TCP");
        assert_eq!(ports[1]["containerPort"], 443);
    }

    /// Arrays whose path is NOT in the merge-key table replace base
    /// entirely. `args` is a representative example — bare scalars, no key.
    #[test]
    fn args_array_replaces() {
        let base = json!({
            "spec": {"containers": [{"name": "coxswain", "args": ["serve", "proxy", "--shared"]}]}
        });
        let patch = json!({
            "spec": {"containers": [{"name": "coxswain", "args": ["serve", "controller"]}]}
        });
        let result = strategic_merge_pod_template(&base, &patch);
        assert_eq!(
            result["spec"]["containers"][0]["args"],
            json!(["serve", "controller"])
        );
    }

    /// Top-level `nodeSelector` is a map-of-string — deep-merges (per
    /// [`deep_merge_objects`]) like any other object.
    #[test]
    fn node_selector_deep_merges() {
        let base = json!({"spec": {"nodeSelector": {"tier": "edge"}}});
        let patch = json!({"spec": {"nodeSelector": {"zone": "us-west-1", "tier": "core"}}});
        let result = strategic_merge_pod_template(&base, &patch);
        assert_eq!(
            result["spec"]["nodeSelector"],
            json!({"tier": "core", "zone": "us-west-1"})
        );
    }

    /// Type mismatch between base and patch (object vs array, etc.): patch
    /// wins outright.
    #[test]
    fn type_mismatch_patch_wins() {
        let base = json!({"spec": {"affinity": {"nodeAffinity": {}}}});
        let patch = json!({"spec": {"affinity": "this is not the right type"}});
        let result = strategic_merge_pod_template(&base, &patch);
        assert_eq!(result["spec"]["affinity"], "this is not the right type");
    }

    /// Patch elements without the merge key (e.g. a container missing `name`)
    /// can't match any base element by key, so they append.
    #[test]
    fn patch_element_without_merge_key_appends() {
        let base = json!({
            "spec": {"containers": [{"name": "coxswain", "image": "coxswain:v0.2"}]}
        });
        let patch = json!({
            "spec": {"containers": [{"image": "no-name-container:latest"}]}
        });
        let result = strategic_merge_pod_template(&base, &patch);
        let cs = result["spec"]["containers"]
            .as_array()
            .expect("containers array");
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0]["name"], "coxswain");
        assert_eq!(cs[1]["image"], "no-name-container:latest");
    }

    /// Base entries with no matching patch entry survive unchanged.
    #[test]
    fn base_only_entries_survive() {
        let base = json!({
            "spec": {"containers": [
                {"name": "coxswain", "image": "coxswain:v0.2"},
                {"name": "preserved", "image": "preserved:v1"}
            ]}
        });
        let patch = json!({
            "spec": {"containers": [{"name": "coxswain", "resources": {}}]}
        });
        let result = strategic_merge_pod_template(&base, &patch);
        let cs = result["spec"]["containers"]
            .as_array()
            .expect("containers array");
        assert_eq!(cs.len(), 2);
        let names: Vec<&str> = cs.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"coxswain"));
        assert!(names.contains(&"preserved"));
    }

    /// The headline scenario from the design conversation: class sets node
    /// selector + tolerations, Gateway adds a sidecar — the merged
    /// `podTemplate` keeps everything and the base Deployment's coxswain
    /// container survives the second-layer merge.
    #[test]
    fn headline_scenario_class_plus_gateway_overlay() {
        // Layer 1: class podTemplate + Gateway podTemplate.
        let class = json!({
            "spec": {
                "nodeSelector": {"tier": "edge"},
                "tolerations": [{"key": "dedicated", "operator": "Equal", "value": "gateway"}]
            }
        });
        let gateway = json!({
            "spec": {
                "nodeSelector": {"zone": "us-west-1"},
                "containers": [{"name": "sidecar", "image": "my-sidecar:v1"}]
            }
        });
        let layer1 = strategic_merge_pod_template(&class, &gateway);

        // Layer 2: layer1 onto a base Deployment with a coxswain container.
        let base = json!({
            "spec": {
                "serviceAccountName": "my-gw-coxswain",
                "containers": [{
                    "name": "coxswain",
                    "image": "coxswain:v0.2",
                    "args": ["serve", "proxy", "--dedicated"]
                }]
            }
        });
        let result = strategic_merge_pod_template(&base, &layer1);

        let cs = result["spec"]["containers"]
            .as_array()
            .expect("containers array");
        assert_eq!(
            cs.len(),
            2,
            "coxswain container survives + sidecar appended"
        );
        assert_eq!(cs[0]["name"], "coxswain");
        assert_eq!(cs[1]["name"], "sidecar");

        assert_eq!(
            result["spec"]["nodeSelector"],
            json!({"tier": "edge", "zone": "us-west-1"})
        );
        assert_eq!(
            result["spec"]["tolerations"][0]["value"], "gateway",
            "class-level toleration survives because Gateway didn't set tolerations"
        );
        assert_eq!(result["spec"]["serviceAccountName"], "my-gw-coxswain");
    }
}
