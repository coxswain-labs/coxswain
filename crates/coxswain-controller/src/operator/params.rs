//! Resolution + per-field overlay of `CoxswainGatewayParameters` for one Gateway.
//!
//! Both `GatewayClass.spec.parametersRef` and
//! `Gateway.spec.infrastructure.parametersRef` can point at a
//! `CoxswainGatewayParameters` object. The two references together produce
//! the *effective* parameters used by the renderer:
//!
//! - Every spec field is `Option`; this module's overlay treats `None` on the
//!   Gateway-level params as "fall through to the GatewayClass-level params".
//! - `pod_template` is merged via [`super::merge::strategic_merge_pod_template`]
//!   when both layers set it, so escape-hatch fields layer cleanly.
//!
//! Missing parametersRef target (the reference exists but the
//! `CoxswainGatewayParameters` object does not) surfaces as
//! [`ParamsError::NotFound`]; the reconciler translates this into an
//! `Accepted=False, reason=InvalidParameters` Gateway condition via the
//! shared [`crate::AcceptedOverrides`] map (Gateway API spec).

use super::merge::strategic_merge_pod_template;
use coxswain_core::crd::{CoxswainGatewayParameters, CoxswainGatewayParametersSpec, ServiceType};
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use k8s_openapi::api::core::v1::ResourceRequirements;
use kube::Resource;
use thiserror::Error;

/// Identifier for a `CoxswainGatewayParameters` object: `(namespace, name)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ParamsRef {
    pub(super) namespace: String,
    pub(super) name: String,
}

/// Errors that can occur while resolving `CoxswainGatewayParameters`.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq)]
pub(super) enum ParamsError {
    /// A `parametersRef` is set but the target object does not exist in the
    /// reflector store. The reconciler surfaces this as `Accepted=False,
    /// reason=InvalidParameters` on the Gateway via the shared
    /// [`crate::AcceptedOverrides`] map (Gateway API spec).
    #[error("parametersRef target {0}/{1} not found")]
    NotFound(String, String),
}

/// Merged parameters for a single Gateway after per-field overlay between
/// the GatewayClass's and Gateway's `parametersRef`s.
///
/// Every field stays optional: the renderer applies its own defaults at the
/// last possible moment (e.g. `replicas` defaults to `1`, `service_type` to
/// `LoadBalancer`). Keeping `EffectiveParams` shaped like
/// `CoxswainGatewayParametersSpec` makes the overlay rule visible at the
/// type level.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct EffectiveParams {
    pub(super) replicas: Option<u32>,
    pub(super) resources: Option<ResourceRequirements>,
    pub(super) image: Option<String>,
    pub(super) service_type: Option<ServiceType>,
    pub(super) pod_template: Option<serde_json::Value>,
}

/// Extract the [`ParamsRef`] the given GatewayClass's `parametersRef` points
/// at — or `None` if no such reference is set or the reference targets a
/// different CRD kind.
///
/// The Gateway API spec requires `parametersRef.namespace` to be present
/// when the referent is namespaced; we treat a missing namespace on a
/// CoxswainGatewayParameters reference as a malformed spec and ignore it
/// (the conformance check for this is the GatewayClass validator's job).
pub(super) fn class_params_ref(class: &GatewayClass) -> Option<ParamsRef> {
    let r = class.spec.parameters_ref.as_ref()?;
    if r.group != group() || r.kind != kind() {
        return None;
    }
    Some(ParamsRef {
        namespace: r.namespace.clone()?,
        name: r.name.clone(),
    })
}

/// Extract the [`ParamsRef`] the given Gateway's
/// `spec.infrastructure.parametersRef` points at — or `None` if no such
/// reference is set or it targets a different CRD kind.
///
/// `Gateway.spec.infrastructure.parametersRef` has no `namespace` field on
/// the upstream type; the implicit namespace is the Gateway's own
/// (Gateways can only reference namespaced parameters in their own
/// namespace, per the spec). We require the Gateway to carry a
/// `metadata.namespace` — it's a runtime invariant on every K8s object the
/// API server serves.
pub(super) fn gateway_params_ref(gw: &Gateway) -> Option<ParamsRef> {
    let r = gw.spec.infrastructure.as_ref()?.parameters_ref.as_ref()?;
    if r.group != group() || r.kind != kind() {
        return None;
    }
    let namespace = gw.metadata.namespace.clone()?;
    Some(ParamsRef {
        namespace,
        name: r.name.clone(),
    })
}

/// Resolve and overlay the effective parameters for one Gateway.
///
/// `lookup` is the caller's hook into the reflector store (or a test fake);
/// it returns `Some(spec)` if a `CoxswainGatewayParameters` object exists at
/// the given (namespace, name) and `None` otherwise.
///
/// Returns:
/// - `Ok(None)` — neither GatewayClass nor Gateway has a `parametersRef` to
///   `CoxswainGatewayParameters`; this is not a dedicated-mode Gateway and
///   the reconciler skips it.
/// - `Ok(Some(params))` — at least one reference exists and resolves
///   successfully; `params` is the per-field overlay.
/// - `Err(NotFound)` — a reference exists but the target doesn't.
///
/// # Errors
///
/// Returns [`ParamsError::NotFound`] when a parametersRef is present but
/// the target [`CoxswainGatewayParameters`] does not exist in the store.
pub(super) fn resolve<F>(
    gateway: &Gateway,
    class: &GatewayClass,
    lookup: F,
) -> Result<Option<EffectiveParams>, ParamsError>
where
    F: Fn(&ParamsRef) -> Option<CoxswainGatewayParametersSpec>,
{
    let class_ref = class_params_ref(class);
    let gateway_ref = gateway_params_ref(gateway);
    if class_ref.is_none() && gateway_ref.is_none() {
        return Ok(None);
    }

    let class_spec = match class_ref.as_ref() {
        Some(r) => Some(
            lookup(r).ok_or_else(|| ParamsError::NotFound(r.namespace.clone(), r.name.clone()))?,
        ),
        None => None,
    };
    let gateway_spec = match gateway_ref.as_ref() {
        Some(r) => Some(
            lookup(r).ok_or_else(|| ParamsError::NotFound(r.namespace.clone(), r.name.clone()))?,
        ),
        None => None,
    };

    Ok(Some(overlay(class_spec.as_ref(), gateway_spec.as_ref())))
}

/// Per-field overlay rule. Gateway's `Some(v)` wins; Gateway's `None` falls
/// through to GatewayClass's value (which may itself be `None`, leaving the
/// renderer to apply its built-in default).
///
/// `pod_template` is the special case: when both layers set it, they
/// strategic-merge into a single combined `PodTemplateSpec`.
fn overlay(
    class: Option<&CoxswainGatewayParametersSpec>,
    gateway: Option<&CoxswainGatewayParametersSpec>,
) -> EffectiveParams {
    EffectiveParams {
        replicas: gateway
            .and_then(|s| s.replicas)
            .or_else(|| class.and_then(|s| s.replicas)),
        resources: gateway
            .and_then(|s| s.resources.clone())
            .or_else(|| class.and_then(|s| s.resources.clone())),
        image: gateway
            .and_then(|s| s.image.clone())
            .or_else(|| class.and_then(|s| s.image.clone())),
        service_type: gateway
            .and_then(|s| s.service_type)
            .or_else(|| class.and_then(|s| s.service_type)),
        pod_template: merge_pod_templates(
            class.and_then(|s| s.pod_template.as_ref()),
            gateway.and_then(|s| s.pod_template.as_ref()),
        ),
    }
}

fn merge_pod_templates(
    class: Option<&serde_json::Value>,
    gateway: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    match (class, gateway) {
        (None, None) => None,
        (Some(c), None) => Some(c.clone()),
        (None, Some(g)) => Some(g.clone()),
        (Some(c), Some(g)) => Some(strategic_merge_pod_template(c, g)),
    }
}

fn group() -> &'static str {
    <CoxswainGatewayParameters as Resource>::group(&())
        .into_owned()
        .leak()
}

fn kind() -> &'static str {
    <CoxswainGatewayParameters as Resource>::kind(&())
        .into_owned()
        .leak()
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_reflector::gw_types::v::gatewayclasses::{
        GatewayClassParametersRef, GatewayClassSpec,
    };
    use coxswain_reflector::gw_types::v::gateways::{
        GatewayInfrastructure, GatewayInfrastructureParametersRef, GatewaySpec,
    };
    use kube::api::ObjectMeta;
    use serde_json::json;

    const CRD_GROUP: &str = "gateway.coxswain-labs.dev";
    const CRD_KIND: &str = "CoxswainGatewayParameters";

    fn gateway_class(
        name: &str,
        params_namespace: Option<&str>,
        params_name: Option<&str>,
    ) -> GatewayClass {
        GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: "coxswain-labs.dev/gateway-controller".to_string(),
                parameters_ref: params_name.map(|n| GatewayClassParametersRef {
                    group: CRD_GROUP.to_string(),
                    kind: CRD_KIND.to_string(),
                    name: n.to_string(),
                    namespace: params_namespace.map(String::from),
                }),
                description: None,
            },
            status: None,
        }
    }

    fn gateway(namespace: &str, name: &str, params_ref_name: Option<&str>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners: vec![],
                infrastructure: params_ref_name.map(|n| GatewayInfrastructure {
                    parameters_ref: Some(GatewayInfrastructureParametersRef {
                        group: CRD_GROUP.to_string(),
                        kind: CRD_KIND.to_string(),
                        name: n.to_string(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        }
    }

    /// Neither GatewayClass nor Gateway has a parametersRef → not dedicated
    /// mode, reconciler skips.
    #[test]
    fn no_params_ref_anywhere_returns_none() {
        let class = gateway_class("coxswain", None, None);
        let gw = gateway("default", "my-gw", None);
        let result = resolve(&gw, &class, |_| None).expect("ok");
        assert!(result.is_none());
    }

    /// Build a [`CoxswainGatewayParametersSpec`] from a JSON fragment.
    /// `CoxswainGatewayParametersSpec` is `#[non_exhaustive]` (so the CRD can
    /// grow fields without breaking downstream construction) — tests in this
    /// crate can't use struct-literal syntax, so we go through serde.
    fn spec_from_json(v: serde_json::Value) -> CoxswainGatewayParametersSpec {
        serde_json::from_value(v).expect("valid CoxswainGatewayParametersSpec JSON")
    }

    /// Build a `lookup` closure that returns the spec associated with each
    /// `ParamsRef` in `known`, or `None` for any other ref. Replaces the
    /// caller's need to spell out `move |r| if r == ... else if r == ...`
    /// in every test that exercises class + Gateway resolution.
    fn lookup_from_pairs(
        known: Vec<(ParamsRef, CoxswainGatewayParametersSpec)>,
    ) -> impl Fn(&ParamsRef) -> Option<CoxswainGatewayParametersSpec> {
        move |r| {
            known
                .iter()
                .find(|(known_ref, _)| known_ref == r)
                .map(|(_, spec)| spec.clone())
        }
    }

    /// Only the GatewayClass has parametersRef and the target exists.
    /// The class's spec becomes the effective spec verbatim.
    #[test]
    fn class_only_resolves_to_class_spec() {
        let class = gateway_class("coxswain", Some("coxswain-system"), Some("class-defaults"));
        let gw = gateway("default", "my-gw", None);
        let class_spec = spec_from_json(json!({
            "replicas": 3,
            "image": "coxswain:v0.2"
        }));
        let lookup = lookup_from_pairs(vec![(
            ParamsRef {
                namespace: "coxswain-system".into(),
                name: "class-defaults".into(),
            },
            class_spec,
        )]);
        let result = resolve(&gw, &class, lookup).expect("ok").expect("some");
        assert_eq!(result.replicas, Some(3));
        assert_eq!(result.image.as_deref(), Some("coxswain:v0.2"));
    }

    /// Only the Gateway has parametersRef.
    #[test]
    fn gateway_only_resolves_to_gateway_spec() {
        let class = gateway_class("coxswain", None, None);
        let gw = gateway("default", "my-gw", Some("gw-params"));
        let gw_spec = spec_from_json(json!({"replicas": 5}));
        let lookup = lookup_from_pairs(vec![(
            ParamsRef {
                namespace: "default".into(),
                name: "gw-params".into(),
            },
            gw_spec,
        )]);
        let result = resolve(&gw, &class, lookup).expect("ok").expect("some");
        assert_eq!(result.replicas, Some(5));
    }

    /// Both reference and both exist — Gateway wins per-field, GatewayClass
    /// fills the rest.
    #[test]
    fn per_field_overlay_gateway_wins_class_fills_rest() {
        let class = gateway_class("coxswain", Some("coxswain-system"), Some("class-defaults"));
        let gw = gateway("default", "my-gw", Some("gw-params"));
        let class_spec = spec_from_json(json!({
            "replicas": 2,
            "image": "class-image:v1",
            "serviceType": "LoadBalancer"
        }));
        let gw_spec = spec_from_json(json!({
            "replicas": 5,
            "serviceType": "ClusterIP"
        }));
        let lookup = lookup_from_pairs(vec![
            (
                ParamsRef {
                    namespace: "coxswain-system".into(),
                    name: "class-defaults".into(),
                },
                class_spec,
            ),
            (
                ParamsRef {
                    namespace: "default".into(),
                    name: "gw-params".into(),
                },
                gw_spec,
            ),
        ]);
        let result = resolve(&gw, &class, lookup).expect("ok").expect("some");
        assert_eq!(result.replicas, Some(5), "Gateway override wins");
        assert_eq!(
            result.image.as_deref(),
            Some("class-image:v1"),
            "class fills"
        );
        assert_eq!(
            result.service_type,
            Some(ServiceType::ClusterIp),
            "Gateway override wins"
        );
    }

    /// Both reference, both have `pod_template` → strategic-merge.
    #[test]
    fn pod_template_layer1_strategic_merges() {
        let class = gateway_class("coxswain", Some("coxswain-system"), Some("class-defaults"));
        let gw = gateway("default", "my-gw", Some("gw-params"));
        let class_spec = spec_from_json(json!({
            "podTemplate": {
                "spec": {
                    "nodeSelector": {"tier": "edge"},
                    "tolerations": [{"key": "dedicated", "operator": "Equal", "value": "gateway"}]
                }
            }
        }));
        let gw_spec = spec_from_json(json!({
            "podTemplate": {
                "spec": {
                    "nodeSelector": {"zone": "us-west-1"},
                    "containers": [{"name": "sidecar", "image": "sc:v1"}]
                }
            }
        }));
        let lookup = lookup_from_pairs(vec![
            (
                ParamsRef {
                    namespace: "coxswain-system".into(),
                    name: "class-defaults".into(),
                },
                class_spec,
            ),
            (
                ParamsRef {
                    namespace: "default".into(),
                    name: "gw-params".into(),
                },
                gw_spec,
            ),
        ]);
        let result = resolve(&gw, &class, lookup).expect("ok").expect("some");
        let pt = result.pod_template.expect("pod_template");
        assert_eq!(
            pt["spec"]["nodeSelector"],
            json!({"tier": "edge", "zone": "us-west-1"})
        );
        assert_eq!(pt["spec"]["tolerations"][0]["value"], "gateway");
        assert_eq!(pt["spec"]["containers"][0]["name"], "sidecar");
    }

    /// Reference exists but target is missing → `NotFound`.
    #[test]
    fn missing_target_returns_not_found() {
        let class = gateway_class("coxswain", None, None);
        let gw = gateway("default", "my-gw", Some("missing"));
        let err = resolve(&gw, &class, |_| None).expect_err("expected NotFound");
        assert_eq!(
            err,
            ParamsError::NotFound("default".to_string(), "missing".to_string())
        );
    }

    /// parametersRef pointing at a different CRD (group/kind mismatch) is
    /// silently ignored.
    #[test]
    fn other_crd_kind_is_ignored() {
        let mut class = gateway_class("coxswain", Some("ns"), Some("foreign"));
        if let Some(r) = class.spec.parameters_ref.as_mut() {
            r.kind = "SomeOtherKind".into();
        }
        let gw = gateway("default", "my-gw", None);
        let result = resolve(&gw, &class, |_| None).expect("ok");
        assert!(
            result.is_none(),
            "non-matching parametersRef is not dedicated mode"
        );
    }
}
