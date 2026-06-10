//! IngressClass ownership checks and `is-default-class` annotation helper.

use k8s_openapi::api::networking::v1::{Ingress, IngressClass};

/// Annotation that marks an `IngressClass` as the cluster-default; Ingresses
/// without an explicit class are claimed by the owner of a default class.
pub const IS_DEFAULT_CLASS_ANNOTATION: &str = "ingressclass.kubernetes.io/is-default-class";

/// Returns `true` when `ic` is annotated as the cluster-default IngressClass.
pub fn is_default_ingress_class(ic: &IngressClass) -> bool {
    ic.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(IS_DEFAULT_CLASS_ANNOTATION).map(String::as_str))
        == Some("true")
}

/// Returns the IngressClass name claimed by `ingress`.
///
/// Checks `spec.ingressClassName` first; falls back to the legacy
/// `kubernetes.io/ingress.class` annotation. Returns `None` when neither
/// is set (opt-in semantics: unclassified Ingresses are ignored).
pub fn claimed_ingress_class(ingress: &Ingress) -> Option<&str> {
    ingress
        .spec
        .as_ref()
        .and_then(|s| s.ingress_class_name.as_deref())
        .or_else(|| {
            ingress
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("kubernetes.io/ingress.class").map(String::as_str))
        })
}
