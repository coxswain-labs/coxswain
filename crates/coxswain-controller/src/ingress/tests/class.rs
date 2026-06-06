use super::*;
use k8s_openapi::api::networking::v1::{IngressClass, IngressClassSpec};
use std::collections::BTreeMap;

fn ic_with_annotation(value: &str) -> IngressClass {
    let mut annotations = BTreeMap::new();
    annotations.insert(
        super::super::class::IS_DEFAULT_CLASS_ANNOTATION.to_string(),
        value.to_string(),
    );
    IngressClass {
        metadata: ObjectMeta {
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(IngressClassSpec {
            controller: Some("coxswain".to_string()),
            ..Default::default()
        }),
    }
}

fn ic_without_annotation() -> IngressClass {
    IngressClass {
        metadata: ObjectMeta::default(),
        spec: Some(IngressClassSpec {
            controller: Some("coxswain".to_string()),
            ..Default::default()
        }),
    }
}

// ── is_default_ingress_class ──────────────────────────────────────────────────

#[test]
fn is_default_when_annotation_is_true() {
    assert!(is_default_ingress_class(&ic_with_annotation("true")));
}

#[test]
fn not_default_when_annotation_is_false() {
    assert!(!is_default_ingress_class(&ic_with_annotation("false")));
}

#[test]
fn not_default_when_annotation_absent() {
    assert!(!is_default_ingress_class(&ic_without_annotation()));
}

#[test]
fn not_default_when_annotation_has_unexpected_value() {
    assert!(!is_default_ingress_class(&ic_with_annotation("yes")));
    assert!(!is_default_ingress_class(&ic_with_annotation("True")));
    assert!(!is_default_ingress_class(&ic_with_annotation("1")));
}

// ── claimed_ingress_class ─────────────────────────────────────────────────────

fn ingress_with_classname(class: &str) -> Ingress {
    make_ingress("default", None, "/", "Prefix", "svc", Some(class), None)
}

fn ingress_with_annotation(annotation: &str) -> Ingress {
    make_ingress(
        "default",
        None,
        "/",
        "Prefix",
        "svc",
        None,
        Some(annotation),
    )
}

fn ingress_with_both(class: &str, annotation: &str) -> Ingress {
    make_ingress(
        "default",
        None,
        "/",
        "Prefix",
        "svc",
        Some(class),
        Some(annotation),
    )
}

fn ingress_with_neither() -> Ingress {
    make_ingress("default", None, "/", "Prefix", "svc", None, None)
}

#[test]
fn claimed_returns_spec_class_name() {
    assert_eq!(
        claimed_ingress_class(&ingress_with_classname("coxswain")),
        Some("coxswain")
    );
}

#[test]
fn claimed_falls_back_to_legacy_annotation() {
    assert_eq!(
        claimed_ingress_class(&ingress_with_annotation("nginx")),
        Some("nginx")
    );
}

#[test]
fn claimed_spec_takes_precedence_over_annotation() {
    // spec.ingressClassName wins even when the legacy annotation is also set
    assert_eq!(
        claimed_ingress_class(&ingress_with_both("coxswain", "nginx")),
        Some("coxswain")
    );
}

#[test]
fn claimed_returns_none_when_neither_set() {
    assert_eq!(claimed_ingress_class(&ingress_with_neither()), None);
}
