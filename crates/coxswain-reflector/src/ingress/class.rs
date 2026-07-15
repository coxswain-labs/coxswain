//! IngressClass ownership checks, the `is-default-class` annotation helper, and
//! resolution of per-class annotation defaults from `IngressClass.spec.parameters`.

use crate::MergedStore;
use coxswain_core::crd::CoxswainIngressClassParameters;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::runtime::reflector;
use std::collections::{BTreeMap, HashMap, HashSet};

/// API group an `IngressClass.spec.parameters` must name to be treated as a
/// Coxswain per-class parameters reference.
pub(crate) const CLASS_PARAMETERS_API_GROUP: &str = "ingress.coxswain-labs.dev";
/// Kind an `IngressClass.spec.parameters` must name to be treated as a Coxswain
/// per-class parameters reference.
pub(crate) const CLASS_PARAMETERS_KIND: &str = "CoxswainIngressClassParameters";

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

/// Resolved class-level parameters for a single `IngressClass`, derived from
/// the linked `CoxswainIngressClassParameters` CR.
///
/// Groups all per-class knobs so the class store is walked once and every
/// caller gets a consistent view without duplicate WARN logging.
#[non_exhaustive]
pub(crate) struct ResolvedClassParams {
    /// Default `ingress.coxswain-labs.dev/*` annotation values applied to
    /// every Ingress claiming this class. Empty when the CR carries no (or an
    /// empty) `spec.defaultAnnotations`.
    pub default_annotations: BTreeMap<String, String>,
    /// Per-class access-log enabled state, from `spec.accessLog`.
    ///
    /// `Some(false)` → suppress access-log lines for this class's routes.
    /// `Some(true)` or `None` → proxy-wide `--access-log` flag governs.
    pub access_log_enabled: Option<bool>,
}

/// Resolve per-class parameters for every owned `IngressClass` that references
/// a `CoxswainIngressClassParameters` CR via `spec.parameters`.
///
/// The returned map is keyed by IngressClass name. A class is absent from the
/// map (degrade gracefully — its Ingresses still route with built-in defaults)
/// when it has no `spec.parameters`, the ref names a non-Coxswain
/// apiGroup/kind, the ref omits its namespace (the CR is namespaced), or the
/// target CR is missing from the store. A class with an empty
/// `defaultAnnotations` **and** no `accessLog` override is also omitted (the
/// reconciler fast-paths classes with no resolved params). Every
/// broken-reference case logs a `WARN` — mirroring how an invalid per-Ingress
/// annotation value WARNs and falls back rather than dropping the Ingress.
///
/// Reads only from the supplied stores; never queries the API server.
pub(crate) fn resolve_class_params(
    class_store: &MergedStore<IngressClass>,
    owned: &HashSet<String>,
    params_store: &MergedStore<CoxswainIngressClassParameters>,
) -> HashMap<String, ResolvedClassParams> {
    let mut out = HashMap::new();
    for ic in class_store.state() {
        let Some(name) = ic.metadata.name.as_deref() else {
            continue;
        };
        if !owned.contains(name) {
            continue;
        }
        let Some(params) = ic.spec.as_ref().and_then(|s| s.parameters.as_ref()) else {
            continue; // No parametersRef — nothing to resolve for this class.
        };
        // A class may legitimately point `parameters` at another
        // implementation's object; only act on Coxswain's parameters CRD.
        if params.api_group.as_deref() != Some(CLASS_PARAMETERS_API_GROUP)
            || params.kind != CLASS_PARAMETERS_KIND
        {
            tracing::warn!(
                class = name,
                api_group = ?params.api_group,
                kind = %params.kind,
                "IngressClass.spec.parameters does not reference a CoxswainIngressClassParameters — ignoring class defaults"
            );
            continue;
        }
        let Some(ns) = params.namespace.as_deref() else {
            tracing::warn!(
                class = name,
                ref_name = %params.name,
                "IngressClass.spec.parameters omits namespace (CoxswainIngressClassParameters is namespaced) — ignoring class defaults"
            );
            continue;
        };
        let key =
            reflector::ObjectRef::<CoxswainIngressClassParameters>::new(&params.name).within(ns);
        let Some(cr) = params_store.get(&key) else {
            tracing::warn!(
                class = name,
                params = %format!("{ns}/{}", params.name),
                "IngressClass.spec.parameters target CoxswainIngressClassParameters not found — ignoring class defaults"
            );
            continue;
        };
        let default_annotations = cr
            .spec
            .default_annotations
            .as_ref()
            .filter(|m| !m.is_empty())
            .cloned()
            .unwrap_or_default();
        let access_log_enabled = cr.spec.access_log;
        // Only insert when the CR contributes something (either non-empty
        // default annotations or an access-log override). Classes with no
        // configured params are kept out so reconcile can fast-path them.
        if !default_annotations.is_empty() || access_log_enabled.is_some() {
            out.insert(
                name.to_string(),
                ResolvedClassParams {
                    default_annotations,
                    access_log_enabled,
                },
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::tests::*;
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

    // ── resolve_class_params ─────────────────────────────────────────

    use coxswain_core::crd::CoxswainIngressClassParametersSpec;
    use k8s_openapi::api::networking::v1::IngressClassParametersReference;
    use kube::runtime::watcher;

    fn params_ref(
        api_group: Option<&str>,
        kind: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> IngressClassParametersReference {
        IngressClassParametersReference {
            api_group: api_group.map(str::to_string),
            kind: kind.to_string(),
            name: name.to_string(),
            namespace: namespace.map(str::to_string),
            scope: namespace.map(|_| "Namespace".to_string()),
        }
    }

    /// A Coxswain-owned IngressClass with the given `spec.parameters`.
    fn ic_with_params(name: &str, params: Option<IngressClassParametersReference>) -> IngressClass {
        IngressClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: Some(IngressClassSpec {
                controller: Some("coxswain".to_string()),
                parameters: params,
            }),
        }
    }

    fn class_store(classes: Vec<IngressClass>) -> MergedStore<IngressClass> {
        let mut writer = reflector::store::Writer::<IngressClass>::default();
        for ic in classes {
            writer.apply_watcher_event(&watcher::Event::Apply(ic));
        }
        MergedStore::single(writer.as_reader())
    }

    fn make_params_cr(
        ns: &str,
        name: &str,
        anns: &[(&str, &str)],
    ) -> CoxswainIngressClassParameters {
        let mut map = BTreeMap::new();
        for (k, v) in anns {
            map.insert((*k).to_string(), (*v).to_string());
        }
        let mut spec = CoxswainIngressClassParametersSpec::default();
        spec.default_annotations = Some(map);
        let mut cr = CoxswainIngressClassParameters::new(name, spec);
        cr.metadata.namespace = Some(ns.to_string());
        cr
    }

    fn params_store(
        crs: Vec<CoxswainIngressClassParameters>,
    ) -> MergedStore<CoxswainIngressClassParameters> {
        let mut writer = reflector::store::Writer::<CoxswainIngressClassParameters>::default();
        for cr in crs {
            writer.apply_watcher_event(&watcher::Event::Apply(cr));
        }
        MergedStore::single(writer.as_reader())
    }

    const GROUP: &str = "ingress.coxswain-labs.dev";
    const KIND: &str = "CoxswainIngressClassParameters";
    const CONNECT: &str = "ingress.coxswain-labs.dev/connect-timeout";

    #[test]
    fn resolves_defaults_for_valid_ref() {
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some(GROUP), KIND, "p", Some("ns"))),
        )]);
        let params = params_store(vec![make_params_cr("ns", "p", &[(CONNECT, "5s")])]);
        let got = resolve_class_params(&classes, &owned(&["coxswain"]), &params);
        assert_eq!(
            got.get("coxswain")
                .and_then(|p| p.default_annotations.get(CONNECT))
                .map(String::as_str),
            Some("5s")
        );
    }

    #[test]
    fn skips_unowned_class() {
        let classes = class_store(vec![ic_with_params(
            "other",
            Some(params_ref(Some(GROUP), KIND, "p", Some("ns"))),
        )]);
        let params = params_store(vec![make_params_cr("ns", "p", &[(CONNECT, "5s")])]);
        assert!(resolve_class_params(&classes, &owned(&["coxswain"]), &params).is_empty());
    }

    #[test]
    fn absent_when_no_parameters() {
        let classes = class_store(vec![ic_with_params("coxswain", None)]);
        assert!(
            resolve_class_params(&classes, &owned(&["coxswain"]), &params_store(vec![])).is_empty()
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn absent_and_warns_when_wrong_api_group() {
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some("other.example.com"), KIND, "p", Some("ns"))),
        )]);
        let params = params_store(vec![make_params_cr("ns", "p", &[(CONNECT, "5s")])]);
        assert!(resolve_class_params(&classes, &owned(&["coxswain"]), &params).is_empty());
        assert!(logs_contain(
            "does not reference a CoxswainIngressClassParameters"
        ));
    }

    #[test]
    #[tracing_test::traced_test]
    fn absent_and_warns_when_namespace_missing() {
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some(GROUP), KIND, "p", None)),
        )]);
        let params = params_store(vec![make_params_cr("ns", "p", &[(CONNECT, "5s")])]);
        assert!(resolve_class_params(&classes, &owned(&["coxswain"]), &params).is_empty());
        assert!(logs_contain("omits namespace"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn absent_and_warns_when_target_cr_missing() {
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some(GROUP), KIND, "missing", Some("ns"))),
        )]);
        assert!(
            resolve_class_params(&classes, &owned(&["coxswain"]), &params_store(vec![])).is_empty()
        );
        assert!(logs_contain("not found"));
    }

    #[test]
    fn absent_when_default_annotations_empty() {
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some(GROUP), KIND, "p", Some("ns"))),
        )]);
        let params = params_store(vec![make_params_cr("ns", "p", &[])]);
        assert!(resolve_class_params(&classes, &owned(&["coxswain"]), &params).is_empty());
    }

    #[test]
    fn resolves_distinct_defaults_per_class() {
        let classes = class_store(vec![
            ic_with_params(
                "public",
                Some(params_ref(Some(GROUP), KIND, "public-p", Some("ns"))),
            ),
            ic_with_params(
                "internal",
                Some(params_ref(Some(GROUP), KIND, "internal-p", Some("ns"))),
            ),
        ]);
        let params = params_store(vec![
            make_params_cr("ns", "public-p", &[(CONNECT, "10s")]),
            make_params_cr("ns", "internal-p", &[(CONNECT, "1s")]),
        ]);
        let got = resolve_class_params(&classes, &owned(&["public", "internal"]), &params);
        assert_eq!(
            got.get("public")
                .and_then(|p| p.default_annotations.get(CONNECT))
                .map(String::as_str),
            Some("10s")
        );
        assert_eq!(
            got.get("internal")
                .and_then(|p| p.default_annotations.get(CONNECT))
                .map(String::as_str),
            Some("1s")
        );
    }

    // ── accessLog field (#279) ────────────────────────────────────────────────

    fn make_params_cr_with_access_log(
        ns: &str,
        name: &str,
        access_log: Option<bool>,
    ) -> CoxswainIngressClassParameters {
        let mut spec = CoxswainIngressClassParametersSpec::default();
        spec.access_log = access_log;
        let mut cr = CoxswainIngressClassParameters::new(name, spec);
        cr.metadata.namespace = Some(ns.to_string());
        cr
    }

    #[test]
    fn resolves_access_log_false() {
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some(GROUP), KIND, "p", Some("ns"))),
        )]);
        let params = params_store(vec![make_params_cr_with_access_log("ns", "p", Some(false))]);
        let got = resolve_class_params(&classes, &owned(&["coxswain"]), &params);
        assert_eq!(
            got.get("coxswain").and_then(|p| p.access_log_enabled),
            Some(false),
            "accessLog: false must be resolved and present"
        );
    }

    #[test]
    fn resolves_access_log_true() {
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some(GROUP), KIND, "p", Some("ns"))),
        )]);
        let params = params_store(vec![make_params_cr_with_access_log("ns", "p", Some(true))]);
        let got = resolve_class_params(&classes, &owned(&["coxswain"]), &params);
        assert_eq!(
            got.get("coxswain").and_then(|p| p.access_log_enabled),
            Some(true),
        );
    }

    #[test]
    fn class_with_only_access_log_is_present_in_map() {
        // A class that sets accessLog but no defaultAnnotations must still appear
        // in the resolved map so the reconciler can propagate the override.
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some(GROUP), KIND, "p", Some("ns"))),
        )]);
        let params = params_store(vec![make_params_cr_with_access_log("ns", "p", Some(false))]);
        let got = resolve_class_params(&classes, &owned(&["coxswain"]), &params);
        assert!(
            got.contains_key("coxswain"),
            "class with only accessLog override must appear in the resolved params map"
        );
        assert!(
            got.get("coxswain")
                .is_some_and(|p| p.default_annotations.is_empty()),
            "default_annotations must be empty when the CR has none"
        );
    }

    #[test]
    fn absent_when_cr_has_neither_annotations_nor_access_log() {
        // A CR with an empty spec contributes nothing; the class is omitted so
        // the reconciler can fast-path it with zero-allocation semantics.
        let classes = class_store(vec![ic_with_params(
            "coxswain",
            Some(params_ref(Some(GROUP), KIND, "p", Some("ns"))),
        )]);
        let params = params_store(vec![{
            let mut cr = CoxswainIngressClassParameters::new(
                "p",
                CoxswainIngressClassParametersSpec::default(),
            );
            cr.metadata.namespace = Some("ns".to_string());
            cr
        }]);
        let got = resolve_class_params(&classes, &owned(&["coxswain"]), &params);
        assert!(
            got.is_empty(),
            "class whose CR has neither defaultAnnotations nor accessLog must be absent"
        );
    }
}
