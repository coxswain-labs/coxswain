//! Tests for [`crate::reference_grants::flatten_grants`]. The function feeds
//! both the shared-proxy reconciler and the dedicated-mode controller RBAC
//! reconciler, so a shared fixture asserts the two consumers see identical
//! key sets — drift would manifest as Gateway API ReferenceGrant conformance
//! violations.

use crate::gw_types::v::referencegrants::{
    ReferenceGrant, ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo,
};
use crate::reference_grants::flatten_grants;
use coxswain_core::reference_grants::ReferenceGrantKey;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::sync::Arc;

fn grant(
    ns: &str,
    from: Vec<(&str, &str, Option<&str>)>,
    to: Vec<(&str, &str, Option<&str>)>,
) -> Arc<ReferenceGrant> {
    Arc::new(ReferenceGrant {
        metadata: ObjectMeta {
            namespace: Some(ns.to_string()),
            name: Some("grant".to_string()),
            ..ObjectMeta::default()
        },
        spec: ReferenceGrantSpec {
            from: from
                .into_iter()
                .map(|(g, k, ns)| ReferenceGrantFrom {
                    group: g.to_string(),
                    kind: k.to_string(),
                    namespace: ns.unwrap_or_default().to_string(),
                })
                .collect(),
            to: to
                .into_iter()
                .map(|(g, k, name)| ReferenceGrantTo {
                    group: g.to_string(),
                    kind: k.to_string(),
                    name: name.map(str::to_string),
                })
                .collect(),
        },
    })
}

#[test]
fn backend_and_cert_grants_partition_by_kind() {
    let grants = vec![
        // HTTPRoute(ns=routes) → Service(svc-a) in ns=backends
        grant(
            "backends",
            vec![("gateway.networking.k8s.io", "HTTPRoute", Some("routes"))],
            vec![("", "Service", Some("svc-a"))],
        ),
        // Gateway(ns=gw) → Secret(*) in ns=certs (wildcard)
        grant(
            "certs",
            vec![("gateway.networking.k8s.io", "Gateway", Some("gw"))],
            vec![("", "Secret", None)],
        ),
    ];

    let (backend, cert) = flatten_grants(&grants);

    assert!(backend.contains(&ReferenceGrantKey::specific("routes", "backends", "svc-a")));
    assert_eq!(backend.len(), 1);
    assert!(cert.contains(&ReferenceGrantKey::wildcard("gw", "certs")));
    assert_eq!(cert.len(), 1);
}

#[test]
fn from_group_other_than_gateway_api_is_ignored() {
    let grants = vec![grant(
        "backends",
        vec![("example.com", "HTTPRoute", Some("routes"))],
        vec![("", "Service", Some("svc-a"))],
    )];

    let (backend, cert) = flatten_grants(&grants);

    assert!(backend.is_empty());
    assert!(cert.is_empty());
}

#[test]
fn to_group_core_alias_matches_empty_group() {
    let grants = vec![grant(
        "backends",
        vec![("gateway.networking.k8s.io", "HTTPRoute", Some("routes"))],
        vec![("core", "Service", Some("svc-a"))],
    )];

    let (backend, _cert) = flatten_grants(&grants);

    assert!(backend.contains(&ReferenceGrantKey::specific("routes", "backends", "svc-a")));
}

#[test]
fn grant_without_namespace_is_dropped() {
    let mut g = grant(
        "placeholder",
        vec![("gateway.networking.k8s.io", "HTTPRoute", Some("routes"))],
        vec![("", "Service", Some("svc-a"))],
    );
    Arc::get_mut(&mut g).unwrap().metadata.namespace = None;

    let (backend, cert) = flatten_grants(&[g]);

    assert!(backend.is_empty());
    assert!(cert.is_empty());
}

#[test]
fn cross_product_yields_all_from_to_pairs() {
    let grants = vec![grant(
        "backends",
        vec![
            ("gateway.networking.k8s.io", "HTTPRoute", Some("ns-a")),
            ("gateway.networking.k8s.io", "HTTPRoute", Some("ns-b")),
        ],
        vec![
            ("", "Service", Some("svc-x")),
            ("", "Service", Some("svc-y")),
        ],
    )];

    let (backend, _cert) = flatten_grants(&grants);

    assert_eq!(backend.len(), 4);
    assert!(backend.contains(&ReferenceGrantKey::specific("ns-a", "backends", "svc-x")));
    assert!(backend.contains(&ReferenceGrantKey::specific("ns-a", "backends", "svc-y")));
    assert!(backend.contains(&ReferenceGrantKey::specific("ns-b", "backends", "svc-x")));
    assert!(backend.contains(&ReferenceGrantKey::specific("ns-b", "backends", "svc-y")));
}
