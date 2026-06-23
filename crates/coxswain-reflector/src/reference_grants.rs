//! `ReferenceGrant` flattening consumed by the proxy reconciler.
//!
//! Centralising the flatten logic here ensures the shared-pool builder and
//! the dedicated-mode snapshot builder derive identical permitted-reference
//! sets from the same input, so the two code paths cannot drift.

use crate::gw_types::v::referencegrants::ReferenceGrant;
use coxswain_core::reference_grants::ReferenceGrantKey;
use std::collections::HashSet;
use std::sync::Arc;

/// A flattened set of permitted cross-namespace references, keyed for O(1)
/// lookup via [`ReferenceGrantKey`].
pub type GrantSet = HashSet<ReferenceGrantKey>;

/// Flatten `ReferenceGrant` objects into the two O(1) sets every consumer
/// needs for cross-namespace reference checks:
///
/// - `backend_grants`: `HTTPRoute → Service` (used by the routing-table
///   builder when resolving HTTPRoute `backendRefs` across namespaces).
/// - `cert_grants`: `Gateway → Secret` (used by the TLS store builder when
///   resolving listener `certificateRefs` across namespaces).
///
/// The filter rules mirror the Gateway API spec: `from.group` must be
/// `gateway.networking.k8s.io` and `to.group` must be empty (core API group)
/// or the literal `"core"`. A `to.name` of `None` flattens to a wildcard
/// [`ReferenceGrantKey::wildcard`]; a `Some(name)` flattens to a
/// [`ReferenceGrantKey::specific`].
#[must_use]
pub fn flatten_grants(grants: &[Arc<ReferenceGrant>]) -> (GrantSet, GrantSet) {
    let backend_grants = flatten(grants, "HTTPRoute", "Service");
    let cert_grants = flatten(grants, "Gateway", "Secret");
    (backend_grants, cert_grants)
}

fn flatten(grants: &[Arc<ReferenceGrant>], from_kind: &str, to_kind: &str) -> GrantSet {
    grants
        .iter()
        .filter_map(|grant| {
            let to_ns = grant.metadata.namespace.clone()?;
            Some((grant, to_ns))
        })
        .flat_map(|(grant, to_ns)| {
            let from_entries: Vec<_> = grant
                .spec
                .from
                .iter()
                .filter(|f| f.group == "gateway.networking.k8s.io" && f.kind == from_kind)
                .map(|f| f.namespace.clone())
                .collect();
            let to_entries: Vec<_> = grant
                .spec
                .to
                .iter()
                .filter(|t| (t.group.is_empty() || t.group == "core") && t.kind == to_kind)
                .map(|t| t.name.clone())
                .collect();
            from_entries.into_iter().flat_map(move |from_ns| {
                let to_ns = to_ns.clone();
                to_entries
                    .clone()
                    .into_iter()
                    .map(move |to_name| match to_name {
                        Some(name) => {
                            ReferenceGrantKey::specific(from_ns.clone(), to_ns.clone(), name)
                        }
                        None => ReferenceGrantKey::wildcard(from_ns.clone(), to_ns.clone()),
                    })
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
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
}
