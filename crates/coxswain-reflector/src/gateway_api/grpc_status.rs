//! [`RouteLike`] impl for `GRPCRoute` — the GRPCRoute-specific projections and
//! filter predicate. The kind-generic `Accepted`/`ResolvedRefs` algorithm lives
//! in [`super::route_status`]; this realizes the abstraction issue #33 deferred
//! until the second concrete route kind existed.

use super::route_status::{BackendRefView, ParentRefView, RouteLike};
use crate::gw_types::v::grpcroutes::{GrpcRoute, GrpcRouteRulesFiltersType};

impl RouteLike for GrpcRoute {
    fn route_namespace(&self) -> Option<&str> {
        self.metadata.namespace.as_deref()
    }

    fn route_name(&self) -> Option<&str> {
        self.metadata.name.as_deref()
    }

    fn route_hostnames(&self) -> Vec<&str> {
        self.spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect()
    }

    fn route_parent_refs(&self) -> Vec<ParentRefView<'_>> {
        self.spec
            .parent_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|pr| ParentRefView {
                namespace: pr.namespace.as_deref(),
                name: pr.name.as_str(),
                section_name: pr.section_name.as_deref(),
                port: pr.port.map(|p| p as u16),
                group: pr.group.as_deref(),
                kind: pr.kind.as_deref(),
            })
            .collect()
    }

    fn has_unsupported_filter(&self) -> bool {
        self.spec.rules.as_deref().unwrap_or(&[]).iter().any(|r| {
            r.filters.as_deref().unwrap_or(&[]).iter().any(|f| {
                if matches!(f.r#type, GrpcRouteRulesFiltersType::RequestMirror) {
                    return true;
                }
                // RateLimit (#25), IpAccessControl (#479), RetryPolicy (#445), and
                // JwtAuth (#441) ExtensionRefs are supported on GRPCRoute; any other
                // ExtensionRef is not — notably BasicAuth (#442), Compression (#446),
                // and RequestSizeLimit (#443), all HTTP-only idioms (#690).
                if matches!(f.r#type, GrpcRouteRulesFiltersType::ExtensionRef)
                    && let Some(ext) = &f.extension_ref
                {
                    return !super::grpc_extension_kind_supported(&ext.group, &ext.kind);
                }
                false
            })
        })
    }

    fn health_backend_refs(&self) -> Vec<BackendRefView<'_>> {
        // GRPCRoute has no RequestRedirect filter, so (unlike HTTPRoute) no rule
        // is skipped — every rule's backend refs are validated.
        let mut out = Vec::new();
        for rule in self.spec.rules.as_deref().unwrap_or(&[]) {
            for b in rule.backend_refs.as_deref().unwrap_or(&[]) {
                out.push(BackendRefView {
                    kind: b.kind.as_deref().unwrap_or("Service"),
                    group: b.group.as_deref().unwrap_or(""),
                    namespace: b.namespace.as_deref(),
                    name: &b.name,
                    has_port: b.port.is_some(),
                });
            }
        }
        out
    }

    fn rule_ext_refs(&self) -> Vec<(&str, &str, &str)> {
        self.spec
            .rules
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .flat_map(|rule| super::filters::ext_refs(rule.filters.as_deref().unwrap_or(&[])))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::gateway_api::route_status::compute_route_health;
    use crate::gw_types::GrpcRoute;
    use crate::gw_types::v::gateways::{Gateway, GatewayListeners, GatewaySpec};
    use crate::gw_types::v::grpcroutes::{
        GrpcRouteParentRefs, GrpcRouteRules, GrpcRouteRulesBackendRefs, GrpcRouteSpec,
    };
    use crate::keys::RouteParentKey;
    use coxswain_core::ownership::ObjectKey;
    use coxswain_core::reference_grants::ReferenceGrantKey;
    use k8s_openapi::api::core::v1::Service;
    use kube::api::ObjectMeta;
    use kube::runtime::{reflector, watcher};
    use std::collections::HashSet;
    use std::sync::Arc;

    /// Smoke test for the GRPCRoute [`RouteLike`] impl exercising the shared
    /// engine end-to-end (the bulk of the algorithm is covered by the HTTPRoute
    /// tests in `status.rs`; this confirms the GRPC projections wire up).
    #[test]
    fn grpc_route_with_owned_gateway_is_accepted_and_resolved() {
        let gw = Arc::new(Gateway {
            metadata: ObjectMeta {
                name: Some("gw".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners: vec![GatewayListeners {
                    name: "grpc".to_string(),
                    protocol: "HTTP".to_string(),
                    port: 80,
                    hostname: None,
                    ..Default::default()
                }],
                ..Default::default()
            },
            status: None,
        });

        let route = Arc::new(GrpcRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GrpcRouteSpec {
                parent_refs: Some(vec![GrpcRouteParentRefs {
                    name: "gw".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                }]),
                rules: Some(vec![GrpcRouteRules {
                    backend_refs: Some(vec![GrpcRouteRulesBackendRefs {
                        name: "svc".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        });

        let mut w = reflector::store::Writer::<Service>::default();
        w.apply_watcher_event(&watcher::Event::Apply(Service {
            metadata: ObjectMeta {
                name: Some("svc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }));
        let services = crate::MergedStore::single(w.as_reader());
        let rate_limits = crate::tests::fixtures::empty_rate_limit_store();
        let retry_policies = crate::tests::fixtures::empty_retry_policy_store();
        let ip_access = crate::tests::fixtures::empty_ip_access_store();
        let jwt_auths = crate::tests::fixtures::empty_jwt_auth_store();
        let stores = crate::gateway_api::RefValidationStores {
            services: &services,
            ext_refs: crate::fingerprint::ExtRefStores {
                rate_limits: &rate_limits,
                retry_policies: &retry_policies,
                ip_access: &ip_access,
                jwt_auths: &jwt_auths,
                path_rewrites: None,
                basic_auths: None,
                external_auths: None,
                request_size_limits: None,
                compressions: None,
            },
        };

        let owned: HashSet<ObjectKey> = std::iter::once(ObjectKey::new("default", "gw")).collect();
        let map = compute_route_health(
            &[route],
            &[gw],
            &owned,
            &std::collections::HashMap::new(),
            &HashSet::<ReferenceGrantKey>::new(),
            &stores,
            "GRPCRoute",
        );

        let h = map
            .get(&RouteParentKey::new(
                "default",
                "route",
                "default",
                "gw",
                String::new(),
            ))
            .expect("health entry for the (route, parent) pair");
        assert!(h.accepted, "expected Accepted=true");
        assert_eq!(h.accepted_reason, "Accepted");
        assert!(h.resolved_refs);
        assert_eq!(h.resolved_refs_reason, "ResolvedRefs");
    }

    /// [`status`][crate::gateway_api::status]'s
    /// `enforcement_and_status_extension_kind_sets_agree`, for GRPCRoute — both
    /// `grpc_reconcile`'s enforcement guard and `has_unsupported_filter` call
    /// [`crate::gateway_api::grpc_extension_kind_supported`], so this test
    /// exercises the same decision function `grpc_reconcile` calls. Before #690
    /// this direction was wrong in *both* senses: `RequestSizeLimit` was falsely
    /// reported `Accepted=True` (`grpc_reconcile` never resolves it —
    /// `request_size_limits: None`) while `JwtAuth` (genuinely enforced) was
    /// falsely reported `Accepted=False/UnsupportedValue`. `ALL_KNOWN_KINDS`
    /// covers every coxswain `ExtensionRef` kind, not just the ones GRPCRoute
    /// supports, so the HTTP-only kinds assert the negative case too.
    #[test]
    fn enforcement_and_status_extension_kind_sets_agree() {
        use crate::gateway_api::route_status::RouteLike;
        use crate::gw_types::v::grpcroutes::{
            GrpcRouteRulesFilters, GrpcRouteRulesFiltersExtensionRef, GrpcRouteRulesFiltersType,
        };

        const ALL_KNOWN_KINDS: &[&str] = &[
            "RateLimit",
            "IpAccessControl",
            "BasicAuth",
            "RequestSizeLimit",
            "Compression",
            "ExternalAuth",
            "RetryPolicy",
            "JwtAuth",
            "PathRewriteRegex",
        ];

        for &kind in ALL_KNOWN_KINDS {
            let route = GrpcRoute {
                metadata: ObjectMeta {
                    name: Some("route".to_string()),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
                spec: GrpcRouteSpec {
                    parent_refs: Some(vec![GrpcRouteParentRefs {
                        name: "gw".to_string(),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    }]),
                    rules: Some(vec![GrpcRouteRules {
                        backend_refs: Some(vec![GrpcRouteRulesBackendRefs {
                            name: "svc".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        filters: Some(vec![GrpcRouteRulesFilters {
                            r#type: GrpcRouteRulesFiltersType::ExtensionRef,
                            extension_ref: Some(GrpcRouteRulesFiltersExtensionRef {
                                group: "gateway.coxswain-labs.dev".to_string(),
                                kind: kind.to_string(),
                                name: "does-not-exist".to_string(),
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                ..Default::default()
            };

            let enforcement_supports = crate::gateway_api::grpc_extension_kind_supported(
                "gateway.coxswain-labs.dev",
                kind,
            );
            let status_supports = !route.has_unsupported_filter();
            assert_eq!(
                enforcement_supports, status_supports,
                "kind {kind}: enforcement supports={enforcement_supports}, \
                 status supports={status_supports} — must agree"
            );
        }
    }
}
