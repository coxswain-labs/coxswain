//! [`RouteLike`] impl for `HTTPRoute` — the HTTPRoute-specific projections and
//! filter predicates. The kind-generic `Accepted`/`ResolvedRefs` algorithm lives
//! in [`super::route_status`].

use super::route_status::{BackendRefView, ParentRefView, RouteLike};
use crate::gw_types::v::httproutes::{HttpRoute, HttpRouteRulesFiltersType};

impl RouteLike for HttpRoute {
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
                if matches!(f.r#type, HttpRouteRulesFiltersType::ExtensionRef)
                    && let Some(ext) = &f.extension_ref
                {
                    return !super::http_extension_kind_supported(&ext.group, &ext.kind);
                }
                false
            })
        })
    }

    fn health_backend_refs(&self) -> Vec<BackendRefView<'_>> {
        let mut out = Vec::new();
        for rule in self.spec.rules.as_deref().unwrap_or(&[]) {
            // HTTPRoute rules carrying a RequestRedirect filter have no upstream
            // backend to resolve — skip them so ResolvedRefs stays true.
            let has_redirect = rule
                .filters
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|f| matches!(f.r#type, HttpRouteRulesFiltersType::RequestRedirect));
            if has_redirect {
                continue;
            }
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
    use crate::MergedStore;
    use crate::gateway_api::route_status::compute_route_health;
    use crate::gateway_api::tests::*;
    use crate::gw_types::v::gateways::{Gateway, GatewayListeners, GatewaySpec};
    use crate::gw_types::v::httproutes::{
        HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteSpec,
    };
    use crate::keys::RouteParentKey;
    use crate::status::RouteStatusMap;
    use coxswain_core::ownership::ObjectKey;
    use coxswain_core::reference_grants::ReferenceGrantKey;
    use k8s_openapi::api::core::v1::Service;
    use kube::api::ObjectMeta;
    use kube::runtime::{reflector, watcher};
    use std::collections::HashSet;
    use std::sync::Arc;

    fn make_gateway(ns: &str, name: &str, listener_hostname: &str, port: u16) -> Arc<Gateway> {
        Arc::new(Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners: vec![GatewayListeners {
                    name: "http".to_string(),
                    protocol: "HTTP".to_string(),
                    port: port as i32,
                    hostname: if listener_hostname.is_empty() {
                        None
                    } else {
                        Some(listener_hostname.to_string())
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            status: None,
        })
    }

    fn make_route(
        route_ns: &str,
        route_name: &str,
        hostnames: &[&str],
        gw_ns: &str,
        gw_name: &str,
    ) -> Arc<HttpRoute> {
        Arc::new(HttpRoute {
            metadata: ObjectMeta {
                name: Some(route_name.to_string()),
                namespace: Some(route_ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: gw_name.to_string(),
                    namespace: Some(gw_ns.to_string()),
                    ..Default::default()
                }]),
                hostnames: if hostnames.is_empty() {
                    None
                } else {
                    Some(hostnames.iter().map(|s| s.to_string()).collect())
                },
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
            },
            ..Default::default()
        })
    }

    fn service_store_with(ns: &str, name: &str) -> MergedStore<Service> {
        let mut w = reflector::store::Writer::<Service>::default();
        w.apply_watcher_event(&watcher::Event::Apply(Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }));
        MergedStore::single(w.as_reader())
    }

    fn run(
        routes: &[Arc<HttpRoute>],
        gateways: &[Arc<Gateway>],
        owned: &[(&str, &str)],
        grants: &HashSet<ReferenceGrantKey>,
        services: &MergedStore<Service>,
    ) -> RouteStatusMap {
        let owned_set: HashSet<ObjectKey> = owned
            .iter()
            .map(|(ns, name)| ObjectKey::new(*ns, *name))
            .collect();
        let rate_limits = empty_rate_limit_store();
        let retry_policies = empty_retry_policy_store();
        let path_rewrites = empty_path_rewrite_store();
        let ip_access = empty_ip_access_store();
        let basic_auths = empty_basic_auth_store();
        let external_auths = empty_external_auth_store();
        let jwt_auths = empty_jwt_auth_store();
        let request_size_limits = empty_request_size_limit_store();
        let compressions = empty_compression_store();
        let stores = crate::gateway_api::RefValidationStores {
            services,
            ext_refs: crate::fingerprint::ExtRefStores {
                rate_limits: &rate_limits,
                retry_policies: &retry_policies,
                ip_access: &ip_access,
                jwt_auths: &jwt_auths,
                path_rewrites: Some(&path_rewrites),
                basic_auths: Some(&basic_auths),
                external_auths: Some(&external_auths),
                request_size_limits: Some(&request_size_limits),
                compressions: Some(&compressions),
            },
        };
        compute_route_health(
            routes,
            gateways,
            &owned_set,
            &std::collections::HashMap::new(),
            grants,
            &stores,
            "HTTPRoute",
        )
    }

    fn key(route_ns: &str, route_name: &str, gw_ns: &str, gw_name: &str) -> RouteParentKey {
        RouteParentKey::new(route_ns, route_name, gw_ns, gw_name, String::new())
    }

    // ── compute_route_health ──────────────────────────────────────────────────────

    #[test]
    fn route_with_owned_gateway_is_accepted() {
        let gw = make_gateway("default", "gw", "", 80);
        let route = make_route("default", "route", &["example.com"], "default", "gw");
        let services = service_store_with("default", "svc");

        let map = run(
            &[route],
            &[gw],
            &[("default", "gw")],
            &HashSet::new(),
            &services,
        );

        let h = map.get(&key("default", "route", "default", "gw")).unwrap();
        assert!(h.accepted, "expected Accepted=true");
        assert_eq!(h.accepted_reason, "Accepted");
        assert!(h.resolved_refs);
        assert_eq!(h.resolved_refs_reason, "ResolvedRefs");
    }

    #[test]
    fn route_with_unowned_gateway_produces_no_entry() {
        let gw = make_gateway("default", "gw", "", 80);
        let route = make_route("default", "route", &[], "default", "gw");

        // owned set is empty — gw is not owned
        let map = run(&[route], &[gw], &[], &HashSet::new(), &empty_svc_store());

        assert!(!map.contains_key(&key("default", "route", "default", "gw")));
    }

    #[test]
    fn route_hostname_not_intersecting_listener_is_rejected() {
        let gw = make_gateway("default", "gw", "other.com", 80);
        let route = make_route("default", "route", &["example.com"], "default", "gw");
        let services = service_store_with("default", "svc");

        let map = run(
            &[route],
            &[gw],
            &[("default", "gw")],
            &HashSet::new(),
            &services,
        );

        let h = map.get(&key("default", "route", "default", "gw")).unwrap();
        assert!(!h.accepted);
        assert_eq!(h.accepted_reason, "NoMatchingListenerHostname");
    }

    #[test]
    fn route_hostname_matching_listener_wildcard_is_accepted() {
        let gw = make_gateway("default", "gw", "*.example.com", 80);
        let route = make_route("default", "route", &["api.example.com"], "default", "gw");
        let services = service_store_with("default", "svc");

        let map = run(
            &[route],
            &[gw],
            &[("default", "gw")],
            &HashSet::new(),
            &services,
        );

        let h = map.get(&key("default", "route", "default", "gw")).unwrap();
        assert!(h.accepted);
    }

    #[test]
    fn backend_service_not_found_sets_resolved_refs_false() {
        let gw = make_gateway("default", "gw", "", 80);
        let route = make_route("default", "route", &[], "default", "gw");

        // "svc" not present in the store
        let map = run(
            &[route],
            &[gw],
            &[("default", "gw")],
            &HashSet::new(),
            &empty_svc_store(),
        );

        let h = map.get(&key("default", "route", "default", "gw")).unwrap();
        assert!(h.accepted);
        assert!(!h.resolved_refs);
        assert_eq!(h.resolved_refs_reason, "BackendNotFound");
    }

    #[test]
    fn dangling_extension_ref_sets_resolved_refs_false_invalid_kind() {
        use crate::gw_types::v::httproutes::{
            HttpRouteRulesFilters, HttpRouteRulesFiltersExtensionRef, HttpRouteRulesFiltersType,
        };

        let gw = make_gateway("default", "gw", "", 80);
        let route = Arc::new(HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: "gw".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                }]),
                hostnames: None,
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    filters: Some(vec![HttpRouteRulesFilters {
                        r#type: HttpRouteRulesFiltersType::ExtensionRef,
                        extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                            group: "gateway.coxswain-labs.dev".to_string(),
                            kind: "RateLimit".to_string(),
                            name: "does-not-exist".to_string(),
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
            },
            ..Default::default()
        });

        // "svc" backend exists, so `check_backend_refs` passes — isolates the
        // failure to the dangling `ExtensionRef` (#689/GEP-1364).
        let map = run(
            &[route],
            &[gw],
            &[("default", "gw")],
            &HashSet::new(),
            &service_store_with("default", "svc"),
        );

        let h = map.get(&key("default", "route", "default", "gw")).unwrap();
        assert!(
            h.accepted,
            "expected Accepted=true — the kind itself is supported"
        );
        assert!(
            !h.resolved_refs,
            "a dangling ExtensionRef must set ResolvedRefs=False"
        );
        assert_eq!(h.resolved_refs_reason, "InvalidKind");
    }

    /// For every coxswain `ExtensionRef` kind, `filters::build_filters`'s
    /// enforcement guard and `has_unsupported_filter`'s `Accepted` guard must
    /// agree on whether HTTPRoute supports it — both now call
    /// [`crate::gateway_api::http_extension_kind_supported`], so this test
    /// exercises the same decision function `build_filters` calls, not just the
    /// constant it's backed by. Before #690 these were two independently
    /// hand-maintained literal lists — `BasicAuth`, `RequestSizeLimit`,
    /// `Compression`, and `ExternalAuth` were enforced but permanently reported
    /// `Accepted=False/UnsupportedValue`. `ALL_KNOWN_KINDS` is written out by
    /// hand (not derived from `HTTP_ROUTE_EXTENSION_KINDS`) so this test is an
    /// independent oracle, not a tautology against the production list.
    #[test]
    fn enforcement_and_status_extension_kind_sets_agree() {
        use crate::gateway_api::route_status::RouteLike;
        use crate::gw_types::v::httproutes::{
            HttpRouteRulesFilters, HttpRouteRulesFiltersExtensionRef, HttpRouteRulesFiltersType,
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
            let route = HttpRoute {
                metadata: ObjectMeta {
                    name: Some("route".to_string()),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
                spec: HttpRouteSpec {
                    parent_refs: Some(vec![HttpRouteParentRefs {
                        name: "gw".to_string(),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    }]),
                    hostnames: None,
                    rules: Some(vec![HttpRouteRules {
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        filters: Some(vec![HttpRouteRulesFilters {
                            r#type: HttpRouteRulesFiltersType::ExtensionRef,
                            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                                group: "gateway.coxswain-labs.dev".to_string(),
                                kind: kind.to_string(),
                                name: "does-not-exist".to_string(),
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }]),
                },
                ..Default::default()
            };

            let enforcement_supports = crate::gateway_api::http_extension_kind_supported(
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

    #[test]
    fn cross_namespace_route_blocked_when_listener_allows_same_only() {
        // Gateway in "gw-ns", route in "app-ns".
        // Listener has no AllowedRoutes override → defaults to Same namespace only.
        let gw = make_gateway("gw-ns", "gw", "", 80);
        let route = make_route("app-ns", "route", &[], "gw-ns", "gw");

        let map = run(
            &[route],
            &[gw],
            &[("gw-ns", "gw")],
            &HashSet::new(),
            &empty_svc_store(),
        );

        let k = RouteParentKey::new("app-ns", "route", "gw-ns", "gw", String::new());
        let h = map.get(&k).unwrap();
        assert!(!h.accepted);
        assert_eq!(h.accepted_reason, "NotAllowedByListeners");
    }
}
