use crate::endpoints;
use crate::tls::{GatewayListenerHealth, ListenerTlsOutcome, load_tls_cert};
use coxswain_core::ownership::parent_ref_owned;
use coxswain_core::reference_grants;
use coxswain_core::routing::{
    HeaderPredicate, HostRouterBuilder, MatchPredicates, QueryPredicate, RouteEntry,
    RoutingTableBuilder, Upstream, ValueMatch,
};
use coxswain_core::tls::TlsStoreBuilder;
use gateway_api::apis::standard::gateways::{Gateway, GatewayListenersTlsMode};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteRulesBackendRefs, HttpRouteRulesMatchesHeadersType,
    HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPathType,
    HttpRouteRulesMatchesQueryParamsType,
};
use http::{HeaderName, Method};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

pub struct GatewayApiReconciler;

impl GatewayApiReconciler {
    /// Skips routes whose `spec.parentRefs` do not include at least one Gateway
    /// managed by this controller. Never queries the API server.
    pub fn reconcile(
        route: &HTTPRoute,
        slices: &reflector::Store<EndpointSlice>,
        owned_gateways: &HashSet<(String, String)>,
        grants: &HashSet<(String, String, Option<String>)>,
        builder: &mut RoutingTableBuilder,
    ) {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_name = route.metadata.name.as_deref().unwrap_or("unknown");
        let route_id = format!("{route_ns}/{route_name}");
        let created_at: Option<SystemTime> = route
            .metadata
            .creation_timestamp
            .as_ref()
            .and_then(|t| t.0.as_millisecond().try_into().ok())
            .map(|ms: u64| SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms));

        // Only reconcile routes attached to at least one Gateway we manage.
        let has_owned_parent = route
            .spec
            .parent_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|p| {
                parent_ref_owned(
                    p.group.as_deref(),
                    p.kind.as_deref(),
                    p.namespace.as_deref(),
                    &p.name,
                    route_ns,
                    owned_gateways,
                )
            });

        if !has_owned_parent {
            tracing::debug!(
                name = ?route.metadata.name,
                ns = route_ns,
                "Skipping HTTPRoute — no parentRef to a Coxswain-managed Gateway"
            );
            return;
        }

        let rules = match route.spec.rules.as_deref() {
            Some(r) if !r.is_empty() => r,
            _ => return,
        };

        let hostnames: Vec<&str> = route
            .spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();

        tracing::debug!(
            name = ?route.metadata.name,
            ns = route_ns,
            rules = rules.len(),
            hostnames = hostnames.len(),
            "Reconciling HTTPRoute"
        );

        for rule in rules {
            let backend_refs = match rule.backend_refs.as_deref() {
                Some(b) if !b.is_empty() => b,
                _ => continue,
            };

            let addrs = Self::resolve_upstream_addrs(backend_refs, route_ns, slices, grants);
            if addrs.is_empty() {
                tracing::warn!(
                    route = ?route.metadata.name,
                    "No ready endpoints for rule — skipping"
                );
                continue;
            }

            let upstream = Arc::new(Upstream::new(
                format!("{route_ns}/{}", backend_refs[0].name),
                addrs,
            ));

            // Default to PathPrefix "/" when no matches are specified (Gateway API §4.1).
            let apply = |pb: &mut HostRouterBuilder| match rule.matches.as_deref() {
                None | Some([]) => {
                    let e = Arc::new(RouteEntry::path_only(
                        Arc::clone(&upstream),
                        route_id.clone(),
                        created_at,
                    ));
                    pb.add_prefix_route("/", e);
                }
                Some(ms) => {
                    for m in ms {
                        // Build predicates, skipping this match if any regex is invalid.
                        let predicates = match Self::build_predicates(m) {
                            Some(p) => p,
                            None => {
                                tracing::warn!(
                                    route = ?route.metadata.name,
                                    "Skipping HTTPRouteMatch — invalid regex in header or query predicate"
                                );
                                continue;
                            }
                        };

                        let e = Arc::new(RouteEntry::new(
                            Arc::clone(&upstream),
                            predicates,
                            route_id.clone(),
                            created_at,
                        ));

                        let val = m
                            .path
                            .as_ref()
                            .and_then(|p| p.value.as_deref())
                            .unwrap_or("/");
                        match m.path.as_ref().and_then(|p| p.r#type.as_ref()) {
                            Some(HttpRouteRulesMatchesPathType::Exact) => {
                                pb.add_exact_route(val, e);
                            }
                            Some(HttpRouteRulesMatchesPathType::RegularExpression) => {
                                pb.add_regex_route(val, e);
                            }
                            // PathPrefix is the default per spec
                            _ => {
                                pb.add_prefix_route(val, e);
                            }
                        }
                    }
                }
            };

            if hostnames.is_empty() {
                apply(builder.catchall());
            } else {
                for h in &hostnames {
                    if h.starts_with("*.") {
                        apply(builder.wildcard_host(h));
                    } else {
                        apply(builder.exact_host(h));
                    }
                }
            }
        }
    }

    /// Walks `gateway.spec.listeners`, resolves TLS certificates for HTTPS
    /// listeners, and registers them in `builder`. Returns a per-listener health
    /// map so the controller can set accurate Gateway status conditions.
    ///
    /// Only `protocol: HTTPS` with `tls.mode: Terminate` (the default) is handled.
    /// `Passthrough` is recorded as `Invalid`. Non-HTTPS listeners are `NotApplicable`.
    /// Cross-namespace `certificateRefs` require a matching entry in `cert_grants`.
    pub fn reconcile_tls(
        gateway: &Gateway,
        secrets: &reflector::Store<Secret>,
        cert_grants: &HashSet<(String, String, Option<String>)>,
        builder: &mut TlsStoreBuilder,
    ) -> GatewayListenerHealth {
        let gw_ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
        let gw_name = gateway.metadata.name.as_deref().unwrap_or("unknown");
        let mut by_listener: BTreeMap<String, ListenerTlsOutcome> = BTreeMap::new();

        for listener in &gateway.spec.listeners {
            let outcome = if listener.protocol != "HTTPS" {
                ListenerTlsOutcome::NotApplicable
            } else {
                Self::resolve_listener_tls(gw_ns, gw_name, listener, secrets, cert_grants, builder)
            };
            by_listener.insert(listener.name.clone(), outcome);
        }

        GatewayListenerHealth { by_listener }
    }

    fn resolve_listener_tls(
        gw_ns: &str,
        gw_name: &str,
        listener: &gateway_api::apis::standard::gateways::GatewayListeners,
        secrets: &reflector::Store<Secret>,
        cert_grants: &HashSet<(String, String, Option<String>)>,
        builder: &mut TlsStoreBuilder,
    ) -> ListenerTlsOutcome {
        let tls = match &listener.tls {
            Some(t) => t,
            None => {
                return ListenerTlsOutcome::InvalidCertificateRef {
                    message: "HTTPS listener has no tls configuration".to_string(),
                };
            }
        };

        if matches!(tls.mode, Some(GatewayListenersTlsMode::Passthrough)) {
            return ListenerTlsOutcome::Invalid {
                message: "tls.mode: Passthrough is not supported; use Terminate".to_string(),
            };
        }

        let hostname = match listener.hostname.as_deref().filter(|h| !h.is_empty()) {
            Some(h) => h,
            None => {
                return ListenerTlsOutcome::Invalid {
                    message: "listener.hostname is required for HTTPS listeners".to_string(),
                };
            }
        };

        let refs = tls.certificate_refs.as_deref().unwrap_or(&[]);
        if refs.is_empty() {
            return ListenerTlsOutcome::InvalidCertificateRef {
                message: "tls.certificateRefs is empty".to_string(),
            };
        }

        let cert_ref = &refs[0];
        let ref_ns = cert_ref.namespace.as_deref().unwrap_or(gw_ns);

        if ref_ns != gw_ns
            && !reference_grants::backend_ref_allowed(gw_ns, ref_ns, &cert_ref.name, cert_grants)
        {
            tracing::warn!(
                gateway = %format!("{gw_ns}/{gw_name}"),
                listener = %listener.name,
                secret = %format!("{ref_ns}/{}", cert_ref.name),
                "Cross-namespace certificateRef denied — no matching ReferenceGrant"
            );
            return ListenerTlsOutcome::RefNotPermitted {
                message: format!(
                    "cross-namespace Secret {ref_ns}/{} requires a ReferenceGrant",
                    cert_ref.name
                ),
            };
        }

        match load_tls_cert(ref_ns, &cert_ref.name, secrets) {
            Ok(cert) => {
                builder.add_cert(hostname, Arc::new(cert));
                tracing::debug!(
                    gateway = %format!("{gw_ns}/{gw_name}"),
                    listener = %listener.name,
                    secret = %format!("{ref_ns}/{}", cert_ref.name),
                    hostname,
                    "Gateway TLS cert installed"
                );
                ListenerTlsOutcome::Resolved
            }
            Err(e) => {
                tracing::warn!(
                    gateway = %format!("{gw_ns}/{gw_name}"),
                    listener = %listener.name,
                    secret = %format!("{ref_ns}/{}", cert_ref.name),
                    error = %e,
                    "Gateway TLS Secret unusable — listener skipped"
                );
                ListenerTlsOutcome::InvalidCertificateRef {
                    message: e.to_string(),
                }
            }
        }
    }

    /// Builds `MatchPredicates` from a single `HttpRouteRulesMatches` entry.
    ///
    /// Returns `None` if any regex pattern in the headers or query predicates is invalid.
    fn build_predicates(
        m: &gateway_api::apis::standard::httproutes::HttpRouteRulesMatches,
    ) -> Option<MatchPredicates> {
        // ── Method ────────────────────────────────────────────────────────────
        let method: Option<Method> = match m.method.as_ref() {
            None => None,
            Some(HttpRouteRulesMatchesMethod::Get) => Some(Method::GET),
            Some(HttpRouteRulesMatchesMethod::Head) => Some(Method::HEAD),
            Some(HttpRouteRulesMatchesMethod::Post) => Some(Method::POST),
            Some(HttpRouteRulesMatchesMethod::Put) => Some(Method::PUT),
            Some(HttpRouteRulesMatchesMethod::Delete) => Some(Method::DELETE),
            Some(HttpRouteRulesMatchesMethod::Connect) => Some(Method::CONNECT),
            Some(HttpRouteRulesMatchesMethod::Options) => Some(Method::OPTIONS),
            Some(HttpRouteRulesMatchesMethod::Trace) => Some(Method::TRACE),
            Some(HttpRouteRulesMatchesMethod::Patch) => Some(Method::PATCH),
        };

        // ── Headers ───────────────────────────────────────────────────────────
        let mut headers: Vec<HeaderPredicate> = Vec::new();
        let mut seen_header_names: Vec<HeaderName> = Vec::new();
        for h in m.headers.as_deref().unwrap_or(&[]) {
            let name = match HeaderName::from_bytes(h.name.to_ascii_lowercase().as_bytes()) {
                Ok(n) => n,
                Err(_) => {
                    tracing::warn!(header_name = %h.name, "Skipping invalid header name in HTTPRouteMatch");
                    continue;
                }
            };
            // Per spec: only the first entry for a given canonical name is honoured.
            if seen_header_names.contains(&name) {
                continue;
            }
            seen_header_names.push(name.clone());

            let matcher = match h.r#type.as_ref() {
                Some(HttpRouteRulesMatchesHeadersType::RegularExpression) => {
                    let re = Regex::new(&h.value).ok()?;
                    ValueMatch::Regex(re)
                }
                _ => ValueMatch::Exact(h.value.clone()),
            };
            headers.push(HeaderPredicate { name, matcher });
        }

        // ── Query parameters ──────────────────────────────────────────────────
        let mut query: Vec<QueryPredicate> = Vec::new();
        for q in m.query_params.as_deref().unwrap_or(&[]) {
            let matcher = match q.r#type.as_ref() {
                Some(HttpRouteRulesMatchesQueryParamsType::RegularExpression) => {
                    let re = Regex::new(&q.value).ok()?;
                    ValueMatch::Regex(re)
                }
                _ => ValueMatch::Exact(q.value.clone()),
            };
            query.push(QueryPredicate {
                name: q.name.clone(),
                matcher,
            });
        }

        Some(MatchPredicates {
            method,
            headers,
            query,
        })
    }

    fn resolve_upstream_addrs(
        backend_refs: &[HttpRouteRulesBackendRefs],
        route_ns: &str,
        slices: &reflector::Store<EndpointSlice>,
        grants: &HashSet<(String, String, Option<String>)>,
    ) -> Vec<SocketAddr> {
        backend_refs
            .iter()
            .filter_map(|b| b.port.map(|port| (b, port)))
            .flat_map(|(b, port)| {
                let ns = b.namespace.as_deref().unwrap_or(route_ns);
                if ns != route_ns
                    && !reference_grants::backend_ref_allowed(route_ns, ns, &b.name, grants)
                {
                    tracing::warn!(
                        route_ns,
                        backend_ns = ns,
                        backend_svc = %b.name,
                        "Cross-namespace backendRef denied — no matching ReferenceGrant"
                    );
                    return vec![];
                }
                endpoints::resolve(ns, &b.name, port, slices)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::RoutingTableBuilder;
    use gateway_api::apis::standard::httproutes::{
        HTTPRoute, HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
        HttpRouteRulesMatches, HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesHeadersType,
        HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType,
        HttpRouteRulesMatchesQueryParams, HttpRouteRulesMatchesQueryParamsType, HttpRouteSpec,
    };
    use http::{HeaderMap, HeaderName, Method};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
    use kube::api::ObjectMeta;
    use kube::runtime::watcher;
    use std::collections::BTreeMap;

    fn make_slice(ns: &str, svc: &str, ip: &str) -> EndpointSlice {
        let mut labels = BTreeMap::new();
        labels.insert("kubernetes.io/service-name".to_string(), svc.to_string());
        EndpointSlice {
            metadata: ObjectMeta {
                name: Some(format!("{svc}-slice")),
                namespace: Some(ns.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            address_type: "IPv4".to_string(),
            endpoints: vec![Endpoint {
                addresses: vec![ip.to_string()],
                conditions: Some(EndpointConditions {
                    ready: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ports: None,
        }
    }

    fn slice_store(slices: Vec<EndpointSlice>) -> reflector::Store<EndpointSlice> {
        let mut writer = reflector::store::Writer::<EndpointSlice>::default();
        for slice in slices {
            writer.apply_watcher_event(&watcher::Event::Apply(slice));
        }
        writer.as_reader()
    }

    fn owned(pairs: &[(&str, &str)]) -> HashSet<(String, String)> {
        pairs
            .iter()
            .map(|(ns, name)| (ns.to_string(), name.to_string()))
            .collect()
    }

    /// Default owned set used by tests that exercise routing logic (not filtering).
    fn default_owned() -> HashSet<(String, String)> {
        owned(&[("default", "gw")])
    }

    /// Default parent refs pointing to the Gateway in `default_owned`.
    fn default_parents() -> Option<Vec<HttpRouteParentRefs>> {
        Some(vec![HttpRouteParentRefs {
            name: "gw".to_string(),
            namespace: Some("default".to_string()),
            ..Default::default()
        }])
    }

    fn make_route(
        ns: &str,
        hostnames: &[&str],
        matches: Option<Vec<HttpRouteRulesMatches>>,
        svc: &str,
    ) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: if hostnames.is_empty() {
                    None
                } else {
                    Some(hostnames.iter().map(|h| h.to_string()).collect())
                },
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: svc.to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    matches,
                    ..Default::default()
                }]),
            },
            ..Default::default()
        }
    }

    fn path_match(path: &str, kind: HttpRouteRulesMatchesPathType) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: Some(kind),
                value: Some(path.to_string()),
            }),
            ..Default::default()
        }
    }

    fn header_exact_match(
        path: &str,
        header_name: &str,
        header_value: &str,
    ) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
                value: Some(path.to_string()),
            }),
            headers: Some(vec![HttpRouteRulesMatchesHeaders {
                name: header_name.to_string(),
                value: header_value.to_string(),
                r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
            }]),
            ..Default::default()
        }
    }

    fn header_regex_match(path: &str, header_name: &str, pattern: &str) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
                value: Some(path.to_string()),
            }),
            headers: Some(vec![HttpRouteRulesMatchesHeaders {
                name: header_name.to_string(),
                value: pattern.to_string(),
                r#type: Some(HttpRouteRulesMatchesHeadersType::RegularExpression),
            }]),
            ..Default::default()
        }
    }

    fn method_match(path: &str, method: HttpRouteRulesMatchesMethod) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
                value: Some(path.to_string()),
            }),
            method: Some(method),
            ..Default::default()
        }
    }

    fn query_exact_match(path: &str, param: &str, value: &str) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
                value: Some(path.to_string()),
            }),
            query_params: Some(vec![HttpRouteRulesMatchesQueryParams {
                name: param.to_string(),
                value: value.to_string(),
                r#type: Some(HttpRouteRulesMatchesQueryParamsType::Exact),
            }]),
            ..Default::default()
        }
    }

    fn ctx_with<'a>(
        method: &'a Method,
        headers: &'a HeaderMap,
        query: Option<&'a str>,
    ) -> coxswain_core::routing::RequestContext<'a> {
        coxswain_core::routing::RequestContext {
            method,
            headers,
            query,
        }
    }

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        m
    }

    // ── Original path-matching tests (unchanged behaviour) ────────────────────

    #[test]
    fn reconcile_exact_path() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![path_match(
                "/api",
                HttpRouteRulesMatchesPathType::Exact,
            )]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route("example.com", "/api", &ctx).is_some());
        assert!(table.route("example.com", "/api/users", &ctx).is_none());
    }

    #[test]
    fn reconcile_prefix_path() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![path_match(
                "/api",
                HttpRouteRulesMatchesPathType::PathPrefix,
            )]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route("example.com", "/api", &ctx).is_some());
        assert!(table.route("example.com", "/api/users", &ctx).is_some());
    }

    #[test]
    fn reconcile_regex_path() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![path_match(
                r"/item/\d+",
                HttpRouteRulesMatchesPathType::RegularExpression,
            )]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route("example.com", "/item/42", &ctx).is_some());
        assert!(table.route("example.com", "/item/abc", &ctx).is_none());
    }

    #[test]
    fn reconcile_no_matches_defaults_to_root_prefix() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route("example.com", "/anything", &ctx).is_some());
    }

    #[test]
    fn reconcile_skips_route_without_owned_parent() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &owned(&[("other", "gw")]),
            &grants,
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route("example.com", "/", &ctx).is_none());
    }

    // ── New predicate tests ────────────────────────────────────────────────────

    #[test]
    fn reconcile_header_exact_routes_to_correct_backend() {
        let store = slice_store(vec![
            make_slice("default", "svc-a", "10.0.0.1"),
            make_slice("default", "svc-b", "10.0.0.2"),
        ]);

        // Two rules: same path, different header → different backends.
        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![
                    HttpRouteRules {
                        matches: Some(vec![header_exact_match("/", "x-tenant", "a")]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-a".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                    HttpRouteRules {
                        matches: Some(vec![header_exact_match("/", "x-tenant", "b")]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-b".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                ]),
            },
            ..Default::default()
        };

        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();

        let hdrs_a = headers_from(&[("x-tenant", "a")]);
        let hdrs_b = headers_from(&[("x-tenant", "b")]);
        let ctx_a = ctx_with(&Method::GET, &hdrs_a, None);
        let ctx_b = ctx_with(&Method::GET, &hdrs_b, None);

        assert_eq!(
            table.route("example.com", "/", &ctx_a).unwrap().name,
            "default/svc-a"
        );
        assert_eq!(
            table.route("example.com", "/", &ctx_b).unwrap().name,
            "default/svc-b"
        );
    }

    #[test]
    fn reconcile_header_regex_routes_to_correct_backend() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![header_regex_match("/", "x-version", r"^v\d+$")]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();

        let hdrs_ok = headers_from(&[("x-version", "v42")]);
        let hdrs_bad = headers_from(&[("x-version", "beta")]);
        let ctx_ok = ctx_with(&Method::GET, &hdrs_ok, None);
        let ctx_bad = ctx_with(&Method::GET, &hdrs_bad, None);

        assert!(table.route("example.com", "/", &ctx_ok).is_some());
        assert!(table.route("example.com", "/", &ctx_bad).is_none());
    }

    #[test]
    fn reconcile_method_routes_to_correct_backend() {
        let store = slice_store(vec![
            make_slice("default", "svc-get", "10.0.0.1"),
            make_slice("default", "svc-post", "10.0.0.2"),
        ]);

        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![
                    HttpRouteRules {
                        matches: Some(vec![method_match("/", HttpRouteRulesMatchesMethod::Get)]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-get".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                    HttpRouteRules {
                        matches: Some(vec![method_match("/", HttpRouteRulesMatchesMethod::Post)]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-post".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                ]),
            },
            ..Default::default()
        };

        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();

        let h = HeaderMap::new();
        let ctx_get = ctx_with(&Method::GET, &h, None);
        let ctx_post = ctx_with(&Method::POST, &h, None);

        assert_eq!(
            table.route("example.com", "/", &ctx_get).unwrap().name,
            "default/svc-get"
        );
        assert_eq!(
            table.route("example.com", "/", &ctx_post).unwrap().name,
            "default/svc-post"
        );
    }

    #[test]
    fn reconcile_query_param_routes_to_correct_backend() {
        let store = slice_store(vec![
            make_slice("default", "svc-v1", "10.0.0.1"),
            make_slice("default", "svc-v2", "10.0.0.2"),
        ]);

        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![
                    HttpRouteRules {
                        matches: Some(vec![query_exact_match("/", "version", "v1")]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-v1".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                    HttpRouteRules {
                        matches: Some(vec![query_exact_match("/", "version", "v2")]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-v2".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                ]),
            },
            ..Default::default()
        };

        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();

        let h = HeaderMap::new();
        let ctx_v1 = ctx_with(&Method::GET, &h, Some("version=v1"));
        let ctx_v2 = ctx_with(&Method::GET, &h, Some("version=v2"));

        assert_eq!(
            table.route("example.com", "/", &ctx_v1).unwrap().name,
            "default/svc-v1"
        );
        assert_eq!(
            table.route("example.com", "/", &ctx_v2).unwrap().name,
            "default/svc-v2"
        );
    }

    #[test]
    fn reconcile_invalid_regex_skips_match_entry() {
        // A route with an invalid regex in a header predicate should log a warning
        // and skip that match entry without poisoning the rest of the route.
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![
                // invalid regex
                HttpRouteRulesMatches {
                    headers: Some(vec![HttpRouteRulesMatchesHeaders {
                        name: "x-bad".to_string(),
                        value: "[invalid".to_string(),
                        r#type: Some(HttpRouteRulesMatchesHeadersType::RegularExpression),
                    }]),
                    ..Default::default()
                },
                // valid path-only fallback
                path_match("/", HttpRouteRulesMatchesPathType::PathPrefix),
            ]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &grants, &mut builder);
        let table = builder.build().unwrap();

        // The valid fallback entry is still registered.
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
        assert!(table.route("example.com", "/", &ctx).is_some());
    }

    #[test]
    fn reconcile_header_name_dedup_keeps_first() {
        // Two entries for the same (case-insensitive) header name in one match:
        // only the first is used (per Gateway API spec).
        let m = HttpRouteRulesMatches {
            headers: Some(vec![
                HttpRouteRulesMatchesHeaders {
                    name: "X-Tenant".to_string(),
                    value: "first".to_string(),
                    r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
                },
                HttpRouteRulesMatchesHeaders {
                    name: "x-tenant".to_string(), // same header, different case
                    value: "second".to_string(),
                    r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
                },
            ]),
            ..Default::default()
        };
        let predicates = GatewayApiReconciler::build_predicates(&m).unwrap();
        assert_eq!(predicates.headers.len(), 1);
        match &predicates.headers[0].matcher {
            ValueMatch::Exact(v) => assert_eq!(v, "first"),
            _ => panic!("expected exact matcher"),
        }
    }
}
