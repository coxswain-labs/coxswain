use crate::endpoints;
use crate::keys::ListenerKey;
use crate::tls::{GatewayListenerHealth, HttpRouteHealthMap, ListenerTlsOutcome, load_tls_cert};
use crate::translate::metadata_created_at;
use coxswain_core::ownership::{ObjectKey, parent_ref_owned};
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    HostRouterBuilder, MatchPredicates, RouteEntry, RoutingTableBuilder, Upstream,
};
use coxswain_core::tls::TlsStoreBuilder;
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayListenersAllowedRoutesNamespacesFrom, GatewayListenersTlsMode,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteRulesBackendRefs, HttpRouteRulesFiltersType, HttpRouteRulesMatchesPathType,
};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

mod filters;
mod hostnames;
mod status;
mod timeouts;

pub(crate) use hostnames::hostnames_intersect;

#[cfg(test)]
mod tests;

pub struct GatewayApiReconciler;

impl GatewayApiReconciler {
    /// Skips routes whose `spec.parentRefs` do not include at least one Gateway
    /// managed by this controller. Never queries the API server.
    ///
    /// `listener_hostnames` maps `(gw_ns, gw_name, listener_name) → hostname` and is
    /// used to scope routes without `spec.hostnames` to their listener's hostname.
    pub fn reconcile(
        route: &HTTPRoute,
        slices: &reflector::Store<EndpointSlice>,
        services: &reflector::Store<Service>,
        owned_gateways: &HashSet<ObjectKey>,
        grants: &HashSet<ReferenceGrantKey>,
        listener_hostnames: &HashMap<ListenerKey, String>,
        builder: &mut RoutingTableBuilder,
    ) {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_name = route.metadata.name.as_deref().unwrap_or("unknown");
        let route_id = format!("{route_ns}/{route_name}");
        let created_at = metadata_created_at(&route.metadata);

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

        let route_hostnames: Vec<&str> = route
            .spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();

        let (use_catchall, effective_hostnames) = compute_effective_hostnames(
            &route_hostnames,
            route.spec.parent_refs.as_deref().unwrap_or(&[]),
            route_ns,
            listener_hostnames,
        );

        tracing::debug!(
            name = ?route.metadata.name,
            ns = route_ns,
            rules = rules.len(),
            effective_hostnames = effective_hostnames.len(),
            catchall = use_catchall,
            "Reconciling HTTPRoute"
        );

        for rule in rules {
            let rule_filters = rule.filters.as_deref().unwrap_or(&[]);
            let rule_timeouts = rule
                .timeouts
                .as_ref()
                .map(timeouts::parse_rule_timeouts)
                .unwrap_or_default();

            // Rules with RequestRedirect are terminal: the proxy short-circuits before
            // upstream_peer() is called, so no real backend is needed. Use a sentinel
            // upstream with no endpoints; the redirect fires first and it is never used.
            let has_redirect = rule_filters
                .iter()
                .any(|f| matches!(f.r#type, HttpRouteRulesFiltersType::RequestRedirect));

            let (upstream, error_status) = if has_redirect {
                (
                    Arc::new(Upstream::new(
                        format!("{route_ns}/redirect-sentinel"),
                        vec![],
                    )),
                    None,
                )
            } else {
                let backend_refs = match rule.backend_refs.as_deref() {
                    Some(b) if !b.is_empty() => b,
                    _ => continue,
                };

                let weighted = Self::resolve_weighted_backends(
                    backend_refs,
                    route_ns,
                    slices,
                    services,
                    grants,
                );
                let upstream_name = upstream_name(backend_refs, route_ns);
                let upstream = Arc::new(Upstream::weighted(upstream_name, weighted));
                if upstream.endpoints().is_empty() {
                    tracing::warn!(
                        route = ?route.metadata.name,
                        "No ready endpoints for rule — installing error route (500)"
                    );
                    (upstream, Some(500u16))
                } else {
                    (upstream, None)
                }
            };

            let apply = |pb: &mut HostRouterBuilder| {
                apply_rule(
                    pb,
                    rule,
                    rule_filters,
                    &rule_timeouts,
                    &upstream,
                    error_status,
                    &route_id,
                    created_at,
                )
            };

            if use_catchall {
                apply(builder.catchall());
            }
            for h in &effective_hostnames {
                if h.starts_with("*.") {
                    apply(builder.wildcard_host(h));
                } else {
                    apply(builder.exact_host(h));
                }
            }
            // If use_catchall=false AND effective_hostnames is empty, the route has no
            // matching listener hostnames — skip (not admitted to the routing table).
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
        cert_grants: &HashSet<ReferenceGrantKey>,
        builder: &mut TlsStoreBuilder,
    ) -> GatewayListenerHealth {
        let gw_ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
        let gw_name = gateway.metadata.name.as_deref().unwrap_or("unknown");
        let mut by_listener: BTreeMap<String, ListenerTlsOutcome> = BTreeMap::new();
        let mut listener_hostnames: BTreeMap<String, String> = BTreeMap::new();
        let mut listener_allows_all_namespaces: BTreeMap<String, bool> = BTreeMap::new();
        let mut listener_ports: BTreeMap<String, u16> = BTreeMap::new();

        for listener in &gateway.spec.listeners {
            let outcome = if listener.protocol != "HTTPS" {
                ListenerTlsOutcome::NotApplicable
            } else {
                Self::resolve_listener_tls(gw_ns, gw_name, listener, secrets, cert_grants, builder)
            };
            let hostname = listener.hostname.as_deref().unwrap_or("").to_string();
            let allows_all = listener
                .allowed_routes
                .as_ref()
                .and_then(|ar| ar.namespaces.as_ref())
                .and_then(|ns| ns.from.as_ref())
                .map(|f| !matches!(f, GatewayListenersAllowedRoutesNamespacesFrom::Same))
                .unwrap_or(false); // default per spec is Same
            by_listener.insert(listener.name.clone(), outcome);
            listener_hostnames.insert(listener.name.clone(), hostname);
            listener_allows_all_namespaces.insert(listener.name.clone(), allows_all);
            listener_ports.insert(listener.name.clone(), listener.port as u16);
        }

        GatewayListenerHealth {
            by_listener,
            listener_hostnames,
            listener_allows_all_namespaces,
            listener_ports,
            ..Default::default()
        }
    }

    fn resolve_listener_tls(
        gw_ns: &str,
        gw_name: &str,
        listener: &gateway_api::apis::standard::gateways::GatewayListeners,
        secrets: &reflector::Store<Secret>,
        cert_grants: &HashSet<ReferenceGrantKey>,
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

        // Empty/absent hostname means "match any SNI" — stored as the default cert.
        let hostname = listener
            .hostname
            .as_deref()
            .filter(|h| !h.is_empty())
            .unwrap_or("");

        let refs = tls.certificate_refs.as_deref().unwrap_or(&[]);
        if refs.is_empty() {
            return ListenerTlsOutcome::InvalidCertificateRef {
                message: "tls.certificateRefs is empty".to_string(),
            };
        }

        let cert_ref = &refs[0];

        // Only core/Secret (empty group, "core", or absent) is supported.
        let ref_kind = cert_ref.kind.as_deref().unwrap_or("Secret");
        let ref_group = cert_ref.group.as_deref().unwrap_or("");
        if ref_kind != "Secret" || (!ref_group.is_empty() && ref_group != "core") {
            return ListenerTlsOutcome::InvalidCertificateRef {
                message: format!(
                    "unsupported certificateRef {ref_group}/{ref_kind}: only core/Secret is supported"
                ),
            };
        }

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

    /// Resolve each backendRef to `(pod_addresses, weight)`.
    ///
    /// Weight defaults to 1 when absent (per the Gateway API spec). Refs with
    /// `weight: 0`, non-Service kind, denied cross-namespace access, or no ready
    /// endpoints contribute an empty entry and are naturally dropped by
    /// `Upstream::weighted`.
    fn resolve_weighted_backends(
        backend_refs: &[HttpRouteRulesBackendRefs],
        route_ns: &str,
        slices: &reflector::Store<EndpointSlice>,
        services: &reflector::Store<Service>,
        grants: &HashSet<ReferenceGrantKey>,
    ) -> Vec<(Vec<SocketAddr>, u16)> {
        backend_refs
            .iter()
            .filter_map(|b| b.port.map(|port| (b, port)))
            .map(|(b, port)| {
                let weight = weight_of(b);
                if weight == 0 {
                    return (vec![], 0);
                }

                let b_kind = b.kind.as_deref().unwrap_or("Service");
                let b_group = b.group.as_deref().unwrap_or("");
                if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                    return (vec![], weight);
                }

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
                    return (vec![], weight);
                }

                (
                    endpoints::resolve(ns, &b.name, port, slices, services),
                    weight,
                )
            })
            .collect()
    }

    pub fn compute_route_health(
        routes: &[Arc<HTTPRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<ObjectKey>,
        backend_grants: &HashSet<ReferenceGrantKey>,
        service_store: &reflector::Store<Service>,
    ) -> HttpRouteHealthMap {
        status::compute_route_health(
            routes,
            gateways,
            owned_gateways,
            backend_grants,
            service_store,
        )
    }
}

/// Computes the effective hostname set for a route across all its parent refs and listeners.
///
/// Returns `(use_catchall, effective_hostnames)`.
fn compute_effective_hostnames(
    route_hostnames: &[&str],
    parent_refs: &[gateway_api::apis::standard::httproutes::HttpRouteParentRefs],
    route_ns: &str,
    listener_hostnames: &HashMap<ListenerKey, String>,
) -> (bool, Vec<String>) {
    let mut use_catchall = false;
    let mut eff_set: std::collections::HashSet<String> = std::collections::HashSet::new();

    if listener_hostnames.is_empty() {
        // No listener info: tests or misconfigured — use original behavior
        if route_hostnames.is_empty() {
            use_catchall = true;
        } else {
            eff_set.extend(route_hostnames.iter().map(|h| h.to_string()));
        }
    } else {
        for pr in parent_refs {
            let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
            let gw_name = pr.name.as_str();

            // Collect listener hostnames for this parentRef (specific or all).
            let l_hosts: Vec<&str> = if let Some(sn) = pr.section_name.as_deref() {
                let key = ListenerKey::new(gw_ns, gw_name, sn);
                listener_hostnames
                    .get(&key)
                    .map(|h| h.as_str())
                    .into_iter()
                    .collect()
            } else {
                listener_hostnames
                    .iter()
                    .filter(|(k, _)| k.gw_ns == gw_ns && k.gw_name == gw_name)
                    .map(|(_, h)| h.as_str())
                    .collect()
            };

            if l_hosts.is_empty() {
                // Listener not in map (not our gateway) — skip
                continue;
            }

            for lh in l_hosts {
                if lh.is_empty() {
                    // Listener accepts any hostname
                    if route_hostnames.is_empty() {
                        use_catchall = true;
                    } else {
                        eff_set.extend(route_hostnames.iter().map(|h| h.to_string()));
                    }
                } else if route_hostnames.is_empty() {
                    // Inherit the listener's hostname
                    eff_set.insert(lh.to_string());
                } else {
                    // Intersection: the effective hostname is the more specific of the two.
                    // If the route has a wildcard (*.foo.com) and the listener has a specific
                    // hostname (bar.foo.com), the intersection is bar.foo.com (GEP-719).
                    for rh in route_hostnames {
                        if hostnames::hostname_matches(rh, lh) {
                            let effective = if rh.starts_with("*.") && !lh.starts_with("*.") {
                                lh.to_string()
                            } else {
                                rh.to_string()
                            };
                            eff_set.insert(effective);
                        }
                    }
                }
            }
        }
    }

    // Listener isolation: drop any effective hostname E that another, more-specific listener
    // in the same gateway would claim exclusively, so routes don't leak across listener
    // boundaries.
    if !listener_hostnames.is_empty() {
        eff_set.retain(|e| {
            // Isolation only applies when the parentRef names a specific listener (sectionName
            // present).  A route without sectionName attaches to all matching listeners and
            // the hostname intersection already handles scoping correctly.
            !parent_refs.iter().any(|pr| {
                let our_sn = match pr.section_name.as_deref() {
                    Some(sn) if !sn.is_empty() => sn,
                    _ => return false, // no sectionName → skip isolation for this parentRef
                };
                let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
                let gw_name = pr.name.as_str();
                let our_spec = listener_hostnames
                    .get(&ListenerKey::new(gw_ns, gw_name, our_sn))
                    .map(|h| hostnames::listener_specificity(h))
                    .unwrap_or(0);
                let e_is_wildcard = e.starts_with("*.");
                listener_hostnames.iter().any(|(k, h_other)| {
                    k.gw_ns == gw_ns
                        && k.gw_name == gw_name
                        && k.listener.as_str() != our_sn
                        && hostnames::listener_specificity(h_other) > our_spec
                        && if e_is_wildcard {
                            // Wildcard E is dominated only by an identical wildcard listener.
                            h_other == e
                        } else {
                            // Concrete E is dominated by any more-specific listener that covers it.
                            hostnames::hostname_matches(e, h_other)
                        }
                })
            })
        });
    }

    (use_catchall, eff_set.into_iter().collect())
}

/// Installs one HTTPRoute rule into a `HostRouterBuilder`.
#[allow(clippy::too_many_arguments)]
fn apply_rule(
    pb: &mut HostRouterBuilder,
    rule: &gateway_api::apis::standard::httproutes::HttpRouteRules,
    rule_filters: &[gateway_api::apis::standard::httproutes::HttpRouteRulesFilters],
    rule_timeouts: &coxswain_core::routing::RouteTimeouts,
    upstream: &Arc<Upstream>,
    error_status: Option<u16>,
    route_id: &str,
    created_at: Option<SystemTime>,
) {
    match rule.matches.as_deref() {
        None | Some([]) => {
            let filter_list = filters::build_filters(rule_filters, "/", false);
            let mut e = RouteEntry::with_filters(
                Arc::clone(upstream),
                MatchPredicates::default(),
                filter_list,
                rule_timeouts.clone(),
                route_id.to_string(),
                created_at,
            );
            e.error_status = error_status;
            pb.add_prefix_route("/", Arc::new(e));
        }
        Some(ms) => {
            for m in ms {
                // Build predicates, skipping this match if any regex is invalid.
                let predicates = match filters::build_predicates(m) {
                    Some(p) => p,
                    None => {
                        tracing::warn!(
                            "Skipping HTTPRouteMatch — invalid regex in header or query predicate"
                        );
                        continue;
                    }
                };

                let val = m
                    .path
                    .as_ref()
                    .and_then(|p| p.value.as_deref())
                    .unwrap_or("/");

                let is_prefix = matches!(
                    m.path.as_ref().and_then(|p| p.r#type.as_ref()),
                    None | Some(HttpRouteRulesMatchesPathType::PathPrefix)
                );
                let filter_list = filters::build_filters(rule_filters, val, is_prefix);

                let mut e = RouteEntry::with_filters(
                    Arc::clone(upstream),
                    predicates,
                    filter_list,
                    rule_timeouts.clone(),
                    route_id.to_string(),
                    created_at,
                );
                e.error_status = error_status;

                match m.path.as_ref().and_then(|p| p.r#type.as_ref()) {
                    Some(HttpRouteRulesMatchesPathType::Exact) => {
                        pb.add_exact_route(val, Arc::new(e));
                    }
                    Some(HttpRouteRulesMatchesPathType::RegularExpression) => {
                        pb.add_regex_route(val, Arc::new(e));
                    }
                    // PathPrefix is the default per spec
                    _ => {
                        pb.add_prefix_route(val, Arc::new(e));
                    }
                }
            }
        }
    }
}

/// Extract weight from a backendRef, clamped to u16. Defaults to 1 when absent.
fn weight_of(b: &HttpRouteRulesBackendRefs) -> u16 {
    match b.weight {
        None => 1,
        Some(w) if w <= 0 => 0,
        Some(w) => w.min(u16::MAX as i32) as u16,
    }
}

/// Build a logging-only upstream name for a rule's backend pool.
fn upstream_name(refs: &[HttpRouteRulesBackendRefs], ns: &str) -> String {
    match refs {
        [] => format!("{ns}/empty"),
        [single] => format!("{ns}/{}", single.name),
        [first, rest @ ..] => format!("{ns}/{}+{}more", first.name, rest.len()),
    }
}
