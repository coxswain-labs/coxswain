//! Core `HTTPRoute`/`Gateway` reconciliation: builds routing table entries from
//! listener bindings and resolved backend groups.

use super::GatewayApiReconciler;
use super::backend_tls::{BackendTlsIndex, ResolvedPolicy};
use super::bindings::{ListenerBinding, compute_listener_bindings};
use crate::endpoints;
use crate::gw_types::{
    HttpRoute,
    v::gateways::{Gateway, GatewayListenersAllowedRoutesNamespacesFrom, GatewayListenersTlsMode},
    v::httproutes::{
        HttpRouteRulesBackendRefs, HttpRouteRulesFilters, HttpRouteRulesFiltersType,
        HttpRouteRulesMatchesPathType,
    },
};
use crate::k8s_utils::metadata_created_at;
use crate::keys::ListenerKey;
use crate::tls::{GatewayListenerHealth, ListenerInfo, ListenerTlsOutcome, load_tls_cert};
use coxswain_core::ownership::{ObjectKey, parent_ref_owned};
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendGroup, BackendProtocol, FilterAction, HostRouterBuilder, MatchPredicates, RouteEntry,
    RouteTimeouts, RoutingTableBuilder, UpstreamTls,
};
use coxswain_core::tls::TlsStoreBuilder;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

impl GatewayApiReconciler {
    /// Skips routes whose `spec.parentRefs` do not include at least one Gateway
    /// managed by this controller. Never queries the API server.
    ///
    /// `listener_info` maps `(gw_ns, gw_name, listener_name) → (hostname, port)`, used
    /// to scope routes to the correct per-port routing table slot and listener hostname.
    ///
    /// `policy_index` maps `(svc_ns, svc_name)` to an `UpstreamTls` derived from an
    /// attached `BackendTLSPolicy`. When a backend ref matches, the group is forced to
    /// TLS and the policy's SNI / CA override is attached.
    pub fn reconcile(
        route: &HttpRoute,
        slices: &reflector::Store<EndpointSlice>,
        services: &reflector::Store<Service>,
        owned_gateways: &HashSet<ObjectKey>,
        grants: &HashSet<ReferenceGrantKey>,
        listener_info: &HashMap<ListenerKey, ListenerBinding>,
        policy_index: &BackendTlsIndex,
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

        let bindings = compute_listener_bindings(
            &route_hostnames,
            route.spec.parent_refs.as_deref().unwrap_or(&[]),
            route_ns,
            listener_info,
        );

        tracing::debug!(
            name = ?route.metadata.name,
            ns = route_ns,
            rules = rules.len(),
            bindings = bindings.len(),
            "Reconciling HTTPRoute"
        );

        for rule in rules {
            let rule_filters = rule.filters.as_deref().unwrap_or(&[]);
            let rule_timeouts = rule
                .timeouts
                .as_ref()
                .map(super::timeouts::parse_rule_timeouts)
                .unwrap_or_default();

            // Rules with RequestRedirect are terminal: the proxy fires the redirect before
            // consulting any upstream, so no BackendGroup is needed.
            let has_redirect = rule_filters
                .iter()
                .any(|f| matches!(f.r#type, HttpRouteRulesFiltersType::RequestRedirect));

            let (group, error_status): (Option<Arc<BackendGroup>>, Option<u16>) = if has_redirect {
                (None, None)
            } else {
                let backend_refs = match rule.backend_refs.as_deref() {
                    Some(b) if !b.is_empty() => b,
                    _ => continue,
                };

                let resolved =
                    resolve_weighted_backends(backend_refs, route_ns, slices, services, grants);
                let group_name = backend_group_name(backend_refs, route_ns);
                let protocols: Vec<BackendProtocol> =
                    resolved.iter().map(|(r, _)| r.app_protocol).collect();
                let mut protocol = pick_route_protocol(&protocols, &group_name);
                let weighted = resolved.into_iter().map(|(r, w)| (r.addrs, w)).collect();

                // Look up BackendTLSPolicy for this rule's backends. Highest-weight ref
                // wins on conflicts (ties break by backendRefs array order).
                let policy_match =
                    pick_backend_tls(backend_refs, route_ns, protocol, policy_index, &group_name);
                let invalid_policy = matches!(policy_match, PolicyMatch::Invalid);
                let policy_tls = match policy_match {
                    PolicyMatch::Valid(tls) => Some(tls),
                    PolicyMatch::None | PolicyMatch::Invalid => None,
                };
                if policy_tls.is_some() {
                    // Policy presence forces TLS regardless of appProtocol.
                    protocol = BackendProtocol::Https;
                }

                let mut group =
                    BackendGroup::weighted(group_name, weighted).with_protocol(protocol);
                if let Some(tls) = policy_tls {
                    group = group.with_tls(tls);
                }
                let group = Arc::new(group);
                if invalid_policy {
                    // GEP-1897: a backend covered by an invalid BackendTLSPolicy MUST
                    // return 5xx, not silently fall back to plain HTTP. 502 reads as
                    // "upstream not reachable" which matches the spec intent.
                    (Some(group), Some(502u16))
                } else if group.endpoints().is_empty() {
                    tracing::warn!(
                        route = ?route.metadata.name,
                        "No ready endpoints for rule — installing error route (500)"
                    );
                    (Some(group), Some(500u16))
                } else {
                    (Some(group), None)
                }
            };

            let ctx = RuleContext {
                filters: rule_filters,
                timeouts: &rule_timeouts,
                error_status,
                route_id: &route_id,
                created_at,
            };
            for (hostname_opt, port) in &bindings {
                let pb = builder.for_port(*port);
                let hb = match hostname_opt {
                    None => pb.catchall(),
                    Some(h) if h.starts_with("*.") => pb.wildcard_host(h),
                    Some(h) => pb.exact_host(h),
                };
                apply_rule(hb, rule, group.as_ref(), &ctx);
            }
            // If bindings is empty, the route has no matching listener — skip.
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
) -> Vec<(endpoints::ResolvedEndpoints, u16)> {
    backend_refs
        .iter()
        .filter_map(|b| b.port.map(|port| (b, port)))
        .map(|(b, port)| {
            let weight = weight_of(b);
            if weight == 0 {
                return (
                    endpoints::ResolvedEndpoints {
                        addrs: vec![],
                        app_protocol: BackendProtocol::default(),
                    },
                    0,
                );
            }

            let b_kind = b.kind.as_deref().unwrap_or("Service");
            let b_group = b.group.as_deref().unwrap_or("");
            if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                return (
                    endpoints::ResolvedEndpoints {
                        addrs: vec![],
                        app_protocol: BackendProtocol::default(),
                    },
                    weight,
                );
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
                return (
                    endpoints::ResolvedEndpoints {
                        addrs: vec![],
                        app_protocol: BackendProtocol::default(),
                    },
                    weight,
                );
            }

            (
                endpoints::resolve(ns, &b.name, port, slices, services),
                weight,
            )
        })
        .collect()
}

struct RuleContext<'a> {
    filters: &'a [HttpRouteRulesFilters],
    timeouts: &'a RouteTimeouts,
    error_status: Option<u16>,
    route_id: &'a str,
    created_at: Option<SystemTime>,
}

/// Installs one HTTPRoute rule into a `HostRouterBuilder`.
///
/// When `group` is `None`, the rule has a `RequestRedirect` filter and no
/// upstream backend — `RouteEntry::redirect_only` is used in that case.
fn apply_rule(
    pb: &mut HostRouterBuilder,
    rule: &crate::gw_types::v::httproutes::HttpRouteRules,
    group: Option<&Arc<BackendGroup>>,
    ctx: &RuleContext<'_>,
) {
    let make_entry = |predicates: MatchPredicates, filter_list: Vec<FilterAction>| -> RouteEntry {
        match group {
            Some(g) => {
                let mut e = RouteEntry::with_filters(
                    Arc::clone(g),
                    predicates,
                    filter_list,
                    ctx.timeouts.clone(),
                    ctx.route_id.to_string(),
                    ctx.created_at,
                );
                e.error_status = ctx.error_status;
                e
            }
            None => RouteEntry::redirect_only(
                predicates,
                filter_list,
                ctx.timeouts.clone(),
                ctx.route_id.to_string(),
                ctx.created_at,
            ),
        }
    };

    match rule.matches.as_deref() {
        None | Some([]) => {
            let filter_list = super::filters::build_filters(ctx.filters, "/", false);
            pb.add_prefix_route(
                "/",
                Arc::new(make_entry(MatchPredicates::default(), filter_list)),
            );
        }
        Some(ms) => {
            for m in ms {
                // Build predicates, skipping this match if any regex is invalid.
                let predicates = match super::filters::build_predicates(m) {
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
                let filter_list = super::filters::build_filters(ctx.filters, val, is_prefix);
                let e = Arc::new(make_entry(predicates, filter_list));

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

/// Build a logging-only name for a rule's backend group.
fn backend_group_name(refs: &[HttpRouteRulesBackendRefs], ns: &str) -> String {
    match refs {
        [] => format!("{ns}/empty"),
        [single] => format!("{ns}/{}", single.name),
        [first, rest @ ..] => format!("{ns}/{}+{}more", first.name, rest.len()),
    }
}

/// Choose the representative `BackendProtocol` for a rule whose backendRefs
/// may declare different `appProtocol` values (per GEP-1911, mixed protocols
/// within a single rule are undefined).
///
/// Returns the first non-`Http1` protocol; falls back to `Http1` if all are
/// default. Emits a warning when more than one distinct non-default protocol
/// is present.
fn pick_route_protocol(protocols: &[BackendProtocol], group_name: &str) -> BackendProtocol {
    let non_default: Vec<BackendProtocol> = protocols
        .iter()
        .copied()
        .filter(|&p| p != BackendProtocol::Http1)
        .collect();

    match non_default.as_slice() {
        [] => BackendProtocol::Http1,
        [single] => *single,
        [first, ..] => {
            let all_same = non_default.iter().all(|&p| p == *first);
            if !all_same {
                tracing::warn!(
                    backend_group = group_name,
                    "Mixed appProtocol across backendRefs is undefined per GEP-1911; \
                     using first non-default"
                );
            }
            *first
        }
    }
}

/// Result of looking up a `BackendTLSPolicy` for a rule's backend refs.
enum PolicyMatch {
    /// No backend in this rule has an attached policy — route as normal.
    None,
    /// A valid policy is attached; install TLS to upstream with this configuration.
    Valid(Arc<UpstreamTls>),
    /// A policy is attached but invalid (e.g. CA cert ref unresolvable). Per
    /// GEP-1897 the data plane MUST return 5xx instead of falling back to plain
    /// HTTP; the caller installs a 502 error route for this rule.
    Invalid,
}

/// Select the `BackendTLSPolicy` to attach to a rule's `BackendGroup`.
///
/// Scans `backend_refs` and looks each up in `policy_index`. If ANY backend has
/// an invalid policy, the rule is blocked and the result is `PolicyMatch::Invalid`
/// — this is conservative but correct per GEP-1897, which forbids silently
/// falling back to plain HTTP when a policy was meant to apply.
///
/// Otherwise, when one or more backends have valid policies, the policy of the
/// highest-weight ref wins (ties broken by array order). When the matched
/// policies differ across backends, the winner is logged.
fn pick_backend_tls(
    backend_refs: &[HttpRouteRulesBackendRefs],
    route_ns: &str,
    current_protocol: BackendProtocol,
    policy_index: &BackendTlsIndex,
    group_name: &str,
) -> PolicyMatch {
    let mut best: Option<(Arc<UpstreamTls>, u16)> = None; // (tls, weight)
    let mut saw_invalid = false;

    // Per-port best-match lookup: try (svc, Some(port)) first (section-name policy
    // applied to this specific port), then fall back to (svc, None) (catch-all
    // policy covering the whole Service). This matches the GEP-1897 spec where
    // section-name policies override the catch-all for their specific port.
    let lookup = |svc_key: &ObjectKey, port: u16| -> Option<&ResolvedPolicy> {
        policy_index
            .get(&(svc_key.clone(), Some(port)))
            .or_else(|| policy_index.get(&(svc_key.clone(), None)))
    };

    for b in backend_refs {
        let b_ns = b.namespace.as_deref().unwrap_or(route_ns);
        let svc_key = ObjectKey::new(b_ns, &b.name);
        let Some(port) = b.port.and_then(|p| u16::try_from(p).ok()) else {
            continue;
        };
        let Some(resolved) = lookup(&svc_key, port) else {
            continue;
        };
        let Some(tls) = resolved.tls.as_ref() else {
            saw_invalid = true;
            continue;
        };
        let w = match b.weight {
            None => 1u16,
            Some(w) if w <= 0 => 0u16,
            Some(w) => w.min(u16::MAX as i32) as u16,
        };
        match &best {
            None => best = Some((Arc::clone(tls), w)),
            Some((_, best_w)) if w > *best_w => best = Some((Arc::clone(tls), w)),
            _ => {}
        }
    }

    if saw_invalid {
        tracing::warn!(
            backend_group = group_name,
            "BackendTLSPolicy attached to one of this rule's backends is invalid — \
             rule will return 502 (GEP-1897)"
        );
        return PolicyMatch::Invalid;
    }

    if let Some((ref tls, _)) = best {
        if !current_protocol.is_tls() {
            tracing::debug!(
                backend_group = group_name,
                sni = %tls.sni,
                "BackendTLSPolicy attached — forcing TLS to upstream"
            );
        }
        let distinct = backend_refs
            .iter()
            .filter_map(|b| {
                let b_ns = b.namespace.as_deref().unwrap_or(route_ns);
                let svc_key = ObjectKey::new(b_ns, &b.name);
                let port = b.port.and_then(|p| u16::try_from(p).ok())?;
                lookup(&svc_key, port)
            })
            .map(|r| &r.policy_key)
            .collect::<HashSet<_>>()
            .len();
        if distinct > 1 {
            tracing::warn!(
                backend_group = group_name,
                "Multiple BackendTLSPolicies across backendRefs in one rule — \
                 using highest-weight ref's policy"
            );
        }
    }

    match best {
        Some((tls, _)) => PolicyMatch::Valid(tls),
        None => PolicyMatch::None,
    }
}

// ── Gateway TLS listener reconciliation ──────────────────────────────────────

impl GatewayApiReconciler {
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
        let mut listeners = BTreeMap::new();

        for listener in &gateway.spec.listeners {
            let tls_outcome = if listener.protocol != "HTTPS" {
                ListenerTlsOutcome::NotApplicable
            } else {
                resolve_listener_tls(gw_ns, gw_name, listener, secrets, cert_grants, builder)
            };
            let hostname = listener.hostname.as_deref().unwrap_or("").to_string();
            let allows_all_namespaces = listener
                .allowed_routes
                .as_ref()
                .and_then(|ar| ar.namespaces.as_ref())
                .and_then(|ns| ns.from.as_ref())
                .map(|f| !matches!(f, GatewayListenersAllowedRoutesNamespacesFrom::Same))
                .unwrap_or(false); // default per spec is Same
            listeners.insert(
                listener.name.clone(),
                ListenerInfo {
                    tls_outcome,
                    attached_routes: 0,
                    hostname,
                    allows_all_namespaces,
                    port: listener.port as u16,
                },
            );
        }

        GatewayListenerHealth { listeners }
    }
}

fn resolve_listener_tls(
    gw_ns: &str,
    gw_name: &str,
    listener: &crate::gw_types::v::gateways::GatewayListeners,
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
