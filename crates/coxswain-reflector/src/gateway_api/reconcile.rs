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
use coxswain_core::crd::{PathRewriteRegex, RateLimit};
use coxswain_core::ownership::{ObjectKey, parent_ref_owned};
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendGroup, BackendProtocol, FilterAction, GatewayRoutingTableBuilder, HostRouterBuilder,
    MatchPredicates, RateLimitConfig, RouteEntry, RouteTimeouts, UpstreamTls, WildcardKind,
};
use coxswain_core::tls::TlsStoreBuilder;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

/// Precomputed lookup tables consumed by [`GatewayApiReconciler::reconcile`].
///
/// Bundles the per-rebuild context that doesn't change between routes — the
/// listener-binding table, the `BackendTLSPolicy` index, and the `RateLimit`
/// CR store — so the function stays under the workspace
/// `clippy::too_many_arguments` threshold without each call site repeating the
/// three-arg suffix.
#[non_exhaustive]
pub struct RouteResolution<'a> {
    /// `(gw_ns, gw_name, listener_name) → (hostname, port)` mapping for every
    /// listener on every Gateway we own.
    pub listener_info: &'a HashMap<ListenerKey, ListenerBinding>,
    /// Per-(Service, port) `BackendTLSPolicy` lookup table; lookups try
    /// `(svc, Some(port))` first and fall back to `(svc, None)`.
    pub policy_index: &'a BackendTlsIndex,
    /// `RateLimit` CR store for resolving `ExtensionRef` filters on
    /// `HTTPRouteRule`s. Looked up by `(namespace, name)` from the filter;
    /// missing CRs produce a WARN and fail-open (route is not limited).
    pub rate_limits: &'a reflector::Store<RateLimit>,
    /// `PathRewriteRegex` CR store for resolving `ExtensionRef` filters on
    /// `HTTPRouteRule`s.
    pub path_rewrites: &'a reflector::Store<PathRewriteRegex>,
}

impl GatewayApiReconciler {
    /// Skips routes whose `spec.parentRefs` do not include at least one Gateway
    /// managed by this controller. Never queries the API server.
    ///
    /// `resolution` bundles the precomputed lookup tables used to resolve a route:
    /// - `listener_info` maps `(gw_ns, gw_name, listener_name) → (hostname, port)`, used
    ///   to scope routes to the correct per-port routing table slot and listener hostname.
    /// - `policy_index` maps `(svc, port?)` to an `UpstreamTls` derived from an attached
    ///   `BackendTLSPolicy`. When a backend ref matches, the group is forced to TLS and
    ///   the policy's SNI / CA override is attached.
    pub fn reconcile(
        route: &HttpRoute,
        slices: &reflector::Store<EndpointSlice>,
        services: &reflector::Store<Service>,
        owned_gateways: &HashSet<ObjectKey>,
        grants: &HashSet<ReferenceGrantKey>,
        resolution: RouteResolution<'_>,
        builder: &mut GatewayRoutingTableBuilder,
    ) {
        let RouteResolution {
            listener_info,
            policy_index,
            rate_limits,
            path_rewrites,
        } = resolution;
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

        for (rule_index, rule) in rules.iter().enumerate() {
            let metric_route_id: Arc<str> =
                Arc::from(format!("httproute/{route_ns}/{route_name}:{rule_index}"));
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
                // Per-backend filters from `backendRefs[].filters` — index-aligned
                // with the `resolved` list so they match the order `BackendGroup`
                // stores backends in. Backends that were dropped from `resolved`
                // (zero weight, missing addrs) also contribute nothing here.
                let per_backend_filters: Vec<Vec<FilterAction>> = resolved
                    .iter()
                    .zip(backend_refs.iter())
                    .filter(|((r, w), _)| *w > 0 && !r.addrs.is_empty())
                    .map(|((_, _), bref)| {
                        bref.filters
                            .as_deref()
                            .map(super::filters::build_backend_ref_filters)
                            .unwrap_or_default()
                    })
                    .collect();
                // A backendRef that points to an existing Service which currently
                // has zero ready endpoints drives a 503; invalid refs (missing
                // Service, wrong kind, denied cross-namespace) and all-zero-weight
                // rules drive a 500. Computed before `resolved` is consumed below.
                let has_valid_empty_backend = resolved
                    .iter()
                    .any(|(r, w)| *w > 0 && r.service_exists && r.addrs.is_empty());
                let weighted: Vec<(Vec<SocketAddr>, u16)> = resolved
                    .into_iter()
                    .filter(|(r, w)| *w > 0 && !r.addrs.is_empty())
                    .map(|(r, w)| (r.addrs, w))
                    .collect();

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

                let mut group = BackendGroup::weighted(group_name, weighted)
                    .with_protocol(protocol)
                    .with_per_backend_filters(per_backend_filters);
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
                    // HTTPRoute spec: a valid Service with zero ready endpoints
                    // SHOULD return 503; an invalid/missing backend or all-zero-
                    // weight rule MUST return 500.
                    let status = if has_valid_empty_backend {
                        503u16
                    } else {
                        500u16
                    };
                    tracing::warn!(
                        route = ?route.metadata.name,
                        status,
                        "No ready endpoints for rule — installing error route"
                    );
                    (Some(group), Some(status))
                } else {
                    (Some(group), None)
                }
            };

            let rate_limit =
                super::filters::resolve_rate_limit(rule_filters, route_ns, rate_limits);
            let ctx = RuleContext {
                filters: rule_filters,
                timeouts: &rule_timeouts,
                error_status,
                route_id: &route_id,
                metric_route_id: &metric_route_id,
                created_at,
                rate_limit,
                route_ns,
                path_rewrites,
            };
            for (hostname_opt, port) in &bindings {
                let pb = builder.for_port(*port);
                let hb = match hostname_opt {
                    None => pb.catchall(),
                    Some(h) if h.starts_with("*.") => pb.wildcard_host(h, WildcardKind::MultiLabel),
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
                        service_exists: false,
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
                        service_exists: false,
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
                        service_exists: false,
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
    metric_route_id: &'a Arc<str>,
    created_at: Option<SystemTime>,
    rate_limit: Option<Arc<RateLimitConfig>>,
    route_ns: &'a str,
    path_rewrites: &'a reflector::Store<PathRewriteRegex>,
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
        let entry = match group {
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
        };
        entry
            .with_metric_route_id(Arc::clone(ctx.metric_route_id))
            .with_rate_limit(ctx.rate_limit.clone())
    };

    match rule.matches.as_deref() {
        None | Some([]) => {
            let filter_list = super::filters::build_filters(
                ctx.filters,
                "/",
                false,
                ctx.route_ns,
                ctx.path_rewrites,
            );
            pb.add_prefix_route(
                "/",
                Arc::new(
                    make_entry(MatchPredicates::default(), filter_list)
                        .with_path_pattern(Arc::from("/")),
                ),
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
                let filter_list = super::filters::build_filters(
                    ctx.filters,
                    val,
                    is_prefix,
                    ctx.route_ns,
                    ctx.path_rewrites,
                );
                let e =
                    Arc::new(make_entry(predicates, filter_list).with_path_pattern(Arc::from(val)));

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
    let lookup = |svc_ns: &str, svc_name: &str, port: u16| -> Option<&ResolvedPolicy> {
        policy_index
            .iter()
            .find(|((k, p), _)| k.ns == svc_ns && k.name == svc_name && *p == Some(port))
            .or_else(|| {
                policy_index
                    .iter()
                    .find(|((k, p), _)| k.ns == svc_ns && k.name == svc_name && p.is_none())
            })
            .map(|(_, v)| v)
    };

    for b in backend_refs {
        let b_ns = b.namespace.as_deref().unwrap_or(route_ns);
        let Some(port) = b.port.and_then(|p| u16::try_from(p).ok()) else {
            continue;
        };
        let Some(resolved) = lookup(b_ns, &b.name, port) else {
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
                let port = b.port.and_then(|p| u16::try_from(p).ok())?;
                lookup(b_ns, &b.name, port)
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
            let mut li = ListenerInfo::default();
            li.tls_outcome = tls_outcome;
            li.attached_routes = 0;
            li.hostname = hostname;
            li.allows_all_namespaces = allows_all_namespaces;
            li.port = listener.port as u16;
            listeners.insert(listener.name.clone(), li);
        }

        let mut glh = GatewayListenerHealth::default();
        glh.listeners = listeners;
        glh
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_api::tests::*;

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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/api", &ctx).is_some());
        assert!(table.route(80, "example.com", "/api/users", &ctx).is_none());
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/api", &ctx).is_some());
        assert!(table.route(80, "example.com", "/api/users", &ctx).is_some());
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/item/42", &ctx).is_some());
        assert!(table.route(80, "example.com", "/item/abc", &ctx).is_none());
    }

    #[test]
    fn reconcile_no_matches_defaults_to_root_prefix() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/anything", &ctx).is_some());
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
            &empty_svc_store(),
            &owned(&[("other", "gw")]),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/", &ctx).is_none());
    }

    // ── New predicate tests ────────────────────────────────────────────────────

    #[test]
    fn reconcile_header_exact_routes_to_correct_backend() {
        let store = slice_store(vec![
            make_slice("default", "svc-a", "10.0.0.1"),
            make_slice("default", "svc-b", "10.0.0.2"),
        ]);

        // Two rules: same path, different header → different backends.
        let route = HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                use_default_gateways: None,
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let hdrs_a = headers_from(&[("x-tenant", "a")]);
        let hdrs_b = headers_from(&[("x-tenant", "b")]);
        let ctx_a = ctx_with(&Method::GET, &hdrs_a, None);
        let ctx_b = ctx_with(&Method::GET, &hdrs_b, None);

        assert_eq!(
            table.route(80, "example.com", "/", &ctx_a).unwrap().name(),
            "default/svc-a"
        );
        assert_eq!(
            table.route(80, "example.com", "/", &ctx_b).unwrap().name(),
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let hdrs_ok = headers_from(&[("x-version", "v42")]);
        let hdrs_bad = headers_from(&[("x-version", "beta")]);
        let ctx_ok = ctx_with(&Method::GET, &hdrs_ok, None);
        let ctx_bad = ctx_with(&Method::GET, &hdrs_bad, None);

        assert!(table.route(80, "example.com", "/", &ctx_ok).is_some());
        assert!(table.route(80, "example.com", "/", &ctx_bad).is_none());
    }

    #[test]
    fn reconcile_method_routes_to_correct_backend() {
        let store = slice_store(vec![
            make_slice("default", "svc-get", "10.0.0.1"),
            make_slice("default", "svc-post", "10.0.0.2"),
        ]);

        let route = HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                use_default_gateways: None,
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let h = HeaderMap::new();
        let ctx_get = ctx_with(&Method::GET, &h, None);
        let ctx_post = ctx_with(&Method::POST, &h, None);

        assert_eq!(
            table
                .route(80, "example.com", "/", &ctx_get)
                .unwrap()
                .name(),
            "default/svc-get"
        );
        assert_eq!(
            table
                .route(80, "example.com", "/", &ctx_post)
                .unwrap()
                .name(),
            "default/svc-post"
        );
    }

    #[test]
    fn reconcile_query_param_routes_to_correct_backend() {
        let store = slice_store(vec![
            make_slice("default", "svc-v1", "10.0.0.1"),
            make_slice("default", "svc-v2", "10.0.0.2"),
        ]);

        let route = HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                use_default_gateways: None,
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let h = HeaderMap::new();
        let ctx_v1 = ctx_with(&Method::GET, &h, Some("version=v1"));
        let ctx_v2 = ctx_with(&Method::GET, &h, Some("version=v2"));

        assert_eq!(
            table.route(80, "example.com", "/", &ctx_v1).unwrap().name(),
            "default/svc-v1"
        );
        assert_eq!(
            table.route(80, "example.com", "/", &ctx_v2).unwrap().name(),
            "default/svc-v2"
        );
    }

    #[test]
    fn reconcile_invalid_regex_skips_match_entry() {
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
        assert!(table.route(80, "example.com", "/", &ctx).is_some());
    }

    #[test]
    fn reconcile_header_name_dedup_keeps_first() {
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
        let predicates = super::super::filters::build_predicates(&m).unwrap();
        assert_eq!(predicates.headers.len(), 1);
        match &predicates.headers[0].matcher {
            coxswain_core::routing::ValueMatch::Exact(v) => assert_eq!(v, "first"),
            _ => panic!("expected exact matcher"),
        }
    }

    // ── Weighted backendRefs (issue #17) ─────────────────────────────────────────

    fn weighted_route(ns: &str, refs: &[(&str, Option<i32>)]) -> HttpRoute {
        HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                use_default_gateways: None,
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(
                        refs.iter()
                            .map(|(svc, w)| HttpRouteRulesBackendRefs {
                                name: svc.to_string(),
                                port: Some(80),
                                weight: *w,
                                ..Default::default()
                            })
                            .collect(),
                    ),
                    ..Default::default()
                }]),
            },
            ..Default::default()
        }
    }

    #[test]
    fn weighted_backends_80_20_split() {
        let a_ip = "10.0.0.1";
        let b_ip = "10.0.1.1";
        let store = slice_store(vec![
            make_slice("default", "svc-a", a_ip),
            make_slice("default", "svc-b", b_ip),
        ]);
        let route = weighted_route("default", &[("svc-a", Some(4)), ("svc-b", Some(1))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

        let a: std::net::SocketAddr = format!("{a_ip}:80").parse().unwrap();
        let n = 1000usize;
        let mut a_count = 0usize;
        for _ in 0..n {
            let addr = upstream.next_endpoint().unwrap();
            if addr == a {
                a_count += 1;
            }
        }
        let ratio = a_count as f64 / n as f64;
        assert!(
            (0.75..=0.85).contains(&ratio),
            "backend-A ratio {ratio:.3} expected 0.75–0.85"
        );
    }

    #[test]
    fn zero_weight_backend_gets_no_traffic() {
        let a_ip = "10.0.0.1";
        let b_ip = "10.0.1.1";
        let store = slice_store(vec![
            make_slice("default", "svc-a", a_ip),
            make_slice("default", "svc-b", b_ip),
        ]);
        let route = weighted_route("default", &[("svc-a", Some(0)), ("svc-b", Some(1))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

        let b: std::net::SocketAddr = format!("{b_ip}:80").parse().unwrap();
        for _ in 0..100 {
            assert_eq!(
                upstream.next_endpoint().unwrap(),
                b,
                "weight-0 backend should receive no traffic"
            );
        }
    }

    #[test]
    fn all_zero_weights_installs_error_route() {
        let store = slice_store(vec![
            make_slice("default", "svc-a", "10.0.0.1"),
            make_slice("default", "svc-b", "10.0.1.1"),
        ]);
        let route = weighted_route("default", &[("svc-a", Some(0)), ("svc-b", Some(0))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        // All weights zero → empty upstream → error_status = Some(500) → RouteOutcome::Error
        let outcome = table.find(80, "example.com", "/", &ctx_get());
        assert!(
            matches!(outcome, coxswain_core::routing::RouteOutcome::Error(500)),
            "all-zero-weight rule must resolve to Error(500)"
        );
    }

    #[test]
    fn valid_service_zero_endpoints_installs_503() {
        // The referenced Service exists but has no ready endpoints (e.g. scaled
        // to zero). HTTPRoute spec: this SHOULD return 503, not 500.
        let svc = k8s_openapi::api::core::v1::Service {
            metadata: ObjectMeta {
                name: Some("svc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let route = weighted_route("default", &[("svc", Some(1))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &slice_store(vec![]),
            &crate::tests::fixtures::make_svc_store(vec![svc]),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            matches!(
                table.find(80, "example.com", "/", &ctx_get()),
                coxswain_core::routing::RouteOutcome::Error(503)
            ),
            "valid Service with zero ready endpoints must resolve to 503"
        );
    }

    #[test]
    fn missing_service_installs_500() {
        // No such Service in the store → invalid backendRef → MUST return 500.
        let route = weighted_route("default", &[("svc", Some(1))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &slice_store(vec![]),
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            matches!(
                table.find(80, "example.com", "/", &ctx_get()),
                coxswain_core::routing::RouteOutcome::Error(500)
            ),
            "missing Service backendRef must resolve to 500"
        );
    }

    #[test]
    fn absent_weight_defaults_to_1() {
        let a_ip = "10.0.0.1";
        let b_ip = "10.0.1.1";
        let store = slice_store(vec![
            make_slice("default", "svc-a", a_ip),
            make_slice("default", "svc-b", b_ip),
        ]);
        // weight field is None — should default to 1 each → roughly equal split
        let route = weighted_route("default", &[("svc-a", None), ("svc-b", None)]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

        let a: std::net::SocketAddr = format!("{a_ip}:80").parse().unwrap();
        let b: std::net::SocketAddr = format!("{b_ip}:80").parse().unwrap();
        let results: Vec<_> = (0..4).map(|_| upstream.next_endpoint().unwrap()).collect();
        // With equal weights, slots = [0, 1]; cycling: a, b, a, b
        assert_eq!(results, [a, b, a, b]);
    }
}
