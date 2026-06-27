//! Translates `GRPCRoute` rules into routing-table entries.
//!
//! Mirrors the HTTPRoute reconciler in `reconcile.rs` as a sibling module. No
//! shared abstraction — the two reconcilers evolve independently. See the
//! module-level `//!` in `gateway_api/mod.rs` for the design rationale.

use super::backend_tls::{BackendTlsIndex, ResolvedPolicy};
use super::bindings::{ListenerBinding, compute_grpc_listener_bindings};
use crate::endpoints;
use crate::gw_types::{
    GrpcRoute,
    v::grpcroutes::{
        GrpcRouteRulesBackendRefs, GrpcRouteRulesBackendRefsFilters,
        GrpcRouteRulesBackendRefsFiltersType, GrpcRouteRulesFilters, GrpcRouteRulesFiltersType,
        GrpcRouteRulesMatchesHeaders, GrpcRouteRulesMatchesHeadersType,
        GrpcRouteRulesMatchesMethod, GrpcRouteRulesMatchesMethodType,
    },
};
use crate::k8s_utils::metadata_created_at;
use crate::keys::ListenerKey;
use coxswain_core::ownership::{ObjectKey, parent_ref_owned};
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendGroup, BackendProtocol, FilterAction, GatewayRoutingTableBuilder, HeaderMod,
    HeaderPredicate, HostRouterBuilder, MatchPredicates, RouteEntry, RouteTimeouts, UpstreamTls,
    ValueMatch, WildcardKind,
};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

/// Precomputed context for GRPCRoute reconciliation.
///
/// Intentionally slim compared to [`super::reconcile::RouteResolution`]: GRPCRoute has no
/// RateLimit or PathRewriteRegex ExtensionRef support.
#[non_exhaustive]
pub struct GrpcRouteResolution<'a> {
    /// `(gw_ns, gw_name, listener_name) → (hostname, port)` for every listener on owned Gateways.
    pub listener_info: &'a HashMap<ListenerKey, ListenerBinding>,
    /// Per-(Service, port) `BackendTLSPolicy` lookup table.
    pub policy_index: &'a BackendTlsIndex,
}

/// Result of looking up a `BackendTLSPolicy` for a rule's backend refs.
enum PolicyMatch {
    None,
    Valid(Arc<UpstreamTls>),
    Invalid,
}

/// Installs one GRPCRoute's rules into the shared routing-table builder.
///
/// Skips routes with no parentRef to an owned Gateway. Maps each rule's
/// `method` matcher to an HTTP path pattern (gRPC uses `POST /{service}/{method}`)
/// and translates the `headers` matcher into `MatchPredicates`.
pub(super) fn reconcile(
    route: &GrpcRoute,
    slices: &reflector::Store<EndpointSlice>,
    services: &reflector::Store<Service>,
    owned_gateways: &HashSet<ObjectKey>,
    grants: &HashSet<ReferenceGrantKey>,
    resolution: GrpcRouteResolution<'_>,
    builder: &mut GatewayRoutingTableBuilder,
) {
    let GrpcRouteResolution {
        listener_info,
        policy_index,
    } = resolution;
    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let route_name = route.metadata.name.as_deref().unwrap_or("unknown");
    let route_id = format!("{route_ns}/{route_name}");
    let created_at = metadata_created_at(&route.metadata);

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
            "Skipping GRPCRoute — no parentRef to a Coxswain-managed Gateway"
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

    let bindings = compute_grpc_listener_bindings(
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
        "Reconciling GRPCRoute"
    );

    for (rule_index, rule) in rules.iter().enumerate() {
        let metric_route_id: Arc<str> =
            Arc::from(format!("grpcroute/{route_ns}/{route_name}:{rule_index}"));
        let rule_filters = rule.filters.as_deref().unwrap_or(&[]);

        // GRPCRoute has no RequestRedirect — every rule resolves backends.
        let backend_refs = match rule.backend_refs.as_deref() {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };

        let resolved = resolve_weighted_backends(backend_refs, route_ns, slices, services, grants);
        let group_name = backend_group_name(backend_refs, route_ns);
        let protocols: Vec<BackendProtocol> =
            resolved.iter().map(|(r, _)| r.app_protocol).collect();
        let protocol = pick_route_protocol(&protocols, &group_name);

        let per_backend_filters: Vec<Vec<FilterAction>> = resolved
            .iter()
            .zip(backend_refs.iter())
            .filter(|((r, w), _)| *w > 0 && !r.addrs.is_empty())
            .map(|((_, _), bref)| {
                bref.filters
                    .as_deref()
                    .map(build_backend_ref_filters)
                    .unwrap_or_default()
            })
            .collect();

        let has_valid_empty_backend = resolved
            .iter()
            .any(|(r, w)| *w > 0 && r.service_exists && r.addrs.is_empty());
        let weighted: Vec<(Vec<SocketAddr>, u16)> = resolved
            .into_iter()
            .filter(|(r, w)| *w > 0 && !r.addrs.is_empty())
            .map(|(r, w)| (r.addrs, w))
            .collect();

        let policy_match = pick_backend_tls(backend_refs, route_ns, policy_index, &group_name);
        let invalid_policy = matches!(policy_match, PolicyMatch::Invalid);
        let policy_tls = match policy_match {
            PolicyMatch::Valid(tls) => Some(tls),
            PolicyMatch::None | PolicyMatch::Invalid => None,
        };

        let mut group = BackendGroup::weighted(group_name, weighted)
            .with_protocol(protocol)
            .with_per_backend_filters(per_backend_filters);
        if let Some(tls) = policy_tls {
            group = group.with_tls(tls);
        }
        let group = Arc::new(group);

        let (group_opt, error_status): (Option<Arc<BackendGroup>>, Option<u16>) = if invalid_policy
        {
            (Some(group), Some(502u16))
        } else if group.endpoints().is_empty() {
            let status = if has_valid_empty_backend {
                503u16
            } else {
                500u16
            };
            tracing::warn!(
                route = ?route.metadata.name,
                status,
                "No ready endpoints for GRPCRoute rule — installing error route"
            );
            (Some(group), Some(status))
        } else {
            (Some(group), None)
        };

        let ctx = GrpcRuleContext {
            filters: rule_filters,
            error_status,
            route_id: &route_id,
            metric_route_id: &metric_route_id,
            created_at,
        };
        for (hostname_opt, port) in &bindings {
            let pb = builder.for_port(*port);
            let hb = match hostname_opt {
                None => pb.catchall(),
                Some(h) if h.starts_with("*.") => pb.wildcard_host(h, WildcardKind::MultiLabel),
                Some(h) => pb.exact_host(h),
            };
            apply_grpc_rule(hb, rule, group_opt.as_ref(), &ctx);
        }
    }
}

struct GrpcRuleContext<'a> {
    filters: &'a [GrpcRouteRulesFilters],
    error_status: Option<u16>,
    route_id: &'a str,
    metric_route_id: &'a Arc<str>,
    created_at: Option<SystemTime>,
}

/// Installs one GRPCRoute rule (all its matches) into a `HostRouterBuilder`.
fn apply_grpc_rule(
    pb: &mut HostRouterBuilder,
    rule: &crate::gw_types::v::grpcroutes::GrpcRouteRules,
    group: Option<&Arc<BackendGroup>>,
    ctx: &GrpcRuleContext<'_>,
) {
    let make_entry = |predicates: MatchPredicates, filter_list: Vec<FilterAction>| -> RouteEntry {
        let entry = match group {
            Some(g) => {
                let mut e = RouteEntry::with_filters(
                    Arc::clone(g),
                    predicates,
                    filter_list,
                    RouteTimeouts::default(),
                    ctx.route_id.to_string(),
                    ctx.created_at,
                );
                e.error_status = ctx.error_status;
                e
            }
            None => RouteEntry::redirect_only(
                predicates,
                filter_list,
                RouteTimeouts::default(),
                ctx.route_id.to_string(),
                ctx.created_at,
            ),
        };
        entry
            .with_metric_route_id(Arc::clone(ctx.metric_route_id))
            .with_rate_limit(None)
    };

    match rule.matches.as_deref() {
        None | Some([]) => {
            let filter_list = build_filters(ctx.filters);
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
                let (path, kind) = method_to_path(m.method.as_ref());

                let predicates = match build_header_predicates(m.headers.as_deref()) {
                    Some(p) => p,
                    None => {
                        tracing::warn!(
                            "Skipping GRPCRouteMatch — invalid regex in header predicate"
                        );
                        continue;
                    }
                };

                let filter_list = build_filters(ctx.filters);
                let e = Arc::new(
                    make_entry(predicates, filter_list).with_path_pattern(Arc::from(path.as_str())),
                );

                match kind {
                    GrpcPathKind::Exact => {
                        pb.add_exact_route(&path, e);
                    }
                    GrpcPathKind::Prefix => {
                        pb.add_prefix_route(&path, e);
                    }
                    GrpcPathKind::Regex => {
                        pb.add_regex_route(&path, e);
                    }
                }
            }
        }
    }
}

enum GrpcPathKind {
    Exact,
    Prefix,
    Regex,
}

/// Maps a gRPC method matcher to an HTTP path string and routing kind.
///
/// gRPC calls are always `POST /{Service}/{Method}`. The spec allows matching by
/// service, method, or regex patterns — each maps to a distinct path-based
/// routing entry.
///
/// # Mapping table
///
/// | Matcher spec | Path | Kind |
/// |---|---|---|
/// | none (no method field) | `/` | Prefix (match-all) |
/// | Exact, service + method | `/{S}/{M}` | Exact |
/// | Exact, service only | `/{S}/` | Prefix |
/// | Exact, method only | `^/[^/]+/{escaped-M}$` | Regex |
/// | Exact, both empty (spec-invalid, fail-soft) | `/` | Prefix |
/// | RegularExpression, service + method | `^/{Sp}/{Mp}$` | Regex |
/// | RegularExpression, service only | `^/{Sp}/[^/]+$` | Regex |
/// | RegularExpression, method only | `^/[^/]+/{Mp}$` | Regex |
/// | RegularExpression, neither | `/` | Prefix |
fn method_to_path(method: Option<&GrpcRouteRulesMatchesMethod>) -> (String, GrpcPathKind) {
    let Some(m) = method else {
        return ("/".to_string(), GrpcPathKind::Prefix);
    };

    let svc = m.service.as_deref().unwrap_or("").trim();
    let meth = m.method.as_deref().unwrap_or("").trim();

    match m.r#type.as_ref() {
        None | Some(GrpcRouteRulesMatchesMethodType::Exact) => match (svc, meth) {
            ("", "") => ("/".to_string(), GrpcPathKind::Prefix),
            (s, "") => (format!("/{s}/"), GrpcPathKind::Prefix),
            ("", m_) => (
                format!("^/[^/]+/{}$", regex::escape(m_)),
                GrpcPathKind::Regex,
            ),
            (s, m_) => (format!("/{s}/{m_}"), GrpcPathKind::Exact),
        },
        Some(GrpcRouteRulesMatchesMethodType::RegularExpression) => match (svc, meth) {
            ("", "") => ("/".to_string(), GrpcPathKind::Prefix),
            (s, "") => (format!("^/{s}/[^/]+$"), GrpcPathKind::Regex),
            ("", m_) => (format!("^/[^/]+/{m_}$"), GrpcPathKind::Regex),
            (s, m_) => (format!("^/{s}/{m_}$"), GrpcPathKind::Regex),
        },
    }
}

/// Builds `MatchPredicates` from gRPC header matchers.
///
/// Returns `None` if any regex pattern is invalid (the whole match is skipped
/// per spec, mirroring the HTTPRoute behaviour in `filters::build_predicates`).
fn build_header_predicates(
    headers: Option<&[GrpcRouteRulesMatchesHeaders]>,
) -> Option<MatchPredicates> {
    use http::HeaderName;
    let mut result: Vec<HeaderPredicate> = Vec::new();
    let mut seen: Vec<HeaderName> = Vec::new();

    for h in headers.unwrap_or(&[]) {
        let name = match HeaderName::from_bytes(h.name.to_ascii_lowercase().as_bytes()) {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(header_name = %h.name, "Skipping invalid header name in GRPCRouteMatch");
                continue;
            }
        };
        if seen.contains(&name) {
            continue;
        }
        seen.push(name.clone());

        let matcher = match h.r#type.as_ref() {
            Some(GrpcRouteRulesMatchesHeadersType::RegularExpression) => {
                let re = Regex::new(&h.value).ok()?;
                ValueMatch::Regex(re)
            }
            _ => ValueMatch::Exact(h.value.clone()),
        };
        result.push(HeaderPredicate { name, matcher });
    }

    Some(MatchPredicates {
        method: None, // gRPC is always POST; no HTTP method predicate needed
        headers: result,
        query: vec![],
    })
}

/// Translates `GRPCRouteFilter` entries into `FilterAction` values.
///
/// Only `RequestHeaderModifier` and `ResponseHeaderModifier` are implemented.
/// `RequestMirror` and `ExtensionRef` are logged and skipped.
fn build_filters(filters: &[GrpcRouteRulesFilters]) -> Vec<FilterAction> {
    let mut out = Vec::new();
    for f in filters {
        match f.r#type {
            GrpcRouteRulesFiltersType::RequestHeaderModifier => {
                let Some(m) = &f.request_header_modifier else {
                    tracing::warn!("Skipping RequestHeaderModifier filter — payload is missing");
                    continue;
                };
                let add: Vec<(&str, &str)> = m
                    .add
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str()))
                    .collect();
                let set: Vec<(&str, &str)> = m
                    .set
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str()))
                    .collect();
                let remove: Vec<&str> = m
                    .remove
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(String::as_str)
                    .collect();
                match HeaderMod::parse(&add, &set, &remove) {
                    Ok(hm) => out.push(FilterAction::RequestHeaderModifier(hm)),
                    Err(e) => {
                        tracing::warn!(error = %e, "Skipping RequestHeaderModifier — invalid header")
                    }
                }
            }
            GrpcRouteRulesFiltersType::ResponseHeaderModifier => {
                let Some(m) = &f.response_header_modifier else {
                    tracing::warn!("Skipping ResponseHeaderModifier filter — payload is missing");
                    continue;
                };
                let add: Vec<(&str, &str)> = m
                    .add
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str()))
                    .collect();
                let set: Vec<(&str, &str)> = m
                    .set
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str()))
                    .collect();
                let remove: Vec<&str> = m
                    .remove
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(String::as_str)
                    .collect();
                match HeaderMod::parse(&add, &set, &remove) {
                    Ok(hm) => out.push(FilterAction::ResponseHeaderModifier(hm)),
                    Err(e) => {
                        tracing::warn!(error = %e, "Skipping ResponseHeaderModifier — invalid header")
                    }
                }
            }
            GrpcRouteRulesFiltersType::RequestMirror | GrpcRouteRulesFiltersType::ExtensionRef => {
                tracing::warn!(
                    filter_type = ?f.r#type,
                    "Skipping unsupported GRPCRouteFilter type"
                );
            }
        }
    }
    out
}

/// Translates per-backend `GRPCBackendRef.filters` into `FilterAction`s.
///
/// Only `RequestHeaderModifier` and `ResponseHeaderModifier` are allowed at
/// backend-ref scope per the spec; others are logged and skipped.
fn build_backend_ref_filters(filters: &[GrpcRouteRulesBackendRefsFilters]) -> Vec<FilterAction> {
    let mut out = Vec::new();
    for f in filters {
        match f.r#type {
            GrpcRouteRulesBackendRefsFiltersType::RequestHeaderModifier => {
                let Some(m) = &f.request_header_modifier else {
                    tracing::warn!(
                        "Skipping per-backend RequestHeaderModifier filter — payload is missing"
                    );
                    continue;
                };
                let add: Vec<(&str, &str)> = m
                    .add
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str()))
                    .collect();
                let set: Vec<(&str, &str)> = m
                    .set
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str()))
                    .collect();
                let remove: Vec<&str> = m
                    .remove
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(String::as_str)
                    .collect();
                match HeaderMod::parse(&add, &set, &remove) {
                    Ok(hm) => out.push(FilterAction::RequestHeaderModifier(hm)),
                    Err(e) => tracing::warn!(
                        error = %e,
                        "Skipping per-backend RequestHeaderModifier — invalid header"
                    ),
                }
            }
            GrpcRouteRulesBackendRefsFiltersType::ResponseHeaderModifier => {
                let Some(m) = &f.response_header_modifier else {
                    tracing::warn!(
                        "Skipping per-backend ResponseHeaderModifier filter — payload is missing"
                    );
                    continue;
                };
                let add: Vec<(&str, &str)> = m
                    .add
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str()))
                    .collect();
                let set: Vec<(&str, &str)> = m
                    .set
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str()))
                    .collect();
                let remove: Vec<&str> = m
                    .remove
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(String::as_str)
                    .collect();
                match HeaderMod::parse(&add, &set, &remove) {
                    Ok(hm) => out.push(FilterAction::ResponseHeaderModifier(hm)),
                    Err(e) => tracing::warn!(
                        error = %e,
                        "Skipping per-backend ResponseHeaderModifier — invalid header"
                    ),
                }
            }
            GrpcRouteRulesBackendRefsFiltersType::RequestMirror
            | GrpcRouteRulesBackendRefsFiltersType::ExtensionRef => {
                tracing::warn!(
                    filter_type = ?f.r#type,
                    "Skipping unsupported per-backend GRPCRouteFilter type"
                );
            }
        }
    }
    out
}

/// Resolve each backendRef to `(pod_addresses, weight)`.
fn resolve_weighted_backends(
    backend_refs: &[GrpcRouteRulesBackendRefs],
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

fn weight_of(b: &GrpcRouteRulesBackendRefs) -> u16 {
    match b.weight {
        None => 1,
        Some(w) if w <= 0 => 0,
        Some(w) => w.min(u16::MAX as i32) as u16,
    }
}

fn backend_group_name(refs: &[GrpcRouteRulesBackendRefs], ns: &str) -> String {
    match refs {
        [] => format!("{ns}/empty"),
        [single] => format!("{ns}/{}", single.name),
        [first, rest @ ..] => format!("{ns}/{}+{}more", first.name, rest.len()),
    }
}

/// Choose the representative `BackendProtocol` for a rule whose backendRefs may
/// declare different `appProtocol` values.
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

/// Select the `BackendTLSPolicy` to attach to a rule's `BackendGroup`.
fn pick_backend_tls(
    backend_refs: &[GrpcRouteRulesBackendRefs],
    route_ns: &str,
    policy_index: &BackendTlsIndex,
    group_name: &str,
) -> PolicyMatch {
    let mut best: Option<(Arc<UpstreamTls>, u16)> = None;
    let mut saw_invalid = false;

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
            "BackendTLSPolicy attached to one of this GRPCRoute rule's backends is invalid — \
             rule will return 502 (GEP-1897)"
        );
        return PolicyMatch::Invalid;
    }

    if let Some((ref tls, _)) = best {
        tracing::debug!(
            backend_group = group_name,
            sni = %tls.sni,
            "BackendTLSPolicy attached to GRPCRoute — originating TLS to upstream"
        );
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
                "Multiple BackendTLSPolicies across GRPCRoute backendRefs in one rule — \
                 using highest-weight ref's policy"
            );
        }
    }

    match best {
        None => PolicyMatch::None,
        Some((tls, _)) => PolicyMatch::Valid(tls),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(service: &str, method: &str) -> GrpcRouteRulesMatchesMethod {
        GrpcRouteRulesMatchesMethod {
            service: if service.is_empty() {
                None
            } else {
                Some(service.to_string())
            },
            method: if method.is_empty() {
                None
            } else {
                Some(method.to_string())
            },
            r#type: Some(GrpcRouteRulesMatchesMethodType::Exact),
        }
    }

    fn regex(service: &str, method: &str) -> GrpcRouteRulesMatchesMethod {
        GrpcRouteRulesMatchesMethod {
            service: if service.is_empty() {
                None
            } else {
                Some(service.to_string())
            },
            method: if method.is_empty() {
                None
            } else {
                Some(method.to_string())
            },
            r#type: Some(GrpcRouteRulesMatchesMethodType::RegularExpression),
        }
    }

    #[test]
    fn none_method_matches_all() {
        let (path, kind) = method_to_path(None);
        assert_eq!(path, "/");
        assert!(matches!(kind, GrpcPathKind::Prefix));
    }

    #[test]
    fn exact_service_and_method() {
        let m = exact("grpc.health.v1.Health", "Check");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, "/grpc.health.v1.Health/Check");
        assert!(matches!(kind, GrpcPathKind::Exact));
    }

    #[test]
    fn exact_service_only() {
        let m = exact("mypackage.MyService", "");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, "/mypackage.MyService/");
        assert!(matches!(kind, GrpcPathKind::Prefix));
    }

    #[test]
    fn exact_method_only() {
        let m = exact("", "SomeMethod");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, "^/[^/]+/SomeMethod$");
        assert!(matches!(kind, GrpcPathKind::Regex));
    }

    #[test]
    fn exact_method_special_chars_escaped() {
        let m = exact("", "Method.v2");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, r"^/[^/]+/Method\.v2$");
        assert!(matches!(kind, GrpcPathKind::Regex));
    }

    #[test]
    fn exact_both_empty_failsoft_prefix() {
        let m = exact("", "");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, "/");
        assert!(matches!(kind, GrpcPathKind::Prefix));
    }

    #[test]
    fn regex_service_and_method() {
        let m = regex("mypackage\\..*", "Get.*");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, "^/mypackage\\..*/Get.*$");
        assert!(matches!(kind, GrpcPathKind::Regex));
    }

    #[test]
    fn regex_service_only() {
        let m = regex("mypackage\\..*", "");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, "^/mypackage\\..*/[^/]+$");
        assert!(matches!(kind, GrpcPathKind::Regex));
    }

    #[test]
    fn regex_method_only() {
        let m = regex("", "Get.*");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, "^/[^/]+/Get.*$");
        assert!(matches!(kind, GrpcPathKind::Regex));
    }

    #[test]
    fn regex_both_empty_failsoft_prefix() {
        let m = regex("", "");
        let (path, kind) = method_to_path(Some(&m));
        assert_eq!(path, "/");
        assert!(matches!(kind, GrpcPathKind::Prefix));
    }

    #[test]
    fn header_predicates_dedup_by_name() {
        let headers = vec![
            GrpcRouteRulesMatchesHeaders {
                name: "X-Version".to_string(),
                value: "v1".to_string(),
                r#type: None,
            },
            GrpcRouteRulesMatchesHeaders {
                name: "x-version".to_string(), // same canonical name, must be deduplicated
                value: "v2".to_string(),
                r#type: None,
            },
        ];
        let preds = build_header_predicates(Some(&headers)).unwrap();
        assert_eq!(preds.headers.len(), 1);
        assert!(matches!(&preds.headers[0].matcher, ValueMatch::Exact(v) if v == "v1"));
    }

    #[test]
    fn header_predicates_regex_invalid_returns_none() {
        let headers = vec![GrpcRouteRulesMatchesHeaders {
            name: "x-test".to_string(),
            value: "[invalid".to_string(),
            r#type: Some(GrpcRouteRulesMatchesHeadersType::RegularExpression),
        }];
        assert!(build_header_predicates(Some(&headers)).is_none());
    }

    #[test]
    fn header_predicates_method_always_none() {
        let headers = vec![GrpcRouteRulesMatchesHeaders {
            name: "x-trace".to_string(),
            value: "abc".to_string(),
            r#type: None,
        }];
        let preds = build_header_predicates(Some(&headers)).unwrap();
        assert!(
            preds.method.is_none(),
            "gRPC method predicate must always be None"
        );
    }
}
