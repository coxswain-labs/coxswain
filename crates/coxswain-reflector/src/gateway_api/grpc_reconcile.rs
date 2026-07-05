//! Translates `GRPCRoute` rules into routing-table entries.
//!
//! Mirrors the HTTPRoute reconciler in `reconcile.rs` as a sibling module. No
//! shared abstraction — the two reconcilers evolve independently. See the
//! module-level `//!` in `gateway_api/mod.rs` for the design rationale.

use super::backend_policy::{BackendPolicyIndex, ResolvedBackendPolicy};
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
use coxswain_core::crd::{IpAccessControl, RateLimit};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendGroup, BackendProtocol, FilterAction, GatewayRoutingTableBuilder, HeaderMod,
    HeaderPredicate, HostRouterBuilder, MatchPredicates, RouteEntry, RouteTimeouts, UpstreamTls,
    ValueMatch, WildcardKind, compile_bounded,
};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

/// Precomputed context for GRPCRoute reconciliation.
///
/// Slimmer than [`super::reconcile::RouteResolution`]: GRPCRoute supports the
/// protocol-agnostic ExtensionRef filters — `RateLimit` (#25) and `IpAccessControl`
/// (#479) — but not `PathRewriteRegex` (for gRPC the path *is* the
/// `/{service}/{method}` RPC address, so rewriting it is meaningless), nor
/// `BasicAuth`/`Compression` (HTTP-only idioms, #442/#446), nor `RequestSizeLimit`
/// (#443): a mid-stream body-size cap on HTTP/2 deadlocks the client under pingora
/// (#509), and gRPC never sends `Content-Length` for the up-front check to use — so
/// gRPC messages are size-limited by the backend's own `max_recv_msg_size` until
/// pingora supports request-body buffering (pingora #816/#780).
#[non_exhaustive]
pub struct GrpcRouteResolution<'a> {
    /// `(gw_ns, gw_name, listener_name) → (hostname, port)` for every listener on owned Gateways.
    pub listener_info: &'a HashMap<ListenerKey, ListenerBinding>,
    /// Per-(Service, port) `BackendTLSPolicy` lookup table.
    pub policy_index: &'a BackendTlsIndex,
    /// Per-`Service` connect/idle timeout index from `CoxswainBackendPolicy` (#354).
    pub backend_policy_index: &'a BackendPolicyIndex,
    /// `RateLimit` CR store for resolving `ExtensionRef` filters into per-route
    /// rate-limiting config (#25). A missing CR fails open (route not limited).
    pub rate_limits: &'a reflector::Store<RateLimit>,
    /// `IpAccessControl` CR store for resolving `ExtensionRef` filters into per-route
    /// source-IP allow/deny CIDR sets (#479). A missing CR fails open (no filtering).
    pub ip_access: &'a reflector::Store<IpAccessControl>,
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
        backend_policy_index,
        rate_limits,
        ip_access,
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
            super::bindings::parent_ref_attaches(
                p.group.as_deref(),
                p.kind.as_deref(),
                p.namespace.as_deref(),
                &p.name,
                route_ns,
                owned_gateways,
                listener_info,
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

        // GRPCRoute has no RequestRedirect — every rule resolves backends. A
        // rule with omitted or empty `backendRefs` is not skipped: like HTTPRoute
        // (see reconcile.rs), it routes with a distinct 500 rather than falling
        // through to a 404. GRPCRoute has no direct conformance analog of
        // `HTTPRouteNoBackendRefs`, so this is defensive parity — an empty slice
        // flows through to an empty `BackendGroup` whose `error_status` is 500.
        let backend_refs: &[GrpcRouteRulesBackendRefs] =
            rule.backend_refs.as_deref().unwrap_or(&[]);

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
        // CoxswainBackendPolicy: per-backend connect/idle timeouts (#354) and LB
        // algorithm (#389) on the BackendGroup; the circuit breaker (#478) is
        // RouteEntry-level and carried out to the GrpcRuleContext below.
        let bp = pick_backend_policy(backend_refs, route_ns, backend_policy_index);
        if let Some(bp) = bp {
            if bp.connect.is_some() {
                group = group.with_connect_timeout(bp.connect);
            }
            if bp.idle.is_some() {
                group = group.with_keepalive_timeout(bp.idle);
            }
            if let Some(lb) = &bp.load_balance {
                group = group.with_load_balance(lb.clone());
            }
        }
        let circuit_breaker = bp.and_then(|bp| bp.circuit_breaker.clone());
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

        let (allow_source_range, deny_source_range) =
            resolve_grpc_ip_access(rule_filters, route_ns, ip_access);
        let rate_limit = resolve_grpc_rate_limit(rule_filters, route_ns, rate_limits);
        let ctx = GrpcRuleContext {
            filters: rule_filters,
            error_status,
            route_id: &route_id,
            metric_route_id: &metric_route_id,
            created_at,
            circuit_breaker,
            rate_limit,
            allow_source_range,
            deny_source_range,
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

/// GRPCRoute counterpart to [`super::filters::resolve_ip_access`]: scans a rule's
/// filters for an `IpAccessControl` `ExtensionRef` and resolves it into the
/// `(allow, deny)` source-IP CIDR sets (#479). Source-IP filtering is
/// protocol-agnostic, so gRPC reuses the same per-ref resolver as HTTP; only the
/// filter-list iteration differs (the two route types have distinct filter structs).
fn resolve_grpc_ip_access(
    filters: &[GrpcRouteRulesFilters],
    route_ns: &str,
    ip_access: &reflector::Store<IpAccessControl>,
) -> (super::filters::CidrSet, super::filters::CidrSet) {
    for f in filters {
        if !matches!(f.r#type, GrpcRouteRulesFiltersType::ExtensionRef) {
            continue;
        }
        let Some(ext) = &f.extension_ref else {
            continue;
        };
        if let Some(res) = super::filters::resolve_ip_access_ref(
            &ext.group, &ext.kind, &ext.name, route_ns, ip_access,
        ) {
            return res;
        }
    }
    (None, None)
}

/// GRPCRoute counterpart to [`super::filters::resolve_rate_limit`]: scans a rule's
/// filters for a `RateLimit` `ExtensionRef` and resolves it into a
/// [`RateLimitConfig`] (#25). Rate limiting is protocol-agnostic (gRPC is HTTP/2;
/// IP- and header-keyed limiting both apply), so gRPC reuses the same per-ref
/// resolver as HTTP; only the filter-list iteration differs.
fn resolve_grpc_rate_limit(
    filters: &[GrpcRouteRulesFilters],
    route_ns: &str,
    rate_limits: &reflector::Store<RateLimit>,
) -> Option<Arc<coxswain_core::routing::RateLimitConfig>> {
    for f in filters {
        if !matches!(f.r#type, GrpcRouteRulesFiltersType::ExtensionRef) {
            continue;
        }
        let Some(ext) = &f.extension_ref else {
            continue;
        };
        if let Some(cfg) = super::filters::resolve_rate_limit_ref(
            &ext.group,
            &ext.kind,
            &ext.name,
            route_ns,
            rate_limits,
        ) {
            return cfg;
        }
    }
    None
}

struct GrpcRuleContext<'a> {
    filters: &'a [GrpcRouteRulesFilters],
    error_status: Option<u16>,
    route_id: &'a str,
    metric_route_id: &'a Arc<str>,
    created_at: Option<SystemTime>,
    /// Per-backend circuit breaker from the rule's winning `CoxswainBackendPolicy`
    /// (#478). Shared across every entry the rule installs.
    circuit_breaker: Option<Arc<coxswain_core::routing::CircuitBreakerConfig>>,
    /// Rate-limiting config resolved from the rule's `RateLimit` `ExtensionRef`
    /// (#25). Shared across every entry the rule installs.
    rate_limit: Option<Arc<coxswain_core::routing::RateLimitConfig>>,
    /// Source-IP allow-list resolved from the rule's `IpAccessControl` `ExtensionRef`
    /// (#479). Shared across every entry the rule installs.
    allow_source_range: Option<Arc<Vec<ipnet::IpNet>>>,
    /// Source-IP deny-list resolved from the same `IpAccessControl`. Enforced before
    /// `allow_source_range` in the proxy.
    deny_source_range: Option<Arc<Vec<ipnet::IpNet>>>,
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
            .with_rate_limit(ctx.rate_limit.clone())
            .with_allow_source_range(ctx.allow_source_range.clone())
            .with_deny_source_range(ctx.deny_source_range.clone())
            .with_circuit_breaker(ctx.circuit_breaker.clone())
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
                let re = compile_bounded(&h.value).ok()?;
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
            GrpcRouteRulesFiltersType::ExtensionRef => {
                // RateLimit (#25) and IpAccessControl (#479) ExtensionRefs are
                // resolved separately (into the route's rate-limit config and
                // source-IP allow/deny sets); any other ExtensionRef is unsupported
                // on GRPCRoute — notably BasicAuth (#442), Compression (#446), and
                // RequestSizeLimit (#443, see #509: a mid-stream h2 body cap deadlocks
                // the client under pingora; gRPC is limited by the backend instead).
                let supported = f.extension_ref.as_ref().is_some_and(|ext| {
                    ext.group == super::COXSWAIN_GROUP
                        && (ext.kind == "RateLimit" || ext.kind == "IpAccessControl")
                });
                if !supported {
                    tracing::warn!(
                        filter_type = ?f.r#type,
                        "Skipping unsupported GRPCRouteFilter ExtensionRef"
                    );
                }
            }
            GrpcRouteRulesFiltersType::RequestMirror => {
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

/// Select the `CoxswainBackendPolicy` timeouts to attach to a GRPCRoute rule's
/// `BackendGroup` (#354). Highest-weight backendRef's Service policy wins.
fn pick_backend_policy<'a>(
    backend_refs: &[GrpcRouteRulesBackendRefs],
    route_ns: &str,
    backend_policy_index: &'a BackendPolicyIndex,
) -> Option<&'a ResolvedBackendPolicy> {
    let mut best: Option<(&ResolvedBackendPolicy, u16)> = None;
    for b in backend_refs {
        let b_ns = b.namespace.as_deref().unwrap_or(route_ns);
        let Some(resolved) = backend_policy_index.get(&ObjectKey::new(b_ns, &b.name)) else {
            continue;
        };
        let w = match b.weight {
            None => 1u16,
            Some(w) if w <= 0 => 0u16,
            Some(w) => w.min(u16::MAX as i32) as u16,
        };
        match &best {
            None => best = Some((resolved, w)),
            Some((_, best_w)) if w > *best_w => best = Some((resolved, w)),
            _ => {}
        }
    }
    best.map(|(r, _)| r)
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

    // ── resolve_grpc_ip_access (#479) ─────────────────────────────────────────

    fn grpc_ip_access_filter(name: &str) -> GrpcRouteRulesFilters {
        use crate::gw_types::v::grpcroutes::GrpcRouteRulesFiltersExtensionRef;
        GrpcRouteRulesFilters {
            r#type: GrpcRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(GrpcRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "IpAccessControl".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    // `IpAccessControlSpec` is `#[non_exhaustive]` — deserialize a CR instead.
    fn ip_access_cr(ns: &str, name: &str, allow: &[&str], deny: &[&str]) -> IpAccessControl {
        let list = |items: &[&str]| -> String {
            if items.is_empty() {
                " []".to_string()
            } else {
                items.iter().map(|s| format!("\n    - {s}")).collect()
            }
        };
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: IpAccessControl\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  allow:{}\n  deny:{}\n",
            list(allow),
            list(deny),
        );
        serde_yaml::from_str(&yaml).expect("valid IpAccessControl")
    }

    #[test]
    fn grpc_ip_access_resolves_allow_and_deny() {
        let store = crate::tests::fixtures::make_ip_access_store(vec![ip_access_cr(
            "default",
            "policy",
            &["203.0.113.0/24"],
            &["10.0.0.0/8"],
        )]);
        let (allow, deny) =
            resolve_grpc_ip_access(&[grpc_ip_access_filter("policy")], "default", &store);
        assert_eq!(
            *allow.expect("allow set"),
            vec!["203.0.113.0/24".parse::<ipnet::IpNet>().expect("valid")]
        );
        assert_eq!(
            *deny.expect("deny set"),
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().expect("valid")]
        );
    }

    #[test]
    fn grpc_ip_access_no_ext_ref_is_none() {
        let store = crate::tests::fixtures::empty_ip_access_store();
        let (allow, deny) = resolve_grpc_ip_access(&[], "default", &store);
        assert!(allow.is_none() && deny.is_none());
    }

    #[test]
    fn grpc_ip_access_missing_cr_fails_open() {
        let store = crate::tests::fixtures::empty_ip_access_store();
        let (allow, deny) =
            resolve_grpc_ip_access(&[grpc_ip_access_filter("absent")], "default", &store);
        assert!(
            allow.is_none() && deny.is_none(),
            "missing CR must not filter"
        );
    }

    // ── resolve_grpc_rate_limit (#25) ─────────────────────────────────────────

    fn grpc_rate_limit_filter(name: &str) -> GrpcRouteRulesFilters {
        use crate::gw_types::v::grpcroutes::GrpcRouteRulesFiltersExtensionRef;
        GrpcRouteRulesFilters {
            r#type: GrpcRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(GrpcRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "RateLimit".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    // `RateLimitSpec` is `#[non_exhaustive]` — deserialize a CR instead.
    fn rate_limit_cr(ns: &str, name: &str, rps: u32) -> RateLimit {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RateLimit\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  requestsPerSecond: {rps}\n",
        );
        serde_yaml::from_str(&yaml).expect("valid RateLimit")
    }

    #[test]
    fn grpc_rate_limit_resolves_config() {
        let store =
            crate::tests::fixtures::make_rate_limit_store(vec![rate_limit_cr("default", "rl", 10)]);
        let cfg = resolve_grpc_rate_limit(&[grpc_rate_limit_filter("rl")], "default", &store)
            .expect("rate limit resolved");
        assert_eq!(cfg.requests_per_second.get(), 10);
    }

    #[test]
    fn grpc_rate_limit_no_ext_ref_is_none() {
        let store = crate::tests::fixtures::empty_rate_limit_store();
        assert!(resolve_grpc_rate_limit(&[], "default", &store).is_none());
    }

    #[test]
    fn grpc_rate_limit_missing_cr_fails_open() {
        let store = crate::tests::fixtures::empty_rate_limit_store();
        assert!(
            resolve_grpc_rate_limit(&[grpc_rate_limit_filter("absent")], "default", &store)
                .is_none(),
            "missing CR must fail open (no rate limiting)"
        );
    }

    /// A GRPCRoute attached to owned Gateway `default/gw` whose single rule
    /// (matching every method) carries the given `backend_refs` verbatim.
    fn grpc_route_with_backend_refs(
        backend_refs: Option<Vec<GrpcRouteRulesBackendRefs>>,
    ) -> GrpcRoute {
        use crate::gw_types::v::grpcroutes::{GrpcRouteParentRefs, GrpcRouteRules, GrpcRouteSpec};
        use kube::api::ObjectMeta;
        GrpcRoute {
            metadata: ObjectMeta {
                name: Some("grpc-route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GrpcRouteSpec {
                parent_refs: Some(vec![GrpcRouteParentRefs {
                    name: "gw".to_string(),
                    ..Default::default()
                }]),
                hostnames: None,
                rules: Some(vec![GrpcRouteRules {
                    backend_refs,
                    ..Default::default()
                }]),
            },
            ..Default::default()
        }
    }

    /// Reconcile `route` against empty stores + a single listener on `default/gw`
    /// (port 80, any hostname) and return the built routing table.
    fn reconcile_grpc_route_only(route: &GrpcRoute) -> coxswain_core::routing::GatewayRoutingTable {
        use crate::gateway_api::tests::{default_owned, make_listener_info};
        use crate::tests::fixtures::{
            empty_ip_access_store, empty_rate_limit_store, empty_svc_store,
        };
        let listener_info = make_listener_info("default", "gw", &[("l1", "", 80)]);
        let mut builder = GatewayRoutingTableBuilder::new();
        reconcile(
            route,
            &crate::tests::fixtures::slice_store(vec![]),
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            GrpcRouteResolution {
                listener_info: &listener_info,
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                ip_access: &empty_ip_access_store(),
            },
            &mut builder,
        );
        builder.build().unwrap()
    }

    #[test]
    fn grpc_omitted_backend_refs_installs_500() {
        // Defensive parity with HTTPRoute (no gRPC conformance analog): a rule
        // with omitted backendRefs routes with a distinct 500, not a 404.
        use crate::gateway_api::tests::ctx_get;
        let table = reconcile_grpc_route_only(&grpc_route_with_backend_refs(None));
        assert!(
            matches!(
                table.find(80, "any.example.com", "/", &ctx_get()),
                coxswain_core::routing::RouteOutcome::Error(500)
            ),
            "gRPC rule with omitted backendRefs must resolve to Error(500)"
        );
    }

    #[test]
    fn grpc_empty_backend_refs_installs_500() {
        use crate::gateway_api::tests::ctx_get;
        let table = reconcile_grpc_route_only(&grpc_route_with_backend_refs(Some(vec![])));
        assert!(
            matches!(
                table.find(80, "any.example.com", "/", &ctx_get()),
                coxswain_core::routing::RouteOutcome::Error(500)
            ),
            "gRPC rule with empty backendRefs must resolve to Error(500)"
        );
    }
}
