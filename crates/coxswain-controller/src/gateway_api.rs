use crate::endpoints;
use crate::tls::{
    GatewayListenerHealth, HttpRouteHealthMap, ListenerTlsOutcome, RouteParentHealth, load_tls_cert,
};
use coxswain_core::ownership::parent_ref_owned;
use coxswain_core::reference_grants;
use coxswain_core::routing::{
    FilterAction, HeaderMod, HeaderPredicate, HostRouterBuilder, MatchPredicates, PathModifier,
    QueryPredicate, RouteEntry, RouteTimeouts, RoutingTableBuilder, Upstream, ValueMatch,
};
use coxswain_core::tls::TlsStoreBuilder;
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayListenersAllowedRoutesNamespacesFrom, GatewayListenersTlsMode,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteRulesBackendRefs, HttpRouteRulesFilters, HttpRouteRulesFiltersType,
    HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPathType,
    HttpRouteRulesMatchesQueryParamsType, HttpRouteRulesTimeouts,
};
use http::{HeaderName, Method};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

/// Parse a Gateway API GEP-2257 duration string (Go `time.ParseDuration` format).
///
/// Supported units: `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`. Values may be compounded
/// without spaces (`"1h30m"`). Returns `None` for zero (`"0s"`, `"0"`) or invalid input.
fn parse_gateway_duration(s: &str) -> Option<std::time::Duration> {
    if s.is_empty() || s == "0" {
        return None;
    }
    let mut total = std::time::Duration::ZERO;
    let mut remaining = s;
    while !remaining.is_empty() {
        // Consume the numeric part (digits + optional single decimal point).
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());
        if num_end == 0 {
            tracing::warn!(raw = s, "Skipping invalid Gateway API duration string");
            return None;
        }
        let num: f64 = match remaining[..num_end].parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(raw = s, "Skipping invalid Gateway API duration string");
                return None;
            }
        };
        remaining = &remaining[num_end..];
        // Consume the unit part.
        let unit_end = remaining
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(remaining.len());
        let unit = &remaining[..unit_end];
        remaining = &remaining[unit_end..];
        let unit_dur = match unit {
            "ns" => std::time::Duration::from_nanos(num as u64),
            "us" | "µs" => std::time::Duration::from_micros(num as u64),
            "ms" => std::time::Duration::from_millis(num as u64),
            "s" => std::time::Duration::from_secs_f64(num),
            "m" => std::time::Duration::from_secs_f64(num * 60.0),
            "h" => std::time::Duration::from_secs_f64(num * 3600.0),
            _ => {
                tracing::warn!(
                    raw = s,
                    unit,
                    "Skipping unsupported unit in Gateway API duration string"
                );
                return None;
            }
        };
        total += unit_dur;
    }
    if total.is_zero() { None } else { Some(total) }
}

fn parse_rule_timeouts(t: &HttpRouteRulesTimeouts) -> RouteTimeouts {
    RouteTimeouts {
        request: t.request.as_deref().and_then(parse_gateway_duration),
        backend_request: t
            .backend_request
            .as_deref()
            .and_then(parse_gateway_duration),
    }
}

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
        owned_gateways: &HashSet<(String, String)>,
        grants: &HashSet<(String, String, Option<String>)>,
        listener_hostnames: &HashMap<(String, String, String), String>,
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

        let route_hostnames: Vec<&str> = route
            .spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();

        // Effective hostnames = union over all parentRef listeners of:
        //   - listener hostname empty + route hostnames empty → catchall
        //   - listener hostname empty + route has hostnames → all route hostnames
        //   - listener has hostname + route hostnames empty → listener hostname
        //   - listener has hostname + route has hostnames → intersection
        // When listener_hostnames map is empty (tests) fall back to old behavior.
        let mut use_catchall = false;
        let mut eff_set: HashSet<String> = HashSet::new();
        let parent_refs = route.spec.parent_refs.as_deref().unwrap_or(&[]);

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
                    let key = (gw_ns.to_string(), gw_name.to_string(), sn.to_string());
                    listener_hostnames
                        .get(&key)
                        .map(|h| h.as_str())
                        .into_iter()
                        .collect()
                } else {
                    listener_hostnames
                        .iter()
                        .filter(|((ns, n, _), _)| ns == gw_ns && n == gw_name)
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
                        for rh in &route_hostnames {
                            if hostname_matches(rh, lh) {
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
        //
        // "Claims exclusively" has different semantics for wildcard vs concrete hostnames:
        //   - Concrete E (no `*.`): another listener L' claims it if L' is more specific than
        //     our L and hostname_matches(E, H_L') — i.e. any request for E would prefer L'.
        //   - Wildcard E (`*.X`): another listener L' claims ALL of E only if L' has the exact
        //     same wildcard pattern H_L' == E.  A more-specific exact listener (e.g. `foo.X`)
        //     only claims one host out of the wildcard set, so it does NOT dominate the wildcard.
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
                        .get(&(gw_ns.to_string(), gw_name.to_string(), our_sn.to_string()))
                        .map(|h| listener_specificity(h))
                        .unwrap_or(0);
                    let e_is_wildcard = e.starts_with("*.");
                    listener_hostnames.iter().any(|((ns, gw, ln), h_other)| {
                        ns == gw_ns
                            && gw == gw_name
                            && ln.as_str() != our_sn
                            && listener_specificity(h_other) > our_spec
                            && if e_is_wildcard {
                                // Wildcard E is dominated only by an identical wildcard listener.
                                h_other == e
                            } else {
                                // Concrete E is dominated by any more-specific listener that covers it.
                                hostname_matches(e, h_other)
                            }
                    })
                })
            });
        }

        let effective_hostnames: Vec<String> = eff_set.into_iter().collect();

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
                .map(parse_rule_timeouts)
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

                let addrs =
                    Self::resolve_upstream_addrs(backend_refs, route_ns, slices, services, grants);
                if addrs.is_empty() {
                    tracing::warn!(
                        route = ?route.metadata.name,
                        "No ready endpoints for rule — installing error route (500)"
                    );
                    (
                        Arc::new(Upstream::new(format!("{route_ns}/error-sentinel"), vec![])),
                        Some(500u16),
                    )
                } else {
                    (
                        Arc::new(Upstream::new(
                            format!("{route_ns}/{}", backend_refs[0].name),
                            addrs,
                        )),
                        None,
                    )
                }
            };

            // Default to PathPrefix "/" when no matches are specified (Gateway API §4.1).
            let apply = |pb: &mut HostRouterBuilder| match rule.matches.as_deref() {
                None | Some([]) => {
                    let filters = Self::build_filters(rule_filters, "/", false);
                    let mut e = RouteEntry::with_filters(
                        Arc::clone(&upstream),
                        MatchPredicates::default(),
                        filters,
                        rule_timeouts.clone(),
                        route_id.clone(),
                        created_at,
                    );
                    e.error_status = error_status;
                    pb.add_prefix_route("/", Arc::new(e));
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

                        let val = m
                            .path
                            .as_ref()
                            .and_then(|p| p.value.as_deref())
                            .unwrap_or("/");

                        let is_prefix = matches!(
                            m.path.as_ref().and_then(|p| p.r#type.as_ref()),
                            None | Some(HttpRouteRulesMatchesPathType::PathPrefix)
                        );
                        let filters = Self::build_filters(rule_filters, val, is_prefix);

                        let mut e = RouteEntry::with_filters(
                            Arc::clone(&upstream),
                            predicates,
                            filters,
                            rule_timeouts.clone(),
                            route_id.clone(),
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
        cert_grants: &HashSet<(String, String, Option<String>)>,
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

    /// Translates `HTTPRouteFilter` entries into `FilterAction` values.
    ///
    /// `matched_prefix` is the path pattern for this match rule (used for
    /// `ReplacePrefixMatch`). `is_prefix_match` signals whether the path type is
    /// `PathPrefix`; if it is not, a `ReplacePrefixMatch` path modifier is invalid
    /// per spec and will be skipped with a warning.
    fn build_filters(
        filters: &[HttpRouteRulesFilters],
        matched_prefix: &str,
        is_prefix_match: bool,
    ) -> Vec<FilterAction> {
        let mut out = Vec::new();
        for f in filters {
            match f.r#type {
                HttpRouteRulesFiltersType::RequestHeaderModifier => {
                    let Some(m) = &f.request_header_modifier else {
                        tracing::warn!(
                            "Skipping RequestHeaderModifier filter — payload is missing"
                        );
                        continue;
                    };
                    out.push(FilterAction::RequestHeaderModifier(HeaderMod {
                        add: m
                            .add
                            .as_deref()
                            .unwrap_or(&[])
                            .iter()
                            .map(|h| (h.name.clone(), h.value.clone()))
                            .collect(),
                        set: m
                            .set
                            .as_deref()
                            .unwrap_or(&[])
                            .iter()
                            .map(|h| (h.name.clone(), h.value.clone()))
                            .collect(),
                        remove: m.remove.clone().unwrap_or_default(),
                    }));
                }
                HttpRouteRulesFiltersType::ResponseHeaderModifier => {
                    let Some(m) = &f.response_header_modifier else {
                        tracing::warn!(
                            "Skipping ResponseHeaderModifier filter — payload is missing"
                        );
                        continue;
                    };
                    out.push(FilterAction::ResponseHeaderModifier(HeaderMod {
                        add: m
                            .add
                            .as_deref()
                            .unwrap_or(&[])
                            .iter()
                            .map(|h| (h.name.clone(), h.value.clone()))
                            .collect(),
                        set: m
                            .set
                            .as_deref()
                            .unwrap_or(&[])
                            .iter()
                            .map(|h| (h.name.clone(), h.value.clone()))
                            .collect(),
                        remove: m.remove.clone().unwrap_or_default(),
                    }));
                }
                HttpRouteRulesFiltersType::RequestRedirect => {
                    let Some(r) = &f.request_redirect else {
                        tracing::warn!("Skipping RequestRedirect filter — payload is missing");
                        continue;
                    };
                    let path = Self::parse_redirect_path(&r.path, matched_prefix, is_prefix_match);
                    let scheme = r.scheme.as_ref().map(|s| {
                        use gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersRequestRedirectScheme;
                        match s {
                            HttpRouteRulesFiltersRequestRedirectScheme::Http => "http".to_string(),
                            HttpRouteRulesFiltersRequestRedirectScheme::Https => {
                                "https".to_string()
                            }
                        }
                    });
                    let status_code = r.status_code.unwrap_or(302) as u16;
                    out.push(FilterAction::RequestRedirect {
                        scheme,
                        hostname: r.hostname.clone(),
                        port: r.port.map(|p| p as u16),
                        status_code,
                        path,
                    });
                }
                HttpRouteRulesFiltersType::UrlRewrite => {
                    let Some(rw) = &f.url_rewrite else {
                        tracing::warn!("Skipping URLRewrite filter — payload is missing");
                        continue;
                    };
                    let path = rw.path.as_ref().and_then(|p| {
                        Self::parse_url_rewrite_path(p, matched_prefix, is_prefix_match)
                    });
                    out.push(FilterAction::UrlRewrite {
                        hostname: rw.hostname.clone(),
                        path,
                    });
                }
                HttpRouteRulesFiltersType::RequestMirror
                | HttpRouteRulesFiltersType::ExtensionRef
                | HttpRouteRulesFiltersType::Cors => {
                    tracing::warn!(
                        filter_type = ?f.r#type,
                        "Skipping unsupported HTTPRouteFilter type"
                    );
                }
            }
        }
        out
    }

    fn parse_redirect_path(
        path: &Option<
            gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersRequestRedirectPath,
        >,
        matched_prefix: &str,
        is_prefix_match: bool,
    ) -> Option<PathModifier> {
        use gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersRequestRedirectPathType;
        let p = path.as_ref()?;
        match p.r#type {
            HttpRouteRulesFiltersRequestRedirectPathType::ReplaceFullPath => Some(
                PathModifier::ReplaceFullPath(p.replace_full_path.clone().unwrap_or_default()),
            ),
            HttpRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch => {
                if !is_prefix_match {
                    tracing::warn!(
                        "ReplacePrefixMatch path modifier used with non-prefix match — skipping path modifier"
                    );
                    return None;
                }
                Some(PathModifier::ReplacePrefixMatch {
                    prefix: matched_prefix.to_string(),
                    replacement: p.replace_prefix_match.clone().unwrap_or_default(),
                })
            }
        }
    }

    fn parse_url_rewrite_path(
        path: &gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersUrlRewritePath,
        matched_prefix: &str,
        is_prefix_match: bool,
    ) -> Option<PathModifier> {
        use gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersUrlRewritePathType;
        match path.r#type {
            HttpRouteRulesFiltersUrlRewritePathType::ReplaceFullPath => Some(
                PathModifier::ReplaceFullPath(path.replace_full_path.clone().unwrap_or_default()),
            ),
            HttpRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch => {
                if !is_prefix_match {
                    tracing::warn!(
                        "ReplacePrefixMatch path modifier used with non-prefix match — skipping path modifier"
                    );
                    return None;
                }
                Some(PathModifier::ReplacePrefixMatch {
                    prefix: matched_prefix.to_string(),
                    replacement: path.replace_prefix_match.clone().unwrap_or_default(),
                })
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
        services: &reflector::Store<Service>,
        grants: &HashSet<(String, String, Option<String>)>,
    ) -> Vec<SocketAddr> {
        backend_refs
            .iter()
            .filter_map(|b| b.port.map(|port| (b, port)))
            .flat_map(|(b, port)| {
                let b_kind = b.kind.as_deref().unwrap_or("Service");
                let b_group = b.group.as_deref().unwrap_or("");
                if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                    return vec![];
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
                    return vec![];
                }
                endpoints::resolve(ns, &b.name, port, slices, services)
            })
            .collect()
    }

    /// Computes `Accepted` and `ResolvedRefs` health for every (route, parent) pair
    /// that references an owned gateway. Called during the reconciler's rebuild so the
    /// controller can write accurate HTTPRoute status conditions.
    pub fn compute_route_health(
        routes: &[Arc<HTTPRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<(String, String)>,
        backend_grants: &HashSet<(String, String, Option<String>)>,
        slice_store: &reflector::Store<EndpointSlice>,
        service_store: &reflector::Store<Service>,
    ) -> HttpRouteHealthMap {
        // (listener_name, hostname, allows_all_ns, port)
        type ListenerInfo = Vec<(String, String, bool, u16)>;
        // Build listener info map: (gw_ns, gw_name) → ListenerInfo
        // allows_all_ns = true when allowedRoutes.namespaces.from is All or Selector (not Same).
        let gw_listeners: HashMap<(String, String), ListenerInfo> = gateways
            .iter()
            .filter_map(|gw| {
                let ns = gw.metadata.namespace.as_deref()?.to_string();
                let name = gw.metadata.name.as_deref()?.to_string();
                if !owned_gateways.contains(&(ns.clone(), name.clone())) {
                    return None;
                }
                let listeners: Vec<(String, String, bool, u16)> = gw
                    .spec
                    .listeners
                    .iter()
                    .map(|l| {
                        let allows_all = l
                            .allowed_routes
                            .as_ref()
                            .and_then(|ar| ar.namespaces.as_ref())
                            .and_then(|ns| ns.from.as_ref())
                            .map(|f| {
                                !matches!(f, GatewayListenersAllowedRoutesNamespacesFrom::Same)
                            })
                            .unwrap_or(false);
                        (
                            l.name.clone(),
                            l.hostname.as_deref().unwrap_or("").to_string(),
                            allows_all,
                            l.port as u16,
                        )
                    })
                    .collect();
                Some(((ns, name), listeners))
            })
            .collect();

        let mut map = HttpRouteHealthMap::new();

        for route in routes {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
            let route_name = route.metadata.name.as_deref().unwrap_or("unknown");
            let route_hostnames: Vec<&str> = route
                .spec
                .hostnames
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(String::as_str)
                .collect();

            for pr in route.spec.parent_refs.as_deref().unwrap_or(&[]) {
                let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
                let gw_name = pr.name.as_str();
                let gw_key = (gw_ns.to_string(), gw_name.to_string());

                if !owned_gateways.contains(&gw_key) {
                    continue;
                }

                let section = pr.section_name.as_deref().unwrap_or("").to_string();
                let health_key = (
                    route_ns.to_string(),
                    route_name.to_string(),
                    gw_ns.to_string(),
                    gw_name.to_string(),
                    section.clone(),
                );

                // Cross-namespace check: reject routes whose namespace is not allowed by the
                // listener. Default per spec is Same (only same namespace); must be All or
                // Selector to permit cross-namespace parentRefs.
                if gw_ns != route_ns {
                    let blocked = gw_listeners.get(&gw_key).is_some_and(|ls| {
                        let relevant: Vec<_> = if section.is_empty() {
                            ls.iter().collect()
                        } else {
                            ls.iter()
                                .filter(|(n, _, _, _)| n.as_str() == section)
                                .collect()
                        };
                        !relevant.is_empty() && relevant.iter().all(|(_, _, allows, _)| !allows)
                    });
                    if blocked {
                        map.insert(
                            health_key,
                            RouteParentHealth {
                                accepted: false,
                                accepted_reason: "NotAllowedByListeners",
                                resolved_refs: true,
                                resolved_refs_reason: "ResolvedRefs",
                            },
                        );
                        continue;
                    }
                }

                // Strip allows_all bool, keep port for port-matching check.
                let listeners_hn: ListenerHnMap = std::iter::once((
                    gw_key.clone(),
                    gw_listeners
                        .get(&gw_key)
                        .map(|ls| {
                            ls.iter()
                                .map(|(n, h, _, p)| (n.clone(), h.clone(), *p))
                                .collect()
                        })
                        .unwrap_or_default(),
                ))
                .collect();

                let (accepted, accepted_reason) = compute_accepted(
                    &route_hostnames,
                    &section,
                    pr.port.map(|p| p as u16),
                    &gw_key,
                    &listeners_hn,
                );

                let (resolved_refs, resolved_refs_reason) = if accepted {
                    check_backend_refs(route, route_ns, backend_grants, service_store, slice_store)
                } else {
                    (true, "ResolvedRefs")
                };

                map.insert(
                    health_key,
                    RouteParentHealth {
                        resolved_refs,
                        resolved_refs_reason,
                        accepted,
                        accepted_reason,
                    },
                );
            }
        }

        map
    }
}

/// `(listener_name, hostname, port)` stripped of the `allows_all` flag; passed to
/// `compute_accepted` where cross-namespace checks are already done.
type ListenerHnEntry = (String, String, u16);
type ListenerHnMap = HashMap<(String, String), Vec<ListenerHnEntry>>;

/// Returns `(accepted, reason)` for one (route, parent) pair based on listener hostname and port
/// matching.
fn compute_accepted(
    route_hostnames: &[&str],
    section_name: &str,
    port: Option<u16>,
    gw_key: &(String, String),
    gw_listeners: &ListenerHnMap,
) -> (bool, &'static str) {
    let Some(listeners) = gw_listeners.get(gw_key) else {
        return (true, "Accepted");
    };

    if !section_name.is_empty() {
        let matching: Vec<&(String, String, u16)> = listeners
            .iter()
            .filter(|(n, _, _)| n == section_name)
            .collect();
        if matching.is_empty() {
            return (false, "NoMatchingParent");
        }
        // parentRef.port must match the named listener's port when specified.
        if let Some(p) = port
            && !matching.iter().any(|(_, _, lp)| *lp == p)
        {
            return (false, "NoMatchingParent");
        }
        let intersects = matching
            .iter()
            .any(|(_, hn, _)| hostnames_intersect(route_hostnames, hn));
        return if intersects {
            (true, "Accepted")
        } else {
            (false, "NoMatchingListenerHostname")
        };
    }

    // No sectionName: filter candidate listeners by port first (if specified).
    let port_filtered: Vec<&(String, String, u16)> = if let Some(p) = port {
        listeners.iter().filter(|(_, _, lp)| *lp == p).collect()
    } else {
        listeners.iter().collect()
    };

    if port.is_some() && port_filtered.is_empty() {
        return (false, "NoMatchingParent");
    }

    let intersects = port_filtered
        .iter()
        .any(|(_, hn, _)| hostnames_intersect(route_hostnames, hn));
    if intersects {
        (true, "Accepted")
    } else {
        (false, "NoMatchingListenerHostname")
    }
}

/// Listener isolation priority: exact hostname > wildcard (longer = more specific) > empty.
/// Returns a numeric rank: 0 = empty, wildcard length, usize::MAX = exact.
fn listener_specificity(hostname: &str) -> usize {
    if hostname.is_empty() {
        0
    } else if hostname.starts_with("*.") {
        hostname.len()
    } else {
        usize::MAX
    }
}

/// Returns true when `route_hostnames` and `listener_hostname` have at least one
/// hostname in common, according to Gateway API intersection semantics:
/// - Listener hostname `""` (absent) matches any route hostname.
/// - Route with no hostnames matches any listener hostname.
/// - Wildcard patterns (`*.example.com`) expand to match labels one level deep.
pub(crate) fn hostnames_intersect(route_hostnames: &[&str], listener_hostname: &str) -> bool {
    if listener_hostname.is_empty() {
        return true;
    }
    if route_hostnames.is_empty() {
        return true;
    }
    route_hostnames
        .iter()
        .any(|rh| hostname_matches(rh, listener_hostname))
}

fn hostname_matches(route_host: &str, listener_host: &str) -> bool {
    if route_host == listener_host {
        return true;
    }
    // Route wildcard `*.X` matches listener `Y.X` (single label prefix).
    // Require that the prefix ends with a dot so "*.bar.com" does NOT match "foobar.com"
    // (where "bar.com" appears as a substring but not a domain label boundary).
    if let Some(suffix) = route_host.strip_prefix("*.")
        && let Some(prefix) = listener_host.strip_suffix(suffix)
        && let Some(prefix) = prefix.strip_suffix('.')
        && !prefix.is_empty()
        && !prefix.contains('.')
    {
        return true;
    }
    // Listener wildcard `*.X` matches route `Y.X` (any depth — Gateway API GEP-719).
    // Same dot-boundary requirement: "*.wildcard.io" must NOT match "anotherwildcard.io".
    if let Some(suffix) = listener_host.strip_prefix("*.")
        && let Some(prefix) = route_host.strip_suffix(suffix)
        && let Some(prefix) = prefix.strip_suffix('.')
        && !prefix.is_empty()
    {
        return true;
    }
    false
}

/// Checks all backend refs in a route for validity.
/// Returns `(resolved_refs, reason)` — `resolved_refs=true` means all backends valid.
fn check_backend_refs(
    route: &HTTPRoute,
    route_ns: &str,
    backend_grants: &HashSet<(String, String, Option<String>)>,
    service_store: &reflector::Store<Service>,
    slice_store: &reflector::Store<EndpointSlice>,
) -> (bool, &'static str) {
    let _ = slice_store; // not used for existence check; kept for API symmetry
    for rule in route.spec.rules.as_deref().unwrap_or(&[]) {
        // Rules with RequestRedirect don't need backends
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
            let b_kind = b.kind.as_deref().unwrap_or("Service");
            let b_group = b.group.as_deref().unwrap_or("");

            // Unsupported kind/group
            if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                return (false, "InvalidKind");
            }

            let b_ns = b.namespace.as_deref().unwrap_or(route_ns);

            // Cross-namespace ref requires a ReferenceGrant
            if b_ns != route_ns
                && !reference_grants::backend_ref_allowed(route_ns, b_ns, &b.name, backend_grants)
            {
                return (false, "RefNotPermitted");
            }

            // Service must exist in the store
            if b.port.is_some() {
                let svc_key = reflector::ObjectRef::<Service>::new(&b.name).within(b_ns);
                if service_store.get(&svc_key).is_none() {
                    return (false, "BackendNotFound");
                }
            }
        }
    }
    (true, "ResolvedRefs")
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

    fn empty_svc_store() -> reflector::Store<Service> {
        reflector::store::Writer::<Service>::default().as_reader()
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

    /// Empty listener-hostname map for tests that don't exercise hostname scoping.
    fn no_listeners() -> HashMap<(String, String, String), String> {
        HashMap::new()
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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
            &empty_svc_store(),
            &owned(&[("other", "gw")]),
            &grants,
            &no_listeners(),
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            &no_listeners(),
            &mut builder,
        );
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

    // ── Filter tests ────────────────────────────────────────────────────────────

    use coxswain_core::routing::{FilterAction, PathModifier, RouteOutcome};
    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesFilters, HttpRouteRulesFiltersRequestHeaderModifier,
        HttpRouteRulesFiltersRequestHeaderModifierSet, HttpRouteRulesFiltersRequestRedirect,
        HttpRouteRulesFiltersResponseHeaderModifier,
        HttpRouteRulesFiltersResponseHeaderModifierAdd, HttpRouteRulesFiltersType,
        HttpRouteRulesFiltersUrlRewrite, HttpRouteRulesFiltersUrlRewritePath,
        HttpRouteRulesFiltersUrlRewritePathType,
    };

    fn make_route_with_filters(
        ns: &str,
        hostname: &str,
        path: &str,
        path_type: HttpRouteRulesMatchesPathType,
        svc: &str,
        filters: Vec<HttpRouteRulesFilters>,
    ) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec![hostname.to_string()]),
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: svc.to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    matches: Some(vec![path_match(path, path_type)]),
                    filters: Some(filters),
                    ..Default::default()
                }]),
            },
            ..Default::default()
        }
    }

    fn find_filters(
        table: &coxswain_core::routing::RoutingTable,
        host: &str,
        path: &str,
    ) -> std::sync::Arc<[FilterAction]> {
        let empty_hdrs = http::HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
        match table.find(host, path, &ctx) {
            RouteOutcome::Found(_, f, _) => f,
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn reconcile_request_header_modifier_stored() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_filters(
            "default",
            "example.com",
            "/",
            HttpRouteRulesMatchesPathType::PathPrefix,
            "svc",
            vec![HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::RequestHeaderModifier,
                request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
                    set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
                        name: "X-Env".to_string(),
                        value: "prod".to_string(),
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            &no_listeners(),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filters = find_filters(&table, "example.com", "/");
        assert_eq!(filters.len(), 1);
        match &filters[0] {
            FilterAction::RequestHeaderModifier(m) => {
                assert_eq!(m.set, vec![("X-Env".to_string(), "prod".to_string())]);
            }
            _ => panic!("expected RequestHeaderModifier"),
        }
    }

    #[test]
    fn reconcile_response_header_modifier_stored() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_filters(
            "default",
            "example.com",
            "/",
            HttpRouteRulesMatchesPathType::PathPrefix,
            "svc",
            vec![HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::ResponseHeaderModifier,
                response_header_modifier: Some(HttpRouteRulesFiltersResponseHeaderModifier {
                    add: Some(vec![HttpRouteRulesFiltersResponseHeaderModifierAdd {
                        name: "X-Served-By".to_string(),
                        value: "coxswain".to_string(),
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            &no_listeners(),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filters = find_filters(&table, "example.com", "/");
        assert_eq!(filters.len(), 1);
        match &filters[0] {
            FilterAction::ResponseHeaderModifier(m) => {
                assert_eq!(
                    m.add,
                    vec![("X-Served-By".to_string(), "coxswain".to_string())]
                );
            }
            _ => panic!("expected ResponseHeaderModifier"),
        }
    }

    #[test]
    fn reconcile_request_redirect_stored() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_filters(
            "default",
            "example.com",
            "/old",
            HttpRouteRulesMatchesPathType::PathPrefix,
            "svc",
            vec![HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::RequestRedirect,
                request_redirect: Some(HttpRouteRulesFiltersRequestRedirect {
                    hostname: Some("new.example.com".to_string()),
                    status_code: Some(301),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            &no_listeners(),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filters = find_filters(&table, "example.com", "/old");
        assert_eq!(filters.len(), 1);
        match &filters[0] {
            FilterAction::RequestRedirect {
                hostname,
                status_code,
                ..
            } => {
                assert_eq!(hostname.as_deref(), Some("new.example.com"));
                assert_eq!(*status_code, 301);
            }
            _ => panic!("expected RequestRedirect"),
        }
    }

    #[test]
    fn reconcile_url_rewrite_replace_prefix_stored() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_filters(
            "default",
            "example.com",
            "/api",
            HttpRouteRulesMatchesPathType::PathPrefix,
            "svc",
            vec![HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::UrlRewrite,
                url_rewrite: Some(HttpRouteRulesFiltersUrlRewrite {
                    path: Some(HttpRouteRulesFiltersUrlRewritePath {
                        r#type: HttpRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch,
                        replace_prefix_match: Some("/v3".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            &no_listeners(),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filters = find_filters(&table, "example.com", "/api/users");
        assert_eq!(filters.len(), 1);
        match &filters[0] {
            FilterAction::UrlRewrite {
                hostname,
                path:
                    Some(PathModifier::ReplacePrefixMatch {
                        prefix,
                        replacement,
                    }),
            } => {
                assert!(hostname.is_none());
                assert_eq!(prefix, "/api");
                assert_eq!(replacement, "/v3");
            }
            _ => panic!("expected UrlRewrite with ReplacePrefixMatch"),
        }
    }

    // ── Timeout tests ────────────────────────────────────────────────────────────

    use std::time::Duration;

    fn find_timeouts(
        table: &coxswain_core::routing::RoutingTable,
        host: &str,
        path: &str,
    ) -> coxswain_core::routing::RouteTimeouts {
        let empty_hdrs = http::HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
        match table.find(host, path, &ctx) {
            RouteOutcome::Found(_, _, t) => t,
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn parse_gateway_duration_parses_common_values() {
        assert_eq!(
            super::parse_gateway_duration("10s"),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            super::parse_gateway_duration("500ms"),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            super::parse_gateway_duration("1m"),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            super::parse_gateway_duration("2h45m"),
            Some(Duration::from_secs(2 * 3600 + 45 * 60))
        );
    }

    #[test]
    fn parse_gateway_duration_zero_returns_none() {
        assert_eq!(super::parse_gateway_duration("0s"), None);
        assert_eq!(super::parse_gateway_duration("0"), None);
        assert_eq!(super::parse_gateway_duration(""), None);
    }

    #[test]
    fn parse_gateway_duration_invalid_returns_none() {
        assert_eq!(super::parse_gateway_duration("10x"), None);
        assert_eq!(super::parse_gateway_duration("abc"), None);
    }

    #[test]
    fn reconcile_timeouts_stored_and_round_trip() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);

        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: gateway_api::apis::standard::httproutes::HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![
                    gateway_api::apis::standard::httproutes::HttpRouteRules {
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        timeouts: Some(HttpRouteRulesTimeouts {
                            request: Some("10s".to_string()),
                            backend_request: Some("2s".to_string()),
                        }),
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
            &no_listeners(),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let t = find_timeouts(&table, "example.com", "/");
        assert_eq!(t.request, Some(Duration::from_secs(10)));
        assert_eq!(t.backend_request, Some(Duration::from_secs(2)));
    }

    // ── Listener isolation tests ──────────────────────────────────────────────────

    fn make_listener_hostnames(
        gw_ns: &str,
        gw_name: &str,
        listeners: &[(&str, &str)],
    ) -> HashMap<(String, String, String), String> {
        listeners
            .iter()
            .map(|(ln, h)| {
                (
                    (gw_ns.to_string(), gw_name.to_string(), ln.to_string()),
                    h.to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn listener_isolation_empty_listener_route_not_accessible_via_more_specific_listener() {
        // Route attached to empty-hostname listener with spec.hostnames containing *.example.com.
        // The gateway also has a *.example.com listener, which owns that hostname space.
        // The route should only be registered under bar.com (the non-dominated hostname).
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_hostnames_and_parent(
            "default",
            &["bar.com", "*.example.com"],
            "gw",
            Some("empty-listener"),
        );
        let listeners = make_listener_hostnames(
            "default",
            "gw",
            &[
                ("empty-listener", ""),
                ("specific-listener", "*.example.com"),
            ],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            &listeners,
            &mut builder,
        );
        let table = builder.build().unwrap();
        // bar.com is not dominated by any other listener → accessible
        assert!(
            table.route("bar.com", "/", &ctx_get()).is_some(),
            "bar.com should be routable"
        );
        // *.example.com is dominated by the specific listener → NOT accessible via bar.example.com
        assert!(
            table.route("bar.example.com", "/", &ctx_get()).is_none(),
            "bar.example.com should not leak from the empty-hostname listener"
        );
    }

    fn make_route_with_hostnames_and_parent(
        ns: &str,
        hostnames: &[&str],
        gw_name: &str,
        section_name: Option<&str>,
    ) -> HTTPRoute {
        use gateway_api::apis::standard::httproutes::HttpRouteSpec;
        HTTPRoute {
            metadata: kube::api::ObjectMeta {
                name: Some("test-route".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: gw_name.to_string(),
                    namespace: Some(ns.to_string()),
                    section_name: section_name.map(str::to_string),
                    ..Default::default()
                }]),
                hostnames: Some(hostnames.iter().map(|h| h.to_string()).collect()),
                rules: Some(vec![make_simple_rule("svc")]),
            },
            status: None,
        }
    }

    fn make_simple_rule(svc: &str) -> gateway_api::apis::standard::httproutes::HttpRouteRules {
        use gateway_api::apis::standard::httproutes::{HttpRouteRules, HttpRouteRulesBackendRefs};
        HttpRouteRules {
            backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                name: svc.to_string(),
                port: Some(8080),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    fn ctx_get() -> coxswain_core::routing::RequestContext<'static> {
        static METHOD: std::sync::LazyLock<Method> = std::sync::LazyLock::new(|| Method::GET);
        static HDRS: std::sync::LazyLock<http::HeaderMap> =
            std::sync::LazyLock::new(http::HeaderMap::new);
        coxswain_core::routing::RequestContext {
            method: &METHOD,
            headers: &HDRS,
            query: None,
        }
    }

    #[test]
    fn reconcile_timeouts_missing_field_falls_back_to_none() {
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
            &no_listeners(),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let t = find_timeouts(&table, "example.com", "/");
        assert!(t.request.is_none());
        assert!(t.backend_request.is_none());
    }
}
