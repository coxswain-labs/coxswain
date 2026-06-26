//! Translates `HTTPRouteRule` filter specs into [`FilterAction`][coxswain_core::routing::FilterAction]s.

use crate::endpoints;
use crate::gw_types::v::httproutes::{
    HttpRouteRulesBackendRefsFilters, HttpRouteRulesBackendRefsFiltersType, HttpRouteRulesFilters,
    HttpRouteRulesFiltersCors, HttpRouteRulesFiltersType, HttpRouteRulesMatchesHeadersType,
    HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesQueryParamsType,
};
use coxswain_core::crd::RateLimit;
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendGroup, CorsConfig, CorsOrigin, FilterAction, HeaderMod, HeaderPredicate,
    MatchPredicates, MirrorFraction, PathModifier, QueryPredicate, RateLimitConfig, RateLimitKey,
    ValueMatch,
};
use http::{HeaderName, Method};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use regex::Regex;
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;

/// Store references needed to resolve `backendRef` targets in filters (e.g.
/// `RequestMirror`).
pub(super) struct BackendStores<'a> {
    pub(super) slices: &'a reflector::Store<EndpointSlice>,
    pub(super) services: &'a reflector::Store<Service>,
    pub(super) grants: &'a HashSet<ReferenceGrantKey>,
}

/// Translates `HTTPRouteFilter` entries into `FilterAction` values.
///
/// `matched_prefix` is the path pattern for this match rule (used for
/// `ReplacePrefixMatch`). `is_prefix_match` signals whether the path type is
/// `PathPrefix`; if it is not, a `ReplacePrefixMatch` path modifier is invalid
/// per spec and will be skipped with a warning.
///
/// `stores` carries the reflector stores required to resolve the `backendRef`
/// inside each `RequestMirror` filter (GEP-3171, #261).
pub(super) fn build_filters(
    filters: &[HttpRouteRulesFilters],
    matched_prefix: &str,
    is_prefix_match: bool,
    route_ns: &str,
    path_rewrites: &reflector::Store<coxswain_core::crd::PathRewriteRegex>,
    stores: &BackendStores<'_>,
) -> Vec<FilterAction> {
    let mut out = Vec::new();
    for f in filters {
        match f.r#type {
            HttpRouteRulesFiltersType::RequestHeaderModifier => {
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
            HttpRouteRulesFiltersType::ResponseHeaderModifier => {
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
            HttpRouteRulesFiltersType::RequestRedirect => {
                let Some(r) = &f.request_redirect else {
                    tracing::warn!("Skipping RequestRedirect filter — payload is missing");
                    continue;
                };
                let path = parse_redirect_path(&r.path, matched_prefix, is_prefix_match);
                let scheme = r.scheme.as_ref().map(|s| {
                    use crate::gw_types::v::httproutes::HttpRouteRulesFiltersRequestRedirectScheme;
                    match s {
                        HttpRouteRulesFiltersRequestRedirectScheme::Http => "http".to_string(),
                        HttpRouteRulesFiltersRequestRedirectScheme::Https => "https".to_string(),
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
                let path = rw
                    .path
                    .as_ref()
                    .and_then(|p| parse_url_rewrite_path(p, matched_prefix, is_prefix_match));
                out.push(FilterAction::UrlRewrite {
                    hostname: rw.hostname.clone(),
                    path,
                });
            }
            HttpRouteRulesFiltersType::ExtensionRef => {
                let Some(ext) = &f.extension_ref else {
                    tracing::warn!("Skipping ExtensionRef filter — payload is missing");
                    continue;
                };
                if ext.group == "coxswain-labs.dev" && ext.kind == "PathRewriteRegex" {
                    let obj_ref =
                        reflector::ObjectRef::<coxswain_core::crd::PathRewriteRegex>::new(
                            &ext.name,
                        )
                        .within(route_ns);
                    if let Some(cr) = path_rewrites.get(&obj_ref) {
                        match regex::Regex::new(&cr.spec.pattern) {
                            Ok(regex) => {
                                out.push(FilterAction::UrlRewrite {
                                    hostname: None,
                                    path: Some(PathModifier::RegexReplace {
                                        regex: Arc::new(regex),
                                        replacement: Box::from(cr.spec.replacement.as_str()),
                                    }),
                                });
                            }
                            Err(e) => tracing::warn!(
                                name = %ext.name,
                                ns = route_ns,
                                error = %e,
                                "PathRewriteRegex CR has invalid regex — filter skipped"
                            ),
                        }
                    } else {
                        tracing::warn!(
                            name = %ext.name,
                            ns = route_ns,
                            "PathRewriteRegex CR not found — filter skipped"
                        );
                    }
                } else if ext.group == "coxswain-labs.dev" && ext.kind == "RateLimit" {
                    // Handled separately by `resolve_rate_limit`.
                } else {
                    tracing::warn!(
                        group = %ext.group,
                        kind = %ext.kind,
                        "Skipping unsupported ExtensionRef filter"
                    );
                }
            }
            HttpRouteRulesFiltersType::Cors => {
                let Some(cors) = &f.cors else {
                    tracing::warn!("Skipping CORS filter — cors payload is missing");
                    continue;
                };
                if let Some(cfg) = build_cors_config(cors) {
                    out.push(FilterAction::Cors(Arc::new(cfg)));
                }
            }
            HttpRouteRulesFiltersType::RequestMirror => {
                let Some(mirror) = &f.request_mirror else {
                    tracing::warn!(
                        "Skipping RequestMirror filter — request_mirror payload is missing"
                    );
                    continue;
                };
                let bref = &mirror.backend_ref;

                // Validate kind/group (only core Service is supported).
                let b_kind = bref.kind.as_deref().unwrap_or("Service");
                let b_group = bref.group.as_deref().unwrap_or("");
                if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                    tracing::warn!(
                        kind = b_kind,
                        group = b_group,
                        "Skipping RequestMirror — only core Service backendRefs are supported"
                    );
                    continue;
                }

                let Some(port) = bref.port else {
                    tracing::warn!(
                        name = %bref.name,
                        "Skipping RequestMirror — port is required"
                    );
                    continue;
                };

                let mirror_ns = bref.namespace.as_deref().unwrap_or(route_ns);

                // Cross-namespace mirror refs require a ReferenceGrant (GEP-3171).
                if mirror_ns != route_ns
                    && !reference_grants::backend_ref_allowed(
                        route_ns,
                        mirror_ns,
                        &bref.name,
                        stores.grants,
                    )
                {
                    tracing::warn!(
                        route_ns,
                        mirror_ns,
                        mirror_svc = %bref.name,
                        "Skipping RequestMirror — cross-namespace ref denied (no matching ReferenceGrant)"
                    );
                    continue;
                }

                // Normalize GEP-3171 sampling.  Spec: only one of `fraction`/`percent`
                // may be set; if neither is set, mirror 100% of requests.
                let fraction: Option<MirrorFraction> = if mirror.fraction.is_some()
                    && mirror.percent.is_some()
                {
                    tracing::warn!(
                        "RequestMirror has both fraction and percent set — using fraction"
                    );
                    mirror.fraction.as_ref().and_then(|fr| {
                        MirrorFraction::new(
                            fr.numerator as u32,
                            fr.denominator.unwrap_or(100) as u32,
                        )
                    })
                } else if let Some(fr) = &mirror.fraction {
                    MirrorFraction::new(fr.numerator as u32, fr.denominator.unwrap_or(100) as u32)
                } else {
                    mirror
                        .percent
                        .and_then(|p| MirrorFraction::new(p as u32, 100))
                };

                let resolved =
                    endpoints::resolve(mirror_ns, &bref.name, port, stores.slices, stores.services);
                if !resolved.service_exists {
                    tracing::warn!(
                        mirror_ns,
                        mirror_svc = %bref.name,
                        "RequestMirror backend Service not found — skipping"
                    );
                    continue;
                }
                // Empty addrs: Service exists but has no ready endpoints. Install the
                // filter anyway so the proxy can log the drop at dispatch time.
                let mirror_group = Arc::new(BackendGroup::new(
                    format!("{mirror_ns}/{}", bref.name),
                    resolved.addrs,
                ));
                out.push(FilterAction::Mirror {
                    backend: mirror_group,
                    fraction,
                });
            }
            // ExternalAuth is an alpha filter that only exists in the experimental channel.
            #[cfg(feature = "experimental")]
            HttpRouteRulesFiltersType::ExternalAuth => {
                tracing::warn!("Skipping ExternalAuth filter — not yet implemented");
            }
        }
    }
    out
}

fn parse_redirect_path(
    path: &Option<crate::gw_types::v::httproutes::HttpRouteRulesFiltersRequestRedirectPath>,
    matched_prefix: &str,
    is_prefix_match: bool,
) -> Option<PathModifier> {
    use crate::gw_types::v::httproutes::HttpRouteRulesFiltersRequestRedirectPathType;
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
    path: &crate::gw_types::v::httproutes::HttpRouteRulesFiltersUrlRewritePath,
    matched_prefix: &str,
    is_prefix_match: bool,
) -> Option<PathModifier> {
    use crate::gw_types::v::httproutes::HttpRouteRulesFiltersUrlRewritePathType;
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

/// Translates an `HTTPRoute` CORS filter payload into a [`CorsConfig`].
///
/// Returns `None` only when there is nothing meaningful to apply (e.g. both
/// `allowOrigins` and the wildcard flag are absent).  Individual sub-fields with
/// invalid header bytes are skipped with a WARN log rather than aborting the whole
/// filter — a partial CORS policy is still useful.
fn build_cors_config(cors: &HttpRouteRulesFiltersCors) -> Option<CorsConfig> {
    use http::HeaderValue;

    let origins_raw = cors.allow_origins.as_deref().unwrap_or(&[]);
    let mut allow_origins: Vec<CorsOrigin> = Vec::with_capacity(origins_raw.len());
    let mut allow_all_origins = false;

    for origin in origins_raw {
        if origin == "*" {
            allow_all_origins = true;
        } else if let Some(star_pos) = origin.find('*') {
            let prefix = origin[..star_pos].to_ascii_lowercase().into_boxed_str();
            let suffix = origin[star_pos + 1..].to_ascii_lowercase().into_boxed_str();
            allow_origins.push(CorsOrigin::Wildcard { prefix, suffix });
        } else {
            allow_origins.push(CorsOrigin::Exact(origin.to_ascii_lowercase()));
        }
    }

    if !allow_all_origins && allow_origins.is_empty() {
        tracing::warn!("CORS filter has no allowOrigins entries — filter skipped");
        return None;
    }

    let join_header = |items: &[String], field: &'static str| -> Option<HeaderValue> {
        if items.is_empty() {
            return None;
        }
        let joined = items.join(", ");
        HeaderValue::from_str(&joined)
            .map_err(|e| {
                tracing::warn!(field, error = %e, "CORS filter sub-field has invalid header bytes — skipping");
            })
            .ok()
    };

    let allow_methods = cors
        .allow_methods
        .as_deref()
        .and_then(|v| join_header(v, "allowMethods"));
    let allow_headers = cors
        .allow_headers
        .as_deref()
        .and_then(|v| join_header(v, "allowHeaders"));
    let expose_headers = cors
        .expose_headers
        .as_deref()
        .and_then(|v| join_header(v, "exposeHeaders"));

    let max_age_secs = cors.max_age.unwrap_or(5);
    let max_age = HeaderValue::from(max_age_secs);

    Some(CorsConfig::new(
        allow_origins,
        allow_all_origins,
        cors.allow_credentials.unwrap_or(false),
        allow_methods,
        allow_headers,
        expose_headers,
        max_age,
    ))
}

/// Builds `MatchPredicates` from a single `HttpRouteRulesMatches` entry.
///
/// Returns `None` if any regex pattern in the headers or query predicates is invalid.
pub(super) fn build_predicates(
    m: &crate::gw_types::v::httproutes::HttpRouteRulesMatches,
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

/// Translate `HTTPBackendRef.filters` (per-backend filters) into `FilterAction`s.
///
/// Per Gateway API GEP-1492, backendRef-scope filters may only be
/// `RequestHeaderModifier` or `ResponseHeaderModifier`. Other types
/// (`RequestRedirect`, `URLRewrite`, `RequestMirror`, `ExtensionRef`, `CORS`)
/// are spec-invalid at backend-ref scope and are logged + skipped here. The
/// returned `Vec` is index-aligned with the caller's backendRef list.
pub(super) fn build_backend_ref_filters(
    filters: &[HttpRouteRulesBackendRefsFilters],
) -> Vec<FilterAction> {
    let mut out = Vec::new();
    for f in filters {
        match f.r#type {
            HttpRouteRulesBackendRefsFiltersType::RequestHeaderModifier => {
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
            HttpRouteRulesBackendRefsFiltersType::ResponseHeaderModifier => {
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
            _ => {
                tracing::warn!(
                    filter_type = ?f.r#type,
                    "Skipping spec-invalid per-backend filter type \
                     (only RequestHeaderModifier and ResponseHeaderModifier are allowed at backendRef scope)"
                );
            }
        }
    }
    out
}

/// Scans `filters` for an `ExtensionRef` pointing at a `RateLimit` CR
/// (`group: coxswain-labs.dev`, `kind: RateLimit`) and, if found, resolves
/// the named CR from `rate_limits` and converts its spec to a
/// [`RateLimitConfig`].
///
/// Only the first matching `ExtensionRef` is used; subsequent ones are
/// ignored. Non-`RateLimit` extension refs continue to log a warning and are
/// skipped. Missing CRs or a zero `requestsPerSecond` value log a warning and
/// return `None` (fail-open: the route is not limited).
pub(super) fn resolve_rate_limit(
    filters: &[HttpRouteRulesFilters],
    route_ns: &str,
    rate_limits: &reflector::Store<RateLimit>,
) -> Option<Arc<RateLimitConfig>> {
    for f in filters {
        if !matches!(f.r#type, HttpRouteRulesFiltersType::ExtensionRef) {
            continue;
        }
        let Some(ext) = &f.extension_ref else {
            tracing::warn!("Skipping ExtensionRef filter — payload is missing");
            continue;
        };
        if ext.group != "coxswain-labs.dev" || ext.kind != "RateLimit" {
            tracing::warn!(
                group = %ext.group,
                kind  = %ext.kind,
                name  = %ext.name,
                "Skipping unsupported ExtensionRef (expected group=coxswain-labs.dev kind=RateLimit)"
            );
            continue;
        }
        let obj_ref = reflector::ObjectRef::<RateLimit>::new(&ext.name).within(route_ns);
        let Some(cr) = rate_limits.get(&obj_ref) else {
            tracing::warn!(
                ns   = route_ns,
                name = %ext.name,
                "RateLimit CR not found — rate limiting skipped (fail-open)"
            );
            return None;
        };
        let Some(rps) = NonZeroU32::new(cr.spec.requests_per_second) else {
            tracing::warn!(
                ns   = route_ns,
                name = %ext.name,
                "RateLimit CR has requestsPerSecond=0 — rate limiting skipped (fail-open)"
            );
            return None;
        };
        let key = match &cr.spec.by_header {
            Some(h) => RateLimitKey::Header(Arc::from(h.to_ascii_lowercase().as_str())),
            None => RateLimitKey::ClientIp,
        };
        return Some(Arc::new(RateLimitConfig::new(rps, cr.spec.burst, key)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_api::tests::*;

    // ── Filter tests ────────────────────────────────────────────────────────────

    use crate::gw_types::v::httproutes::{
        HttpRouteRulesFilters, HttpRouteRulesFiltersCors,
        HttpRouteRulesFiltersRequestHeaderModifier, HttpRouteRulesFiltersRequestHeaderModifierSet,
        HttpRouteRulesFiltersRequestRedirect, HttpRouteRulesFiltersResponseHeaderModifier,
        HttpRouteRulesFiltersResponseHeaderModifierAdd, HttpRouteRulesFiltersType,
        HttpRouteRulesFiltersUrlRewrite, HttpRouteRulesFiltersUrlRewritePath,
        HttpRouteRulesFiltersUrlRewritePathType,
    };
    use coxswain_core::routing::{FilterAction, PathModifier, RouteOutcome};

    fn make_route_with_filters(
        ns: &str,
        hostname: &str,
        path: &str,
        path_type: HttpRouteRulesMatchesPathType,
        svc: &str,
        filters: Vec<HttpRouteRulesFilters>,
    ) -> HttpRoute {
        HttpRoute {
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
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn find_filters(
        table: &coxswain_core::routing::GatewayRoutingTable,
        host: &str,
        path: &str,
    ) -> std::sync::Arc<[FilterAction]> {
        let empty_hdrs = http::HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
        match table.find(80, host, path, &ctx) {
            RouteOutcome::Found(m) => m.filters,
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
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filter_list = find_filters(&table, "example.com", "/");
        assert_eq!(filter_list.len(), 1);
        match &filter_list[0] {
            FilterAction::RequestHeaderModifier(m) => {
                assert_eq!(m.set.len(), 1);
                assert_eq!(m.set[0].0.as_str(), "x-env");
                assert_eq!(m.set[0].1, "prod");
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
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filter_list = find_filters(&table, "example.com", "/");
        assert_eq!(filter_list.len(), 1);
        match &filter_list[0] {
            FilterAction::ResponseHeaderModifier(m) => {
                assert_eq!(m.add.len(), 1);
                assert_eq!(m.add[0].0.as_str(), "x-served-by");
                assert_eq!(m.add[0].1, "coxswain");
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
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filter_list = find_filters(&table, "example.com", "/old");
        assert_eq!(filter_list.len(), 1);
        match &filter_list[0] {
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
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filter_list = find_filters(&table, "example.com", "/api/users");
        assert_eq!(filter_list.len(), 1);
        match &filter_list[0] {
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

    #[test]
    fn reconcile_cors_filter_stored() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_filters(
            "default",
            "example.com",
            "/",
            HttpRouteRulesMatchesPathType::PathPrefix,
            "svc",
            vec![HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::Cors,
                cors: Some(HttpRouteRulesFiltersCors {
                    allow_origins: Some(vec![
                        "https://allowed.example".to_string(),
                        "https://*.trusted.example".to_string(),
                    ]),
                    allow_methods: Some(vec!["GET".to_string(), "POST".to_string()]),
                    allow_headers: Some(vec!["Content-Type".to_string()]),
                    expose_headers: Some(vec!["X-Custom-Header".to_string()]),
                    allow_credentials: Some(true),
                    max_age: Some(3600),
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
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let filter_list = find_filters(&table, "example.com", "/");
        assert_eq!(filter_list.len(), 1, "expected exactly one CORS filter");
        match &filter_list[0] {
            FilterAction::Cors(cfg) => {
                // Origins: exact + wildcard, case-folded
                assert_eq!(cfg.allow_origins.len(), 2);
                assert!(
                    cfg.allow_origins[0].matches("https://allowed.example"),
                    "exact origin should match"
                );
                assert!(
                    cfg.allow_origins[1].matches("https://foo.trusted.example"),
                    "wildcard origin should match subdomain"
                );
                assert!(!cfg.allow_all_origins);
                assert!(cfg.allow_credentials);
                // Pre-joined header values
                assert_eq!(
                    cfg.allow_methods.as_ref().expect("allow_methods set"),
                    "GET, POST"
                );
                assert_eq!(
                    cfg.allow_headers.as_ref().expect("allow_headers set"),
                    "Content-Type"
                );
                assert_eq!(
                    cfg.expose_headers.as_ref().expect("expose_headers set"),
                    "X-Custom-Header"
                );
                assert_eq!(cfg.max_age, "3600");
            }
            _ => panic!("expected FilterAction::Cors"),
        }
    }
}
