//! Translates `HTTPRouteRule` filter specs into [`FilterAction`][coxswain_core::routing::FilterAction]s.

use crate::endpoints;
use crate::gw_types::v::grpcroutes::{GrpcRouteRulesFilters, GrpcRouteRulesFiltersType};
use crate::gw_types::v::httproutes::{
    HttpRouteRulesBackendRefsFilters, HttpRouteRulesBackendRefsFiltersType, HttpRouteRulesFilters,
    HttpRouteRulesFiltersCors, HttpRouteRulesFiltersType, HttpRouteRulesMatchesHeadersType,
    HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesQueryParamsType,
};
use coxswain_core::crd::{
    BasicAuth, Compression, CoxswainExternalAuth, IpAccessControl, RateLimit, RequestSizeLimit,
};
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendGroup, CompressionConfig, CorsConfig, CorsOrigin, FilterAction, HeaderMod,
    HeaderPredicate, IngressAuthConfig, MatchPredicates, MirrorFraction, PathModifier,
    QueryPredicate, RateLimitConfig, RateLimitKey, ValueMatch, compile_bounded,
};
use http::{HeaderName, Method};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;

/// A resolved source-IP CIDR set attached to a route (allow or deny list), or
/// `None` when the set is absent (no filtering on that side). Matches the shape
/// of `RouteEntry::{allow,deny}_source_range`.
pub(super) type CidrSet = Option<Arc<Vec<ipnet::IpNet>>>;

/// Store references needed to resolve `backendRef` targets in filters (e.g.
/// `RequestMirror`).
pub(super) struct BackendStores<'a> {
    pub(super) slices: &'a reflector::Store<EndpointSlice>,
    pub(super) services: &'a reflector::Store<Service>,
    pub(super) grants: &'a HashSet<ReferenceGrantKey>,
}

/// Outcome of resolving one route-rule `ExtensionRef` against a specific coxswain
/// filter kind. Replaces the earlier ad-hoc per-resolver shapes (`Option<Option<T>>`,
/// an `(allow, deny)` tuple, and an overloaded `Option`) with three named,
/// mutually-exclusive states, so a single shared scan ([`ext_refs`]) drives every
/// resolver. `NotMine` means keep scanning the rule's filters; `Resolved`/`FailOpen`
/// both mean "this ref was a hit" — whether that stops the scan (first-match-wins) is
/// each wrapper's choice (all stop except `resolve_basic_auth`, which preserves its
/// historical keep-scanning-on-missing-CR behaviour).
#[non_exhaustive]
pub(super) enum RefResolution<T> {
    /// The ref does not target this resolver's kind — keep scanning.
    NotMine,
    /// The ref targets this kind and resolved to an enforceable value.
    Resolved(T),
    /// The ref targets this kind but the CR is missing / a no-op — fail open (no
    /// enforcement on the route). Distinct from [`Self::NotMine`]: the kind matched.
    FailOpen,
}

/// One route-rule filter that may carry an `ExtensionRef` payload, abstracted over
/// HTTPRoute/GRPCRoute so the ext-ref scan is written once ([`ext_refs`]). kopium
/// emits a distinct filter struct per route kind with an identical `type` +
/// `extension_ref` shape, so a one-method accessor collapses the two — mirroring the
/// [`ParentRefLike`][super::bindings] pattern used for listener binding.
pub(super) trait ExtRefFilter {
    /// `(group, kind, name)` when this filter is an `ExtensionRef` carrying a payload;
    /// `None` for any other filter type, or an `ExtensionRef` with no payload (skipped,
    /// matching the pre-refactor `continue`).
    fn ext_ref(&self) -> Option<(&str, &str, &str)>;
}

impl ExtRefFilter for HttpRouteRulesFilters {
    fn ext_ref(&self) -> Option<(&str, &str, &str)> {
        if !matches!(self.r#type, HttpRouteRulesFiltersType::ExtensionRef) {
            return None;
        }
        let ext = self.extension_ref.as_ref()?;
        Some((ext.group.as_str(), ext.kind.as_str(), ext.name.as_str()))
    }
}

impl ExtRefFilter for GrpcRouteRulesFilters {
    fn ext_ref(&self) -> Option<(&str, &str, &str)> {
        if !matches!(self.r#type, GrpcRouteRulesFiltersType::ExtensionRef) {
            return None;
        }
        let ext = self.extension_ref.as_ref()?;
        Some((ext.group.as_str(), ext.kind.as_str(), ext.name.as_str()))
    }
}

/// Iterate a rule's filters, yielding `(group, kind, name)` for each `ExtensionRef`
/// that carries a payload. The single scan every `resolve_*` wrapper `find_map`s over
/// — replaces the seven byte-identical hand-rolled loops (#523).
pub(super) fn ext_refs<F: ExtRefFilter>(filters: &[F]) -> impl Iterator<Item = (&str, &str, &str)> {
    filters.iter().filter_map(F::ext_ref)
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
                match (ext.group.as_str(), ext.kind.as_str()) {
                    (super::COXSWAIN_GROUP, "PathRewriteRegex") => {
                        let obj_ref =
                            reflector::ObjectRef::<coxswain_core::crd::PathRewriteRegex>::new(
                                &ext.name,
                            )
                            .within(route_ns);
                        if let Some(cr) = path_rewrites.get(&obj_ref) {
                            match compile_bounded(&cr.spec.pattern) {
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
                    }
                    // Resolved separately by the `resolve_*` scanners into per-route
                    // config off the filter list — no `FilterAction` emitted here.
                    (
                        super::COXSWAIN_GROUP,
                        "RateLimit" | "IpAccessControl" | "BasicAuth" | "RequestSizeLimit"
                        | "Compression" | "ExternalAuth",
                    ) => {}
                    _ => tracing::warn!(
                        group = %ext.group,
                        kind = %ext.kind,
                        "Skipping unsupported ExtensionRef filter"
                    ),
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
                let re = compile_bounded(&h.value).ok()?;
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
                let re = compile_bounded(&q.value).ok()?;
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
/// (`group: gateway.coxswain-labs.dev`, `kind: RateLimit`) and, if found, resolves
/// the named CR from `rate_limits` and converts its spec to a
/// [`RateLimitConfig`].
///
/// Only the first matching `ExtensionRef` is used; other extension refs (and
/// non-`RateLimit` kinds) are ignored here — `build_filters` owns the
/// "unsupported ExtensionRef" WARN, so this scan stays silent on them. Missing
/// CRs or a zero `requestsPerSecond` value log a warning and return `None`
/// (fail-open: the route is not limited).
pub(super) fn resolve_rate_limit<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    rate_limits: &reflector::Store<RateLimit>,
) -> Option<Arc<RateLimitConfig>> {
    ext_refs(filters)
        .find_map(
            |(g, k, n)| match resolve_rate_limit_ref(g, k, n, route_ns, rate_limits) {
                RefResolution::NotMine => None,
                RefResolution::Resolved(cfg) => Some(Some(cfg)),
                RefResolution::FailOpen => Some(None),
            },
        )
        .flatten()
}

/// Resolve a single `ExtensionRef` (by `group`/`kind`/`name`) into a
/// [`RateLimitConfig`], if it targets a `RateLimit` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** a `RateLimit` (`group ==
/// gateway.coxswain-labs.dev`, `kind == RateLimit`) so the caller keeps scanning;
/// [`RefResolution::FailOpen`] on a missing CR or `requestsPerSecond=0` (WARN — the
/// route is not limited); [`RefResolution::Resolved`] otherwise. Shared by the
/// HTTPRoute and GRPCRoute reconcilers (rate limiting is protocol-agnostic; only the
/// differently-typed filter-list iteration differs).
pub(super) fn resolve_rate_limit_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    rate_limits: &reflector::Store<RateLimit>,
) -> RefResolution<Arc<RateLimitConfig>> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "RateLimit" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<RateLimit>::new(ext_name).within(route_ns);
    let Some(cr) = rate_limits.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "RateLimit CR not found — rate limiting skipped (fail-open)"
        );
        return RefResolution::FailOpen;
    };
    let Some(rps) = NonZeroU32::new(cr.spec.requests_per_second) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "RateLimit CR has requestsPerSecond=0 — rate limiting skipped (fail-open)"
        );
        return RefResolution::FailOpen;
    };
    let key = match &cr.spec.by_header {
        Some(h) => RateLimitKey::Header(Arc::from(h.to_ascii_lowercase().as_str())),
        None => RateLimitKey::ClientIp,
    };
    RefResolution::Resolved(Arc::new(RateLimitConfig::new(rps, cr.spec.burst, key)))
}

/// Scans `filters` for an `ExtensionRef` pointing at an `IpAccessControl` CR
/// (`group: gateway.coxswain-labs.dev`, `kind: IpAccessControl`) and, if found, resolves
/// the named CR from `ip_access` and parses its `allow` / `deny` CIDR sets into
/// the `(allow_source_range, deny_source_range)` lists the proxy enforces (deny
/// evaluated first — the same fields the Ingress `allow-source-range` /
/// `deny-source-range` annotations feed).
///
/// Only the first matching `ExtensionRef` is used; other extension refs (and
/// non-`IpAccessControl` kinds) are ignored here — `build_filters` owns the
/// "unsupported ExtensionRef" WARN, so this scan stays silent on them. A missing
/// CR logs a WARN and returns `(None, None)` (fail-open: the route is not
/// filtered). Each CIDR set is `None` when empty or entirely unparseable, so an
/// empty/typo'd list never silently changes the route's admit behaviour.
pub(super) fn resolve_ip_access<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    ip_access: &reflector::Store<IpAccessControl>,
) -> (CidrSet, CidrSet) {
    ext_refs(filters)
        .find_map(
            |(g, k, n)| match resolve_ip_access_ref(g, k, n, route_ns, ip_access) {
                RefResolution::NotMine => None,
                RefResolution::Resolved(sets) => Some(sets),
                RefResolution::FailOpen => Some((None, None)),
            },
        )
        .unwrap_or((None, None))
}

/// Resolve a single `ExtensionRef` (identified by its `group`/`kind`/`name`) into
/// the `(allow, deny)` source-IP CIDR sets, if it targets an `IpAccessControl` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** an `IpAccessControl`
/// (`group == gateway.coxswain-labs.dev`, `kind == IpAccessControl`) so the caller
/// keeps scanning; [`RefResolution::FailOpen`] when the CR is missing (WARN — the
/// route is not filtered); [`RefResolution::Resolved((allow, deny))`] otherwise (each
/// set `None` when empty/unparseable). Shared by the HTTPRoute and GRPCRoute
/// reconcilers, which iterate their own (differently-typed) filter lists.
pub(super) fn resolve_ip_access_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    ip_access: &reflector::Store<IpAccessControl>,
) -> RefResolution<(CidrSet, CidrSet)> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "IpAccessControl" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<IpAccessControl>::new(ext_name).within(route_ns);
    let Some(cr) = ip_access.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "IpAccessControl CR not found — IP access control skipped (fail-open)"
        );
        return RefResolution::FailOpen;
    };
    let deny = parse_cidr_set(&cr.spec.deny, route_ns, ext_name, "deny");
    let allow = parse_cidr_set(&cr.spec.allow, route_ns, ext_name, "allow");
    RefResolution::Resolved((allow, deny))
}

/// Parse an `IpAccessControl` CIDR list into an `Arc<Vec<IpNet>>`, promoting bare
/// IPs to host routes and skipping invalid tokens with a WARN.
///
/// Returns `None` when the list is empty or every token is unparseable, so the
/// caller treats the set as absent rather than as an empty (all-blocking /
/// nothing-matching) list. `field` names the offending set (`"allow"` / `"deny"`)
/// in skipped-token WARNs.
fn parse_cidr_set(
    tokens: &[String],
    route_ns: &str,
    cr_name: &str,
    field: &'static str,
) -> CidrSet {
    let nets: Vec<ipnet::IpNet> = tokens
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .filter_map(|token| {
            match crate::ingress::annotations::edge_access::parse_cidr_or_host(token) {
                Some(net) => Some(net),
                None => {
                    tracing::warn!(
                        ns = route_ns,
                        name = cr_name,
                        field,
                        token,
                        "IpAccessControl has an invalid CIDR — skipping token"
                    );
                    None
                }
            }
        })
        .collect();
    if nets.is_empty() {
        None
    } else {
        Some(Arc::new(nets))
    }
}

/// Scans `filters` for an `ExtensionRef` pointing at a `BasicAuth` CR
/// (`group: gateway.coxswain-labs.dev`, `kind: BasicAuth`) and, if found, resolves
/// the named CR's `secretRef`, reads the label-scoped htpasswd Secret from
/// `auth_secrets`, and produces the same [`IngressAuthConfig`] the Ingress
/// `auth-basic-secret` annotation feeds (same fail-closed ladder: missing CR,
/// missing/unlabeled Secret, missing `auth` data key, or zero parseable
/// entries all resolve to `IngressAuthConfig::Unavailable` → `503`).
///
/// Only the first matching `ExtensionRef` is used; other extension refs (and
/// non-`BasicAuth` kinds) are ignored here — `build_filters` owns the
/// "unsupported ExtensionRef" WARN. Returns `None` when no `BasicAuth`
/// `ExtensionRef` is present on this rule (no auth on the route) or the
/// referenced CR itself is missing (fail-open — matches `resolve_rate_limit`).
pub(super) fn resolve_basic_auth<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    basic_auths: &reflector::Store<BasicAuth>,
    auth_secrets: &reflector::Store<Secret>,
    secret_grants: &HashSet<ReferenceGrantKey>,
) -> Option<Arc<IngressAuthConfig>> {
    // `FailOpen` (missing CR) maps to `None` — unlike the other resolvers, basic-auth
    // historically *kept scanning* after a missing CR rather than stopping, so a later
    // `BasicAuth` ref on the same rule could still resolve. Preserved verbatim.
    ext_refs(filters).find_map(|(g, k, n)| {
        match resolve_basic_auth_ref(g, k, n, route_ns, basic_auths, auth_secrets, secret_grants) {
            RefResolution::NotMine | RefResolution::FailOpen => None,
            RefResolution::Resolved(cfg) => Some(cfg),
        }
    })
}

/// Resolve the first `CoxswainExternalAuth` `ExtensionRef` on the rule into an
/// [`IngressAuthConfig`] (#23).
///
/// Returns `None` when no `ExternalAuth` ref is present (no ext-auth on the
/// route) or the referenced CR is missing (fail-open — matches the other
/// ExtensionRef resolvers). A present-but-broken backend (no endpoints, ungranted
/// cross-namespace ref, unsupported protocol) fails **closed** via
/// [`IngressAuthConfig::Unavailable`], resolved in
/// [`super::external_auth::resolve_spec`].
pub(super) fn resolve_external_auth<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    external_auths: &reflector::Store<CoxswainExternalAuth>,
    services: &reflector::Store<Service>,
    slices: &reflector::Store<EndpointSlice>,
    grants: &HashSet<ReferenceGrantKey>,
) -> Option<Arc<IngressAuthConfig>> {
    ext_refs(filters).find_map(|(g, k, n)| {
        if g != super::COXSWAIN_GROUP || k != "ExternalAuth" {
            return None;
        }
        let obj_ref = reflector::ObjectRef::<CoxswainExternalAuth>::new(n).within(route_ns);
        let Some(cr) = external_auths.get(&obj_ref) else {
            tracing::warn!(
                ns = route_ns,
                name = n,
                "CoxswainExternalAuth CR not found — ext-auth skipped (fail-open)"
            );
            return None;
        };
        Some(Arc::new(super::external_auth::resolve_spec(
            &cr.spec, route_ns, services, slices, grants,
        )))
    })
}

/// Resolve a single `ExtensionRef` (by `group`/`kind`/`name`) into an
/// [`IngressAuthConfig`], if it targets a `BasicAuth` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** a `BasicAuth` so the
/// caller keeps scanning, or [`RefResolution::FailOpen`] when the `BasicAuth` CR
/// itself is missing (no auth on the route). Once a CR is found, every subsequent
/// failure (missing/unlabeled Secret, missing `auth` key, zero parseable credentials)
/// fails **closed** — [`RefResolution::Resolved`] carrying
/// [`IngressAuthConfig::Unavailable`] — because an operator who attached this filter
/// expects auth enforcement, so a broken Secret must not silently open the route.
pub(super) fn resolve_basic_auth_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    basic_auths: &reflector::Store<BasicAuth>,
    auth_secrets: &reflector::Store<Secret>,
    secret_grants: &HashSet<ReferenceGrantKey>,
) -> RefResolution<Arc<IngressAuthConfig>> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "BasicAuth" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<BasicAuth>::new(ext_name).within(route_ns);
    let Some(cr) = basic_auths.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "BasicAuth CR not found — auth skipped (fail-open)"
        );
        return RefResolution::FailOpen;
    };
    let route_id = format!("{route_ns}/{ext_name}");
    let secret_ref = &cr.spec.secret_ref;

    // Cross-namespace secretRef requires a matching `BasicAuth → Secret`
    // ReferenceGrant (#520). Without one, fail closed (503) rather than binding a
    // Secret in another namespace — the Ingress single-namespace precedent does not
    // carry over to the Gateway-API trust model. Same-namespace refs need no grant.
    if secret_ref.namespace != route_ns
        && !reference_grants::backend_ref_allowed(
            route_ns,
            &secret_ref.namespace,
            &secret_ref.name,
            secret_grants,
        )
    {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            secret_ns = %secret_ref.namespace,
            secret_name = %secret_ref.name,
            "BasicAuth secretRef crosses namespaces with no matching ReferenceGrant — \
             failing closed (503)"
        );
        return RefResolution::Resolved(Arc::new(IngressAuthConfig::Unavailable));
    }

    let secret_obj_ref =
        reflector::ObjectRef::<Secret>::new(&secret_ref.name).within(&secret_ref.namespace);
    let Some(secret) = auth_secrets.get(&secret_obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            secret_ns = %secret_ref.namespace,
            secret_name = %secret_ref.name,
            "BasicAuth secretRef not found in auth-secret reflector — \
             is the Secret labeled ingress.coxswain-labs.dev/auth-basic=true? \
             failing closed (503)"
        );
        return RefResolution::Resolved(Arc::new(IngressAuthConfig::Unavailable));
    };
    let Some(data) = secret
        .data
        .as_ref()
        .and_then(|d| d.get("auth"))
        .map(|b| &b.0)
    else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            secret_ns = %secret_ref.namespace,
            secret_name = %secret_ref.name,
            "BasicAuth Secret has no 'auth' data key (expected htpasswd file) — \
             failing closed (503)"
        );
        return RefResolution::Resolved(Arc::new(IngressAuthConfig::Unavailable));
    };
    let mut diag = Vec::new();
    let creds = crate::ingress::annotations::auth::parse_htpasswd(data, &route_id, &mut diag);
    if creds.is_empty() {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            secret_ns = %secret_ref.namespace,
            secret_name = %secret_ref.name,
            "BasicAuth Secret has no parseable htpasswd entries \
             (supported: bcrypt $2y/$2b/$2a, SHA1 {{SHA}}...) — failing closed (503)"
        );
        return RefResolution::Resolved(Arc::new(IngressAuthConfig::Unavailable));
    }
    RefResolution::Resolved(Arc::new(IngressAuthConfig::Basic(creds.into())))
}

/// Scans `filters` for an `ExtensionRef` pointing at a `RequestSizeLimit` CR
/// (`group: gateway.coxswain-labs.dev`, `kind: RequestSizeLimit`) and, if found,
/// resolves the named CR's `maxSize` into a byte count via
/// [`parse_byte_size`][crate::ingress::annotations::parse_byte_size] — the
/// same parser the Ingress `max-body-size` annotation uses.
///
/// Only the first matching `ExtensionRef` is used. Missing CRs and
/// unparseable `maxSize` values log a WARN and return `None` (fail-open: no
/// limit enforced). Protocol-agnostic — shared by the HTTPRoute and
/// GRPCRoute reconcilers (#443); only the filter-list iteration differs.
pub(super) fn resolve_request_size_limit<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    request_size_limits: &reflector::Store<RequestSizeLimit>,
) -> Option<u64> {
    ext_refs(filters)
        .find_map(|(g, k, n)| {
            match resolve_request_size_limit_ref(g, k, n, route_ns, request_size_limits) {
                RefResolution::NotMine => None,
                RefResolution::Resolved(limit) => Some(Some(limit)),
                RefResolution::FailOpen => Some(None),
            }
        })
        .flatten()
}

/// Resolve a single `ExtensionRef` into a byte-count limit, if it targets a
/// `RequestSizeLimit` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** a `RequestSizeLimit` so
/// the caller keeps scanning; [`RefResolution::FailOpen`] on a missing CR or an
/// unparseable `maxSize` (WARN — no limit enforced); [`RefResolution::Resolved(n)`]
/// otherwise.
pub(super) fn resolve_request_size_limit_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    request_size_limits: &reflector::Store<RequestSizeLimit>,
) -> RefResolution<u64> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "RequestSizeLimit" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<RequestSizeLimit>::new(ext_name).within(route_ns);
    let Some(cr) = request_size_limits.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "RequestSizeLimit CR not found — limit skipped (fail-open)"
        );
        return RefResolution::FailOpen;
    };
    match crate::ingress::annotations::parse_byte_size(&cr.spec.max_size) {
        Some(limit) => RefResolution::Resolved(limit),
        None => {
            tracing::warn!(
                ns = route_ns,
                name = ext_name,
                value = %cr.spec.max_size,
                "RequestSizeLimit CR has invalid maxSize — limit skipped (fail-open)"
            );
            RefResolution::FailOpen
        }
    }
}

/// Scans `filters` for an `ExtensionRef` pointing at a `Compression` CR
/// (`group: gateway.coxswain-labs.dev`, `kind: Compression`) and, if found,
/// resolves the named CR into a [`CompressionConfig`].
///
/// Only the first matching `ExtensionRef` is used. A missing CR logs a WARN
/// and returns `None` (fail-open: no compression). When both `gzip` and
/// `brotli` are `false` the CR is a no-op and `None` is returned, mirroring
/// `parse_compression`'s Ingress-annotation behaviour — the proxy never
/// constructs an encoder for a route with nothing to compress.
pub(super) fn resolve_compression<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    compressions: &reflector::Store<Compression>,
) -> Option<Arc<CompressionConfig>> {
    ext_refs(filters)
        .find_map(
            |(g, k, n)| match resolve_compression_ref(g, k, n, route_ns, compressions) {
                RefResolution::NotMine => None,
                RefResolution::Resolved(cfg) => Some(Some(cfg)),
                RefResolution::FailOpen => Some(None),
            },
        )
        .flatten()
}

/// Resolve a single `ExtensionRef` into a [`CompressionConfig`], if it
/// targets a `Compression` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** a `Compression` so the
/// caller keeps scanning; [`RefResolution::FailOpen`] on a missing CR or a CR with
/// both `gzip`/`brotli` disabled (a no-op — the proxy builds no encoder);
/// [`RefResolution::Resolved(cfg)`] otherwise.
pub(super) fn resolve_compression_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    compressions: &reflector::Store<Compression>,
) -> RefResolution<Arc<CompressionConfig>> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "Compression" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<Compression>::new(ext_name).within(route_ns);
    let Some(cr) = compressions.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "Compression CR not found — compression skipped (fail-open)"
        );
        return RefResolution::FailOpen;
    };
    if !cr.spec.gzip && !cr.spec.brotli {
        return RefResolution::FailOpen;
    }
    let level = cr.spec.level.filter(|l| (1..=9).contains(l)).unwrap_or(6);
    let min_size = cr.spec.min_size.unwrap_or(1024);
    let types: Box<[Box<str>]> = if cr.spec.types.is_empty() {
        crate::ingress::annotations::default_compression_types()
    } else {
        cr.spec
            .types
            .iter()
            .map(|t| t.to_lowercase().into_boxed_str())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    };
    RefResolution::Resolved(Arc::new(CompressionConfig::new(
        cr.spec.gzip,
        cr.spec.brotli,
        level,
        min_size,
        types,
    )))
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
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
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
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
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
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
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
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
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
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
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

    // ── resolve_ip_access ─────────────────────────────────────────────────────

    use crate::gw_types::v::httproutes::HttpRouteRulesFiltersExtensionRef;
    use coxswain_core::crd::IpAccessControl;

    fn ip_access_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "IpAccessControl".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    // `IpAccessControlSpec` is `#[non_exhaustive]`, so it cannot be built with a
    // struct literal from this crate — deserialize a CR instead.
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
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("valid IpAccessControl: {e}\n{yaml}"))
    }

    #[test]
    fn resolve_ip_access_no_ext_ref_is_none() {
        let store = empty_ip_access_store();
        let (allow, deny) = resolve_ip_access::<HttpRouteRulesFilters>(&[], "default", &store);
        assert!(allow.is_none());
        assert!(deny.is_none());
    }

    #[test]
    fn resolve_ip_access_present_cr_parses_allow_and_deny() {
        let store = make_ip_access_store(vec![ip_access_cr(
            "default",
            "policy",
            &["203.0.113.0/24"],
            &["10.0.0.0/8"],
        )]);
        let (allow, deny) = resolve_ip_access(&[ip_access_ext_ref("policy")], "default", &store);
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
    fn resolve_ip_access_bare_ip_becomes_host_route() {
        let store = make_ip_access_store(vec![ip_access_cr(
            "default",
            "policy",
            &["203.0.113.10"],
            &[],
        )]);
        let (allow, _) = resolve_ip_access(&[ip_access_ext_ref("policy")], "default", &store);
        assert_eq!(
            *allow.expect("allow set"),
            vec!["203.0.113.10/32".parse::<ipnet::IpNet>().expect("valid")]
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_ip_access_missing_cr_fails_open() {
        let store = empty_ip_access_store();
        let (allow, deny) = resolve_ip_access(&[ip_access_ext_ref("absent")], "default", &store);
        assert!(allow.is_none(), "missing CR must not filter");
        assert!(deny.is_none(), "missing CR must not filter");
        assert!(logs_contain("IpAccessControl CR not found"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_ip_access_skips_invalid_cidr_tokens() {
        let store = make_ip_access_store(vec![ip_access_cr(
            "default",
            "policy",
            &["not-a-cidr", "203.0.113.0/24"],
            &["also-bad"],
        )]);
        let (allow, deny) = resolve_ip_access(&[ip_access_ext_ref("policy")], "default", &store);
        assert_eq!(allow.expect("one valid allow").len(), 1);
        assert!(deny.is_none(), "all-invalid deny list collapses to None");
        assert!(logs_contain("invalid CIDR"));
    }

    // ── resolve_basic_auth ────────────────────────────────────────────────────

    use coxswain_core::crd::BasicAuth;
    use k8s_openapi::ByteString;
    use std::collections::BTreeMap;

    fn basic_auth_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "BasicAuth".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    // `BasicAuthSpec` is `#[non_exhaustive]` — deserialize a CR instead.
    fn basic_auth_cr(ns: &str, name: &str, secret_ns: &str, secret_name: &str) -> BasicAuth {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: BasicAuth\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  secretRef:\n    name: {secret_name}\n    namespace: {secret_ns}\n",
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("valid BasicAuth: {e}\n{yaml}"))
    }

    fn htpasswd_secret(ns: &str, name: &str, auth_data: &str) -> Secret {
        let mut data = BTreeMap::new();
        data.insert(
            "auth".to_string(),
            ByteString(auth_data.as_bytes().to_vec()),
        );
        Secret {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        }
    }

    #[test]
    fn resolve_basic_auth_no_ext_ref_is_none() {
        let basic_auths = empty_basic_auth_store();
        let auth_secrets = empty_secret_store();
        assert!(
            resolve_basic_auth::<HttpRouteRulesFilters>(
                &[],
                "default",
                &basic_auths,
                &auth_secrets,
                &std::collections::HashSet::new()
            )
            .is_none()
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_basic_auth_missing_cr_fails_open() {
        let basic_auths = empty_basic_auth_store();
        let auth_secrets = empty_secret_store();
        let cfg = resolve_basic_auth(
            &[basic_auth_ext_ref("absent")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        );
        assert!(cfg.is_none(), "missing CR must not enforce auth");
        assert!(logs_contain("BasicAuth CR not found"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_basic_auth_missing_secret_fails_closed() {
        let basic_auths = make_basic_auth_store(vec![basic_auth_cr(
            "default",
            "policy",
            "default",
            "my-htpasswd",
        )]);
        let auth_secrets = empty_secret_store();
        let cfg = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        )
        .expect("Some when CR present");
        assert!(matches!(*cfg, IngressAuthConfig::Unavailable));
        assert!(logs_contain("failing closed"));
    }

    #[test]
    fn resolve_basic_auth_valid_secret_produces_basic_config() {
        let basic_auths = make_basic_auth_store(vec![basic_auth_cr(
            "default",
            "policy",
            "default",
            "my-htpasswd",
        )]);
        let auth_secrets = make_secret_store(vec![htpasswd_secret(
            "default",
            "my-htpasswd",
            "alice:$2y$12$abcdefghijklmnopqrstuuVGKkqzuSFPb0h.d.XRjRijkFvxONxfy\n",
        )]);
        let cfg = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        )
        .expect("Some when CR and Secret present");
        assert!(matches!(*cfg, IngressAuthConfig::Basic(ref creds) if creds.len() == 1));
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_basic_auth_empty_htpasswd_fails_closed() {
        let basic_auths = make_basic_auth_store(vec![basic_auth_cr(
            "default",
            "policy",
            "default",
            "my-htpasswd",
        )]);
        let auth_secrets = make_secret_store(vec![htpasswd_secret("default", "my-htpasswd", "")]);
        let cfg = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        )
        .expect("Some when CR present");
        assert!(matches!(*cfg, IngressAuthConfig::Unavailable));
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_basic_auth_cross_namespace_without_grant_fails_closed() {
        // BasicAuth CR in `default` references a Secret in `other` with no
        // ReferenceGrant → must fail closed (503), never bind the cross-ns Secret.
        let basic_auths = make_basic_auth_store(vec![basic_auth_cr(
            "default",
            "policy",
            "other",
            "my-htpasswd",
        )]);
        let auth_secrets = make_secret_store(vec![htpasswd_secret(
            "other",
            "my-htpasswd",
            "alice:$2y$12$abcdefghijklmnopqrstuuVGKkqzuSFPb0h.d.XRjRijkFvxONxfy\n",
        )]);
        let cfg = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        )
        .expect("Some when CR present");
        assert!(matches!(*cfg, IngressAuthConfig::Unavailable));
        assert!(logs_contain("no matching ReferenceGrant"));
    }

    #[test]
    fn resolve_basic_auth_cross_namespace_with_grant_resolves() {
        // A matching BasicAuth→Secret ReferenceGrant permits the cross-ns ref.
        let basic_auths = make_basic_auth_store(vec![basic_auth_cr(
            "default",
            "policy",
            "other",
            "my-htpasswd",
        )]);
        let auth_secrets = make_secret_store(vec![htpasswd_secret(
            "other",
            "my-htpasswd",
            "alice:$2y$12$abcdefghijklmnopqrstuuVGKkqzuSFPb0h.d.XRjRijkFvxONxfy\n",
        )]);
        let mut grants = std::collections::HashSet::new();
        grants.insert(ReferenceGrantKey::specific(
            "default",
            "other",
            "my-htpasswd",
        ));
        let cfg = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &grants,
        )
        .expect("Some when CR and Secret present");
        assert!(matches!(*cfg, IngressAuthConfig::Basic(ref creds) if creds.len() == 1));
    }

    // ── resolve_request_size_limit ────────────────────────────────────────────

    use coxswain_core::crd::RequestSizeLimit;

    fn request_size_limit_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "RequestSizeLimit".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    fn request_size_limit_cr(ns: &str, name: &str, max_size: &str) -> RequestSizeLimit {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RequestSizeLimit\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  maxSize: {max_size}\n",
        );
        serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("valid RequestSizeLimit: {e}\n{yaml}"))
    }

    #[test]
    fn resolve_request_size_limit_no_ext_ref_is_none() {
        let store = empty_request_size_limit_store();
        assert!(
            resolve_request_size_limit::<HttpRouteRulesFilters>(&[], "default", &store).is_none()
        );
    }

    #[test]
    fn resolve_request_size_limit_parses_byte_suffix() {
        let store =
            make_request_size_limit_store(vec![request_size_limit_cr("default", "rsl", "8m")]);
        let limit =
            resolve_request_size_limit(&[request_size_limit_ext_ref("rsl")], "default", &store);
        assert_eq!(limit, Some(8 * 1024 * 1024));
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_request_size_limit_missing_cr_fails_open() {
        let store = empty_request_size_limit_store();
        let limit =
            resolve_request_size_limit(&[request_size_limit_ext_ref("absent")], "default", &store);
        assert!(limit.is_none());
        assert!(logs_contain("RequestSizeLimit CR not found"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_request_size_limit_invalid_max_size_fails_open() {
        let store =
            make_request_size_limit_store(vec![request_size_limit_cr("default", "rsl", "bogus")]);
        let limit =
            resolve_request_size_limit(&[request_size_limit_ext_ref("rsl")], "default", &store);
        assert!(limit.is_none());
        assert!(logs_contain("invalid maxSize"));
    }

    // ── resolve_compression ───────────────────────────────────────────────────

    use coxswain_core::crd::Compression;

    fn compression_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "Compression".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    fn compression_cr(ns: &str, name: &str, gzip: bool, brotli: bool) -> Compression {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: Compression\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  gzip: {gzip}\n  brotli: {brotli}\n",
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("valid Compression: {e}\n{yaml}"))
    }

    #[test]
    fn resolve_compression_no_ext_ref_is_none() {
        let store = empty_compression_store();
        assert!(resolve_compression::<HttpRouteRulesFilters>(&[], "default", &store).is_none());
    }

    #[test]
    fn resolve_compression_gzip_only_produces_config() {
        let store = make_compression_store(vec![compression_cr("default", "gz", true, false)]);
        let cfg = resolve_compression(&[compression_ext_ref("gz")], "default", &store)
            .expect("Some when gzip enabled");
        assert!(cfg.gzip);
        assert!(!cfg.brotli);
        assert_eq!(cfg.level, 6);
        assert_eq!(cfg.min_size, 1024);
    }

    #[test]
    fn resolve_compression_both_disabled_is_none() {
        let store = make_compression_store(vec![compression_cr("default", "noop", false, false)]);
        assert!(resolve_compression(&[compression_ext_ref("noop")], "default", &store).is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_compression_missing_cr_fails_open() {
        let store = empty_compression_store();
        let cfg = resolve_compression(&[compression_ext_ref("absent")], "default", &store);
        assert!(cfg.is_none());
        assert!(logs_contain("Compression CR not found"));
    }
}
