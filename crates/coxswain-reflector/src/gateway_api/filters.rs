//! Translates `HTTPRouteRule` filter specs into [`FilterAction`][coxswain_core::routing::FilterAction]s.

use crate::MergedStore;
use crate::endpoints::pool::EndpointCache;
use crate::gw_types::v::grpcroutes::{GrpcRouteRulesFilters, GrpcRouteRulesFiltersType};
use crate::gw_types::v::httproutes::{
    HttpRouteRulesBackendRefsFilters, HttpRouteRulesBackendRefsFiltersType, HttpRouteRulesFilters,
    HttpRouteRulesFiltersCors, HttpRouteRulesFiltersType, HttpRouteRulesMatchesHeadersType,
    HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesQueryParamsType,
};
use coxswain_core::crd::{
    BasicAuth, Compression, CoxswainExternalAuth, IpAccessControl, RateLimit, RequestSizeLimit,
    RetryPolicy,
};
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendGroup, CompressionConfig, CorsConfig, CorsOrigin, FilterAction, HeaderMod,
    HeaderPredicate, IngressAuthConfig, MatchPredicates, MirrorFraction, PathModifier,
    QueryPredicate, RateLimitConfig, RetryPolicyConfig, ValueMatch, compile_bounded,
};
use http::{HeaderName, Method};
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;

/// A resolved source-IP CIDR set attached to a route (allow or deny list), or
/// `None` when the set is absent (no filtering on that side). Matches the shape
/// of `RouteEntry::{allow,deny}_source_range`.
pub(super) use super::ip_access_control::CidrSet;

/// Store references needed to resolve `backendRef` targets in filters (e.g.
/// `RequestMirror`).
pub(super) struct BackendStores<'a> {
    pub(super) endpoint_cache: &'a EndpointCache,
    pub(super) services: &'a MergedStore<Service>,
    pub(super) grants: &'a HashSet<ReferenceGrantKey>,
}

/// Outcome of resolving one route-rule `ExtensionRef` against a specific coxswain
/// filter kind. Replaces the earlier ad-hoc per-resolver shapes (`Option<Option<T>>`,
/// an `(allow, deny)` tuple, and an overloaded `Option`) with four named,
/// mutually-exclusive states, so a single shared scan ([`ext_refs`]) drives every
/// resolver. `NotMine` means keep scanning the rule's filters; `Resolved`/`Inert`/
/// `MissingCr` all mean "this ref was a hit" — whether that stops the scan
/// (first-match-wins) is each wrapper's choice (all stop except `resolve_basic_auth`,
/// `resolve_external_auth`, and `resolve_jwt_auth`, which preserve their historical
/// keep-scanning-past-a-miss behaviour).
pub(super) enum RefResolution<T> {
    /// The ref does not target this resolver's kind — keep scanning.
    NotMine,
    /// The ref targets this kind and resolved to an enforceable value.
    Resolved(T),
    /// The ref targets this kind, its CR **exists**, but the resolved value is a
    /// no-op (an explicit disabling value like `requestsPerSecond: 0`, or a
    /// malformed sub-field skipped with a WARN, e.g. an invalid regex) — the
    /// route installs with no enforcement, same as today. NOT a dangling
    /// reference (the CR resolved), so #689/GEP-1364 does not apply here: an
    /// operator's intentional "policy exists but currently disabled" config
    /// must not start 500ing.
    Inert,
    /// The referenced CR does not exist — a dangling `ExtensionRef`. Distinct
    /// from [`Self::Inert`]: per GEP-1364 ("If a reference to a custom filter
    /// type cannot be resolved, the filter MUST NOT be skipped... requests...
    /// MUST receive a HTTP error response"), the caller installs a 500 error
    /// route rather than silently admitting traffic the filter never saw (#689).
    MissingCr,
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

/// `(namespace, name, port)` of each `RequestMirror` filter's backend Service.
///
/// The partition fingerprint (#511) needs these: a mirror backend's endpoints
/// are baked into the compiled router (a `BackendGroup`) but are **not** a
/// `backend_ref`, so their pod churn would otherwise not dirty the partition,
/// leaving a reused router mirroring to dead IPs. Over-inclusive by design
/// (any ref carrying a port, before the core-Service eligibility check the
/// translator applies) — forfeiting reuse for an exotic mirror ref is safe;
/// missing one risks stale mirror endpoints.
pub(super) fn mirror_backend_refs(
    filters: &[HttpRouteRulesFilters],
) -> impl Iterator<Item = (Option<&str>, &str, i32)> {
    filters.iter().filter_map(|f| {
        if !matches!(f.r#type, HttpRouteRulesFiltersType::RequestMirror) {
            return None;
        }
        let bref = &f.request_mirror.as_ref()?.backend_ref;
        let port = bref.port?;
        Some((bref.namespace.as_deref(), bref.name.as_str(), port))
    })
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
///
/// `path_rewrite` is the `FilterAction` already resolved (once per rule, not
/// once per match) from the rule's `PathRewriteRegex` `ExtensionRef`, if any
/// (`super::filters::resolve_path_rewrite`, #689). Threading it in rather than
/// resolving it here keeps it at its **declared position** in `filters` — an
/// HTTPRoute rule may legally combine one `PathRewriteRegex` `ExtensionRef`
/// with a `URLRewrite` filter, and the proxy applies path modifiers in
/// declaration order with each rewrite fully replacing the previous one
/// (`coxswain-proxy`'s `rewrite_path` always recomputes from the original
/// path), so which one is declared last decides which one wins.
pub(super) fn build_filters(
    filters: &[HttpRouteRulesFilters],
    matched_prefix: &str,
    is_prefix_match: bool,
    route_ns: &str,
    path_rewrite: Option<&FilterAction>,
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
                    // Resolved once per rule by `resolve_path_rewrite` (#689) so its
                    // "CR missing" case can drive the shared fail-closed decision;
                    // emitted here, at its declared position, so a rule combining a
                    // PathRewriteRegex ExtensionRef with a URLRewrite filter keeps
                    // "last declared wins" (see this function's doc).
                    (super::COXSWAIN_GROUP, "PathRewriteRegex") => {
                        if let Some(action) = path_rewrite {
                            out.push(action.clone());
                        }
                    }
                    // Resolved separately by the `resolve_*` scanners into per-route
                    // config off the filter list — no `FilterAction` emitted here.
                    (
                        super::COXSWAIN_GROUP,
                        "RateLimit" | "IpAccessControl" | "BasicAuth" | "RequestSizeLimit"
                        | "Compression" | "ExternalAuth" | "RetryPolicy" | "JwtAuth",
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
                    stores
                        .endpoint_cache
                        .get(mirror_ns, &bref.name, port, stores.services);
                if !resolved.service_exists {
                    tracing::warn!(
                        mirror_ns,
                        mirror_svc = %bref.name,
                        "RequestMirror backend Service not found — skipping"
                    );
                    continue;
                }
                // Empty addrs: Service exists but has no ready endpoints. Install the
                // filter anyway so the proxy can log the drop at dispatch time. The
                // ref carries its endpoint key (#383) so the mirror target survives a
                // wire delta while its endpoints are transiently absent.
                let key = stores.endpoint_cache.key(mirror_ns, &bref.name, port);
                let mirror_group = Arc::new(BackendGroup::weighted_with_endpoints(
                    format!("{mirror_ns}/{}", bref.name),
                    vec![(resolved, Some(key), 1)],
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
/// Coxswain supports only `RequestHeaderModifier` and `ResponseHeaderModifier`
/// at backend-ref scope; other types (`RequestRedirect`, `URLRewrite`,
/// `RequestMirror`, `ExtensionRef`, `CORS`) are logged + skipped here. This is
/// an implementation choice, not a spec requirement — the spec itself permits
/// all of these inside `backendRefs` (`URLRewrite`/`RequestMirror`/`CORS` at
/// `Support: Extended`, `RequestRedirect` at `Support: Core`, `ExtensionRef` at
/// `Support: Implementation-specific`) and CEL-validates them there. The
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
                    "Skipping unsupported per-backend filter type \
                     (coxswain implements only RequestHeaderModifier and ResponseHeaderModifier at backendRef scope)"
                );
            }
        }
    }
    out
}

/// Scans `filters` for an `ExtensionRef` pointing at a `PathRewriteRegex` CR
/// and, if found, resolves it into a [`FilterAction::UrlRewrite`]. Extracted
/// out of `build_filters` (#689) so its "CR missing" case can drive the same
/// `error_status` fail-closed decision as every other resolver — the caller
/// appends the returned `FilterAction` to the per-match filter list.
///
/// Only the first matching `ExtensionRef` is used. Returns `(action,
/// unresolved)`: `unresolved=true` only when the CR itself does not exist
/// (WARN, #689/GEP-1364 — the caller installs a 500 error route). An
/// **invalid regex** on an existing CR is a resolved-but-inert ref (WARN,
/// filter skipped, path left as-is) — not a dangling reference.
pub(super) fn resolve_path_rewrite<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    path_rewrites: &MergedStore<coxswain_core::crd::PathRewriteRegex>,
) -> (Option<FilterAction>, bool) {
    for (g, k, n) in ext_refs(filters) {
        match resolve_path_rewrite_ref(g, k, n, route_ns, path_rewrites) {
            RefResolution::NotMine => continue,
            RefResolution::Resolved(action) => return (Some(action), false),
            RefResolution::Inert => return (None, false),
            RefResolution::MissingCr => return (None, true),
        }
    }
    (None, false)
}

/// Resolve a single `ExtensionRef` into a [`FilterAction::UrlRewrite`], if it
/// targets a `PathRewriteRegex` CR.
fn resolve_path_rewrite_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    path_rewrites: &MergedStore<coxswain_core::crd::PathRewriteRegex>,
) -> RefResolution<FilterAction> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "PathRewriteRegex" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<coxswain_core::crd::PathRewriteRegex>::new(ext_name)
        .within(route_ns);
    let Some(cr) = path_rewrites.get(&obj_ref) else {
        tracing::warn!(
            name = ext_name,
            ns = route_ns,
            "PathRewriteRegex CR not found — failing closed (500)"
        );
        return RefResolution::MissingCr;
    };
    match compile_bounded(&cr.spec.pattern) {
        Ok(regex) => RefResolution::Resolved(FilterAction::UrlRewrite {
            hostname: None,
            path: Some(PathModifier::RegexReplace {
                regex: Arc::new(regex),
                replacement: Box::from(cr.spec.replacement.as_str()),
            }),
        }),
        Err(e) => {
            tracing::warn!(
                name = ext_name,
                ns = route_ns,
                error = %e,
                "PathRewriteRegex CR has invalid regex — filter skipped"
            );
            RefResolution::Inert
        }
    }
}

/// Scans `filters` for an `ExtensionRef` pointing at a `RateLimit` CR
/// (`group: gateway.coxswain-labs.dev`, `kind: RateLimit`) and, if found, resolves
/// the named CR from `rate_limits` and converts its spec to a
/// [`RateLimitConfig`].
///
/// Only the first matching `ExtensionRef` is used; other extension refs (and
/// non-`RateLimit` kinds) are ignored here — `build_filters` owns the
/// "unsupported ExtensionRef" WARN, so this scan stays silent on them. Returns
/// `(config, unresolved)`: `unresolved=true` only when the CR itself does not
/// exist (WARN, #689/GEP-1364 — the caller installs a 500 error route). A CR
/// with `requestsPerSecond=0` is resolved-but-inert (WARN, no limit enforced)
/// — not a dangling reference.
pub(super) fn resolve_rate_limit<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    rate_limits: &MergedStore<RateLimit>,
) -> (Option<Arc<RateLimitConfig>>, bool) {
    for (g, k, n) in ext_refs(filters) {
        match resolve_rate_limit_ref(g, k, n, route_ns, rate_limits) {
            RefResolution::NotMine => continue,
            RefResolution::Resolved(cfg) => return (Some(cfg), false),
            RefResolution::Inert => return (None, false),
            RefResolution::MissingCr => return (None, true),
        }
    }
    (None, false)
}

/// Resolve a single `ExtensionRef` (by `group`/`kind`/`name`) into a
/// [`RateLimitConfig`], if it targets a `RateLimit` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** a `RateLimit` (`group ==
/// gateway.coxswain-labs.dev`, `kind == RateLimit`) so the caller keeps scanning;
/// [`RefResolution::MissingCr`] on a missing CR (WARN, #689 — the caller fails
/// closed); [`RefResolution::Inert`] on `requestsPerSecond=0` (WARN, no limit
/// enforced); [`RefResolution::Resolved`] otherwise. Shared by the HTTPRoute and
/// GRPCRoute reconcilers (rate limiting is protocol-agnostic; only the
/// differently-typed filter-list iteration differs).
pub(super) fn resolve_rate_limit_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    rate_limits: &MergedStore<RateLimit>,
) -> RefResolution<Arc<RateLimitConfig>> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "RateLimit" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<RateLimit>::new(ext_name).within(route_ns);
    let Some(cr) = rate_limits.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "RateLimit CR not found — failing closed (500)"
        );
        return RefResolution::MissingCr;
    };
    match super::rate_limit::resolve_spec(&cr.spec) {
        Some(cfg) => RefResolution::Resolved(cfg),
        None => {
            tracing::warn!(
                ns = route_ns,
                name = ext_name,
                "RateLimit CR has requestsPerSecond=0 — rate limiting skipped"
            );
            RefResolution::Inert
        }
    }
}

/// Scans `filters` for an `ExtensionRef` pointing at a `RetryPolicy` CR and resolves
/// it into the runtime [`RetryPolicyConfig`] the backend group carries.
///
/// Protocol-agnostic via [`ExtRefFilter`]: `is_grpc` selects the code defaulting
/// (`GRPCRoute` also honours `grpcCodes` and defaults it to `[14]`; `HTTPRoute`
/// ignores gRPC codes). Only the first matching `ExtensionRef` is used. Returns
/// `(policy, unresolved)`: `unresolved=true` only when the CR itself does not
/// exist (WARN, #689/GEP-1364 — the caller installs a 500 error route); the
/// default (disabled) policy otherwise, including when no `RetryPolicy` ref is
/// present at all.
pub(super) fn resolve_retry_policy<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    retry_policies: &MergedStore<RetryPolicy>,
    is_grpc: bool,
) -> (RetryPolicyConfig, bool) {
    for (g, k, n) in ext_refs(filters) {
        match resolve_retry_policy_ref(g, k, n, route_ns, retry_policies, is_grpc) {
            RefResolution::NotMine => continue,
            RefResolution::Resolved(cfg) => return (cfg, false),
            RefResolution::Inert => return (RetryPolicyConfig::default(), false),
            RefResolution::MissingCr => return (RetryPolicyConfig::default(), true),
        }
    }
    (RetryPolicyConfig::default(), false)
}

/// Resolve a single `ExtensionRef` into a [`RetryPolicyConfig`], if it targets a
/// `RetryPolicy` CR. [`RefResolution::NotMine`] keeps the caller scanning;
/// [`RefResolution::MissingCr`] (missing CR) yields the default disabled policy
/// and signals the caller to fail closed (#689).
fn resolve_retry_policy_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    retry_policies: &MergedStore<RetryPolicy>,
    is_grpc: bool,
) -> RefResolution<RetryPolicyConfig> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "RetryPolicy" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<RetryPolicy>::new(ext_name).within(route_ns);
    let Some(cr) = retry_policies.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "RetryPolicy CR not found — failing closed (500)"
        );
        return RefResolution::MissingCr;
    };
    RefResolution::Resolved(super::retry::resolve_spec(&cr.spec, is_grpc, route_ns))
}

/// Scans `filters` for an `ExtensionRef` pointing at an `IpAccessControl` CR
/// (`group: gateway.coxswain-labs.dev`, `kind: IpAccessControl`) and, if found, resolves
/// the named CR from `ip_access` and parses its `allow` / `deny` CIDR sets into
/// the `(allow_source_range, deny_source_range)` lists the proxy enforces (deny
/// evaluated first — the same fields the Ingress `ip-access-control`
/// annotation feeds, #553).
///
/// Only the first matching `ExtensionRef` is used; other extension refs (and
/// non-`IpAccessControl` kinds) are ignored here — `build_filters` owns the
/// "unsupported ExtensionRef" WARN, so this scan stays silent on them. Returns
/// `((allow, deny), unresolved)`: `unresolved=true` only when the CR itself
/// does not exist (WARN, #689/GEP-1364 — the caller installs a 500 error
/// route). Each CIDR set is `None` when empty or entirely unparseable, so an
/// empty/typo'd list never silently changes the route's admit behaviour.
pub(super) fn resolve_ip_access<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    ip_access: &MergedStore<IpAccessControl>,
) -> ((CidrSet, CidrSet), bool) {
    for (g, k, n) in ext_refs(filters) {
        match resolve_ip_access_ref(g, k, n, route_ns, ip_access) {
            RefResolution::NotMine => continue,
            RefResolution::Resolved(sets) => return (sets, false),
            RefResolution::Inert => return ((None, None), false),
            RefResolution::MissingCr => return ((None, None), true),
        }
    }
    ((None, None), false)
}

/// Resolve a single `ExtensionRef` (identified by its `group`/`kind`/`name`) into
/// the `(allow, deny)` source-IP CIDR sets, if it targets an `IpAccessControl` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** an `IpAccessControl`
/// (`group == gateway.coxswain-labs.dev`, `kind == IpAccessControl`) so the caller
/// keeps scanning; [`RefResolution::MissingCr`] when the CR is missing (WARN,
/// #689 — the caller fails closed); [`RefResolution::Resolved((allow, deny))`]
/// otherwise (each set `None` when empty/unparseable). Shared by the HTTPRoute
/// and GRPCRoute reconcilers, which iterate their own (differently-typed)
/// filter lists.
pub(super) fn resolve_ip_access_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    ip_access: &MergedStore<IpAccessControl>,
) -> RefResolution<(CidrSet, CidrSet)> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "IpAccessControl" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<IpAccessControl>::new(ext_name).within(route_ns);
    let Some(cr) = ip_access.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "IpAccessControl CR not found — failing closed (500)"
        );
        return RefResolution::MissingCr;
    };
    RefResolution::Resolved(super::ip_access_control::resolve_spec(
        &cr.spec, route_ns, ext_name,
    ))
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
/// "unsupported ExtensionRef" WARN. Returns `(config, unresolved)`.
/// `config=None` when no `BasicAuth` `ExtensionRef` is present on this rule
/// (no auth on the route) *and* every `BasicAuth` ref present had a missing
/// CR. `unresolved=true` only in that latter case (WARN, #689/GEP-1364 — the
/// caller installs a 500 error route) — never when a present ref resolved.
pub(super) fn resolve_basic_auth<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    basic_auths: &MergedStore<BasicAuth>,
    auth_secrets: &MergedStore<Secret>,
    secret_grants: &HashSet<ReferenceGrantKey>,
) -> (Option<Arc<IngressAuthConfig>>, bool) {
    // Unlike the other resolvers, basic-auth historically *kept scanning* past
    // a missing CR rather than stopping, so a later `BasicAuth` ref on the same
    // rule could still resolve. Preserved verbatim — `missing` only reflects
    // the outcome if no ref ever resolves.
    let mut missing = false;
    for (g, k, n) in ext_refs(filters) {
        match resolve_basic_auth_ref(g, k, n, route_ns, basic_auths, auth_secrets, secret_grants) {
            RefResolution::NotMine | RefResolution::Inert => {}
            RefResolution::MissingCr => missing = true,
            RefResolution::Resolved(cfg) => return (Some(cfg), false),
        }
    }
    (None, missing)
}

/// Resolve the first `CoxswainExternalAuth` `ExtensionRef` on the rule into an
/// [`IngressAuthConfig`] (#23).
///
/// Returns `(config, unresolved)` with the same keep-scanning-past-a-miss
/// semantics as [`resolve_basic_auth`]: `unresolved=true` only when every
/// `ExternalAuth` ref present had a missing CR (WARN, #689/GEP-1364 — the
/// caller installs a 500 error route). A present-but-broken backend (no
/// endpoints, ungranted cross-namespace ref, or a `backendRef` that isn't a
/// core `Service`) fails **closed** via [`IngressAuthConfig::Unavailable`],
/// resolved in [`super::external_auth::resolve_spec`] — unaffected by this
/// change, since the CR itself resolved.
pub(super) fn resolve_external_auth<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    external_auths: &MergedStore<CoxswainExternalAuth>,
    services: &MergedStore<Service>,
    endpoint_cache: &EndpointCache,
    grants: &HashSet<ReferenceGrantKey>,
) -> (Option<Arc<IngressAuthConfig>>, bool) {
    let mut missing = false;
    for (g, k, n) in ext_refs(filters) {
        if g != super::COXSWAIN_GROUP || k != "ExternalAuth" {
            continue;
        }
        let obj_ref = reflector::ObjectRef::<CoxswainExternalAuth>::new(n).within(route_ns);
        let Some(cr) = external_auths.get(&obj_ref) else {
            tracing::warn!(
                ns = route_ns,
                name = n,
                "CoxswainExternalAuth CR not found — failing closed (500)"
            );
            missing = true;
            continue;
        };
        return (
            Some(Arc::new(super::external_auth::resolve_spec(
                &cr.spec,
                route_ns,
                services,
                endpoint_cache,
                grants,
            ))),
            false,
        );
    }
    (None, missing)
}

/// Resolve the first `JwtAuth` `ExtensionRef` on the rule into an
/// [`IngressAuthConfig`] (#441).
///
/// Returns `(config, unresolved)` with the same keep-scanning-past-a-miss
/// semantics as [`resolve_basic_auth`]: `unresolved=true` only when every
/// `JwtAuth` ref present had a missing CR (WARN, #689/GEP-1364 — the caller
/// installs a 500 error route). A present-but-unresolved JWKS (broken
/// `jwksUri`, or neither `remote`/`inline` set) fails **closed** via
/// [`IngressAuthConfig::Unavailable`], resolved in
/// [`super::jwt_auth::resolve_spec`] — unaffected by this change, since the CR
/// itself resolved.
pub(super) fn resolve_jwt_auth<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    jwt_auths: &MergedStore<coxswain_core::crd::JwtAuth>,
    jwks_cache: &crate::jwks::JwksCacheHandle,
) -> (Option<Arc<IngressAuthConfig>>, bool) {
    let mut missing = false;
    for (g, k, n) in ext_refs(filters) {
        if g != super::COXSWAIN_GROUP || k != "JwtAuth" {
            continue;
        }
        let obj_ref = reflector::ObjectRef::<coxswain_core::crd::JwtAuth>::new(n).within(route_ns);
        let Some(cr) = jwt_auths.get(&obj_ref) else {
            tracing::warn!(
                ns = route_ns,
                name = n,
                "JwtAuth CR not found — failing closed (500)"
            );
            missing = true;
            continue;
        };
        let route_id = format!("{route_ns}/{n}");
        return (
            Some(Arc::new(super::jwt_auth::resolve_spec(
                &cr.spec, jwks_cache, &route_id,
            ))),
            false,
        );
    }
    (None, missing)
}

/// Resolve a single `ExtensionRef` (by `group`/`kind`/`name`) into an
/// [`IngressAuthConfig`], if it targets a `BasicAuth` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** a `BasicAuth` so the
/// caller keeps scanning, or [`RefResolution::MissingCr`] when the `BasicAuth` CR
/// itself is missing (WARN, #689 — the caller fails closed unless a later ref on
/// the same rule resolves). Once a CR is found, every subsequent
/// failure (missing/unlabeled Secret, missing `auth` key, zero parseable credentials)
/// fails **closed** — [`RefResolution::Resolved`] carrying
/// [`IngressAuthConfig::Unavailable`] — because an operator who attached this filter
/// expects auth enforcement, so a broken Secret must not silently open the route.
pub(super) fn resolve_basic_auth_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    basic_auths: &MergedStore<BasicAuth>,
    auth_secrets: &MergedStore<Secret>,
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
            "BasicAuth CR not found — failing closed (500)"
        );
        return RefResolution::MissingCr;
    };
    let route_id = format!("{route_ns}/{ext_name}");
    let secret_ref = &cr.spec.secret_ref;

    // Cross-namespace secretRef requires a matching `BasicAuth → Secret`
    // ReferenceGrant (#520). Without one, fail closed (503) rather than binding a
    // Secret in another namespace. Both surfaces now reject an ungranted
    // cross-namespace secretRef — the Gateway BasicAuth CRD via this
    // ReferenceGrant check, the Ingress auth-basic-secret annotation via a
    // hard namespace lock with no grant model at all (#688). Same-namespace
    // refs need no grant.
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
/// Only the first matching `ExtensionRef` is used. Returns `(limit,
/// unresolved)`: `unresolved=true` only when the CR itself does not exist
/// (WARN, #689/GEP-1364 — the caller installs a 500 error route). An
/// unparseable `maxSize` on an existing CR is resolved-but-inert (WARN, no
/// limit enforced) — not a dangling reference. **HTTPRoute only** —
/// `grpc_reconcile.rs` never calls this; gRPC message sizes are governed by
/// the backend's own limits instead (see `RequestSizeLimit is not enforced on
/// GRPCRoute` in `docs/src/gateway-api/route-extensions.md`).
pub(super) fn resolve_request_size_limit<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    request_size_limits: &MergedStore<RequestSizeLimit>,
) -> (Option<u64>, bool) {
    for (g, k, n) in ext_refs(filters) {
        match resolve_request_size_limit_ref(g, k, n, route_ns, request_size_limits) {
            RefResolution::NotMine => continue,
            RefResolution::Resolved(limit) => return (Some(limit), false),
            RefResolution::Inert => return (None, false),
            RefResolution::MissingCr => return (None, true),
        }
    }
    (None, false)
}

/// Resolve a single `ExtensionRef` into a byte-count limit, if it targets a
/// `RequestSizeLimit` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** a `RequestSizeLimit` so
/// the caller keeps scanning; [`RefResolution::MissingCr`] on a missing CR (WARN,
/// #689 — the caller fails closed); [`RefResolution::Inert`] on an unparseable
/// `maxSize` (WARN — no limit enforced); [`RefResolution::Resolved(n)`] otherwise.
pub(super) fn resolve_request_size_limit_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    request_size_limits: &MergedStore<RequestSizeLimit>,
) -> RefResolution<u64> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "RequestSizeLimit" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<RequestSizeLimit>::new(ext_name).within(route_ns);
    let Some(cr) = request_size_limits.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "RequestSizeLimit CR not found — failing closed (500)"
        );
        return RefResolution::MissingCr;
    };
    match crate::ingress::annotations::parse_byte_size(&cr.spec.max_size) {
        Some(limit) => RefResolution::Resolved(limit),
        None => {
            tracing::warn!(
                ns = route_ns,
                name = ext_name,
                value = %cr.spec.max_size,
                "RequestSizeLimit CR has invalid maxSize — limit skipped"
            );
            RefResolution::Inert
        }
    }
}

/// Scans `filters` for an `ExtensionRef` pointing at a `Compression` CR
/// (`group: gateway.coxswain-labs.dev`, `kind: Compression`) and, if found,
/// resolves the named CR into a [`CompressionConfig`].
///
/// Only the first matching `ExtensionRef` is used. Returns `(config,
/// unresolved)`: `unresolved=true` only when the CR itself does not exist
/// (WARN, #689/GEP-1364 — the caller installs a 500 error route). When both
/// `gzip` and `brotli` are `false` the CR is a resolved-but-inert no-op (not a
/// dangling reference) — the same [`super::compression::resolve_spec`] the
/// Ingress `compression` annotation (#550) resolves through — the proxy never
/// constructs an encoder for a route with nothing to compress.
pub(super) fn resolve_compression<F: ExtRefFilter>(
    filters: &[F],
    route_ns: &str,
    compressions: &MergedStore<Compression>,
) -> (Option<Arc<CompressionConfig>>, bool) {
    for (g, k, n) in ext_refs(filters) {
        match resolve_compression_ref(g, k, n, route_ns, compressions) {
            RefResolution::NotMine => continue,
            RefResolution::Resolved(cfg) => return (Some(cfg), false),
            RefResolution::Inert => return (None, false),
            RefResolution::MissingCr => return (None, true),
        }
    }
    (None, false)
}

/// Resolve a single `ExtensionRef` into a [`CompressionConfig`], if it
/// targets a `Compression` CR.
///
/// Returns [`RefResolution::NotMine`] when the ref is **not** a `Compression` so the
/// caller keeps scanning; [`RefResolution::MissingCr`] on a missing CR (WARN, #689
/// — the caller fails closed); [`RefResolution::Inert`] on a CR with both
/// `gzip`/`brotli` disabled (a no-op — the proxy builds no encoder);
/// [`RefResolution::Resolved(cfg)`] otherwise.
pub(super) fn resolve_compression_ref(
    ext_group: &str,
    ext_kind: &str,
    ext_name: &str,
    route_ns: &str,
    compressions: &MergedStore<Compression>,
) -> RefResolution<Arc<CompressionConfig>> {
    if ext_group != super::COXSWAIN_GROUP || ext_kind != "Compression" {
        return RefResolution::NotMine;
    }
    let obj_ref = reflector::ObjectRef::<Compression>::new(ext_name).within(route_ns);
    let Some(cr) = compressions.get(&obj_ref) else {
        tracing::warn!(
            ns = route_ns,
            name = ext_name,
            "Compression CR not found — failing closed (500)"
        );
        return RefResolution::MissingCr;
    };
    match super::compression::resolve_spec(&cr.spec) {
        Some(cfg) => RefResolution::Resolved(cfg),
        None => RefResolution::Inert,
    }
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
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
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
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
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

    /// #689 regression: extracting `PathRewriteRegex` resolution out of
    /// `build_filters` must not change *where* its `FilterAction` lands in the
    /// filter list. A rule may legally combine a `PathRewriteRegex`
    /// `ExtensionRef` with a `URLRewrite` filter; the proxy applies path
    /// modifiers in declaration order and each fully recomputes from the
    /// original path, so whichever is declared LAST wins. Proves both
    /// orderings produce a filter list in the same order as the source rule —
    /// not the ExtensionRef-derived action always landing last regardless of
    /// where it was declared.
    #[test]
    fn path_rewrite_ext_ref_and_url_rewrite_keep_declared_order() {
        use crate::gw_types::v::httproutes::{
            HttpRouteRulesFiltersExtensionRef, HttpRouteRulesFiltersUrlRewritePath,
        };

        let path_rewrites = make_path_rewrite_store(vec![{
            let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                 kind: PathRewriteRegex\n\
                 metadata:\n  name: rw\n  namespace: default\n\
                 spec:\n  pattern: \"^/old\"\n  replacement: \"/new\"\n";
            serde_yaml::from_str(yaml).expect("valid PathRewriteRegex")
        }]);
        let ext_ref_filter = HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "PathRewriteRegex".to_string(),
                name: "rw".to_string(),
            }),
            ..Default::default()
        };
        let url_rewrite_filter = HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::UrlRewrite,
            url_rewrite: Some(HttpRouteRulesFiltersUrlRewrite {
                hostname: None,
                path: Some(HttpRouteRulesFiltersUrlRewritePath {
                    r#type: HttpRouteRulesFiltersUrlRewritePathType::ReplaceFullPath,
                    replace_full_path: Some("/v3".to_string()),
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
        let reconcile = |filters: Vec<HttpRouteRulesFilters>| {
            let route = make_route_with_filters(
                "default",
                "example.com",
                "/",
                HttpRouteRulesMatchesPathType::PathPrefix,
                "svc",
                filters,
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
                    retry_policies: &empty_retry_policy_store(),
                    path_rewrites: &path_rewrites,
                    ip_access: &empty_ip_access_store(),
                    basic_auths: &empty_basic_auth_store(),
                    external_auths: &empty_external_auth_store(),
                    external_auth_gateway_index: &std::collections::HashMap::new(),
                    jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                    jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
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
            find_filters(&table, "example.com", "/")
        };

        // PathRewriteRegex declared first, URLRewrite last -> URLRewrite wins.
        let filters = reconcile(vec![ext_ref_filter.clone(), url_rewrite_filter.clone()]);
        assert_eq!(
            filters.len(),
            2,
            "both rewrites must be preserved, not deduped"
        );
        assert!(
            matches!(
                &filters[0],
                FilterAction::UrlRewrite {
                    path: Some(PathModifier::RegexReplace { .. }),
                    ..
                }
            ),
            "PathRewriteRegex-derived action must stay at its declared (first) position"
        );
        assert!(
            matches!(
                &filters[1],
                FilterAction::UrlRewrite {
                    path: Some(PathModifier::ReplaceFullPath(_)),
                    ..
                }
            ),
            "URLRewrite declared last must be last, so it wins at the proxy"
        );

        // URLRewrite declared first, PathRewriteRegex last -> PathRewriteRegex wins.
        let filters = reconcile(vec![url_rewrite_filter, ext_ref_filter]);
        assert_eq!(filters.len(), 2);
        assert!(
            matches!(
                &filters[0],
                FilterAction::UrlRewrite {
                    path: Some(PathModifier::ReplaceFullPath(_)),
                    ..
                }
            ),
            "URLRewrite declared first must stay first"
        );
        assert!(
            matches!(
                &filters[1],
                FilterAction::UrlRewrite {
                    path: Some(PathModifier::RegexReplace { .. }),
                    ..
                }
            ),
            "PathRewriteRegex-derived action declared last must be last, so it wins at the proxy"
        );
    }

    #[test]
    fn reconcile_response_header_modifier_stored() {
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
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
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
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
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
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
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
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
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
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
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
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
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
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
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
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

    // ── resolve_rate_limit ────────────────────────────────────────────────────

    use coxswain_core::crd::RateLimit;

    fn rate_limit_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(
                crate::gw_types::v::httproutes::HttpRouteRulesFiltersExtensionRef {
                    group: "gateway.coxswain-labs.dev".to_string(),
                    kind: "RateLimit".to_string(),
                    name: name.to_string(),
                },
            ),
            ..Default::default()
        }
    }

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
    fn resolve_rate_limit_no_ext_ref_is_none() {
        let store = empty_rate_limit_store();
        let (cfg, unresolved) = resolve_rate_limit::<HttpRouteRulesFilters>(&[], "default", &store);
        assert!(cfg.is_none());
        assert!(!unresolved);
    }

    #[test]
    fn resolve_rate_limit_present_cr_resolves() {
        let store = make_rate_limit_store(vec![rate_limit_cr("default", "rl", 10)]);
        let (cfg, unresolved) = resolve_rate_limit(&[rate_limit_ext_ref("rl")], "default", &store);
        assert_eq!(
            cfg.expect("Some when CR present").requests_per_second.get(),
            10
        );
        assert!(!unresolved);
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_rate_limit_missing_cr_fails_closed() {
        let store = empty_rate_limit_store();
        let (cfg, unresolved) =
            resolve_rate_limit(&[rate_limit_ext_ref("absent")], "default", &store);
        assert!(cfg.is_none(), "missing CR installs no rate limit config");
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
        assert!(logs_contain("RateLimit CR not found"));
    }

    /// The flagship `Inert` example: a CR that **exists** but sets
    /// `requestsPerSecond: 0` is a resolved, intentional no-op — it must NOT
    /// be conflated with a missing CR, or every route referencing a
    /// deliberately-disabled `RateLimit` would start 500ing all its traffic.
    #[test]
    #[tracing_test::traced_test]
    fn resolve_rate_limit_zero_rps_is_inert() {
        let store = make_rate_limit_store(vec![rate_limit_cr("default", "rl", 0)]);
        let (cfg, unresolved) = resolve_rate_limit(&[rate_limit_ext_ref("rl")], "default", &store);
        assert!(cfg.is_none(), "rps=0 installs no rate limit config");
        assert!(
            !unresolved,
            "a resolved CR with rps=0 is an intentional no-op, not dangling"
        );
        assert!(logs_contain("requestsPerSecond=0"));
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
        let ((allow, deny), unresolved) =
            resolve_ip_access::<HttpRouteRulesFilters>(&[], "default", &store);
        assert!(allow.is_none());
        assert!(deny.is_none());
        assert!(!unresolved);
    }

    #[test]
    fn resolve_ip_access_present_cr_parses_allow_and_deny() {
        let store = make_ip_access_store(vec![ip_access_cr(
            "default",
            "policy",
            &["203.0.113.0/24"],
            &["10.0.0.0/8"],
        )]);
        let ((allow, deny), unresolved) =
            resolve_ip_access(&[ip_access_ext_ref("policy")], "default", &store);
        assert_eq!(
            *allow.expect("allow set"),
            vec!["203.0.113.0/24".parse::<ipnet::IpNet>().expect("valid")]
        );
        assert_eq!(
            *deny.expect("deny set"),
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().expect("valid")]
        );
        assert!(!unresolved);
    }

    #[test]
    fn resolve_ip_access_bare_ip_becomes_host_route() {
        let store = make_ip_access_store(vec![ip_access_cr(
            "default",
            "policy",
            &["203.0.113.10"],
            &[],
        )]);
        let ((allow, _), _) = resolve_ip_access(&[ip_access_ext_ref("policy")], "default", &store);
        assert_eq!(
            *allow.expect("allow set"),
            vec!["203.0.113.10/32".parse::<ipnet::IpNet>().expect("valid")]
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_ip_access_missing_cr_fails_closed() {
        let store = empty_ip_access_store();
        let ((allow, deny), unresolved) =
            resolve_ip_access(&[ip_access_ext_ref("absent")], "default", &store);
        assert!(allow.is_none(), "missing CR installs no filter config");
        assert!(deny.is_none(), "missing CR installs no filter config");
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
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
        let ((allow, deny), unresolved) =
            resolve_ip_access(&[ip_access_ext_ref("policy")], "default", &store);
        assert_eq!(allow.expect("one valid allow").len(), 1);
        assert!(deny.is_none(), "all-invalid deny list collapses to None");
        assert!(
            !unresolved,
            "a resolved CR with skipped sub-fields is not dangling"
        );
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
        let (cfg, unresolved) = resolve_basic_auth::<HttpRouteRulesFilters>(
            &[],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        );
        assert!(cfg.is_none());
        assert!(!unresolved);
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_basic_auth_missing_cr_fails_closed() {
        let basic_auths = empty_basic_auth_store();
        let auth_secrets = empty_secret_store();
        let (cfg, unresolved) = resolve_basic_auth(
            &[basic_auth_ext_ref("absent")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        );
        assert!(cfg.is_none(), "missing CR installs no auth config");
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
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
        let (cfg, unresolved) = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        );
        let cfg = cfg.expect("Some when CR present");
        assert!(matches!(*cfg, IngressAuthConfig::Unavailable));
        assert!(
            !unresolved,
            "the BasicAuth CR itself resolved — 503 via Unavailable, not #689's 500"
        );
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
        let (cfg, _) = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        );
        let cfg = cfg.expect("Some when CR and Secret present");
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
        let (cfg, _) = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        );
        let cfg = cfg.expect("Some when CR present");
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
        let (cfg, _) = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &std::collections::HashSet::new(),
        );
        let cfg = cfg.expect("Some when CR present");
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
        let (cfg, _) = resolve_basic_auth(
            &[basic_auth_ext_ref("policy")],
            "default",
            &basic_auths,
            &auth_secrets,
            &grants,
        );
        let cfg = cfg.expect("Some when CR and Secret present");
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
        let (limit, unresolved) =
            resolve_request_size_limit::<HttpRouteRulesFilters>(&[], "default", &store);
        assert!(limit.is_none());
        assert!(!unresolved);
    }

    #[test]
    fn resolve_request_size_limit_parses_byte_suffix() {
        let store =
            make_request_size_limit_store(vec![request_size_limit_cr("default", "rsl", "8m")]);
        let (limit, unresolved) =
            resolve_request_size_limit(&[request_size_limit_ext_ref("rsl")], "default", &store);
        assert_eq!(limit, Some(8 * 1024 * 1024));
        assert!(!unresolved);
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_request_size_limit_missing_cr_fails_closed() {
        let store = empty_request_size_limit_store();
        let (limit, unresolved) =
            resolve_request_size_limit(&[request_size_limit_ext_ref("absent")], "default", &store);
        assert!(limit.is_none());
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
        assert!(logs_contain("RequestSizeLimit CR not found"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_request_size_limit_invalid_max_size_is_inert() {
        let store =
            make_request_size_limit_store(vec![request_size_limit_cr("default", "rsl", "bogus")]);
        let (limit, unresolved) =
            resolve_request_size_limit(&[request_size_limit_ext_ref("rsl")], "default", &store);
        assert!(limit.is_none());
        assert!(
            !unresolved,
            "a resolved CR with a malformed field is not dangling"
        );
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
        let (cfg, unresolved) =
            resolve_compression::<HttpRouteRulesFilters>(&[], "default", &store);
        assert!(cfg.is_none());
        assert!(!unresolved);
    }

    #[test]
    fn resolve_compression_gzip_only_produces_config() {
        let store = make_compression_store(vec![compression_cr("default", "gz", true, false)]);
        let (cfg, _) = resolve_compression(&[compression_ext_ref("gz")], "default", &store);
        let cfg = cfg.expect("Some when gzip enabled");
        assert!(cfg.gzip);
        assert!(!cfg.brotli);
        assert_eq!(cfg.level, 6);
        assert_eq!(cfg.min_size, 1024);
    }

    #[test]
    fn resolve_compression_both_disabled_is_inert() {
        let store = make_compression_store(vec![compression_cr("default", "noop", false, false)]);
        let (cfg, unresolved) =
            resolve_compression(&[compression_ext_ref("noop")], "default", &store);
        assert!(cfg.is_none());
        assert!(!unresolved, "a resolved no-op CR is not dangling");
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_compression_missing_cr_fails_closed() {
        let store = empty_compression_store();
        let (cfg, unresolved) =
            resolve_compression(&[compression_ext_ref("absent")], "default", &store);
        assert!(cfg.is_none());
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
        assert!(logs_contain("Compression CR not found"));
    }

    // ── resolve_retry_policy (#445) ───────────────────────────────────────────

    use crate::tests::fixtures::{empty_retry_policy_store, make_retry_policy_store};
    use coxswain_core::crd::RetryPolicy;

    fn retry_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "RetryPolicy".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    fn retry_cr(ns: &str, name: &str, spec_body: &str) -> RetryPolicy {
        let indented = spec_body.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RetryPolicy\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("valid RetryPolicy: {e}\n{yaml}"))
    }

    #[test]
    fn resolve_retry_http_defaults_codes_when_omitted() {
        let store = make_retry_policy_store(vec![retry_cr("default", "r", "attempts: 3")]);
        let (p, _) = resolve_retry_policy(&[retry_ext_ref("r")], "default", &store, false);
        assert_eq!(p.attempts, 3);
        assert_eq!(&*p.http_codes, &[502, 503, 504]);
        // HTTPRoute ignores gRPC codes entirely.
        assert!(p.grpc_codes.is_empty());
        assert!(p.backoff.is_none());
    }

    #[test]
    fn resolve_retry_http_explicit_codes_and_backoff() {
        let store = make_retry_policy_store(vec![retry_cr(
            "default",
            "r",
            "attempts: 2\nbackoff: 100ms\ncodes: [503, 503, 500]",
        )]);
        let (p, _) = resolve_retry_policy(&[retry_ext_ref("r")], "default", &store, false);
        // Sorted + deduped.
        assert_eq!(&*p.http_codes, &[500, 503]);
        assert_eq!(p.backoff, Some(std::time::Duration::from_millis(100)));
    }

    #[test]
    fn resolve_retry_grpc_defaults_grpc_codes() {
        let store = make_retry_policy_store(vec![retry_cr("default", "r", "attempts: 1")]);
        let (p, _) = resolve_retry_policy(&[retry_ext_ref("r")], "default", &store, true);
        // GRPCRoute: grpcCodes defaults to [14], and HTTP codes still default too.
        assert_eq!(&*p.grpc_codes, &[14]);
        assert_eq!(&*p.http_codes, &[502, 503, 504]);
    }

    #[test]
    fn resolve_retry_explicit_empty_codes_opts_out() {
        let store = make_retry_policy_store(vec![retry_cr(
            "default",
            "r",
            "attempts: 2\ncodes: []\ngrpcCodes: []",
        )]);
        let (p, _) = resolve_retry_policy(&[retry_ext_ref("r")], "default", &store, true);
        // Explicit empty ⇒ no response-code retries, but still enabled (connection retries).
        assert!(p.http_codes.is_empty());
        assert!(p.grpc_codes.is_empty());
        assert!(!p.is_disabled());
    }

    #[test]
    fn resolve_retry_absent_attempts_defaults_to_one() {
        let store = make_retry_policy_store(vec![retry_cr("default", "r", "codes: [503]")]);
        let (p, _) = resolve_retry_policy(&[retry_ext_ref("r")], "default", &store, false);
        assert_eq!(p.attempts, 1);
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_retry_missing_cr_fails_closed() {
        let store = empty_retry_policy_store();
        let (p, unresolved) =
            resolve_retry_policy(&[retry_ext_ref("absent")], "default", &store, false);
        assert!(p.is_disabled());
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
        assert!(logs_contain("RetryPolicy CR not found"));
    }

    #[test]
    fn resolve_retry_no_ref_returns_default() {
        let store = empty_retry_policy_store();
        // A route with an unrelated ExtensionRef (or none) gets the disabled default.
        let (p, unresolved) =
            resolve_retry_policy(&[ip_access_ext_ref("x")], "default", &store, false);
        assert!(p.is_disabled());
        assert!(!unresolved);
    }

    // ── resolve_external_auth (#23, #689) ─────────────────────────────────────

    fn external_auth_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "ExternalAuth".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    fn external_auth_cr(ns: &str, name: &str) -> coxswain_core::crd::CoxswainExternalAuth {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: CoxswainExternalAuth\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  protocol: HTTP\n  backendRef:\n    name: auth-svc\n    port: 4000\n",
        );
        serde_yaml::from_str(&yaml).expect("valid CoxswainExternalAuth")
    }

    #[test]
    fn resolve_external_auth_no_ext_ref_is_none() {
        let external_auths = empty_external_auth_store();
        let (cfg, unresolved) = resolve_external_auth::<HttpRouteRulesFilters>(
            &[],
            "default",
            &external_auths,
            &empty_svc_store(),
            &endpoint_cache(vec![]),
            &std::collections::HashSet::new(),
        );
        assert!(cfg.is_none());
        assert!(!unresolved);
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_external_auth_missing_cr_fails_closed() {
        let external_auths = empty_external_auth_store();
        let (cfg, unresolved) = resolve_external_auth(
            &[external_auth_ext_ref("absent")],
            "default",
            &external_auths,
            &empty_svc_store(),
            &endpoint_cache(vec![]),
            &std::collections::HashSet::new(),
        );
        assert!(cfg.is_none(), "missing CR installs no auth config");
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
        assert!(logs_contain("CoxswainExternalAuth CR not found"));
    }

    #[test]
    fn resolve_external_auth_present_cr_resolves() {
        let external_auths = make_external_auth_store(vec![external_auth_cr("default", "policy")]);
        let (cfg, unresolved) = resolve_external_auth(
            &[external_auth_ext_ref("policy")],
            "default",
            &external_auths,
            &empty_svc_store(),
            &endpoint_cache(vec![]),
            &std::collections::HashSet::new(),
        );
        // The CR itself resolved; no ready endpoints on the auth backend fails
        // **closed** via `Unavailable` (a distinct mechanism, unaffected by
        // #689) — still `Some`, and NOT the #689 unresolved signal.
        assert!(cfg.is_some(), "Some when CR present");
        assert!(!unresolved);
    }

    // ── JwtAuth (#441) ───────────────────────────────────────────────────────────

    fn jwt_auth_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "JwtAuth".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    fn jwt_auth_cr(ns: &str, name: &str) -> coxswain_core::crd::JwtAuth {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: JwtAuth\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  issuer: https://issuer.example.com\n  jwks:\n    inline:\n      jwks:\n        keys: []\n",
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("valid JwtAuth: {e}\n{yaml}"))
    }

    #[test]
    fn resolve_jwt_auth_no_ext_ref_is_none() {
        let jwt_auths = empty_jwt_auth_store();
        let cache = empty_jwks_cache();
        let (cfg, unresolved) =
            resolve_jwt_auth::<HttpRouteRulesFilters>(&[], "default", &jwt_auths, &cache);
        assert!(cfg.is_none());
        assert!(!unresolved);
    }

    #[test]
    fn resolve_jwt_auth_missing_cr_fails_closed() {
        let jwt_auths = empty_jwt_auth_store();
        let cache = empty_jwks_cache();
        let (cfg, unresolved) =
            resolve_jwt_auth(&[jwt_auth_ext_ref("absent")], "default", &jwt_auths, &cache);
        assert!(cfg.is_none(), "missing CR installs no auth config");
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
    }

    #[test]
    fn resolve_jwt_auth_present_cr_resolves() {
        let jwt_auths = make_jwt_auth_store(vec![jwt_auth_cr("default", "my-jwt")]);
        let cache = empty_jwks_cache();
        let (resolved, unresolved) =
            resolve_jwt_auth(&[jwt_auth_ext_ref("my-jwt")], "default", &jwt_auths, &cache);
        let resolved = resolved.expect("present JwtAuth CR must resolve");
        assert!(matches!(
            resolved.as_ref(),
            coxswain_core::routing::IngressAuthConfig::Jwt(_)
        ));
        assert!(!unresolved);
    }

    // ── resolve_path_rewrite (#689) ───────────────────────────────────────────

    use coxswain_core::crd::PathRewriteRegex;

    fn path_rewrite_ext_ref(name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ExtensionRef,
            extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                group: "gateway.coxswain-labs.dev".to_string(),
                kind: "PathRewriteRegex".to_string(),
                name: name.to_string(),
            }),
            ..Default::default()
        }
    }

    fn path_rewrite_cr(ns: &str, name: &str, pattern: &str, replacement: &str) -> PathRewriteRegex {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: PathRewriteRegex\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  pattern: {pattern}\n  replacement: {replacement}\n",
        );
        serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("valid PathRewriteRegex: {e}\n{yaml}"))
    }

    #[test]
    fn resolve_path_rewrite_present_cr_produces_url_rewrite() {
        let store =
            make_path_rewrite_store(vec![path_rewrite_cr("default", "pr", "^/old", "/new")]);
        let (action, unresolved) =
            resolve_path_rewrite(&[path_rewrite_ext_ref("pr")], "default", &store);
        assert!(matches!(action, Some(FilterAction::UrlRewrite { .. })));
        assert!(!unresolved);
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_path_rewrite_missing_cr_fails_closed() {
        let store = empty_path_rewrite_store();
        let (action, unresolved) =
            resolve_path_rewrite(&[path_rewrite_ext_ref("absent")], "default", &store);
        assert!(action.is_none());
        assert!(
            unresolved,
            "missing CR must signal the caller to fail closed (500)"
        );
        assert!(logs_contain("PathRewriteRegex CR not found"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn resolve_path_rewrite_invalid_regex_is_inert() {
        let store =
            make_path_rewrite_store(vec![path_rewrite_cr("default", "pr", "(unclosed", "/new")]);
        let (action, unresolved) =
            resolve_path_rewrite(&[path_rewrite_ext_ref("pr")], "default", &store);
        assert!(action.is_none());
        assert!(
            !unresolved,
            "a resolved CR with an invalid regex is not dangling"
        );
        assert!(logs_contain("invalid regex"));
    }
}
