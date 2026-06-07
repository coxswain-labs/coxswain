//! Translates `HTTPRouteRule` filter specs into [`FilterAction`][coxswain_core::routing::FilterAction]s.

use crate::gw_types::v::httproutes::{
    HttpRouteRulesBackendRefsFilters, HttpRouteRulesBackendRefsFiltersType, HttpRouteRulesFilters,
    HttpRouteRulesFiltersType, HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod,
    HttpRouteRulesMatchesQueryParamsType,
};
use coxswain_core::routing::{
    FilterAction, HeaderMod, HeaderPredicate, MatchPredicates, PathModifier, QueryPredicate,
    ValueMatch,
};
use http::{HeaderName, Method};
use regex::Regex;

/// Translates `HTTPRouteFilter` entries into `FilterAction` values.
///
/// `matched_prefix` is the path pattern for this match rule (used for
/// `ReplacePrefixMatch`). `is_prefix_match` signals whether the path type is
/// `PathPrefix`; if it is not, a `ReplacePrefixMatch` path modifier is invalid
/// per spec and will be skipped with a warning.
pub(super) fn build_filters(
    filters: &[HttpRouteRulesFilters],
    matched_prefix: &str,
    is_prefix_match: bool,
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
            HttpRouteRulesFiltersType::RequestMirror
            | HttpRouteRulesFiltersType::ExtensionRef
            | HttpRouteRulesFiltersType::Cors => {
                tracing::warn!(
                    filter_type = ?f.r#type,
                    "Skipping unsupported HTTPRouteFilter type"
                );
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
