//! Per-request match predicates: method, header, and query-parameter conditions.

use http::{HeaderMap, HeaderName, Method};
use regex::Regex;
use smallvec::SmallVec;

/// How a value is compared in a predicate — used by header and query matchers.
#[non_exhaustive]
#[derive(Clone)]
pub enum ValueMatch {
    /// Case-sensitive equality comparison.
    Exact(String),
    /// Regular-expression match (anchored by the regex itself).
    Regex(Regex),
}

impl ValueMatch {
    pub(crate) fn matches(&self, value: &str) -> bool {
        match self {
            ValueMatch::Exact(s) => s == value,
            ValueMatch::Regex(r) => r.is_match(value),
        }
    }
}

/// Matches a single request header.
///
/// `name` is the canonical (lowercased) `HeaderName`, enabling O(1) lookup in
/// `HeaderMap`. The comparison is against the header value string.
// intentionally open: field-literal constructed in crates/coxswain-reflector/src/gateway_api/filters.rs while translating HTTPRoute matches.
#[derive(Clone)]
pub struct HeaderPredicate {
    /// Canonical (lowercased) header name for O(1) `HeaderMap` lookup.
    pub name: HeaderName,
    /// Value comparison strategy.
    pub matcher: ValueMatch,
}

/// Matches a single query parameter by name and value.
///
/// Query parameter names are case-sensitive per RFC 3986.
// intentionally open: field-literal constructed in crates/coxswain-reflector/src/gateway_api/filters.rs while translating HTTPRoute matches.
#[derive(Clone)]
pub struct QueryPredicate {
    /// Query parameter name (case-sensitive).
    pub name: String,
    /// Value comparison strategy.
    pub matcher: ValueMatch,
}

/// All predicates for a single `HTTPRouteMatch`.
///
/// Every predicate in this struct must pass for the match to succeed
/// (AND semantics). Empty fields pass unconditionally.
// intentionally open: field-literal constructed in crates/coxswain-reflector/src/gateway_api/filters.rs while translating HTTPRoute matches.
#[derive(Clone, Default)]
pub struct MatchPredicates {
    /// Required HTTP method, or `None` to match any method.
    pub method: Option<Method>,
    /// All header predicates (must all pass).
    pub headers: Vec<HeaderPredicate>,
    /// All query-parameter predicates (must all pass).
    pub query: Vec<QueryPredicate>,
}

impl MatchPredicates {
    /// Returns `true` when no predicates are set (matches any request unconditionally).
    pub fn is_empty(&self) -> bool {
        self.method.is_none() && self.headers.is_empty() && self.query.is_empty()
    }

    pub(crate) fn matches(&self, ctx: &RequestContext<'_>) -> bool {
        if let Some(m) = &self.method
            && m != ctx.method
        {
            return false;
        }
        for h in &self.headers {
            let matched = ctx
                .headers
                .get_all(&h.name)
                .iter()
                .any(|v| v.to_str().is_ok_and(|s| h.matcher.matches(s)));
            if !matched {
                return false;
            }
        }
        if !self.query.is_empty() {
            let query_str = ctx.query.unwrap_or("");
            // Collect once per call to avoid re-parsing for each predicate.
            // SmallVec avoids heap allocation for the typical case of ≤4 pairs.
            let pairs: SmallVec<[(std::borrow::Cow<str>, std::borrow::Cow<str>); 4]> =
                form_urlencoded::parse(query_str.as_bytes()).collect();
            for q in &self.query {
                let found = pairs
                    .iter()
                    .any(|(k, v)| k.as_ref() == q.name && q.matcher.matches(v.as_ref()));
                if !found {
                    return false;
                }
            }
        }
        true
    }
}

/// Per-request context passed into the hot-path route lookup.
///
/// All fields are borrows from the live request — no allocations.
// intentionally open: field-literal constructed per-request in crates/coxswain-proxy/src/common/hooks.rs (proxy hot path).
pub struct RequestContext<'a> {
    /// HTTP method of the incoming request.
    pub method: &'a Method,
    /// Full request headers map.
    pub headers: &'a HeaderMap,
    /// Raw query string (the part after `?`), if present.
    pub query: Option<&'a str>,
}

impl Default for RequestContext<'static> {
    fn default() -> Self {
        static EMPTY_HEADERS: std::sync::LazyLock<HeaderMap> =
            std::sync::LazyLock::new(HeaderMap::new);
        Self {
            method: &Method::GET,
            headers: &EMPTY_HEADERS,
            query: None,
        }
    }
}
