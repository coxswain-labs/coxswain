use http::{HeaderMap, HeaderName, Method};
use regex::Regex;

/// How a value is compared in a predicate — used by header and query matchers.
#[derive(Clone)]
pub enum ValueMatch {
    Exact(String),
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
#[derive(Clone)]
pub struct HeaderPredicate {
    pub name: HeaderName,
    pub matcher: ValueMatch,
}

/// Matches a single query parameter by name and value.
///
/// Query parameter names are case-sensitive per RFC 3986.
#[derive(Clone)]
pub struct QueryPredicate {
    pub name: String,
    pub matcher: ValueMatch,
}

/// All predicates for a single `HTTPRouteMatch`.
///
/// Every predicate in this struct must pass for the match to succeed
/// (AND semantics). Empty fields pass unconditionally.
#[derive(Clone, Default)]
pub struct MatchPredicates {
    pub method: Option<Method>,
    pub headers: Vec<HeaderPredicate>,
    pub query: Vec<QueryPredicate>,
}

impl MatchPredicates {
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
            // Collect once per call so we don't re-parse for each predicate.
            let pairs: Vec<(std::borrow::Cow<str>, std::borrow::Cow<str>)> =
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
pub struct RequestContext<'a> {
    pub method: &'a Method,
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
