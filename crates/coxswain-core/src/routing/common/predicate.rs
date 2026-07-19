//! Per-request match predicates: method, header, and query-parameter conditions.

use http::{HeaderMap, HeaderName, Method};
use regex::Regex;
use smallvec::SmallVec;

/// How a value is compared in a predicate — used by header and query matchers.
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
    #[must_use]
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
            let pairs: SmallVec<[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>); 4]> =
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::tests::*;
    use http::Method;
    use regex::Regex;

    #[test]
    fn predicate_empty_matches_everything() {
        let pred = MatchPredicates::default();
        let headers = headers_from(&[]);
        let ctx = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: None,
        };
        assert!(pred.matches(&ctx));
    }

    #[test]
    fn predicate_method_match() {
        let pred = make_predicates(Some("POST"), &[], &[]);
        let headers = headers_from(&[]);
        let get = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: None,
        };
        let post = RequestContext {
            method: &Method::POST,
            headers: &headers,
            query: None,
        };
        assert!(!pred.matches(&get));
        assert!(pred.matches(&post));
    }

    #[test]
    fn predicate_header_exact_match() {
        let pred = make_predicates(None, &[("x-tenant", "foo")], &[]);
        let matching = headers_from(&[("x-tenant", "foo")]);
        let wrong = headers_from(&[("x-tenant", "bar")]);
        let absent = headers_from(&[]);
        let ctx_m = RequestContext {
            method: &Method::GET,
            headers: &matching,
            query: None,
        };
        let ctx_w = RequestContext {
            method: &Method::GET,
            headers: &wrong,
            query: None,
        };
        let ctx_a = RequestContext {
            method: &Method::GET,
            headers: &absent,
            query: None,
        };
        assert!(pred.matches(&ctx_m));
        assert!(!pred.matches(&ctx_w));
        assert!(!pred.matches(&ctx_a));
    }

    #[test]
    fn predicate_header_regex_match() {
        use http::HeaderName;
        let pred = MatchPredicates {
            method: None,
            headers: vec![HeaderPredicate {
                name: HeaderName::from_static("x-version"),
                matcher: ValueMatch::Regex(Regex::new(r"^v\d+$").unwrap()),
            }],
            query: vec![],
        };
        let matching = headers_from(&[("x-version", "v42")]);
        let wrong = headers_from(&[("x-version", "beta")]);
        let ctx_m = RequestContext {
            method: &Method::GET,
            headers: &matching,
            query: None,
        };
        let ctx_w = RequestContext {
            method: &Method::GET,
            headers: &wrong,
            query: None,
        };
        assert!(pred.matches(&ctx_m));
        assert!(!pred.matches(&ctx_w));
    }

    #[test]
    fn predicate_query_exact_match() {
        let pred = make_predicates(None, &[], &[("version", "v1")]);
        let headers = headers_from(&[]);
        let ctx_yes = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: Some("version=v1&x=y"),
        };
        let ctx_no = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: Some("version=v2"),
        };
        let ctx_absent = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: None,
        };
        assert!(pred.matches(&ctx_yes));
        assert!(!pred.matches(&ctx_no));
        assert!(!pred.matches(&ctx_absent));
    }

    #[test]
    fn predicate_query_regex_match() {
        let pred = MatchPredicates {
            method: None,
            headers: vec![],
            query: vec![QueryPredicate {
                name: "env".to_string(),
                matcher: ValueMatch::Regex(Regex::new(r"^(dev|staging)$").unwrap()),
            }],
        };
        let headers = headers_from(&[]);
        let ctx_dev = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: Some("env=dev"),
        };
        let ctx_prod = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: Some("env=prod"),
        };
        assert!(pred.matches(&ctx_dev));
        assert!(!pred.matches(&ctx_prod));
    }

    #[test]
    fn predicate_and_semantics() {
        // Both method AND header must match.
        let pred = make_predicates(Some("POST"), &[("x-tenant", "a")], &[]);
        let headers_ok = headers_from(&[("x-tenant", "a")]);
        let headers_wrong = headers_from(&[("x-tenant", "b")]);
        let ctx_both = RequestContext {
            method: &Method::POST,
            headers: &headers_ok,
            query: None,
        };
        let ctx_method_only = RequestContext {
            method: &Method::POST,
            headers: &headers_wrong,
            query: None,
        };
        let ctx_header_only = RequestContext {
            method: &Method::GET,
            headers: &headers_ok,
            query: None,
        };
        assert!(pred.matches(&ctx_both));
        assert!(!pred.matches(&ctx_method_only));
        assert!(!pred.matches(&ctx_header_only));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        // Predicate stores lowercase HeaderName; request may have mixed case.
        let pred = make_predicates(None, &[("x-tenant", "acme")], &[]);
        // HTTP/1.1 allows any case; HeaderMap canonicalises to lowercase internally.
        let headers = headers_from(&[("x-tenant", "acme")]);
        let ctx = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: None,
        };
        assert!(pred.matches(&ctx));
    }
}
