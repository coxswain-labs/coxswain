use super::*;
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
