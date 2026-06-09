use crate::common::filter::{apply_header_mod, rewrite_path};
use coxswain_core::routing::HeaderMod;
use pingora_http::{RequestHeader, ResponseHeader};

fn req() -> RequestHeader {
    let mut r = RequestHeader::build("GET", b"/original/path?q=1", None).unwrap();
    r.insert_header("x-keep", "yes").unwrap();
    r
}

fn resp() -> ResponseHeader {
    ResponseHeader::build(200, None).unwrap()
}

fn hmod(add: &[(&str, &str)], set: &[(&str, &str)], remove: &[&str]) -> HeaderMod {
    HeaderMod::parse(add, set, remove).unwrap()
}

#[test]
fn request_header_set_overwrites() {
    let mut r = req();
    let m = hmod(&[], &[("x-keep", "overwritten")], &[]);
    apply_header_mod(&mut r, &m, "RequestHeaderModifier");
    assert_eq!(r.headers.get("x-keep").unwrap(), "overwritten");
}

#[test]
fn request_header_add_appends() {
    let mut r = req();
    let m = hmod(&[("x-keep", "extra")], &[], &[]);
    apply_header_mod(&mut r, &m, "RequestHeaderModifier");
    let vals: Vec<_> = r.headers.get_all("x-keep").iter().collect();
    assert_eq!(vals.len(), 2);
}

#[test]
fn request_header_remove() {
    let mut r = req();
    let m = hmod(&[], &[], &["x-keep"]);
    apply_header_mod(&mut r, &m, "RequestHeaderModifier");
    assert!(r.headers.get("x-keep").is_none());
}

#[test]
fn response_header_set_overwrites() {
    let mut r = resp();
    r.insert_header("x-old", "old").unwrap();
    let m = hmod(&[], &[("x-old", "new")], &[]);
    apply_header_mod(&mut r, &m, "ResponseHeaderModifier");
    assert_eq!(r.headers.get("x-old").unwrap(), "new");
}

#[test]
fn response_header_add_appends() {
    let mut r = resp();
    r.insert_header("x-multi", "a").unwrap();
    let m = hmod(&[("x-multi", "b")], &[], &[]);
    apply_header_mod(&mut r, &m, "ResponseHeaderModifier");
    let vals: Vec<_> = r.headers.get_all("x-multi").iter().collect();
    assert_eq!(vals.len(), 2);
}

#[test]
fn url_rewrite_full_path_replaces_path_and_keeps_query() {
    let mut r = req();
    let pm = coxswain_core::routing::PathModifier::ReplaceFullPath("/new".to_string());
    rewrite_path(&mut r, &pm, "/original/path");
    assert_eq!(r.uri.path(), "/new");
    assert_eq!(r.uri.query(), Some("q=1"));
}

#[test]
fn url_rewrite_prefix_match_replaces_prefix() {
    let mut r = RequestHeader::build("GET", b"/api/v2/users", None).unwrap();
    let pm = coxswain_core::routing::PathModifier::ReplacePrefixMatch {
        prefix: "/api".to_string(),
        replacement: "/v3".to_string(),
    };
    rewrite_path(&mut r, &pm, "/api/v2/users");
    assert_eq!(r.uri.path(), "/v3/v2/users");
}

#[test]
fn url_rewrite_prefix_match_exact_path_becomes_replacement() {
    let mut r = RequestHeader::build("GET", b"/api", None).unwrap();
    let pm = coxswain_core::routing::PathModifier::ReplacePrefixMatch {
        prefix: "/api".to_string(),
        replacement: "/v3".to_string(),
    };
    rewrite_path(&mut r, &pm, "/api");
    assert_eq!(r.uri.path(), "/v3");
}

#[test]
fn url_rewrite_prefix_match_trailing_slash_path() {
    let mut r = RequestHeader::build("GET", b"/api/", None).unwrap();
    let pm = coxswain_core::routing::PathModifier::ReplacePrefixMatch {
        prefix: "/api".to_string(),
        replacement: "/v3".to_string(),
    };
    rewrite_path(&mut r, &pm, "/api/");
    assert_eq!(r.uri.path(), "/v3");
}

#[test]
fn url_rewrite_prefix_match_strip_to_root() {
    // Exact path match with replacement "/" must yield "/" not ""
    let mut r = RequestHeader::build("GET", b"/strip-prefix", None).unwrap();
    let pm = coxswain_core::routing::PathModifier::ReplacePrefixMatch {
        prefix: "/strip-prefix".to_string(),
        replacement: "/".to_string(),
    };
    rewrite_path(&mut r, &pm, "/strip-prefix");
    assert_eq!(r.uri.path(), "/");
}

#[test]
fn url_rewrite_prefix_match_strip_to_root_with_suffix() {
    // Path with suffix after stripped prefix: /strip-prefix/foo -> /foo
    let mut r = RequestHeader::build("GET", b"/strip-prefix/foo", None).unwrap();
    let pm = coxswain_core::routing::PathModifier::ReplacePrefixMatch {
        prefix: "/strip-prefix".to_string(),
        replacement: "/".to_string(),
    };
    rewrite_path(&mut r, &pm, "/strip-prefix/foo");
    assert_eq!(r.uri.path(), "/foo");
}
