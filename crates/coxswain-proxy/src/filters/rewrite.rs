//! `UrlRewrite` path-modifier handling: rewrites the upstream request path
//! (preserving the query string) while leaving the client-visible URL unchanged.

use coxswain_core::routing::PathModifier;
use pingora_http::RequestHeader;

/// Apply a [`PathModifier`] to the upstream request URI, preserving the query.
pub(crate) fn rewrite_path(req: &mut RequestHeader, modifier: &PathModifier, original_path: &str) {
    // `apply` already owns an allocation; when a query is present, extend it in
    // place rather than allocating a second string via `format!`.
    let mut path_and_query = modifier.apply(original_path);
    if let Some(q) = req.uri.query() {
        path_and_query.reserve(1 + q.len());
        path_and_query.push('?');
        path_and_query.push_str(q);
    }
    match http::Uri::builder()
        .path_and_query(path_and_query.as_str())
        .build()
    {
        Ok(uri) => req.set_uri(uri),
        Err(e) => tracing::warn!(error = %e, "URLRewrite: failed to build new URI"),
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_path;
    use pingora_http::RequestHeader;

    #[test]
    fn url_rewrite_full_path_replaces_path_and_keeps_query() {
        let mut r = RequestHeader::build("GET", b"/original/path?q=1", None).unwrap();
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
}
