//! Request and response filter application: header modifiers, URL rewrites, and the
//! `Forwarded` header injection for PROXY-protocol connections.

use super::ctx::ProxyCtx;
use coxswain_core::routing::{FilterAction, HeaderMod, PathModifier};
use http::{HeaderName, HeaderValue};
use std::sync::LazyLock;

static X_PROXY_ENGINE: LazyLock<HeaderValue> =
    LazyLock::new(|| HeaderValue::from_static(concat!("Coxswain/", env!("CARGO_PKG_VERSION"))));
use pingora_core::Result;
use pingora_http::{RequestHeader, ResponseHeader};

/// Applies Gateway-API and Ingress filter actions to the in-flight request
/// and response headers, plus the fixed `X-Proxy-Engine` and RFC-7239
/// `Forwarded` infrastructure headers.
#[non_exhaustive]
pub struct TrafficFilter;

impl TrafficFilter {
    /// Apply request-side filters (header modifiers and URL rewrites), then
    /// stamp the fixed infrastructure headers.
    ///
    /// `original_host` and `original_path` carry the pre-rewrite Host and path
    /// so a `UrlRewrite` filter can compose against the user-visible request.
    ///
    /// # Errors
    /// Propagates Pingora header-mutation errors from the fixed-header inserts.
    #[must_use = "ignoring the result drops request-filter header-mutation errors"]
    pub fn apply_request_filters(
        upstream_request: &mut RequestHeader,
        filters: &[FilterAction],
        _original_host: &str,
        original_path: &str,
        ctx: &ProxyCtx,
    ) -> Result<()> {
        // Apply Gateway API request-side filters in declaration order.
        for filter in filters {
            match filter {
                FilterAction::RequestHeaderModifier(m) => {
                    apply_header_mod(upstream_request, m, "RequestHeaderModifier");
                }
                FilterAction::UrlRewrite { hostname, path } => {
                    if let Some(h) = hostname {
                        if let Ok(v) = HeaderValue::from_str(h) {
                            let _ = upstream_request.insert_header(http::header::HOST, v);
                        } else {
                            tracing::warn!(%h, "URLRewrite hostname is not a valid header value — skipping");
                        }
                    }
                    if let Some(pm) = path {
                        rewrite_path(upstream_request, pm, original_path);
                    }
                }
                // Redirect and response filters are handled elsewhere.
                FilterAction::RequestRedirect { .. } | FilterAction::ResponseHeaderModifier(_) => {}
                // Skip unknown filter variants — new types added to the core crate
                // are handled by the proxy once explicitly wired.
                _ => {}
            }
        }

        // Fixed infrastructure headers added after user-defined filters.
        upstream_request.insert_header("X-Proxy-Engine", X_PROXY_ENGINE.clone())?;

        if let Some(addr) = ctx.real_client_addr {
            let proto = ctx.real_client_proto.unwrap_or("http");
            // Build the Forwarded value in a single allocation (RFC 7239). IPv6
            // addresses are bracketed (`[2001:db8::1]:12345`); IPv4 are not.
            use std::fmt::Write;
            let mut value = String::with_capacity(64);
            match addr {
                std::net::SocketAddr::V4(v4) => {
                    let _ = write!(value, "for=\"{}:{}\";proto={proto}", v4.ip(), v4.port());
                }
                std::net::SocketAddr::V6(v6) => {
                    let _ = write!(value, "for=\"[{}]:{}\";proto={proto}", v6.ip(), v6.port());
                }
            };
            upstream_request.insert_header("Forwarded", value)?;
        }

        Ok(())
    }

    /// Apply response-side filters (header modifiers only).
    pub fn apply_response_filters(
        upstream_response: &mut ResponseHeader,
        filters: &[FilterAction],
    ) {
        for filter in filters {
            if let FilterAction::ResponseHeaderModifier(m) = filter {
                apply_header_mod(upstream_response, m, "ResponseHeaderModifier");
            }
        }
    }
}

pub(crate) trait HeaderTarget {
    fn hdr_set(&mut self, name: HeaderName, value: HeaderValue);
    fn hdr_add(&mut self, name: HeaderName, value: HeaderValue);
    fn hdr_remove(&mut self, name: &HeaderName);
}

impl HeaderTarget for RequestHeader {
    fn hdr_set(&mut self, name: HeaderName, value: HeaderValue) {
        let _ = self.insert_header(name, value);
    }
    fn hdr_add(&mut self, name: HeaderName, value: HeaderValue) {
        let _ = self.append_header(name, value);
    }
    fn hdr_remove(&mut self, name: &HeaderName) {
        self.remove_header(name);
    }
}

impl HeaderTarget for ResponseHeader {
    fn hdr_set(&mut self, name: HeaderName, value: HeaderValue) {
        let _ = self.insert_header(name, value);
    }
    fn hdr_add(&mut self, name: HeaderName, value: HeaderValue) {
        let _ = self.append_header(name, value);
    }
    fn hdr_remove(&mut self, name: &HeaderName) {
        self.remove_header(name);
    }
}

pub(crate) fn apply_header_mod<H: HeaderTarget>(
    target: &mut H,
    m: &HeaderMod,
    _kind: &'static str,
) {
    for (name, value) in &m.set {
        target.hdr_set(name.clone(), value.clone());
    }
    for (name, value) in &m.add {
        target.hdr_add(name.clone(), value.clone());
    }
    for name in &m.remove {
        target.hdr_remove(name);
    }
}

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
    use super::{apply_header_mod, rewrite_path};
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
}
