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

/// Headers the proxy unconditionally owns on every upstream request.
///
/// The proxy strips whatever the downstream client sent and, when PROXY-protocol
/// is active, replaces `Forwarded` with a proxy-generated value derived from the
/// real client address.  Route operators must also not re-inject these headers via
/// `RequestHeaderModifier` filters — `apply_header_mod` skips `set`/`add` operations
/// for any name in this list when called on the request path (#409, #410).
///
/// Never extend this list with headers the proxy does not itself set;
/// strip-without-replace is the safe default for unknown infrastructure headers.
static CLIENT_FORWARDING_HEADERS: std::sync::LazyLock<[http::HeaderName; 4]> =
    std::sync::LazyLock::new(|| {
        [
            http::HeaderName::from_static("forwarded"),
            http::HeaderName::from_static("x-forwarded-for"),
            http::HeaderName::from_static("x-forwarded-proto"),
            http::HeaderName::from_static("x-real-ip"),
        ]
    });

/// Returns `true` when `name` is a proxy-owned forwarding header that neither
/// clients nor route operators may inject.
///
/// Used by [`apply_header_mod`] to gate `set`/`add` operations on the request
/// path — the `remove` operation is always allowed.
pub(crate) fn is_owned_forwarding_header(name: &http::HeaderName) -> bool {
    CLIENT_FORWARDING_HEADERS.iter().any(|h| h == name)
}

/// Applies Gateway-API and Ingress filter actions to the in-flight request
/// and response headers, plus the fixed `X-Proxy-Engine` and RFC-7239
/// `Forwarded` infrastructure headers.
#[non_exhaustive]
pub struct TrafficFilter;

impl TrafficFilter {
    /// Strip client-supplied forwarding headers from the upstream request.
    ///
    /// Called unconditionally in [`super::hooks::upstream_request_filter`]
    /// **before** any operator filter or proxy-generated header insertion runs.
    /// This ensures client-injected values for `Forwarded`, `X-Forwarded-For`,
    /// `X-Forwarded-Proto`, and `X-Real-IP` never reach the backend regardless
    /// of whether PROXY protocol is enabled.
    ///
    /// Zero allocations — `remove_header` is an in-place map removal.
    pub(crate) fn strip_client_forwarding_headers(upstream_request: &mut RequestHeader) {
        for name in CLIENT_FORWARDING_HEADERS.iter() {
            upstream_request.remove_header(name);
        }
    }

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
                    apply_header_mod(upstream_request, m, is_owned_forwarding_header);
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
                apply_header_mod(upstream_response, m, |_| false);
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

/// Apply a [`HeaderMod`] to `target`, skipping `set`/`add` entries for which
/// `skip` returns `true`.
///
/// On the **request path** pass [`is_owned_forwarding_header`] as `skip` so that
/// route operators cannot re-inject proxy-owned forwarding headers after the
/// client-strip step (#409, #410).  On the **response path** pass `|_| false`.
///
/// The `remove` loop is never gated — silently removing a blocked header is
/// harmless and prevents stale values reaching the backend.
pub(crate) fn apply_header_mod<H: HeaderTarget>(
    target: &mut H,
    m: &HeaderMod,
    skip: impl Fn(&http::HeaderName) -> bool,
) {
    for (name, value) in &m.set {
        if !skip(name) {
            target.hdr_set(name.clone(), value.clone());
        }
    }
    for (name, value) in &m.add {
        if !skip(name) {
            target.hdr_add(name.clone(), value.clone());
        }
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
    use super::{TrafficFilter, apply_header_mod, is_owned_forwarding_header, rewrite_path};
    use coxswain_core::routing::{FilterAction, HeaderMod};
    use pingora_http::{RequestHeader, ResponseHeader};

    use crate::common::ctx::ProxyCtx;

    #[test]
    fn strip_removes_all_client_forwarding_headers() {
        let mut r = RequestHeader::build("GET", b"/", None).unwrap();
        r.insert_header("forwarded", "for=1.2.3.4;by=evil").unwrap();
        r.insert_header("x-forwarded-for", "1.2.3.4").unwrap();
        r.insert_header("x-forwarded-proto", "https").unwrap();
        r.insert_header("x-real-ip", "1.2.3.4").unwrap();
        // Unrelated header must survive the strip.
        r.insert_header("x-custom-app", "keep-me").unwrap();

        TrafficFilter::strip_client_forwarding_headers(&mut r);

        assert!(
            r.headers.get("forwarded").is_none(),
            "forwarded must be stripped"
        );
        assert!(
            r.headers.get("x-forwarded-for").is_none(),
            "x-forwarded-for must be stripped"
        );
        assert!(
            r.headers.get("x-forwarded-proto").is_none(),
            "x-forwarded-proto must be stripped"
        );
        assert!(
            r.headers.get("x-real-ip").is_none(),
            "x-real-ip must be stripped"
        );
        assert_eq!(
            r.headers.get("x-custom-app").map(|v| v.as_bytes()),
            Some(b"keep-me".as_ref()),
            "unrelated header must survive"
        );
    }

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
        apply_header_mod(&mut r, &m, |_| false);
        assert_eq!(r.headers.get("x-keep").unwrap(), "overwritten");
    }

    #[test]
    fn request_header_add_appends() {
        let mut r = req();
        let m = hmod(&[("x-keep", "extra")], &[], &[]);
        apply_header_mod(&mut r, &m, |_| false);
        let vals: Vec<_> = r.headers.get_all("x-keep").iter().collect();
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn request_header_remove() {
        let mut r = req();
        let m = hmod(&[], &[], &["x-keep"]);
        apply_header_mod(&mut r, &m, |_| false);
        assert!(r.headers.get("x-keep").is_none());
    }

    #[test]
    fn response_header_set_overwrites() {
        let mut r = resp();
        r.insert_header("x-old", "old").unwrap();
        let m = hmod(&[], &[("x-old", "new")], &[]);
        apply_header_mod(&mut r, &m, |_| false);
        assert_eq!(r.headers.get("x-old").unwrap(), "new");
    }

    #[test]
    fn response_header_add_appends() {
        let mut r = resp();
        r.insert_header("x-multi", "a").unwrap();
        let m = hmod(&[("x-multi", "b")], &[], &[]);
        apply_header_mod(&mut r, &m, |_| false);
        let vals: Vec<_> = r.headers.get_all("x-multi").iter().collect();
        assert_eq!(vals.len(), 2);
    }

    // ── Operator deny-list (#410) ──────────────────────────────────────────────

    fn request_filters_with(m: HeaderMod) -> RequestHeader {
        let ctx = ProxyCtx::default();
        let mut r = RequestHeader::build("GET", b"/", None).unwrap();
        let filters = vec![FilterAction::RequestHeaderModifier(m)];
        TrafficFilter::apply_request_filters(&mut r, &filters, "host.local", "/", &ctx).unwrap();
        r
    }

    #[test]
    fn request_filter_drops_set_of_blocked_forwarding_header() {
        let m = hmod(&[], &[("x-forwarded-for", "10.0.0.1")], &[]);
        let r = request_filters_with(m);
        assert!(
            r.headers.get("x-forwarded-for").is_none(),
            "operator RequestHeaderModifier must not inject x-forwarded-for (#410)"
        );
    }

    #[test]
    fn request_filter_drops_add_of_blocked_forwarding_header() {
        let m = hmod(&[("x-real-ip", "10.0.0.1")], &[], &[]);
        let r = request_filters_with(m);
        assert!(
            r.headers.get("x-real-ip").is_none(),
            "operator RequestHeaderModifier must not add x-real-ip (#410)"
        );
    }

    #[test]
    fn request_filter_drops_all_four_blocked_headers() {
        let m = hmod(
            &[],
            &[
                ("forwarded", "for=evil"),
                ("x-forwarded-for", "1.2.3.4"),
                ("x-forwarded-proto", "https"),
                ("x-real-ip", "1.2.3.4"),
            ],
            &[],
        );
        let r = request_filters_with(m);
        for h in &[
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-real-ip",
        ] {
            assert!(
                r.headers.get(*h).is_none(),
                "operator must not inject {h} via RequestHeaderModifier (#410)"
            );
        }
    }

    #[test]
    fn request_filter_keeps_custom_header_alongside_blocked() {
        let m = hmod(
            &[],
            &[
                ("x-forwarded-for", "10.0.0.1"),
                ("x-team-header", "keep-me"),
            ],
            &[],
        );
        let r = request_filters_with(m);
        assert!(
            r.headers.get("x-forwarded-for").is_none(),
            "blocked header must be dropped (#410)"
        );
        assert_eq!(
            r.headers.get("x-team-header").map(|v| v.as_bytes()),
            Some(b"keep-me".as_ref()),
            "custom header must survive alongside the blocked one (#410)"
        );
    }

    #[test]
    fn request_filter_still_stamps_proxy_engine() {
        let m = hmod(&[], &[("x-forwarded-for", "1.2.3.4")], &[]);
        let r = request_filters_with(m);
        assert!(
            r.headers.get("X-Proxy-Engine").is_some() || r.headers.get("x-proxy-engine").is_some(),
            "X-Proxy-Engine must be present after a blocked-header modifier (#410)"
        );
    }

    #[test]
    fn response_filter_allows_forwarding_header_name() {
        // Response modifiers are NOT gated — the deny-list is request-path only.
        let mut r = resp();
        let m = hmod(&[], &[("x-forwarded-for", "10.0.0.1")], &[]);
        let filters = vec![FilterAction::ResponseHeaderModifier(m)];
        TrafficFilter::apply_response_filters(&mut r, &filters);
        assert_eq!(
            r.headers.get("x-forwarded-for").map(|v| v.as_bytes()),
            Some(b"10.0.0.1".as_ref()),
            "response-side modifier must be allowed to set forwarding header names (#410)"
        );
    }

    #[test]
    fn is_owned_forwarding_header_recognises_all_four() {
        for name in &[
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-real-ip",
        ] {
            let h = http::HeaderName::from_bytes(name.as_bytes()).unwrap();
            assert!(
                is_owned_forwarding_header(&h),
                "{name} must be recognised as a proxy-owned header (#410)"
            );
        }
    }

    #[test]
    fn is_owned_forwarding_header_allows_custom_headers() {
        for name in &["x-team-id", "x-request-id", "x-proxy-engine"] {
            let h = http::HeaderName::from_bytes(name.as_bytes()).unwrap();
            assert!(
                !is_owned_forwarding_header(&h),
                "{name} must NOT be treated as a proxy-owned header (#410)"
            );
        }
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
