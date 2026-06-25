//! Declarative Gateway-API/Ingress `FilterAction` handlers.
//!
//! This module's [`TrafficFilter`] is the in-band dispatch facade: it walks a
//! route's `FilterAction` list and applies the request/response header modifiers,
//! URL rewrites, and CORS response headers, plus the proxy-owned `Forwarded` /
//! `X-Proxy-Engine` infrastructure headers. The per-variant mechanics live in
//! submodules so that adding a GEP filter touches a single file:
//! [`header`] (header modifiers + the proxy-owned forwarding deny-list),
//! [`rewrite`] (`UrlRewrite` path rewriting), [`redirect`] (`RequestRedirect`
//! short-circuit), [`cors`] (CORS preflight, GEP-1767), and [`mirror`]
//! (`RequestMirror` fire-and-forget dispatch, GEP-3171).

pub(crate) mod cors;
pub(crate) mod header;
pub(crate) mod mirror;
pub(crate) mod redirect;
pub(crate) mod rewrite;

use crate::ctx::ProxyCtx;
use coxswain_core::routing::FilterAction;
use http::HeaderValue;
use http::header as hdr;
use pingora_core::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use std::sync::LazyLock;

static X_PROXY_ENGINE: LazyLock<HeaderValue> =
    LazyLock::new(|| HeaderValue::from_static(concat!("Coxswain/", env!("CARGO_PKG_VERSION"))));

/// Applies Gateway-API and Ingress filter actions to the in-flight request
/// and response headers, plus the fixed `X-Proxy-Engine` and RFC-7239
/// `Forwarded` infrastructure headers.
#[non_exhaustive]
pub struct TrafficFilter;

impl TrafficFilter {
    /// Strip client-supplied forwarding headers from the upstream request.
    ///
    /// Called unconditionally in [`crate::hooks::upstream_request_filter`]
    /// **before** any operator filter or proxy-generated header insertion runs.
    /// This ensures client-injected values for `Forwarded`, `X-Forwarded-For`,
    /// `X-Forwarded-Proto`, and `X-Real-IP` never reach the backend regardless
    /// of whether PROXY protocol is enabled.
    ///
    /// Zero allocations — `remove_header` is an in-place map removal.
    pub(crate) fn strip_client_forwarding_headers(upstream_request: &mut RequestHeader) {
        for name in header::CLIENT_FORWARDING_HEADERS.iter() {
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
                    header::apply_header_mod(
                        upstream_request,
                        m,
                        header::is_owned_forwarding_header,
                    );
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
                        rewrite::rewrite_path(upstream_request, pm, original_path);
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

    /// Apply response-side filters: header modifiers and CORS response headers.
    ///
    /// `cors_origin` is the request `Origin` header value captured in
    /// `request_filter`.  Pass `None` on the non-CORS fast path — the CORS arm
    /// exits immediately with zero work.
    pub fn apply_response_filters(
        upstream_response: &mut ResponseHeader,
        filters: &[FilterAction],
        cors_origin: Option<&str>,
    ) {
        for filter in filters {
            match filter {
                FilterAction::ResponseHeaderModifier(m) => {
                    header::apply_header_mod(upstream_response, m, |_| false);
                }
                FilterAction::Cors(cfg) => {
                    let Some(origin_str) = cors_origin else {
                        continue;
                    };
                    let Some(allow_origin) = cfg.resolve_origin(origin_str) else {
                        continue;
                    };
                    let _ = upstream_response
                        .insert_header(hdr::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
                    if cfg.allow_credentials {
                        let _ = upstream_response.insert_header(
                            hdr::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                            HeaderValue::from_static("true"),
                        );
                    }
                    if let Some(expose) = &cfg.expose_headers {
                        let _ = upstream_response
                            .insert_header(hdr::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TrafficFilter;
    use coxswain_core::routing::{FilterAction, HeaderMod};
    use pingora_http::{RequestHeader, ResponseHeader};

    use crate::ctx::ProxyCtx;

    fn resp() -> ResponseHeader {
        ResponseHeader::build(200, None).unwrap()
    }

    fn hmod(add: &[(&str, &str)], set: &[(&str, &str)], remove: &[&str]) -> HeaderMod {
        HeaderMod::parse(add, set, remove).unwrap()
    }

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
        TrafficFilter::apply_response_filters(&mut r, &filters, None);
        assert_eq!(
            r.headers.get("x-forwarded-for").map(|v| v.as_bytes()),
            Some(b"10.0.0.1".as_ref()),
            "response-side modifier must be allowed to set forwarding header names (#410)"
        );
    }
}
