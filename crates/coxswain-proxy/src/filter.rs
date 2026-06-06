//! Request and response filter application: header modifiers, URL rewrites, and the
//! `Forwarded` header injection for PROXY-protocol connections.

use crate::proxy::ProxyCtx;
use coxswain_core::routing::{FilterAction, HeaderMod, PathModifier};
use http::{HeaderName, HeaderValue};
use std::sync::LazyLock;

static X_PROXY_ENGINE: LazyLock<HeaderValue> =
    LazyLock::new(|| HeaderValue::from_static(concat!("Coxswain/", env!("CARGO_PKG_VERSION"))));
use pingora_core::Result;
use pingora_http::{RequestHeader, ResponseHeader};

pub struct TrafficFilter;

impl TrafficFilter {
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
            let for_value = format_forwarded_for(&addr);
            upstream_request
                .insert_header("Forwarded", format!("for=\"{for_value}\";proto={proto}"))?;
        }

        Ok(())
    }

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
    let new_path = modifier.apply(original_path);
    let path_and_query = match req.uri.query() {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };
    match http::Uri::builder()
        .path_and_query(path_and_query.as_str())
        .build()
    {
        Ok(uri) => req.set_uri(uri),
        Err(e) => tracing::warn!(error = %e, "URLRewrite: failed to build new URI"),
    }
}

/// Format the `for=` component of a Forwarded header per RFC 7239.
///
/// IPv6 addresses are bracketed: `[2001:db8::1]:12345`.
/// IPv4 addresses are not: `198.51.100.42:12345`.
fn format_forwarded_for(addr: &std::net::SocketAddr) -> String {
    match addr {
        std::net::SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        std::net::SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}
