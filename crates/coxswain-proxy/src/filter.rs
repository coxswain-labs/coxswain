use crate::proxy::ProxyCtx;
use coxswain_core::routing::{FilterAction, PathModifier};
use http::{HeaderName, HeaderValue};
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
                    apply_header_mod_request(upstream_request, m);
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
            }
        }

        // Fixed infrastructure headers added after user-defined filters.
        upstream_request.insert_header(
            "X-Proxy-Engine",
            concat!("Coxswain/", env!("CARGO_PKG_VERSION")),
        )?;

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
                apply_header_mod_response(upstream_response, m);
            }
        }
    }
}

fn apply_header_mod_request(req: &mut RequestHeader, m: &coxswain_core::routing::HeaderMod) {
    for (name, value) in &m.set {
        match (
            HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(n), Ok(v)) => {
                let _ = req.insert_header(n, v);
            }
            _ => tracing::warn!(%name, "RequestHeaderModifier set: invalid header name or value"),
        }
    }
    for (name, value) in &m.add {
        match (
            HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(n), Ok(v)) => {
                let _ = req.append_header(n, v);
            }
            _ => tracing::warn!(%name, "RequestHeaderModifier add: invalid header name or value"),
        }
    }
    for name in &m.remove {
        match HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()) {
            Ok(n) => {
                req.remove_header(&n);
            }
            Err(_) => tracing::warn!(%name, "RequestHeaderModifier remove: invalid header name"),
        }
    }
}

fn apply_header_mod_response(resp: &mut ResponseHeader, m: &coxswain_core::routing::HeaderMod) {
    for (name, value) in &m.set {
        match (
            HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(n), Ok(v)) => {
                let _ = resp.insert_header(n, v);
            }
            _ => tracing::warn!(%name, "ResponseHeaderModifier set: invalid header name or value"),
        }
    }
    for (name, value) in &m.add {
        match (
            HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(n), Ok(v)) => {
                let _ = resp.append_header(n, v);
            }
            _ => tracing::warn!(%name, "ResponseHeaderModifier add: invalid header name or value"),
        }
    }
    for name in &m.remove {
        match HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()) {
            Ok(n) => {
                resp.remove_header(&n);
            }
            Err(_) => tracing::warn!(%name, "ResponseHeaderModifier remove: invalid header name"),
        }
    }
}

fn rewrite_path(req: &mut RequestHeader, modifier: &PathModifier, original_path: &str) {
    let query = req.uri.query();
    let new_path = match modifier {
        PathModifier::ReplaceFullPath(p) => p.clone(),
        PathModifier::ReplacePrefixMatch {
            prefix,
            replacement,
        } => {
            let prefix_trimmed = prefix.trim_end_matches('/');
            if original_path == prefix_trimmed || original_path.starts_with(prefix_trimmed) {
                let suffix = &original_path[prefix_trimmed.len()..];
                let rep = replacement.trim_end_matches('/');
                match suffix {
                    "" | "/" => {
                        if rep.is_empty() {
                            "/".to_string()
                        } else {
                            rep.to_string()
                        }
                    }
                    s => format!("{rep}{s}"),
                }
            } else {
                original_path.to_string()
            }
        }
    };

    let path_and_query = if let Some(q) = query {
        format!("{new_path}?{q}")
    } else {
        new_path
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

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn request_header_set_overwrites() {
        let mut r = req();
        let m = HeaderMod {
            set: vec![("x-keep".to_string(), "overwritten".to_string())],
            ..Default::default()
        };
        apply_header_mod_request(&mut r, &m);
        assert_eq!(r.headers.get("x-keep").unwrap(), "overwritten");
    }

    #[test]
    fn request_header_add_appends() {
        let mut r = req();
        let m = HeaderMod {
            add: vec![("x-keep".to_string(), "extra".to_string())],
            ..Default::default()
        };
        apply_header_mod_request(&mut r, &m);
        let vals: Vec<_> = r.headers.get_all("x-keep").iter().collect();
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn request_header_remove() {
        let mut r = req();
        let m = HeaderMod {
            remove: vec!["x-keep".to_string()],
            ..Default::default()
        };
        apply_header_mod_request(&mut r, &m);
        assert!(r.headers.get("x-keep").is_none());
    }

    #[test]
    fn response_header_set_overwrites() {
        let mut r = resp();
        r.insert_header("x-old", "old").unwrap();
        let m = HeaderMod {
            set: vec![("x-old".to_string(), "new".to_string())],
            ..Default::default()
        };
        apply_header_mod_response(&mut r, &m);
        assert_eq!(r.headers.get("x-old").unwrap(), "new");
    }

    #[test]
    fn response_header_add_appends() {
        let mut r = resp();
        r.insert_header("x-multi", "a").unwrap();
        let m = HeaderMod {
            add: vec![("x-multi".to_string(), "b".to_string())],
            ..Default::default()
        };
        apply_header_mod_response(&mut r, &m);
        let vals: Vec<_> = r.headers.get_all("x-multi").iter().collect();
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn url_rewrite_full_path_replaces_path_and_keeps_query() {
        let mut r = req();
        let pm = PathModifier::ReplaceFullPath("/new".to_string());
        rewrite_path(&mut r, &pm, "/original/path");
        assert_eq!(r.uri.path(), "/new");
        assert_eq!(r.uri.query(), Some("q=1"));
    }

    #[test]
    fn url_rewrite_prefix_match_replaces_prefix() {
        let mut r = RequestHeader::build("GET", b"/api/v2/users", None).unwrap();
        let pm = PathModifier::ReplacePrefixMatch {
            prefix: "/api".to_string(),
            replacement: "/v3".to_string(),
        };
        rewrite_path(&mut r, &pm, "/api/v2/users");
        assert_eq!(r.uri.path(), "/v3/v2/users");
    }

    #[test]
    fn url_rewrite_prefix_match_exact_path_becomes_replacement() {
        let mut r = RequestHeader::build("GET", b"/api", None).unwrap();
        let pm = PathModifier::ReplacePrefixMatch {
            prefix: "/api".to_string(),
            replacement: "/v3".to_string(),
        };
        rewrite_path(&mut r, &pm, "/api");
        assert_eq!(r.uri.path(), "/v3");
    }

    #[test]
    fn url_rewrite_prefix_match_trailing_slash_path() {
        let mut r = RequestHeader::build("GET", b"/api/", None).unwrap();
        let pm = PathModifier::ReplacePrefixMatch {
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
        let pm = PathModifier::ReplacePrefixMatch {
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
        let pm = PathModifier::ReplacePrefixMatch {
            prefix: "/strip-prefix".to_string(),
            replacement: "/".to_string(),
        };
        rewrite_path(&mut r, &pm, "/strip-prefix/foo");
        assert_eq!(r.uri.path(), "/foo");
    }
}
