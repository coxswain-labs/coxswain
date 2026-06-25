//! `RequestRedirect` filter handling: the preflight short-circuit
//! ([`try_redirect`]) that writes a 3xx without contacting the upstream, plus
//! the [`Location`][build_redirect_location] URL construction it relies on.

use coxswain_core::routing::{FilterAction, PathModifier};
use http::header;
use pingora_core::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

/// Extract the bare hostname from a request (strips port suffix, prefers URI host over Host header).
///
/// Returns a slice borrowed from `req` — the Host-header fallback splits on `:`
/// over the borrowed header value rather than allocating a scratch `String`, so
/// the caller's `Arc::from` is the only allocation on the request path (#397).
pub(crate) fn extract_host(req: &RequestHeader) -> &str {
    if let Some(h) = req.uri.host() {
        return h;
    }
    let host = req
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    host.split(':').next().unwrap_or("")
}

/// Request-context fields needed to build a redirect `Location` URL.
pub(crate) struct RedirectOrigin<'a> {
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

/// Build the `Location` URL for a `RequestRedirect` filter.
pub(crate) fn build_redirect_location(
    filter_scheme: Option<&str>,
    filter_hostname: Option<&str>,
    filter_port: Option<u16>,
    path_modifier: Option<&PathModifier>,
    origin: &RedirectOrigin<'_>,
) -> String {
    let eff_scheme = filter_scheme.unwrap_or(origin.scheme);
    let eff_host = filter_hostname.unwrap_or(origin.host);

    // Per Gateway API spec:
    // - filter_port set → use filter_port
    // - filter_port nil, filter_scheme set → use well-known port for new scheme
    // - filter_port nil, filter_scheme nil → preserve Listener (incoming) port
    let eff_port = filter_port.unwrap_or_else(|| {
        if filter_scheme.is_some() {
            match eff_scheme {
                "https" => 443,
                _ => 80,
            }
        } else {
            origin.port
        }
    });

    let new_path = match path_modifier {
        None => origin.path.to_string(),
        Some(pm) => pm.apply(origin.path),
    };

    let path_and_query = match origin.query {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };

    // Omit default ports per Gateway API spec.
    let omit_port =
        (eff_scheme == "http" && eff_port == 80) || (eff_scheme == "https" && eff_port == 443);

    if omit_port {
        format!("{eff_scheme}://{eff_host}{path_and_query}")
    } else {
        format!("{eff_scheme}://{}:{eff_port}{path_and_query}", eff_host)
    }
}

/// If `filters` contains a `RequestRedirect`, build the `Location` header,
/// write the 3xx response, and return `true`. Returns `false` otherwise.
///
/// # Errors
/// Propagates Pingora I/O errors from response-header construction.
pub(crate) async fn try_redirect(
    session: &mut Session,
    filters: &[FilterAction],
    proto: &str,
    host: &str,
    incoming_port: u16,
    path: &str,
    query: Option<&str>,
) -> Result<bool> {
    for f in filters {
        if let FilterAction::RequestRedirect {
            scheme,
            hostname,
            port,
            status_code,
            path: path_mod,
        } = f
        {
            let origin = RedirectOrigin {
                scheme: proto,
                host,
                port: incoming_port,
                path,
                query,
            };
            let location = build_redirect_location(
                scheme.as_deref(),
                hostname.as_deref(),
                *port,
                path_mod.as_ref(),
                &origin,
            );
            let mut resp = ResponseHeader::build(*status_code, Some(2))?;
            resp.insert_header(header::LOCATION, location)?;
            session
                .write_response_header(Box::new(resp), true)
                .await
                .unwrap_or_else(|e| tracing::error!("failed to write redirect response: {e}"));
            return Ok(true);
        }
    }
    Ok(false)
}
