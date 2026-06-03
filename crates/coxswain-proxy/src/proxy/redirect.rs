use coxswain_core::routing::PathModifier;
use http::header;
use pingora_http::RequestHeader;

/// Extract the bare hostname from a request (strips port suffix, prefers URI host over Host header).
pub(super) fn extract_host<'a>(req: &'a RequestHeader, host_hdr: &'a mut String) -> &'a str {
    if let Some(h) = req.uri.host() {
        return h;
    }
    *host_hdr = req
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    host_hdr.split(':').next().unwrap_or("")
}

/// Request-context fields needed to build a redirect `Location` URL.
pub(super) struct RedirectOrigin<'a> {
    pub scheme: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

/// Build the `Location` URL for a `RequestRedirect` filter.
pub(super) fn build_redirect_location(
    filter_scheme: Option<&str>,
    filter_hostname: Option<&str>,
    filter_port: Option<u16>,
    path_modifier: Option<&PathModifier>,
    origin: &RedirectOrigin<'_>,
) -> String {
    let eff_scheme = filter_scheme.unwrap_or(origin.scheme);
    let eff_host = filter_hostname.unwrap_or(origin.host);

    let new_path = match path_modifier {
        None => origin.path.to_string(),
        Some(PathModifier::ReplaceFullPath(p)) => p.clone(),
        Some(PathModifier::ReplacePrefixMatch {
            prefix,
            replacement,
        }) => {
            let prefix_trimmed = prefix.trim_end_matches('/');
            let suffix = &origin.path[prefix_trimmed.len().min(origin.path.len())..];
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
        }
    };

    let path_and_query = match origin.query {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };

    // Omit default ports per Gateway API spec.
    let omit_port = filter_port.is_none()
        || (eff_scheme == "http" && filter_port == Some(80))
        || (eff_scheme == "https" && filter_port == Some(443));

    if omit_port {
        format!("{eff_scheme}://{eff_host}{path_and_query}")
    } else {
        format!(
            "{eff_scheme}://{}:{}{path_and_query}",
            eff_host,
            filter_port.unwrap()
        )
    }
}
