//! CORS preflight short-circuit for the `Cors` filter (GEP-1767).
//!
//! The matching CORS *response*-header injection on non-preflight requests lives
//! in [`super::TrafficFilter::apply_response_filters`]; this module owns only the
//! `OPTIONS` preflight that must never reach the upstream.

use coxswain_core::routing::FilterAction;
use http::header;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

/// If `filters` contains a `Cors` filter AND the request is a preflight `OPTIONS`
/// (identified by the presence of `Access-Control-Request-Method`), write a
/// `204 No Content` and return `true`. Returns `false` only when there is no CORS
/// filter, the method is not `OPTIONS`, or no `Origin` header is present.
///
/// A genuine preflight on a CORS-enabled route is *always* short-circuited so the
/// upstream is never contacted (GEP-1767). When the request origin matches the
/// allow-list the 204 carries the full `Access-Control-*` set (origin echoed,
/// optional credentials/methods/headers/expose-headers, max-age). When the origin
/// does not match, the 204 carries no CORS headers — the browser then blocks the
/// cross-origin request because `Access-Control-Allow-Origin` is absent.
///
/// Must be called after routing is resolved but before forwarding to the upstream.
///
/// # Errors
/// Propagates Pingora I/O errors from response-header construction.
pub(crate) async fn try_cors_preflight(
    session: &mut Session,
    filters: &[FilterAction],
    cors_origin: Option<&str>,
) -> Result<bool> {
    let Some(origin_str) = cors_origin else {
        return Ok(false);
    };
    // Capture the preflight request values up front so the session is free to be
    // borrowed mutably for the response write below. A wildcard `allowMethods` /
    // `allowHeaders` reflects these (GEP-1767): `*` is invalid when credentials are
    // allowed, so browsers require the concrete requested method/headers echoed back.
    let (req_method, req_headers) = {
        let req = session.req_header();
        if req.method != http::Method::OPTIONS {
            return Ok(false);
        }
        let Some(acrm) = req.headers.get(header::ACCESS_CONTROL_REQUEST_METHOD) else {
            // Not a real preflight (OPTIONS without ACRM is a regular request).
            return Ok(false);
        };
        (
            acrm.clone(),
            req.headers
                .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
                .cloned(),
        )
    };
    for f in filters {
        if let FilterAction::Cors(cfg) = f {
            // Cap of 6 covers origin + credentials + methods + headers + expose + max-age.
            let mut resp = ResponseHeader::build(204, Some(6))?;
            if let Some(allow_origin) = cfg.resolve_origin(origin_str) {
                resp.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin)?;
                if cfg.allow_credentials {
                    resp.insert_header(
                        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                        http::HeaderValue::from_static("true"),
                    )?;
                }
                if let Some(methods) = &cfg.allow_methods {
                    // Wildcard reflects the requested method; otherwise echo the config.
                    let value = if methods.as_bytes() == b"*" {
                        req_method.clone()
                    } else {
                        methods.clone()
                    };
                    resp.insert_header(header::ACCESS_CONTROL_ALLOW_METHODS, value)?;
                }
                if let Some(headers) = &cfg.allow_headers {
                    // Wildcard reflects the requested headers; if none were requested,
                    // omit the header entirely (nothing to allow).
                    if headers.as_bytes() == b"*" {
                        if let Some(req_hdrs) = &req_headers {
                            resp.insert_header(
                                header::ACCESS_CONTROL_ALLOW_HEADERS,
                                req_hdrs.clone(),
                            )?;
                        }
                    } else {
                        resp.insert_header(header::ACCESS_CONTROL_ALLOW_HEADERS, headers.clone())?;
                    }
                }
                if let Some(expose) = &cfg.expose_headers {
                    resp.insert_header(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone())?;
                }
                resp.insert_header(header::ACCESS_CONTROL_MAX_AGE, cfg.max_age.clone())?;
            }
            session
                .write_response_header(Box::new(resp), true)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("failed to write CORS preflight response: {e}")
                });
            return Ok(true);
        }
    }
    Ok(false)
}
