//! Response-caching policy (#40): the Pingora cache hooks that decide whether a
//! request is cacheable, build its cache/variance key, gate the upstream
//! response, and record hit/miss metrics. The actual storage is owned by
//! [`coxswain_cache::ResponseCache`]; this module is the per-request glue.

use crate::ctx::ProxyCtx;
use coxswain_cache::ResponseCache;
use pingora_cache::key::{CacheKey, HashBinary};
use pingora_cache::{CacheMeta, NoCacheReason, RespCacheable, VarianceBuilder};
use pingora_core::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

/// Default cache freshness: never cache implicitly.
///
/// Returning `None` for every status means an object is admitted only when the
/// upstream gives it explicit freshness (`Cache-Control: max-age` / `Expires`),
/// matching the issue's explicit-freshness-only scope.
fn no_implicit_freshness(_status: http::StatusCode) -> Option<std::time::Duration> {
    None
}

/// Cache metadata defaults: no implicit TTL, no stale-while-revalidate, no
/// stale-if-error. Shared across all requests.
static CACHE_DEFAULTS: pingora_cache::CacheMetaDefaults =
    pingora_cache::CacheMetaDefaults::new(no_implicit_freshness, 0, 0);

/// Enable Pingora's response cache for this request when the matched route
/// opted in and the request is safely cacheable.
///
/// Caching is restricted to `GET`/`HEAD`, and bypassed for requests carrying
/// `Authorization` or `Cookie` (per-user state must never be shared between
/// clients). When this returns without enabling, the request proxies normally
/// with no caching. `cache` is `None` when the process started without a cache
/// (e.g. `--cache-max-size=0`).
///
/// # Errors
/// Propagates Pingora errors from enabling the session cache.
pub(crate) fn request_cache_filter(
    cache: Option<ResponseCache>,
    session: &mut Session,
    ctx: &ProxyCtx,
) -> Result<()> {
    let Some(cache) = cache else { return Ok(()) };
    if !ctx.resolved.as_ref().is_some_and(|r| r.cache_enabled) {
        return Ok(());
    }
    let req = session.req_header();
    if !matches!(req.method, http::Method::GET | http::Method::HEAD) {
        return Ok(());
    }
    if req.headers.contains_key(http::header::AUTHORIZATION)
        || req.headers.contains_key(http::header::COOKIE)
    {
        return Ok(());
    }
    session
        .cache
        .enable(cache.storage(), Some(cache.eviction()), None, None, None);
    Ok(())
}

/// Build the cache key for this request: host namespace + `"{method} {path?query}"`.
///
/// Routes through [`coxswain_cache::cache_key`] so it derives identically to the
/// admin purge path; the host is taken from the resolved route's captured
/// `original_host` to match what was routed.
pub(crate) fn cache_key_callback(session: &Session, ctx: &ProxyCtx) -> CacheKey {
    let req = session.req_header();
    let method = req.method.as_str();
    let path_and_query = req
        .uri
        .path_and_query()
        .map_or_else(|| req.uri.path(), |pq| pq.as_str());
    let host = ctx
        .resolved
        .as_ref()
        .map_or("", |r| r.original_host.as_ref());
    coxswain_cache::cache_key(method, host, path_and_query)
}

/// Decide whether the upstream response is cacheable per RFC 7234.
///
/// Delegates to Pingora's `resp_cacheable`, which honors `Cache-Control`
/// (`no-store`/`no-cache`/`private`/`max-age`) and `Expires`. With
/// [`CACHE_DEFAULTS`] supplying no implicit TTL, only explicitly-fresh responses
/// are admitted.
///
/// A response carrying `Set-Cookie` is refused outright: `resp_cacheable` would
/// otherwise store and replay the cookie verbatim to every client (it only
/// strips it when the origin uses the qualified `Cache-Control: no-cache=
/// "set-cookie"` form), which is session leakage / cache poisoning on a shared
/// cache. RFC 7234 §3 permits caching `Set-Cookie` responses only with explicit
/// authorization; we take the conservative stance and never do.
pub(crate) fn response_cache_filter(resp: &ResponseHeader) -> RespCacheable {
    if resp.headers.contains_key(http::header::SET_COOKIE) {
        return RespCacheable::Uncacheable(NoCacheReason::OriginNotCache);
    }
    let cc = pingora_cache::cache_control::CacheControl::from_resp_headers(resp);
    pingora_cache::filters::resp_cacheable(cc.as_ref(), resp.clone(), false, &CACHE_DEFAULTS)
}

/// Build the `Vary` variance key from the cached response's `Vary` header and
/// the incoming request's matching header values.
///
/// Returns `None` when the response carries no `Vary` (the common case), so such
/// entries are keyed by URL alone.
pub(crate) fn cache_vary_filter(meta: &CacheMeta, req: &RequestHeader) -> Option<HashBinary> {
    let vary = meta.headers().get(http::header::VARY)?.to_str().ok()?;
    let names: Vec<&str> = vary
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut builder = VarianceBuilder::new();
    for name in &names {
        let value = req
            .headers
            .get(*name)
            .map_or_else(Vec::new, |v| v.as_bytes().to_vec());
        builder.add_owned_value(name, value);
    }
    builder.finalize()
}

/// The `route` metric label for the matched route, or `"none"` when unresolved.
fn route_label(ctx: &ProxyCtx) -> &str {
    ctx.resolved
        .as_ref()
        .map_or("none", |r| r.metric_route_id.as_ref())
}

/// Increment `coxswain_cache_hits_total` for the matched route.
pub(crate) fn record_cache_hit(ctx: &ProxyCtx) {
    coxswain_cache::cache_hits_total()
        .with_label_values(&[route_label(ctx)])
        .inc();
}

/// Increment `coxswain_cache_misses_total` for the matched route.
pub(crate) fn record_cache_miss(ctx: &ProxyCtx) {
    coxswain_cache::cache_misses_total()
        .with_label_values(&[route_label(ctx)])
        .inc();
}

#[cfg(test)]
mod tests {
    #[test]
    fn cacheable_response_without_set_cookie_is_admitted() {
        use super::response_cache_filter;
        use pingora_cache::RespCacheable;
        use pingora_http::ResponseHeader;

        let mut resp = ResponseHeader::build(200, None).expect("build response");
        resp.insert_header("Cache-Control", "max-age=300")
            .expect("insert cache-control");
        assert!(
            matches!(response_cache_filter(&resp), RespCacheable::Cacheable(_)),
            "an explicitly-fresh response with no Set-Cookie must be cacheable"
        );
    }

    #[test]
    fn response_with_set_cookie_is_never_cached() {
        use super::response_cache_filter;
        use pingora_cache::RespCacheable;
        use pingora_http::ResponseHeader;

        // A Set-Cookie response that is otherwise fresh must be refused: caching it
        // would replay one client's cookie to every other client (session leakage).
        let mut resp = ResponseHeader::build(200, None).expect("build response");
        resp.insert_header("Cache-Control", "max-age=300")
            .expect("insert cache-control");
        resp.insert_header("Set-Cookie", "session=secret")
            .expect("insert set-cookie");
        assert!(
            matches!(response_cache_filter(&resp), RespCacheable::Uncacheable(_)),
            "a Set-Cookie response must never be admitted to the shared cache"
        );
    }
}
