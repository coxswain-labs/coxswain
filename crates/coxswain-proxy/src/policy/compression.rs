//! Response compression policy (#270): decides whether an upstream response
//! qualifies for on-the-fly compression and, if so, installs a streaming encoder
//! on the per-request context. The chunk-by-chunk encoding itself runs in
//! [`crate::hooks::response_body_filter`]; this module owns only the setup
//! decision and the algorithm selection.

use crate::ctx::ProxyCtx;
use coxswain_core::routing::CompressionConfig;
use http::header;
use pingora_core::protocols::http::compression::Algorithm;
use pingora_http::{RequestHeader, ResponseHeader};

/// Decide whether to compress this response and, if so, initialise a streaming
/// encoder on `ctx.compression_encoder`.
///
/// Called from [`crate::hooks::upstream_response_filter`] when the matched route
/// carries a [`CompressionConfig`].  The decision is a conjunction of six guards:
///
/// 1. The response status is a normal body-bearing code (not 1xx/204/304).
/// 2. The response does not already have a `Content-Encoding` header.
/// 3. The response `Content-Type` is not `application/grpc*` (#446) — checked
///    unconditionally, independent of `cfg.types`, since gRPC framing (not HTTP
///    `Content-Encoding`) owns response compression and corrupting it is never safe.
/// 4. The response `Content-Type` (media type before `;`) is in the allow-list.
/// 5. The response `Content-Length` is either absent or ≥ `min_size`.
/// 6. The client's `Accept-Encoding` advertises an enabled algorithm.
///
/// On a positive decision, the encoder is stored in `ctx.compression_encoder`;
/// the response headers are adjusted (add `Content-Encoding`, add/extend `Vary`,
/// remove `Content-Length` and `Accept-Ranges`) so that downstream sees a chunked
/// compressed body. On any negative branch the function returns without touching
/// `ctx` or the headers.
pub(crate) fn maybe_setup_compression(
    req: &RequestHeader,
    resp: &mut ResponseHeader,
    ctx: &mut ProxyCtx,
    cfg: &CompressionConfig,
) {
    use http::header::{
        ACCEPT_RANGES, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING, VARY,
    };

    // Guard 1: skip 1xx, 204 (no content), 304 (not modified) — no body.
    let status = resp.status.as_u16();
    if status < 200 || status == 204 || status == 304 {
        return;
    }

    // Guard 2: already compressed — pass through untouched.
    if resp.headers.contains_key(CONTENT_ENCODING) {
        return;
    }

    let ct = resp
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .unwrap_or("");

    // Guard 3: never compress a gRPC response — gRPC compresses per-message at
    // the framing layer (`grpc-encoding`), not via HTTP `Content-Encoding`; doing
    // so here would corrupt the framing on a gRPC-over-HTTPRoute response. This
    // check ignores `cfg.types` on purpose — a misconfigured allow-list must not
    // be able to defeat it.
    let media_type = ct.split(';').next().unwrap_or("").trim().as_bytes();
    if media_type.len() >= 16 && media_type[..16].eq_ignore_ascii_case(b"application/grpc") {
        return;
    }

    // Guard 4: Content-Type must be in the allow-list.
    if !cfg.allows_type(ct) {
        return;
    }

    // Guard 5: Content-Length, when present, must be >= min_size.
    // Absent Content-Length (chunked upstream) is allowed — we cannot know the
    // size in advance, so we compress optimistically.
    if let Some(cl_val) = resp.headers.get(CONTENT_LENGTH) {
        let cl: u64 = std::str::from_utf8(cl_val.as_bytes())
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if cl < cfg.min_size {
            return;
        }
    }

    // Guard 6: client Accept-Encoding — pick algorithm (brotli preferred).
    let ae = req
        .headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .unwrap_or("");

    let algorithm = choose_algorithm(ae, cfg);
    let Some(algorithm) = algorithm else {
        return;
    };

    // Build the encoder. `Algorithm::compressor` may return None for unknown
    // algorithms, but Gzip and Brotli always return Some.
    let Some(encoder) = algorithm.compressor(cfg.level) else {
        return;
    };

    ctx.compression_encoder = Some(encoder);

    // Adjust response headers: set Content-Encoding, extend Vary, remove
    // Content-Length (body length changes) and Accept-Ranges (ranges are
    // meaningless on a compressed stream).
    let ce_value = match algorithm {
        Algorithm::Gzip => "gzip",
        Algorithm::Brotli => "br",
        // Safety: choose_algorithm only returns Gzip or Brotli.
        _ => return,
    };

    // Vary: extend the existing value rather than clobber it.
    let vary = resp
        .headers
        .get(VARY)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let new_vary = match vary {
        Some(existing) if existing.to_ascii_lowercase().contains("accept-encoding") => existing,
        Some(existing) => format!("{existing}, Accept-Encoding"),
        None => "Accept-Encoding".to_string(),
    };

    // Use Pingora's safe header API so both `base.headers` and `header_name_map`
    // stay in sync.  Direct `resp.headers.insert/remove` (via DerefMut) only
    // touches `base.headers`; `write_response_header` later zips the two maps
    // via `case_header_iter` and asserts key-order parity — a mismatch panics,
    // aborting the proxy process (`panic = "abort"` in release profile).
    let _ = resp.insert_header(CONTENT_ENCODING, ce_value);
    let _ = resp.insert_header(VARY, new_vary.as_str());
    resp.remove_header(&CONTENT_LENGTH);
    resp.remove_header(&ACCEPT_RANGES);
    // Pingora's H1 handler decides whether to add Transfer-Encoding: chunked
    // *before* calling upstream_response_filter, based on the upstream's
    // Content-Length. Because we remove Content-Length here, we must set chunked
    // ourselves so an HTTP/1.x downstream has valid body framing. On HTTP/2 the
    // framing is carried by DATA frames and `Transfer-Encoding` is forbidden
    // (RFC 9113 §8.2.2) — inserting it would corrupt or be rejected by the h2
    // encoder, so gate on the downstream protocol.
    if !ctx.is_h2 {
        let _ = resp.insert_header(TRANSFER_ENCODING, "chunked");
    }
}

/// Choose a compression algorithm from the client's `Accept-Encoding` string,
/// respecting the route's `gzip` / `brotli` flags. Brotli is preferred when both
/// are enabled and the client advertises `br`.
///
/// Returns `None` when no enabled algorithm is offered by the client.
fn choose_algorithm(accept_encoding: &str, cfg: &CompressionConfig) -> Option<Algorithm> {
    let brotli_offered = accept_encoding
        .split(',')
        .map(|t| t.trim().split(';').next().unwrap_or("").trim())
        .any(|t| t.eq_ignore_ascii_case("br"));
    let gzip_offered = accept_encoding
        .split(',')
        .map(|t| t.trim().split(';').next().unwrap_or("").trim())
        .any(|t| t.eq_ignore_ascii_case("gzip"));

    if cfg.brotli && brotli_offered {
        Some(Algorithm::Brotli)
    } else if cfg.gzip && gzip_offered {
        Some(Algorithm::Gzip)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{choose_algorithm, maybe_setup_compression};
    use crate::ctx::ProxyCtx;
    use coxswain_core::routing::CompressionConfig;
    use pingora_http::{RequestHeader, ResponseHeader};

    fn gzip_cfg() -> CompressionConfig {
        CompressionConfig::new(
            true,
            false,
            6,
            1024,
            vec!["application/json".into(), "text/html".into()].into_boxed_slice(),
        )
    }

    fn both_cfg() -> CompressionConfig {
        CompressionConfig::new(
            true,
            true,
            6,
            1024,
            vec!["application/json".into()].into_boxed_slice(),
        )
    }

    fn req_with_ae(accept_encoding: &str) -> RequestHeader {
        let mut r = RequestHeader::build("GET", b"/", None).expect("build request");
        r.insert_header("accept-encoding", accept_encoding)
            .expect("insert ae");
        r
    }

    fn resp_200(ct: &str, cl: Option<u64>) -> ResponseHeader {
        let mut r = ResponseHeader::build(200, None).expect("build response");
        r.insert_header("content-type", ct).expect("insert ct");
        if let Some(n) = cl {
            r.insert_header("content-length", n.to_string())
                .expect("insert cl");
        }
        r
    }

    #[test]
    fn choose_algorithm_prefers_brotli_when_both_enabled_and_br_offered() {
        use pingora_core::protocols::http::compression::Algorithm;
        let cfg = both_cfg();
        assert_eq!(
            choose_algorithm("gzip, br", &cfg),
            Some(Algorithm::Brotli),
            "brotli must be preferred when both enabled and br advertised"
        );
    }

    #[test]
    fn choose_algorithm_falls_back_to_gzip() {
        use pingora_core::protocols::http::compression::Algorithm;
        let cfg = both_cfg();
        assert_eq!(
            choose_algorithm("gzip", &cfg),
            Some(Algorithm::Gzip),
            "should fall back to gzip when br not offered"
        );
    }

    #[test]
    fn choose_algorithm_none_when_no_match() {
        let cfg = gzip_cfg();
        assert!(
            choose_algorithm("br", &cfg).is_none(),
            "gzip-only config must not match br"
        );
    }

    #[test]
    fn choose_algorithm_none_when_ae_empty() {
        let cfg = gzip_cfg();
        assert!(choose_algorithm("", &cfg).is_none());
    }

    #[test]
    fn setup_compression_sets_content_encoding_and_vary() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", Some(2048));
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(ctx.compression_encoder.is_some(), "encoder must be set");
        assert_eq!(
            resp.headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("gzip")
        );
        assert!(
            resp.headers
                .get("vary")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("accept-encoding"),
            "Vary must include Accept-Encoding"
        );
        assert!(
            resp.headers.get("content-length").is_none(),
            "Content-Length must be removed"
        );
    }

    #[test]
    fn setup_compression_passes_through_already_compressed() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", Some(2048));
        resp.insert_header("content-encoding", "gzip")
            .expect("insert ce");
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_none(),
            "must not re-compress an already-compressed response"
        );
    }

    #[test]
    fn setup_compression_skips_disallowed_content_type() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("image/png", Some(4096));
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_none(),
            "image/png must not be compressed"
        );
    }

    #[test]
    fn setup_compression_skips_below_min_size() {
        let cfg = gzip_cfg(); // min_size = 1024
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", Some(100));
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_none(),
            "response below min_size must not be compressed"
        );
    }

    #[test]
    fn setup_compression_allows_chunked_without_content_length() {
        // No Content-Length (chunked) → always compress regardless of min_size.
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", None); // no Content-Length
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_some(),
            "chunked response without Content-Length must be compressed"
        );
    }

    #[test]
    fn setup_compression_sets_chunked_te_on_h1_only() {
        use http::header::TRANSFER_ENCODING;
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");

        // HTTP/1.x downstream: chunked framing is required after Content-Length removal.
        let mut resp_h1 = resp_200("application/json", Some(4096));
        let mut ctx_h1 = ProxyCtx {
            is_h2: false,
            ..Default::default()
        };
        maybe_setup_compression(&req, &mut resp_h1, &mut ctx_h1, &cfg);
        assert!(ctx_h1.compression_encoder.is_some());
        assert_eq!(
            resp_h1.headers.get(TRANSFER_ENCODING).map(|v| v.as_bytes()),
            Some(&b"chunked"[..]),
            "h1 downstream must get Transfer-Encoding: chunked"
        );

        // HTTP/2 downstream: Transfer-Encoding is forbidden (RFC 9113 §8.2.2).
        let mut resp_h2 = resp_200("application/json", Some(4096));
        let mut ctx_h2 = ProxyCtx {
            is_h2: true,
            ..Default::default()
        };
        maybe_setup_compression(&req, &mut resp_h2, &mut ctx_h2, &cfg);
        assert!(ctx_h2.compression_encoder.is_some());
        assert!(
            resp_h2.headers.get(TRANSFER_ENCODING).is_none(),
            "h2 downstream must NOT carry Transfer-Encoding"
        );
    }

    #[test]
    fn setup_compression_skips_204_no_content() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = ResponseHeader::build(204, None).expect("build 204");
        resp.insert_header("content-type", "application/json")
            .expect("insert ct");
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(ctx.compression_encoder.is_none(), "204 must be skipped");
    }

    #[test]
    fn setup_compression_skips_grpc_content_type_even_when_allow_listed() {
        // Misconfigured allow-list explicitly includes "application/grpc" — the
        // gRPC guard must still win regardless of `cfg.types` (#446).
        let cfg = CompressionConfig::new(
            true,
            false,
            6,
            0,
            vec!["application/grpc".into()].into_boxed_slice(),
        );
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/grpc", None);
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_none(),
            "application/grpc must never be compressed"
        );
    }

    #[test]
    fn setup_compression_skips_grpc_content_type_with_proto_suffix() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/grpc+proto", Some(4096));
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        assert!(
            ctx.compression_encoder.is_none(),
            "application/grpc+proto must never be compressed"
        );
    }

    #[test]
    fn setup_compression_vary_extends_existing() {
        let cfg = gzip_cfg();
        let req = req_with_ae("gzip");
        let mut resp = resp_200("application/json", None);
        resp.insert_header("vary", "Cookie").expect("insert vary");
        let mut ctx = ProxyCtx::default();
        maybe_setup_compression(&req, &mut resp, &mut ctx, &cfg);
        let vary = resp
            .headers
            .get("vary")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            vary.to_ascii_lowercase().contains("cookie"),
            "original Vary value must be preserved"
        );
        assert!(
            vary.to_ascii_lowercase().contains("accept-encoding"),
            "Accept-Encoding must be appended to Vary"
        );
    }
}
