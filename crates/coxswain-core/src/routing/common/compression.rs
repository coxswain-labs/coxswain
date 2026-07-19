//! Per-route response-compression policy, resolved at reconcile time and
//! carried read-only on the proxy hot path.
//!
//! [`CompressionConfig`] is attached to a
//! [`RouteEntry`](super::entry::RouteEntry) by the Ingress reconciler and
//! snapshotted into a [`RouteMatch`](super::host_router::RouteMatch) on every
//! lookup — immutable config only. The proxy reads it in
//! `upstream_response_filter` to decide whether to compress a response, and
//! which codec to use.

/// Per-route response-compression configuration from the
/// `ingress.coxswain-labs.dev/compression-*` annotations.
///
/// Absent for all Gateway-API routes; `Some` only for Ingress routes that
/// explicitly opt in via `compression-gzip: "true"` or
/// `compression-brotli: "true"`. At least one of `gzip` / `brotli` is `true`
/// whenever this config is `Some` — the reflector returns `None` when both are
/// disabled, so the proxy never constructs an encoder for uncompressed routes.
///
/// Shared as an `Arc` on the hot path so cloning into the per-request
/// `ResolvedRoute` is a refcount bump, not a heap copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressionConfig {
    /// Compress responses with gzip when the client advertises `gzip` in
    /// `Accept-Encoding`. Defaults to `false`.
    pub gzip: bool,
    /// Compress responses with brotli when the client advertises `br` in
    /// `Accept-Encoding`. When both `gzip` and `brotli` are enabled, brotli
    /// is preferred because it achieves ~15–20 % better compression for text.
    /// Defaults to `false`.
    pub brotli: bool,
    /// Compression level, `1`–`9` (validated at parse; `6` if absent or
    /// invalid). Applies to both gzip and brotli.
    pub level: u32,
    /// Minimum response body size in bytes below which compression is skipped.
    ///
    /// The check compares against `Content-Length` when present; responses
    /// without a `Content-Length` (chunked transfer) are always compressed.
    /// Defaults to `1024`.
    pub min_size: u64,
    /// Allow-list of media types (the part of `Content-Type` before `;`),
    /// lower-cased. Responses whose `Content-Type` does not match any entry
    /// are passed through uncompressed.
    ///
    /// Defaults to `["text/html", "text/plain", "text/css",
    /// "application/json", "application/javascript"]`.
    pub types: Box<[Box<str>]>,
}

impl CompressionConfig {
    /// Construct a [`CompressionConfig`].
    ///
    /// Invariant: at least one of `gzip` / `brotli` must be `true`. The
    /// reflector enforces this — `gateway_api::compression::resolve_spec`
    /// returns `None` when both are disabled and never constructs this config.
    pub fn new(
        gzip: bool,
        brotli: bool,
        level: u32,
        min_size: u64,
        types: Box<[Box<str>]>,
    ) -> Self {
        Self {
            gzip,
            brotli,
            level,
            min_size,
            types,
        }
    }

    /// Returns `true` when `content_type` (the full `Content-Type` header
    /// value) matches a media type in `self.types`.
    ///
    /// The comparison strips the `; parameters` suffix, trims ASCII
    /// whitespace, and is case-insensitive. No allocation is performed.
    #[must_use]
    pub fn allows_type(&self, content_type: &str) -> bool {
        // Strip "; parameters" — take everything before the first ';'.
        let media_type = content_type.split(';').next().unwrap_or("").trim_ascii();
        self.types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(media_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(types: &[&str]) -> CompressionConfig {
        CompressionConfig {
            gzip: true,
            brotli: false,
            level: 6,
            min_size: 1024,
            types: types
                .iter()
                .map(|s| s.to_lowercase().into_boxed_str())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    #[test]
    fn allows_type_matches_bare_mime() {
        let c = cfg(&["text/html", "application/json"]);
        assert!(c.allows_type("text/html"));
        assert!(c.allows_type("application/json"));
    }

    #[test]
    fn allows_type_strips_parameters() {
        let c = cfg(&["application/json"]);
        assert!(c.allows_type("application/json; charset=utf-8"));
    }

    #[test]
    fn allows_type_case_insensitive() {
        let c = cfg(&["text/html"]);
        assert!(c.allows_type("Text/HTML"));
    }

    #[test]
    fn allows_type_rejects_unlisted_mime() {
        let c = cfg(&["text/html"]);
        assert!(!c.allows_type("image/png"));
    }

    #[test]
    fn allows_type_empty_content_type() {
        let c = cfg(&["text/html"]);
        assert!(!c.allows_type(""));
    }
}
