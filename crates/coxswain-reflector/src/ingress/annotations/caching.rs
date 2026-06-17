//! Response-caching annotation constant and parse helper.
//!
//! Covers the RFC 7234 response-cache opt-in (#40). Like every annotation in
//! this module, an invalid value emits a structured `WARN` and is treated as
//! absent (caching off) so a typo never rejects the Ingress.

/// Enable RFC 7234 response caching for every route on this Ingress — `"true"`
/// or `"false"` (ASCII-case-insensitive). Absent or invalid means caching is
/// off. When on, only `GET`/`HEAD` responses the upstream marks cacheable
/// (`Cache-Control: max-age` / `Expires`, and not `no-store`/`no-cache`) are
/// stored; requests carrying `Authorization` or `Cookie` bypass the cache.
pub const CACHE_ENABLED: &str = "ingress.coxswain-labs.dev/cache-enabled";

/// Parse the `cache-enabled` value into a boolean.
///
/// Returns `None` (treated by the caller as caching off) for any value other
/// than `"true"`/`"false"`, emitting a contextual `WARN` so the dropped opt-in
/// is traceable.
#[must_use]
pub fn parse_cache_enabled(s: &str) -> Option<bool> {
    match s.trim() {
        v if v.eq_ignore_ascii_case("true") => Some(true),
        v if v.eq_ignore_ascii_case("false") => Some(false),
        _ => {
            tracing::warn!(
                value = s,
                "invalid boolean — treating cache-enabled as false"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_true_false() {
        // References CACHE_ENABLED to satisfy the annotation-coverage gate.
        let _ = CACHE_ENABLED;
        assert_eq!(parse_cache_enabled("true"), Some(true));
        assert_eq!(parse_cache_enabled("  FALSE "), Some(false));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_invalid_warns_and_is_none() {
        assert_eq!(parse_cache_enabled("maybe"), None);
        assert!(logs_contain("treating cache-enabled as false"));
    }
}
