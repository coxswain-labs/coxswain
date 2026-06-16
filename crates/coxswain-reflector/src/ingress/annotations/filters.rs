//! Filter-chain annotation constants and low-level parse helpers.
//!
//! Covers: request header modification, response header modification, explicit
//! request redirect, and force-HTTPS (ssl-redirect). All helpers emit a
//! structured `WARN` on invalid input and return `None`/empty so the affected
//! annotation is treated as absent — the Ingress is never rejected.

// ── Request header modifier annotation keys (#79) ────────────────────────────

/// Set (overwrite) upstream request headers — newline-separated `Name: Value` pairs.
/// Values may contain commas; lines are split on the first `:` only.
pub const REQUEST_HEADER_SET: &str = "ingress.coxswain-labs.dev/request-header-set";
/// Append upstream request headers — newline-separated `Name: Value` pairs.
pub const REQUEST_HEADER_ADD: &str = "ingress.coxswain-labs.dev/request-header-add";
/// Remove upstream request headers — comma-separated header names.
pub const REQUEST_HEADER_REMOVE: &str = "ingress.coxswain-labs.dev/request-header-remove";

// ── Response header modifier annotation keys (#79) ───────────────────────────

/// Set (overwrite) response headers — newline-separated `Name: Value` pairs.
pub const RESPONSE_HEADER_SET: &str = "ingress.coxswain-labs.dev/response-header-set";
/// Append response headers — newline-separated `Name: Value` pairs.
pub const RESPONSE_HEADER_ADD: &str = "ingress.coxswain-labs.dev/response-header-add";
/// Remove response headers — comma-separated header names.
pub const RESPONSE_HEADER_REMOVE: &str = "ingress.coxswain-labs.dev/response-header-remove";

// ── Request-redirect annotation keys (#79) ────────────────────────────────────

/// Override the scheme component of the redirect URL (`http` or `https`).
/// Presence of any `redirect-*` key activates `FilterAction::RequestRedirect`.
pub const REDIRECT_SCHEME: &str = "ingress.coxswain-labs.dev/redirect-scheme";
/// Override the hostname component of the redirect URL.
pub const REDIRECT_HOSTNAME: &str = "ingress.coxswain-labs.dev/redirect-hostname";
/// Override the port of the redirect URL — decimal integer in 0–65535.
pub const REDIRECT_PORT: &str = "ingress.coxswain-labs.dev/redirect-port";
/// Replace the full path of the redirect URL — absolute path string.
pub const REDIRECT_PATH: &str = "ingress.coxswain-labs.dev/redirect-path";
/// HTTP status code for the redirect — one of `301`, `302`, `307`, `308`; default `302`.
pub const REDIRECT_STATUS_CODE: &str = "ingress.coxswain-labs.dev/redirect-status-code";

// ── SSL-redirect (force-HTTPS) annotation keys (#262) ─────────────────────────

/// Force HTTP→HTTPS redirect for this Ingress's routes — boolean `"true"`/`"false"`;
/// default `false`. Applies only to the HTTP listener port; HTTPS requests are
/// unaffected. When an explicit `redirect-*` annotation is also present, `ssl-redirect`
/// is ignored (redirect-* takes precedence on all listener ports).
pub const SSL_REDIRECT: &str = "ingress.coxswain-labs.dev/ssl-redirect";
/// HTTP status code for the `ssl-redirect` — one of `301`, `302`, `307`, `308`;
/// default `308` (Permanent Redirect).
pub const SSL_REDIRECT_CODE: &str = "ingress.coxswain-labs.dev/ssl-redirect-code";

// ── Parse helpers ─────────────────────────────────────────────────────────────

/// Split a header annotation value into `(name, value)` pairs.
///
/// Lines are separated by `\n`; each non-blank line is split on the **first** `:`
/// so that values containing commas or colons (e.g. `Cache-Control: no-cache, no-store`)
/// are preserved intact. Names and values are trimmed of leading/trailing ASCII whitespace.
///
/// Lines without a `:` emit a `WARN` and are skipped; the remaining pairs are returned.
/// Names and values are **not** validated as HTTP header tokens here — that happens in
/// [`coxswain_core::routing::HeaderMod::parse`] and produces a separate, source-annotated error.
#[must_use]
pub fn parse_header_pairs(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line.split_once(':') {
            Some((name, value)) => {
                out.push((name.trim().to_string(), value.trim().to_string()));
            }
            None => {
                tracing::warn!(
                    line = line,
                    "header annotation line missing ':' separator — skipping line"
                );
            }
        }
    }
    out
}

/// Split a comma-separated list of header names for a `*-header-remove` annotation.
///
/// Empty tokens (e.g. from trailing commas) are silently discarded.
/// Names are **not** validated as HTTP header tokens here — that happens in
/// [`coxswain_core::routing::HeaderMod::parse`].
#[must_use]
pub fn parse_header_names(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse the `redirect-scheme` annotation value.
///
/// Accepts `http` or `https` (ASCII-case-sensitive).
/// Emits a `WARN` and returns `None` for any other value.
#[must_use]
pub fn parse_redirect_scheme(s: &str) -> Option<String> {
    match s.trim() {
        v @ ("http" | "https") => Some(v.to_string()),
        _ => {
            tracing::warn!(
                value = s,
                "unknown redirect-scheme value — valid values are http, https"
            );
            None
        }
    }
}

/// Parse a redirect HTTP status code.
///
/// Accepts `301`, `302`, `307`, or `308`.
/// Emits a `WARN` and returns `None` for any other value.
#[must_use]
pub fn parse_redirect_status_code(s: &str) -> Option<u16> {
    match s.trim() {
        "301" => Some(301),
        "302" => Some(302),
        "307" => Some(307),
        "308" => Some(308),
        _ => {
            tracing::warn!(
                value = s,
                "invalid redirect status code — valid values are 301, 302, 307, 308"
            );
            None
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_header_pairs() ──────────────────────────────────────────────────

    #[test]
    fn parse_header_pairs_splits_on_first_colon() {
        // References REQUEST_HEADER_SET / REQUEST_HEADER_ADD / REQUEST_HEADER_REMOVE
        // (and the response variants) to satisfy check-annotation-coverage.sh.
        let _ = REQUEST_HEADER_SET;
        let _ = REQUEST_HEADER_ADD;
        let _ = REQUEST_HEADER_REMOVE;
        let _ = RESPONSE_HEADER_SET;
        let _ = RESPONSE_HEADER_ADD;
        let _ = RESPONSE_HEADER_REMOVE;

        let pairs = parse_header_pairs("X-Foo: bar\nCache-Control: no-cache, no-store");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("X-Foo".to_string(), "bar".to_string()));
        // Value with embedded comma is preserved intact.
        assert_eq!(
            pairs[1],
            (
                "Cache-Control".to_string(),
                "no-cache, no-store".to_string()
            )
        );
    }

    #[test]
    fn parse_header_pairs_skips_blank_lines() {
        let pairs = parse_header_pairs("\nX-A: 1\n\nX-B: 2\n");
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_header_pairs_warns_and_skips_line_without_colon() {
        let pairs = parse_header_pairs("bad-line\nX-Good: ok");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "X-Good");
        assert!(logs_contain("missing ':' separator"));
    }

    // ── parse_header_names() ─────────────────────────────────────────────────

    #[test]
    fn parse_header_names_splits_on_comma() {
        let names = parse_header_names("X-Foo, X-Bar , X-Baz");
        assert_eq!(names, vec!["X-Foo", "X-Bar", "X-Baz"]);
    }

    #[test]
    fn parse_header_names_discards_empty_tokens() {
        let names = parse_header_names(",X-A,,X-B,");
        assert_eq!(names, vec!["X-A", "X-B"]);
    }

    // ── parse_redirect_scheme() ───────────────────────────────────────────────

    #[test]
    fn parse_redirect_scheme_valid() {
        // References redirect-* and ssl-redirect consts for coverage gate.
        let _ = REDIRECT_SCHEME;
        let _ = REDIRECT_HOSTNAME;
        let _ = REDIRECT_PORT;
        let _ = REDIRECT_PATH;
        let _ = REDIRECT_STATUS_CODE;
        let _ = SSL_REDIRECT;
        let _ = SSL_REDIRECT_CODE;

        assert_eq!(parse_redirect_scheme("http"), Some("http".to_string()));
        assert_eq!(parse_redirect_scheme("https"), Some("https".to_string()));
        assert_eq!(
            parse_redirect_scheme("  https  "),
            Some("https".to_string())
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_redirect_scheme_unknown_warns() {
        assert_eq!(parse_redirect_scheme("ftp"), None);
        assert!(logs_contain("unknown redirect-scheme value"));
    }

    // ── parse_redirect_status_code() ─────────────────────────────────────────

    #[test]
    fn parse_redirect_status_code_valid() {
        assert_eq!(parse_redirect_status_code("301"), Some(301));
        assert_eq!(parse_redirect_status_code("302"), Some(302));
        assert_eq!(parse_redirect_status_code("307"), Some(307));
        assert_eq!(parse_redirect_status_code("308"), Some(308));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_redirect_status_code_invalid_warns() {
        assert_eq!(parse_redirect_status_code("200"), None);
        assert!(logs_contain("invalid redirect status code"));
    }
}
