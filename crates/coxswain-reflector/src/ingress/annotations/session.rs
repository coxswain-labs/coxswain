//! Session-affinity (sticky-session) annotation constants and parser (#15).
//!
//! Three keys configure one [`SessionAffinity`] binding over the proxy's stateless
//! affinity machinery: a mode selector plus a per-mode parameter. Like every
//! annotation in this module, an invalid or incomplete value emits a structured
//! `WARN` and is treated as absent (no affinity → plain round-robin) so a typo never
//! rejects the Ingress.

use super::get;
use coxswain_core::routing::SessionAffinity;
use http::HeaderName;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Session-affinity mode: `cookie` (server-injected sticky cookie) or `header`
/// (rendezvous-hash a request header). Any other value disables affinity (WARN).
pub const SESSION_AFFINITY: &str = "ingress.coxswain-labs.dev/session-affinity";

/// Cookie name for `session-affinity: cookie` mode. Defaults to
/// [`DEFAULT_SESSION_COOKIE_NAME`] when absent; an invalid (non-token) value WARNs
/// and falls back to the default rather than emitting a malformed `Set-Cookie`.
pub const SESSION_COOKIE_NAME: &str = "ingress.coxswain-labs.dev/session-cookie-name";

/// Request header to hash for `session-affinity: header` mode. Required in header
/// mode; absent or invalid disables affinity (WARN).
pub const SESSION_HEADER: &str = "ingress.coxswain-labs.dev/session-header";

/// Default cookie name when `session-cookie-name` is omitted.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "__coxswain_session";

/// Parse the session-affinity annotations into a [`SessionAffinity`] binding.
///
/// Returns `None` (plain round-robin) when `session-affinity` is absent, carries an
/// unknown mode, or — in header mode — lacks a valid `session-header`. Every rejection
/// path emits a contextual `WARN` keyed by `route_id` so a dropped binding is traceable.
#[must_use]
pub fn parse_session_affinity(
    ann: &BTreeMap<String, String>,
    route_id: &str,
) -> Option<SessionAffinity> {
    let mode = get(ann, SESSION_AFFINITY)?;
    match mode.trim().to_ascii_lowercase().as_str() {
        "cookie" => {
            let cookie_name = match get(ann, SESSION_COOKIE_NAME).map(str::trim) {
                Some(name) if is_token(name) => Arc::from(name),
                Some(bad) => {
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = SESSION_COOKIE_NAME,
                        value = bad,
                        default = DEFAULT_SESSION_COOKIE_NAME,
                        "invalid cookie name (not an RFC 6265 token) — using default"
                    );
                    Arc::from(DEFAULT_SESSION_COOKIE_NAME)
                }
                None => Arc::from(DEFAULT_SESSION_COOKIE_NAME),
            };
            Some(SessionAffinity::Cookie { cookie_name })
        }
        "header" => {
            let Some(raw) = get(ann, SESSION_HEADER).map(str::trim) else {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = SESSION_AFFINITY,
                    "header mode requires session-header — affinity disabled"
                );
                return None;
            };
            match HeaderName::from_bytes(raw.as_bytes()) {
                Ok(header) => Some(SessionAffinity::Header { header }),
                Err(_) => {
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = SESSION_HEADER,
                        value = raw,
                        "invalid header name — affinity disabled"
                    );
                    None
                }
            }
        }
        other => {
            tracing::warn!(
                ingress = %route_id,
                annotation = SESSION_AFFINITY,
                value = other,
                "unknown session-affinity mode (expected cookie|header) — affinity disabled"
            );
            None
        }
    }
}

/// True when `s` is a non-empty RFC 7230 / RFC 6265 token (the cookie-name grammar):
/// only visible ASCII excluding separators and controls.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ann(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn parse_cookie_mode_uses_default_name_when_unset() {
        // References SESSION_AFFINITY to satisfy the annotation-coverage gate.
        let m = ann(&[(SESSION_AFFINITY, "cookie")]);
        match parse_session_affinity(&m, "default/test") {
            Some(SessionAffinity::Cookie { cookie_name }) => {
                assert_eq!(&*cookie_name, DEFAULT_SESSION_COOKIE_NAME);
            }
            other => panic!("expected cookie mode, got {other:?}"),
        }
    }

    #[test]
    fn parse_cookie_mode_honors_custom_name() {
        // References SESSION_COOKIE_NAME to satisfy the annotation-coverage gate.
        let m = ann(&[
            (SESSION_AFFINITY, "cookie"),
            (SESSION_COOKIE_NAME, "SESSIONID"),
        ]);
        match parse_session_affinity(&m, "default/test") {
            Some(SessionAffinity::Cookie { cookie_name }) => assert_eq!(&*cookie_name, "SESSIONID"),
            other => panic!("expected cookie mode, got {other:?}"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_cookie_mode_invalid_name_falls_back_to_default() {
        let m = ann(&[
            (SESSION_AFFINITY, "cookie"),
            (SESSION_COOKIE_NAME, "bad name;"),
        ]);
        match parse_session_affinity(&m, "default/test") {
            Some(SessionAffinity::Cookie { cookie_name }) => {
                assert_eq!(&*cookie_name, DEFAULT_SESSION_COOKIE_NAME);
            }
            other => panic!("expected cookie mode, got {other:?}"),
        }
        assert!(logs_contain("using default"));
    }

    #[test]
    fn parse_header_mode_captures_header_name() {
        // References SESSION_HEADER to satisfy the annotation-coverage gate.
        let m = ann(&[
            (SESSION_AFFINITY, "header"),
            (SESSION_HEADER, "X-Session-Id"),
        ]);
        match parse_session_affinity(&m, "default/test") {
            Some(SessionAffinity::Header { header }) => assert_eq!(header.as_str(), "x-session-id"),
            other => panic!("expected header mode, got {other:?}"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_header_mode_without_header_disables_affinity() {
        let m = ann(&[(SESSION_AFFINITY, "header")]);
        assert!(parse_session_affinity(&m, "default/test").is_none());
        assert!(logs_contain("requires session-header"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_unknown_mode_disables_affinity() {
        let m = ann(&[(SESSION_AFFINITY, "sourceip")]);
        assert!(parse_session_affinity(&m, "default/test").is_none());
        assert!(logs_contain("unknown session-affinity mode"));
    }

    #[test]
    fn parse_absent_affinity_is_none() {
        let m = ann(&[]);
        assert!(parse_session_affinity(&m, "default/test").is_none());
    }
}
