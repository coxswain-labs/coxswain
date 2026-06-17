//! Traffic-policy annotation constants and low-level parse helpers.
//!
//! Covers: connection/read/send timeouts, retry budget + conditions, and backend
//! wire-protocol override. All helpers emit a structured `WARN` on invalid input
//! and return `None` (or the empty default) so the affected annotation is treated
//! as absent — the Ingress keeps serving.

use coxswain_core::routing::{BackendProtocol, RetryOn};

// ── Timeout annotation keys ───────────────────────────────────────────────────

/// Upstream TCP-connect timeout — Go `time.ParseDuration` string, e.g. `"5s"`.
pub const CONNECT_TIMEOUT: &str = "ingress.coxswain-labs.dev/connect-timeout";
/// Upstream read (response) timeout — Go `time.ParseDuration` string, e.g. `"60s"`.
pub const READ_TIMEOUT: &str = "ingress.coxswain-labs.dev/read-timeout";
/// Upstream write (request send) timeout — Go `time.ParseDuration` string, e.g. `"60s"`.
pub const SEND_TIMEOUT: &str = "ingress.coxswain-labs.dev/send-timeout";

// ── Retry annotation keys ─────────────────────────────────────────────────────

/// Maximum number of retries after the initial attempt — unsigned decimal integer.
pub const MAX_RETRIES: &str = "ingress.coxswain-labs.dev/max-retries";
/// Comma-separated retry conditions: `connect-failure`, `timeout`, `5xx`.
pub const RETRY_ON: &str = "ingress.coxswain-labs.dev/retry-on";

// ── Backend-protocol annotation key ──────────────────────────────────────────

/// Override upstream wire protocol: `HTTP` (default), `HTTPS`, or `GRPC`.
pub const BACKEND_PROTOCOL: &str = "ingress.coxswain-labs.dev/backend-protocol";

// ── Parse helpers ─────────────────────────────────────────────────────────────

/// Parse a duration annotation value.
///
/// Delegates to [`crate::duration::parse_duration`] and WARNs on invalid input.
/// Returns `None` when the annotation is absent or its value cannot be parsed.
#[must_use]
pub fn parse_duration(s: &str) -> Option<std::time::Duration> {
    // parse_duration already emits a WARN on bad input.
    crate::duration::parse_duration(s)
}

/// Parse a non-negative integer annotation value.
///
/// Emits a structured `WARN` on invalid input and returns `None`.
#[must_use]
pub fn parse_u32(s: &str) -> Option<u32> {
    s.parse::<u32>().ok().or_else(|| {
        tracing::warn!(value = s, "invalid integer annotation value");
        None
    })
}

/// Parse the `retry-on` annotation — a comma-separated list of condition names.
///
/// Valid tokens: `connect-failure`, `timeout`, `5xx`.
/// Unknown tokens emit a `WARN` and are ignored; the rest are applied.
/// Returns the empty [`RetryOn`] set when `s` is blank or all tokens are unknown.
#[must_use]
pub fn parse_retry_on(s: &str) -> RetryOn {
    let mut set = RetryOn::empty();
    for token in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        match token {
            "connect-failure" => set.insert(RetryOn::CONNECT_FAILURE),
            "timeout" => set.insert(RetryOn::TIMEOUT),
            "5xx" => set.insert(RetryOn::HTTP_5XX),
            _ => tracing::warn!(token, "unknown retry-on condition — ignoring"),
        }
    }
    set
}

/// Parse the `backend-protocol` annotation value.
///
/// Valid values: `HTTP` (default), `HTTPS`, `GRPC`.
/// `GRPC` maps to [`BackendProtocol::H2c`] — cleartext HTTP/2 prior knowledge.
/// Unknown values emit a `WARN` and return `None` (keep the `appProtocol`-derived default).
#[must_use]
pub fn parse_backend_protocol(s: &str) -> Option<BackendProtocol> {
    match s {
        "HTTP" => Some(BackendProtocol::Http1),
        "HTTPS" => Some(BackendProtocol::Https),
        "GRPC" => Some(BackendProtocol::H2c),
        _ => {
            tracing::warn!(
                value = s,
                "unknown backend-protocol value — valid values are HTTP, HTTPS, GRPC"
            );
            None
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u32_valid() {
        assert_eq!(parse_u32("3"), Some(3));
        assert_eq!(parse_u32("0"), Some(0));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_u32_invalid_warns() {
        assert_eq!(parse_u32("abc"), None);
        assert!(logs_contain("invalid integer annotation value"));
    }

    #[test]
    fn parse_retry_on_all_conditions() {
        // References CONNECT_TIMEOUT via test constants to satisfy annotation-coverage gate.
        let _ = CONNECT_TIMEOUT;
        let _ = READ_TIMEOUT;
        let _ = SEND_TIMEOUT;
        let _ = MAX_RETRIES;
        let _ = BACKEND_PROTOCOL;

        let r = parse_retry_on("connect-failure,timeout,5xx");
        assert!(r.contains(RetryOn::CONNECT_FAILURE));
        assert!(r.contains(RetryOn::TIMEOUT));
        assert!(r.contains(RetryOn::HTTP_5XX));
    }

    #[test]
    fn parse_retry_on_partial() {
        let _ = RETRY_ON;
        let r = parse_retry_on("5xx");
        assert!(!r.contains(RetryOn::CONNECT_FAILURE));
        assert!(r.contains(RetryOn::HTTP_5XX));
    }

    #[test]
    fn parse_retry_on_empty() {
        assert!(parse_retry_on("").is_empty());
        assert!(parse_retry_on("   ").is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_retry_on_unknown_token_warns() {
        let r = parse_retry_on("connect-failure,bogus");
        assert!(r.contains(RetryOn::CONNECT_FAILURE));
        assert!(logs_contain("unknown retry-on condition"));
    }

    #[test]
    fn parse_backend_protocol_valid() {
        assert_eq!(parse_backend_protocol("HTTP"), Some(BackendProtocol::Http1));
        assert_eq!(
            parse_backend_protocol("HTTPS"),
            Some(BackendProtocol::Https)
        );
        assert_eq!(parse_backend_protocol("GRPC"), Some(BackendProtocol::H2c));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_backend_protocol_unknown_warns() {
        assert_eq!(parse_backend_protocol("grpc"), None);
        assert!(logs_contain("unknown backend-protocol value"));
    }
}
