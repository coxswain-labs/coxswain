//! Annotation key constants and parser for the `ingress.coxswain-labs.dev/*` namespace.
//!
//! Every sibling annotation issue (#79, #C1, #C2, #C4, #24, #25, #39, #53, #40) imports
//! this module for its key constants and the shared [`get`] helper.  The top-level
//! [`IngressAnnotations::parse`] function is called once per Ingress in
//! [`super::reconcile`] and threads the results into every rule/path entry.
//!
//! ## WARN + default on bad values
//!
//! Every parse helper emits a structured `WARN` tracing event on invalid input and
//! returns `None` so the annotation is treated as absent — the whole Ingress keeps
//! its routes; only that annotation's effect is suppressed.

use coxswain_core::routing::{BackendProtocol, PathModifier, RetryOn, RetryPolicy, RouteTimeouts};
use std::collections::BTreeMap;

// ── Annotation-namespace prefix ──────────────────────────────────────────────

/// The shared prefix for all Coxswain Ingress annotations.
pub const PREFIX: &str = "ingress.coxswain-labs.dev/";

// ── Per-annotation key constants ─────────────────────────────────────────────

/// Upstream TCP-connect timeout — Go `time.ParseDuration` string, e.g. `"5s"`.
pub const CONNECT_TIMEOUT: &str = "ingress.coxswain-labs.dev/connect-timeout";
/// Upstream read (response) timeout — Go `time.ParseDuration` string, e.g. `"60s"`.
pub const READ_TIMEOUT: &str = "ingress.coxswain-labs.dev/read-timeout";
/// Upstream write (request send) timeout — Go `time.ParseDuration` string, e.g. `"60s"`.
pub const SEND_TIMEOUT: &str = "ingress.coxswain-labs.dev/send-timeout";
/// Maximum number of retries after the initial attempt — unsigned decimal integer.
pub const MAX_RETRIES: &str = "ingress.coxswain-labs.dev/max-retries";
/// Comma-separated retry conditions: `connect-failure`, `timeout`, `5xx`.
pub const RETRY_ON: &str = "ingress.coxswain-labs.dev/retry-on";
/// Rewrite the upstream request path — literal replacement string (regex capture groups added by #C4).
pub const REWRITE_TARGET: &str = "ingress.coxswain-labs.dev/rewrite-target";
/// Override upstream wire protocol: `HTTP` (default), `HTTPS`, or `GRPC`.
pub const BACKEND_PROTOCOL: &str = "ingress.coxswain-labs.dev/backend-protocol";

// ── Shared lookup helper ──────────────────────────────────────────────────────

/// Look up an `ingress.coxswain-labs.dev/*` annotation value by its full key.
///
/// Returns `None` when the `annotations` map is empty or the key is absent.
#[must_use]
pub fn get<'a>(annotations: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    annotations.get(key).map(String::as_str)
}

// ── Low-level parse helpers ───────────────────────────────────────────────────

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
/// `GRPC` maps to [`BackendProtocol::H2c`] — cleartext HTTP/2 prior knowledge;
/// for gRPC-over-TLS combine with `backend-protocol: HTTPS` once that
/// distinction is added to a future annotation.
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

// ── Parsed annotation set ─────────────────────────────────────────────────────

/// Parsed result of all `ingress.coxswain-labs.dev/*` annotations on a single Ingress.
///
/// Produced by [`IngressAnnotations::parse`] and applied uniformly to every route entry
/// generated from that Ingress (both rule-path entries and the `spec.defaultBackend`).
#[derive(Default)]
pub(super) struct IngressAnnotations {
    /// Partial timeout overrides: the connect/read/send fields come from annotations;
    /// `request` and `backend_request` stay `None` (those come from HTTPRoute/GW API only).
    pub timeouts: RouteTimeouts,
    /// Retry policy from `max-retries` + `retry-on`.
    pub retries: RetryPolicy,
    /// Path rewrite from `rewrite-target` — emitted as a `FilterAction::UrlRewrite`.
    pub rewrite: Option<PathModifier>,
    /// Explicit backend-protocol override, or `None` to keep the `appProtocol`-derived default.
    pub backend_protocol: Option<BackendProtocol>,
}

impl IngressAnnotations {
    /// Parse all `ingress.coxswain-labs.dev/*` annotations from the Ingress metadata map.
    ///
    /// `route_id` is used as context in WARN messages so operators can trace the
    /// offending Ingress without digging into log correlations.
    ///
    /// Invalid values emit a `WARN` and fall back to the absent / default behaviour;
    /// the Ingress is never rejected.
    pub(super) fn parse(annotations: Option<&BTreeMap<String, String>>, route_id: &str) -> Self {
        let Some(ann) = annotations else {
            return Self::default();
        };

        // ── Timeouts ──────────────────────────────────────────────────────────
        let connect = get(ann, CONNECT_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = CONNECT_TIMEOUT,
                    value = v,
                    "invalid duration — using default"
                );
            }
            d
        });
        let read = get(ann, READ_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = READ_TIMEOUT,
                    value = v,
                    "invalid duration — using default"
                );
            }
            d
        });
        let send = get(ann, SEND_TIMEOUT).and_then(|v| {
            let d = parse_duration(v);
            if d.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = SEND_TIMEOUT,
                    value = v,
                    "invalid duration — using default"
                );
            }
            d
        });

        // ── Retries ───────────────────────────────────────────────────────────
        let max_retries = get(ann, MAX_RETRIES).and_then(|v| {
            let n = parse_u32(v);
            if n.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = MAX_RETRIES,
                    value = v,
                    "invalid integer — using default (no retries)"
                );
            }
            n
        });
        let retry_on = get(ann, RETRY_ON).map(parse_retry_on);
        let retries = match (max_retries, retry_on) {
            (Some(n), Some(on)) => RetryPolicy::new(n, on),
            (Some(n), None) => {
                // max-retries set but no retry-on — retries are disabled (no conditions).
                tracing::warn!(
                    ingress = %route_id,
                    max_retries = n,
                    "max-retries set but retry-on is absent — retries disabled"
                );
                RetryPolicy::default()
            }
            (None, Some(_)) => {
                // retry-on set but no max-retries — retries are disabled (no budget).
                tracing::warn!(
                    ingress = %route_id,
                    "retry-on set but max-retries is absent — retries disabled"
                );
                RetryPolicy::default()
            }
            (None, None) => RetryPolicy::default(),
        };

        // ── Path rewrite ──────────────────────────────────────────────────────
        let rewrite =
            get(ann, REWRITE_TARGET).map(|v| PathModifier::ReplaceFullPath(v.to_string()));

        // ── Backend protocol ──────────────────────────────────────────────────
        let backend_protocol = get(ann, BACKEND_PROTOCOL).and_then(|v| {
            let p = parse_backend_protocol(v);
            if p.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = BACKEND_PROTOCOL,
                    value = v,
                    "unknown protocol — using appProtocol-derived default"
                );
            }
            p
        });

        Self {
            timeouts: RouteTimeouts {
                request: None,
                backend_request: None,
                connect,
                read,
                send,
            },
            retries,
            rewrite,
            backend_protocol,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn ann(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ── get() ─────────────────────────────────────────────────────────────────

    #[test]
    fn get_returns_value_when_present() {
        let m = ann(&[(CONNECT_TIMEOUT, "5s")]);
        assert_eq!(get(&m, CONNECT_TIMEOUT), Some("5s"));
    }

    #[test]
    fn get_returns_none_when_absent() {
        let m = BTreeMap::new();
        assert_eq!(get(&m, CONNECT_TIMEOUT), None);
    }

    // ── parse_u32() ───────────────────────────────────────────────────────────

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

    // ── parse_retry_on() ──────────────────────────────────────────────────────

    #[test]
    fn parse_retry_on_all_conditions() {
        let r = parse_retry_on("connect-failure,timeout,5xx");
        assert!(r.contains(RetryOn::CONNECT_FAILURE));
        assert!(r.contains(RetryOn::TIMEOUT));
        assert!(r.contains(RetryOn::HTTP_5XX));
    }

    #[test]
    fn parse_retry_on_partial() {
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

    // ── parse_backend_protocol() ──────────────────────────────────────────────

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

    // ── IngressAnnotations::parse() ───────────────────────────────────────────

    #[test]
    fn parse_returns_defaults_when_no_annotations() {
        let ann = IngressAnnotations::parse(None, "default/test");
        assert!(ann.timeouts.connect.is_none());
        assert!(ann.retries.is_disabled());
        assert!(ann.rewrite.is_none());
        assert!(ann.backend_protocol.is_none());
    }

    #[test]
    fn parse_timeout_annotations() {
        let m = ann(&[
            (CONNECT_TIMEOUT, "5s"),
            (READ_TIMEOUT, "30s"),
            (SEND_TIMEOUT, "10s"),
        ]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.timeouts.connect, Some(Duration::from_secs(5)));
        assert_eq!(a.timeouts.read, Some(Duration::from_secs(30)));
        assert_eq!(a.timeouts.send, Some(Duration::from_secs(10)));
        assert!(a.timeouts.request.is_none());
        assert!(a.timeouts.backend_request.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_invalid_timeout_warns_and_uses_default() {
        let m = ann(&[(CONNECT_TIMEOUT, "not-a-duration")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.timeouts.connect.is_none());
        assert!(logs_contain("invalid duration — using default"));
    }

    #[test]
    fn parse_retries_full() {
        let m = ann(&[(MAX_RETRIES, "3"), (RETRY_ON, "connect-failure,timeout")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.retries.max_retries, 3);
        assert!(a.retries.on.contains(RetryOn::CONNECT_FAILURE));
        assert!(a.retries.on.contains(RetryOn::TIMEOUT));
        assert!(!a.retries.on.contains(RetryOn::HTTP_5XX));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_retries_max_without_on_warns_and_disables() {
        let m = ann(&[(MAX_RETRIES, "3")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.retries.is_disabled());
        assert!(logs_contain("retry-on is absent"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_retries_on_without_max_warns_and_disables() {
        let m = ann(&[(RETRY_ON, "5xx")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.retries.is_disabled());
        assert!(logs_contain("max-retries is absent"));
    }

    #[test]
    fn parse_rewrite_target() {
        let m = ann(&[(REWRITE_TARGET, "/api")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        match a.rewrite {
            Some(PathModifier::ReplaceFullPath(s)) => assert_eq!(s, "/api"),
            _ => panic!("expected ReplaceFullPath"),
        }
    }

    #[test]
    fn parse_backend_protocol_https() {
        let m = ann(&[(BACKEND_PROTOCOL, "HTTPS")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert_eq!(a.backend_protocol, Some(BackendProtocol::Https));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_backend_protocol_unknown_annotation_warns() {
        let m = ann(&[(BACKEND_PROTOCOL, "h2c")]);
        let a = IngressAnnotations::parse(Some(&m), "default/test");
        assert!(a.backend_protocol.is_none());
        assert!(logs_contain("unknown backend-protocol value"));
    }
}
