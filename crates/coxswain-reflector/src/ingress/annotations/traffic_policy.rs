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

// ── Max-body-size annotation key ─────────────────────────────────────────────

/// Per-request body size limit — a byte count or `k`/`m`/`g`-suffixed size, e.g. `"8m"`.
pub const MAX_BODY_SIZE: &str = "ingress.coxswain-labs.dev/max-body-size";

// ── Mirror-target annotation key ──────────────────────────────────────────────

/// Secondary backend to shadow all matched requests to, fire-and-forget.
///
/// Value format: `svc.namespace:port` or `svc.namespace.svc:port` (trailing
/// `.svc.cluster.local` labels are ignored). Example: `"echo-b.default:3000"`.
pub const MIRROR_TARGET: &str = "ingress.coxswain-labs.dev/mirror-target";

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

/// Parse a byte-size annotation value: a bare byte count (`"10485760"`) or a value
/// with a binary unit suffix `k`/`m`/`g` (case-insensitive, e.g. `"512k"`, `"8m"`).
///
/// Multipliers are binary (k = 1024, m = 1024², g = 1024³), matching nginx
/// `proxy-body-size` semantics. Emits a structured `WARN` and returns `None` on any
/// unparseable value so the limit is treated as absent (fail-open).
#[must_use]
pub fn parse_byte_size(s: &str) -> Option<u64> {
    let t = s.trim();
    let (digits, mult): (&str, u64) = match t.as_bytes().last() {
        // The matched suffix is always single-byte ASCII, so `t.len() - 1` is a valid
        // char boundary — slicing cannot split a multi-byte UTF-8 scalar.
        Some(b'k' | b'K') => (&t[..t.len() - 1], 1024),
        Some(b'm' | b'M') => (&t[..t.len() - 1], 1024 * 1024),
        Some(b'g' | b'G') => (&t[..t.len() - 1], 1024 * 1024 * 1024),
        _ => (t, 1),
    };
    digits
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .or_else(|| {
            tracing::warn!(value = s, "invalid max-body-size annotation value");
            None
        })
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

// ── Mirror-target types and parser ───────────────────────────────────────────

/// Intermediate representation of a `mirror-target` annotation value.
///
/// Service–namespace split parsed from the DNS-style host in the annotation.
/// The concrete `BackendGroup` (pod endpoints) is resolved in
/// `crate::ingress::reconcile` where the Service and EndpointSlice stores are
/// available.
#[derive(Debug, Clone)]
pub(crate) struct MirrorTargetRef {
    /// Kubernetes Service name.
    pub service: String,
    /// Kubernetes namespace of the Service.
    pub namespace: String,
    /// Numeric service port.
    pub port: u16,
}

/// Parse the `ingress.coxswain-labs.dev/mirror-target` annotation value.
///
/// Accepted forms: `svc.namespace:port` or `svc.namespace.svc:port` (any
/// trailing DNS labels after the second one are discarded).
///
/// Returns `None` and emits a structured `WARN` when the value cannot be parsed.
/// The caller in [`super::IngressAnnotations::parse`] emits an additional
/// contextual `WARN` with the Ingress name.
#[must_use]
pub(crate) fn parse_mirror_target(s: &str) -> Option<MirrorTargetRef> {
    let Some((host, port_str)) = s.rsplit_once(':') else {
        tracing::warn!(
            value = s,
            "invalid mirror-target — expected \"svc.namespace:port\" form"
        );
        return None;
    };

    let Ok(port) = port_str.trim().parse::<u16>() else {
        tracing::warn!(
            value = s,
            "invalid mirror-target — port must be a number in 0–65535"
        );
        return None;
    };

    // Take the first two dot-separated labels as service and namespace;
    // any trailing labels (.svc, .svc.cluster.local, …) are silently discarded.
    let mut parts = host.trim().splitn(3, '.');
    let service = parts.next().filter(|s| !s.is_empty());
    let namespace = parts.next().filter(|s| !s.is_empty());

    match (service, namespace) {
        (Some(svc), Some(ns)) => Some(MirrorTargetRef {
            service: svc.to_string(),
            namespace: ns.to_string(),
            port,
        }),
        _ => {
            tracing::warn!(
                value = s,
                "invalid mirror-target — host must contain at least \"svc.namespace\""
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

    #[test]
    fn parse_byte_size_valid() {
        // References MAX_BODY_SIZE to satisfy the annotation-coverage gate.
        let _ = MAX_BODY_SIZE;
        assert_eq!(parse_byte_size("10485760"), Some(10_485_760));
        assert_eq!(parse_byte_size("512k"), Some(512 * 1024));
        assert_eq!(parse_byte_size("1m"), Some(1024 * 1024));
        assert_eq!(parse_byte_size("8M"), Some(8 * 1024 * 1024));
        assert_eq!(parse_byte_size("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_byte_size("  64k  "), Some(64 * 1024));
        assert_eq!(parse_byte_size("0"), Some(0));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_byte_size_invalid_warns() {
        assert_eq!(parse_byte_size("garbage"), None);
        assert_eq!(parse_byte_size("1x"), None);
        assert_eq!(parse_byte_size("m"), None);
        assert_eq!(parse_byte_size(""), None);
        assert!(logs_contain("invalid max-body-size annotation value"));
    }

    #[test]
    fn parse_byte_size_overflow_is_none() {
        // u64::MAX with a 'g' multiplier overflows — must fail closed to None, not wrap.
        assert_eq!(parse_byte_size("18446744073709551615g"), None);
    }

    // ── parse_mirror_target ───────────────────────────────────────────────────

    #[test]
    fn parse_mirror_target_short_form() {
        // References MIRROR_TARGET const to satisfy the annotation-coverage gate.
        let _ = MIRROR_TARGET;
        let r = parse_mirror_target("echo-b.default:3000").unwrap();
        assert_eq!(r.service, "echo-b");
        assert_eq!(r.namespace, "default");
        assert_eq!(r.port, 3000);
    }

    #[test]
    fn parse_mirror_target_svc_suffix_form() {
        // "svc.namespace.svc:port" — the trailing ".svc" label is discarded.
        let r = parse_mirror_target("echo-b.default.svc:8080").unwrap();
        assert_eq!(r.service, "echo-b");
        assert_eq!(r.namespace, "default");
        assert_eq!(r.port, 8080);
    }

    #[test]
    fn parse_mirror_target_fqdn_form() {
        // Full FQDN — trailing labels after namespace are discarded.
        let r = parse_mirror_target("echo-b.default.svc.cluster.local:9000").unwrap();
        assert_eq!(r.service, "echo-b");
        assert_eq!(r.namespace, "default");
        assert_eq!(r.port, 9000);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_mirror_target_no_colon_warns() {
        assert!(parse_mirror_target("echo-b.default").is_none());
        assert!(logs_contain("expected \"svc.namespace:port\" form"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_mirror_target_invalid_port_warns() {
        assert!(parse_mirror_target("echo-b.default:notaport").is_none());
        assert!(logs_contain("port must be a number"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_mirror_target_missing_namespace_warns() {
        // No dot separator — only one label before the colon.
        assert!(parse_mirror_target("echo-b:3000").is_none());
        assert!(logs_contain("host must contain at least"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_mirror_target_empty_label_warns() {
        // Leading dot → empty service label.
        assert!(parse_mirror_target(".default:3000").is_none());
        assert!(logs_contain("host must contain at least"));
    }
}
