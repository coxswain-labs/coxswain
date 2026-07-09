//! Edge access-control annotation parsing: the `ip-access-control`
//! `IpAccessControl` reference and the trust-forwarded-for cluster (with the
//! anti-spoofing CIDR guard). Also hosts [`parse_cidr_or_host`], the shared
//! bare-IP/CIDR token parser reused by the `IpAccessControl` CR resolver
//! (`gateway_api::ip_access_control`) so the Ingress and Gateway API surfaces
//! parse CIDR tokens identically.
//!
//! Every helper emits a structured `WARN` on invalid input and skips the
//! offending token so a single typo never rejects the whole Ingress.

use super::AnnotationIssue;

/// Reference to an `IpAccessControl` CR in `namespace/name` form, e.g.
/// `"default/my-policy"` (#553). Resolves to the same `(allow_source_range,
/// deny_source_range)` CIDR sets the HTTPRoute/GRPCRoute `ExtensionRef`
/// filter produces (Gateway API parity). Replaces the former inline
/// `allow-source-range` / `deny-source-range` annotation pair, whose CIDR
/// lists now live on the `IpAccessControl` CRD spec. A missing CR fails
/// **open** (no IP filtering) — matching the `ExtensionRef` path's fail-open
/// behaviour.
pub const IP_ACCESS_CONTROL: &str = "ingress.coxswain-labs.dev/ip-access-control";

/// Master switch for trusting a forwarded client-IP header on this Ingress.
/// When `"true"`, the proxy reads the client IP from the header named by
/// `forwarded-for-header` (default `X-Forwarded-For`) instead of the L4 peer.
/// When combined with `forwarded-for-trusted-cidrs`, the header is only trusted
/// when the L4 peer IP falls inside one of those CIDRs (anti-spoofing guard).
/// When absent or `"false"`, the L4 peer address is always used (current behavior).
pub const TRUST_FORWARDED_FOR: &str = "ingress.coxswain-labs.dev/trust-forwarded-for";

/// Header name from which to read the real client IP when `trust-forwarded-for`
/// is `"true"`.  Defaults to `X-Forwarded-For` when absent.  The proxy performs a
/// case-insensitive header lookup, so `x-forwarded-for`, `X-Forwarded-For`, and
/// `CF-Connecting-IP` are all valid values.  The first non-private IP in the
/// header value is used as the client IP.
pub const FORWARDED_FOR_HEADER: &str = "ingress.coxswain-labs.dev/forwarded-for-header";

/// Comma-separated IPv4/IPv6 CIDR blocks that identify trusted upstream proxies.
/// When set, the forwarded header is only trusted when the L4 peer IP falls
/// inside one of these CIDRs; requests from outside the list use the L4 peer
/// address directly, preventing spoofing from untrusted callers.  When absent,
/// the header is trusted unconditionally (suitable when Coxswain is always behind
/// a controlled proxy).  Bare addresses without a prefix are accepted as host
/// routes (`/32` / `/128`).
pub const FORWARDED_FOR_TRUSTED_CIDRS: &str =
    "ingress.coxswain-labs.dev/forwarded-for-trusted-cidrs";

/// Parse the `trust-forwarded-for` annotation cluster into a [`ForwardedForConfig`].
///
/// Returns `None` when `trust-forwarded-for` is absent or does not parse as
/// `"true"` — the proxy uses the L4 peer address as the client IP (current
/// behavior, fail-safe). When truthy, the header name defaults to
/// `X-Forwarded-For` when `forwarded-for-header` is absent. Invalid CIDR tokens
/// in `forwarded-for-trusted-cidrs` emit a `WARN` and are skipped. An empty
/// `trusted_cidrs` after parsing is **fail-closed**: the proxy trusts no peer and
/// ignores the forwarded header (using the L4 peer address), so this parser emits a
/// `WARN` telling the operator the header will not be honored until they configure
/// `forwarded-for-trusted-cidrs`.
///
/// # Arguments
/// * `annotations` — raw annotation map for the Ingress.
/// * `route_id` — human-readable identifier used in `WARN` log messages.
/// * `diag` — collects machine-readable issues alongside the warn log.
#[must_use]
pub fn parse_forwarded_for(
    annotations: &std::collections::BTreeMap<String, String>,
    route_id: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<coxswain_core::routing::ForwardedForConfig> {
    use coxswain_core::routing::ForwardedForConfig;

    let trust = super::get(annotations, TRUST_FORWARDED_FOR)?;
    if !super::parse_bool(trust).unwrap_or(false) {
        if super::parse_bool(trust).is_none() {
            tracing::warn!(
                ingress = %route_id,
                annotation = TRUST_FORWARDED_FOR,
                value = trust,
                "invalid trust-forwarded-for — expected \"true\" or \"false\"; treating as false"
            );
            diag.push(AnnotationIssue {
                annotation: TRUST_FORWARDED_FOR,
                message: format!(
                    "invalid trust-forwarded-for value '{trust}' — expected \"true\" or \"false\"; treating as false"
                ),
            });
        }
        return None;
    }

    let header: Box<str> = super::get(annotations, FORWARDED_FOR_HEADER)
        .filter(|s| !s.trim().is_empty())
        .map(|s| Box::from(s.trim()))
        .unwrap_or_else(|| Box::from("X-Forwarded-For"));

    let trusted_cidrs: Box<[ipnet::IpNet]> = super::get(annotations, FORWARDED_FOR_TRUSTED_CIDRS)
        .and_then(|s| parse_cidr_list(s, FORWARDED_FOR_TRUSTED_CIDRS, route_id, diag))
        .unwrap_or_default()
        .into_boxed_slice();

    if trusted_cidrs.is_empty() {
        tracing::warn!(
            ingress = %route_id,
            annotation = TRUST_FORWARDED_FOR,
            "trust-forwarded-for is enabled but no forwarded-for-trusted-cidrs are set — \
             the forwarded header will NOT be honored (fail-closed anti-spoofing); the L4 \
             peer address is used until trusted proxy CIDRs are configured"
        );
        diag.push(AnnotationIssue {
            annotation: TRUST_FORWARDED_FOR,
            message: "trust-forwarded-for enabled without forwarded-for-trusted-cidrs — \
                      header ignored (fail-closed); configure trusted proxy CIDRs to honor it"
                .to_string(),
        });
    }

    Some(ForwardedForConfig::new(header, trusted_cidrs))
}

/// Shared CIDR-list parser used by `parse_forwarded_for`. `annotation_key` is the
/// full annotation key constant (e.g. `FORWARDED_FOR_TRUSTED_CIDRS`) used in WARN
/// messages and diagnostic issues.
fn parse_cidr_list(
    s: &str,
    annotation_key: &'static str,
    route_id: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<Vec<ipnet::IpNet>> {
    let nets: Vec<ipnet::IpNet> = s
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|token| match parse_cidr_or_host(token) {
            Some(net) => Some(net),
            None => {
                tracing::warn!(
                    ingress = %route_id,
                    token = token,
                    annotation = annotation_key,
                    "invalid CIDR — skipping token"
                );
                diag.push(AnnotationIssue {
                    annotation: annotation_key,
                    message: format!("invalid CIDR token '{token}' — skipping"),
                });
                None
            }
        })
        .collect();
    if nets.is_empty() { None } else { Some(nets) }
}

/// Parse a single token as a CIDR block, falling back to a bare host address
/// (`10.0.0.1` → `10.0.0.1/32`, `2001:db8::1` → `2001:db8::1/128`).
///
/// Shared with the Gateway-API `IpAccessControl` filter resolver so both the
/// Ingress annotation and the Gateway CRD promote bare IPs to host routes
/// identically.
pub(crate) fn parse_cidr_or_host(token: &str) -> Option<ipnet::IpNet> {
    token.parse::<ipnet::IpNet>().ok().or_else(|| {
        token
            .parse::<std::net::IpAddr>()
            .ok()
            .map(ipnet::IpNet::from)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_or_host_bare_ip_becomes_host_route() {
        assert_eq!(
            parse_cidr_or_host("10.0.0.1"),
            Some("10.0.0.1/32".parse().expect("valid"))
        );
        assert_eq!(
            parse_cidr_or_host("2001:db8::1"),
            Some("2001:db8::1/128".parse().expect("valid"))
        );
    }

    #[test]
    fn parse_cidr_or_host_invalid_is_none() {
        assert!(parse_cidr_or_host("not-a-cidr").is_none());
    }

    // ── trust-forwarded-for ───────────────────────────────────────────────────

    fn ann(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn forwarded_for_absent_is_none() {
        // References all three consts to satisfy check-annotation-coverage.sh part (a).
        let _ = TRUST_FORWARDED_FOR;
        let _ = FORWARDED_FOR_HEADER;
        let _ = FORWARDED_FOR_TRUSTED_CIDRS;
        assert!(parse_forwarded_for(&ann(&[]), "ns/test", &mut vec![]).is_none());
    }

    #[test]
    fn forwarded_for_false_is_none() {
        let m = ann(&[(TRUST_FORWARDED_FOR, "false")]);
        assert!(parse_forwarded_for(&m, "ns/test", &mut vec![]).is_none());
    }

    #[test]
    fn forwarded_for_true_defaults_to_x_forwarded_for() {
        let m = ann(&[(TRUST_FORWARDED_FOR, "true")]);
        let cfg = parse_forwarded_for(&m, "ns/test", &mut vec![]).expect("Some");
        assert_eq!(&*cfg.header, "X-Forwarded-For");
        assert!(cfg.trusted_cidrs.is_empty());
    }

    #[test]
    fn forwarded_for_empty_trusted_cidrs_pushes_fail_closed_diag() {
        // trust-forwarded-for enabled without trusted CIDRs is fail-closed at the
        // proxy; the parser must surface that the header will be ignored.
        let m = ann(&[(TRUST_FORWARDED_FOR, "true")]);
        let mut diag = vec![];
        let cfg = parse_forwarded_for(&m, "ns/test", &mut diag).expect("Some");
        assert!(cfg.trusted_cidrs.is_empty());
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, TRUST_FORWARDED_FOR);
    }

    #[test]
    fn forwarded_for_custom_header() {
        let m = ann(&[
            (TRUST_FORWARDED_FOR, "true"),
            (FORWARDED_FOR_HEADER, "CF-Connecting-IP"),
        ]);
        let cfg = parse_forwarded_for(&m, "ns/test", &mut vec![]).expect("Some");
        assert_eq!(&*cfg.header, "CF-Connecting-IP");
    }

    #[test]
    fn forwarded_for_trusted_cidrs_populated() {
        let m = ann(&[
            (TRUST_FORWARDED_FOR, "true"),
            (FORWARDED_FOR_TRUSTED_CIDRS, "10.0.0.0/8,192.168.0.0/16"),
        ]);
        let cfg = parse_forwarded_for(&m, "ns/test", &mut vec![]).expect("Some");
        assert_eq!(cfg.trusted_cidrs.len(), 2);
    }

    #[test]
    #[tracing_test::traced_test]
    fn forwarded_for_bad_cidr_warns_and_is_skipped() {
        let m = ann(&[
            (TRUST_FORWARDED_FOR, "true"),
            (FORWARDED_FOR_TRUSTED_CIDRS, "10.0.0.0/8,not-a-cidr"),
        ]);
        let cfg = parse_forwarded_for(&m, "ns/test", &mut vec![]).expect("Some");
        assert_eq!(cfg.trusted_cidrs.len(), 1);
        assert!(logs_contain("invalid CIDR"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn forwarded_for_invalid_bool_warns_and_is_none() {
        let m = ann(&[(TRUST_FORWARDED_FOR, "yes")]);
        assert!(parse_forwarded_for(&m, "ns/test", &mut vec![]).is_none());
        assert!(logs_contain("invalid trust-forwarded-for"));
    }
}
