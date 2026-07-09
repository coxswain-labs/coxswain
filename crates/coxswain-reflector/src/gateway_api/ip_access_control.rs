//! `IpAccessControl` resolution (#553): spec → runtime `(allow, deny)` CIDR-set
//! translation shared by the route-level `ExtensionRef` filter (in
//! [`super::filters`]) and the Ingress `ip-access-control` annotation
//! (`crate::ingress`).
//!
//! Like [`super::rate_limit`], [`super::compression`], and [`super::retry`],
//! there is nothing to resolve besides the CR's own fields — no `backendRef`,
//! no external cache lookup — so `resolve_spec` is pure, synchronous
//! spec→config translation.

use coxswain_core::crd::IpAccessControlSpec;
use std::sync::Arc;

/// One resolved CIDR set (`allow` or `deny`) — `None` when the source list is
/// empty or every token is unparseable. Named to keep `resolve_spec`'s and
/// `resolve_ip_access_ref`'s signatures out of clippy's `type_complexity`
/// lint; `pub(crate)` so [`super::filters`] (the `ExtensionRef` scanner) and
/// [`crate::ingress::reconcile_helpers`] (the Ingress annotation resolver)
/// share one definition rather than each declaring their own alias.
pub(crate) type CidrSet = Option<Arc<Vec<ipnet::IpNet>>>;

/// Resolve an `IpAccessControl` spec into the `(allow, deny)` CIDR sets the
/// proxy enforces — deny evaluated first, then allow (the same
/// `allow_source_range` / `deny_source_range` fields the Ingress
/// `ip-access-control` annotation resolves to, #553).
///
/// Each set is `None` when its list is empty or every token is unparseable —
/// an invalid CIDR token is logged and skipped rather than failing the whole
/// policy, so a single typo never silently locks out (or fails to protect) a
/// route. `log_ns`/`log_name` identify the CR in skipped-token WARNs.
///
/// Never fails — the caller (the `ExtensionRef` scanner or the Ingress
/// resolver) is responsible for the *missing CR* fail-open case.
///
/// `pub(crate)` (not `pub(super)` like most Gateway API spec resolvers) —
/// reused directly by [`crate::ingress::reconcile_helpers`] so the Ingress
/// `ip-access-control` annotation resolves to the identical CIDR sets the
/// HTTPRoute/GRPCRoute `ExtensionRef` filter produces (Gateway API parity, #553).
#[must_use]
pub(crate) fn resolve_spec(
    spec: &IpAccessControlSpec,
    log_ns: &str,
    log_name: &str,
) -> (CidrSet, CidrSet) {
    let deny = parse_cidr_set(&spec.deny, log_ns, log_name, "deny");
    let allow = parse_cidr_set(&spec.allow, log_ns, log_name, "allow");
    (allow, deny)
}

/// Parse an `IpAccessControl` CIDR list into an `Arc<Vec<IpNet>>`, promoting bare
/// IPs to host routes and skipping invalid tokens with a WARN.
///
/// Returns `None` when the list is empty or every token is unparseable, so the
/// caller treats the set as absent rather than as an empty (all-blocking /
/// nothing-matching) list. `field` names the offending set (`"allow"` / `"deny"`)
/// in skipped-token WARNs.
pub(super) fn parse_cidr_set(
    tokens: &[String],
    log_ns: &str,
    log_name: &str,
    field: &'static str,
) -> CidrSet {
    let nets: Vec<ipnet::IpNet> = tokens
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .filter_map(|token| {
            match crate::ingress::annotations::edge_access::parse_cidr_or_host(token) {
                Some(net) => Some(net),
                None => {
                    tracing::warn!(
                        ns = log_ns,
                        name = log_name,
                        field,
                        token,
                        "IpAccessControl has an invalid CIDR — skipping token"
                    );
                    None
                }
            }
        })
        .collect();
    if nets.is_empty() {
        None
    } else {
        Some(Arc::new(nets))
    }
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use coxswain_core::crd::IpAccessControl;

    fn spec_with(yaml_fragment: &str) -> IpAccessControlSpec {
        let indented = yaml_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: IpAccessControl\n\
             metadata:\n  name: t\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str::<IpAccessControl>(&yaml)
            .unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
            .spec
    }

    #[test]
    fn empty_spec_resolves_to_no_filtering() {
        let (allow, deny) = resolve_spec(&spec_with("{}"), "default", "t");
        assert!(allow.is_none());
        assert!(deny.is_none());
    }

    #[test]
    fn allow_only_parses() {
        let (allow, deny) = resolve_spec(&spec_with("allow:\n- 203.0.113.0/24"), "default", "t");
        assert_eq!(
            *allow.expect("allow set"),
            vec!["203.0.113.0/24".parse::<ipnet::IpNet>().expect("valid")]
        );
        assert!(deny.is_none());
    }

    #[test]
    fn deny_only_parses() {
        let (allow, deny) = resolve_spec(&spec_with("deny:\n- 10.0.0.0/8"), "default", "t");
        assert_eq!(
            *deny.expect("deny set"),
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().expect("valid")]
        );
        assert!(allow.is_none());
    }

    #[test]
    fn bare_ip_becomes_host_route() {
        let (allow, _) = resolve_spec(&spec_with("allow:\n- 203.0.113.10"), "default", "t");
        assert_eq!(
            *allow.expect("allow set"),
            vec!["203.0.113.10/32".parse::<ipnet::IpNet>().expect("valid")]
        );
    }

    #[test]
    fn invalid_token_is_skipped() {
        let (allow, _) = resolve_spec(
            &spec_with("allow:\n- not-a-cidr\n- 10.0.0.0/8"),
            "default",
            "t",
        );
        assert_eq!(
            *allow.expect("allow set"),
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().expect("valid")]
        );
    }

    #[test]
    fn all_invalid_tokens_yields_none() {
        let (allow, _) = resolve_spec(&spec_with("allow:\n- not-a-cidr"), "default", "t");
        assert!(allow.is_none());
    }
}
