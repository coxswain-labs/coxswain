//! `Ingress` load-balancer status patch builder and staleness check.

use super::config::StatusAddress;
use k8s_openapi::api::networking::v1::Ingress;

pub(super) fn ingress_lb_already_matches(ingress: &Ingress, addr: &StatusAddress) -> bool {
    let entry = ingress
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_deref())
        .and_then(|entries| entries.first());
    match (entry, addr) {
        (Some(e), StatusAddress::Ip(ip)) => e.ip.as_deref() == Some(&ip.to_string()),
        (Some(e), StatusAddress::Hostname(h)) => e.hostname.as_deref() == Some(h.as_str()),
        (None, _) => false,
    }
}

pub(super) fn build_ingress_status_patch(addr: &StatusAddress) -> serde_json::Value {
    let entry = match addr {
        StatusAddress::Ip(ip) => serde_json::json!({ "ip": ip.to_string() }),
        StatusAddress::Hostname(h) => serde_json::json!({ "hostname": h }),
    };
    serde_json::json!({ "status": { "loadBalancer": { "ingress": [entry] } } })
}

#[cfg(test)]
mod tests {
    use super::super::config::StatusAddress;
    use super::{build_ingress_status_patch, ingress_lb_already_matches};
    use k8s_openapi::api::networking::v1::{
        Ingress, IngressLoadBalancerIngress, IngressLoadBalancerStatus, IngressStatus,
    };

    fn ingress_with_lb(ip: Option<&str>, hostname: Option<&str>) -> Ingress {
        Ingress {
            status: Some(IngressStatus {
                load_balancer: Some(IngressLoadBalancerStatus {
                    ingress: Some(vec![IngressLoadBalancerIngress {
                        ip: ip.map(str::to_string),
                        hostname: hostname.map(str::to_string),
                        ..Default::default()
                    }]),
                }),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn lb_already_matches_false_when_lb_has_ip_but_addr_is_hostname() {
        let ing = ingress_with_lb(Some("203.0.113.1"), None);
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_false_when_lb_has_hostname_but_addr_is_ip() {
        let ing = ingress_with_lb(None, Some("coxswain.example.com"));
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_false_when_lb_list_empty() {
        let ing = Ingress {
            status: Some(IngressStatus {
                load_balancer: Some(IngressLoadBalancerStatus {
                    ingress: Some(vec![]),
                }),
            }),
            ..Default::default()
        };
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn build_patch_is_valid_json_for_ip() {
        let addr = StatusAddress::Ip("10.0.0.1".parse().unwrap());
        let patch = build_ingress_status_patch(&addr);
        let entry = &patch["status"]["loadBalancer"]["ingress"][0];
        assert_eq!(entry["ip"], "10.0.0.1");
        assert!(entry.get("hostname").is_none() || entry["hostname"].is_null());
    }

    #[test]
    fn build_patch_is_valid_json_for_hostname() {
        let addr = StatusAddress::Hostname("lb.example.com".into());
        let patch = build_ingress_status_patch(&addr);
        let entry = &patch["status"]["loadBalancer"]["ingress"][0];
        assert_eq!(entry["hostname"], "lb.example.com");
        assert!(entry.get("ip").is_none() || entry["ip"].is_null());
    }

    // ── Migrated from controller/tests/controller.rs ─────────────────────────

    #[test]
    fn patch_uses_ip_field_for_ip_address() {
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        let patch = build_ingress_status_patch(&addr);
        assert_eq!(
            patch,
            serde_json::json!({
                "status": { "loadBalancer": { "ingress": [{ "ip": "203.0.113.1" }] } }
            })
        );
    }

    #[test]
    fn patch_uses_hostname_field_for_hostname() {
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        let patch = build_ingress_status_patch(&addr);
        assert_eq!(
            patch,
            serde_json::json!({
                "status": { "loadBalancer": { "ingress": [{ "hostname": "coxswain.example.com" }] } }
            })
        );
    }

    #[test]
    fn lb_already_matches_returns_true_when_ip_equal() {
        let ing = ingress_with_lb(Some("203.0.113.1"), None);
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_returns_false_when_ip_differs() {
        let ing = ingress_with_lb(Some("10.0.0.1"), None);
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_returns_true_when_hostname_equal() {
        let ing = ingress_with_lb(None, Some("coxswain.example.com"));
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        assert!(ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_returns_false_when_hostname_differs() {
        let ing = ingress_with_lb(None, Some("other.example.com"));
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_returns_false_when_status_empty() {
        let ing = Ingress {
            status: None,
            ..Default::default()
        };
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }
}
