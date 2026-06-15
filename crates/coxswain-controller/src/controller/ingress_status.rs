//! `Ingress` load-balancer status patch builder and staleness check.

use super::config::StatusAddress;
use coxswain_reflector::ingress::IngressPorts;
use k8s_openapi::api::networking::v1::{Ingress, IngressPortStatus};

pub(super) fn ingress_lb_already_matches(
    ingress: &Ingress,
    addr: &StatusAddress,
    ports: IngressPorts,
) -> bool {
    let entry = ingress
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_deref())
        .and_then(|entries| entries.first());
    match (entry, addr) {
        (Some(e), StatusAddress::Ip(ip)) => {
            e.ip.as_deref() == Some(&ip.to_string())
                && ports_already_match(e.ports.as_deref(), ports)
        }
        (Some(e), StatusAddress::Hostname(h)) => {
            e.hostname.as_deref() == Some(h.as_str())
                && ports_already_match(e.ports.as_deref(), ports)
        }
        (None, _) => false,
    }
}

/// Returns `true` when the port entries already in the status match the
/// ports we would write.
fn ports_already_match(current: Option<&[IngressPortStatus]>, ports: IngressPorts) -> bool {
    let expected = port_numbers(ports);
    let current_ports: Vec<i32> = current.unwrap_or_default().iter().map(|p| p.port).collect();
    current_ports == expected
}

/// Sorted list of port numbers we will write, derived from `IngressPorts`.
fn port_numbers(ports: IngressPorts) -> Vec<i32> {
    let mut out = Vec::with_capacity(2);
    if let Some(p) = ports.http {
        out.push(i32::from(p));
    }
    if let Some(p) = ports.https {
        out.push(i32::from(p));
    }
    out
}

pub(super) fn build_ingress_status_patch(
    addr: &StatusAddress,
    ports: IngressPorts,
) -> serde_json::Value {
    let port_statuses = port_status_json(ports);
    let entry = match addr {
        StatusAddress::Ip(ip) if port_statuses.is_empty() => {
            serde_json::json!({ "ip": ip.to_string() })
        }
        StatusAddress::Ip(ip) => {
            serde_json::json!({ "ip": ip.to_string(), "ports": port_statuses })
        }
        StatusAddress::Hostname(h) if port_statuses.is_empty() => {
            serde_json::json!({ "hostname": h })
        }
        StatusAddress::Hostname(h) => {
            serde_json::json!({ "hostname": h, "ports": port_statuses })
        }
    };
    serde_json::json!({ "status": { "loadBalancer": { "ingress": [entry] } } })
}

/// Build the `ports` array for the JSON patch from the configured listener ports.
fn port_status_json(ports: IngressPorts) -> Vec<serde_json::Value> {
    let mut out = Vec::with_capacity(2);
    if let Some(p) = ports.http {
        out.push(serde_json::json!({ "port": i32::from(p), "protocol": "TCP" }));
    }
    if let Some(p) = ports.https {
        out.push(serde_json::json!({ "port": i32::from(p), "protocol": "TCP" }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::config::StatusAddress;
    use super::{build_ingress_status_patch, ingress_lb_already_matches};
    use coxswain_reflector::ingress::IngressPorts;
    use k8s_openapi::api::networking::v1::{
        Ingress, IngressLoadBalancerIngress, IngressLoadBalancerStatus, IngressPortStatus,
        IngressStatus,
    };

    fn ports_http_https() -> IngressPorts {
        IngressPorts::new(Some(80), Some(443))
    }

    fn ports_http_only() -> IngressPorts {
        IngressPorts::new(Some(80), None)
    }

    fn ports_none() -> IngressPorts {
        IngressPorts::new(None, None)
    }

    fn ingress_with_lb(
        ip: Option<&str>,
        hostname: Option<&str>,
        ports: Option<Vec<IngressPortStatus>>,
    ) -> Ingress {
        Ingress {
            status: Some(IngressStatus {
                load_balancer: Some(IngressLoadBalancerStatus {
                    ingress: Some(vec![IngressLoadBalancerIngress {
                        ip: ip.map(str::to_string),
                        hostname: hostname.map(str::to_string),
                        ports,
                    }]),
                }),
            }),
            ..Default::default()
        }
    }

    fn port_status(port: i32) -> IngressPortStatus {
        IngressPortStatus {
            port,
            protocol: "TCP".to_string(),
            error: None,
        }
    }

    // ── ingress_lb_already_matches ────────────────────────────────────────────

    #[test]
    fn lb_already_matches_false_when_lb_has_ip_but_addr_is_hostname() {
        let ing = ingress_with_lb(Some("203.0.113.1"), None, None);
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        assert!(!ingress_lb_already_matches(&ing, &addr, ports_none()));
    }

    #[test]
    fn lb_already_matches_false_when_lb_has_hostname_but_addr_is_ip() {
        let ing = ingress_with_lb(None, Some("coxswain.example.com"), None);
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr, ports_none()));
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
        assert!(!ingress_lb_already_matches(&ing, &addr, ports_none()));
    }

    #[test]
    fn lb_already_matches_returns_true_when_ip_and_ports_equal() {
        let ing = ingress_with_lb(
            Some("203.0.113.1"),
            None,
            Some(vec![port_status(80), port_status(443)]),
        );
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(ingress_lb_already_matches(&ing, &addr, ports_http_https()));
    }

    #[test]
    fn lb_already_matches_returns_false_when_ip_differs() {
        let ing = ingress_with_lb(
            Some("10.0.0.1"),
            None,
            Some(vec![port_status(80), port_status(443)]),
        );
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr, ports_http_https()));
    }

    #[test]
    fn lb_already_matches_returns_false_when_ports_differ() {
        let ing = ingress_with_lb(Some("203.0.113.1"), None, Some(vec![port_status(80)]));
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        // We now expect both 80 and 443 but status only has 80.
        assert!(!ingress_lb_already_matches(&ing, &addr, ports_http_https()));
    }

    #[test]
    fn lb_already_matches_returns_false_when_ports_absent_but_expected() {
        let ing = ingress_with_lb(Some("203.0.113.1"), None, None);
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr, ports_http_https()));
    }

    #[test]
    fn lb_already_matches_returns_true_when_no_ports_configured_and_none_present() {
        let ing = ingress_with_lb(Some("203.0.113.1"), None, None);
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(ingress_lb_already_matches(&ing, &addr, ports_none()));
    }

    #[test]
    fn lb_already_matches_returns_true_when_hostname_and_ports_equal() {
        let ing = ingress_with_lb(
            None,
            Some("coxswain.example.com"),
            Some(vec![port_status(80), port_status(443)]),
        );
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        assert!(ingress_lb_already_matches(&ing, &addr, ports_http_https()));
    }

    #[test]
    fn lb_already_matches_returns_false_when_hostname_differs() {
        let ing = ingress_with_lb(
            None,
            Some("other.example.com"),
            Some(vec![port_status(80), port_status(443)]),
        );
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        assert!(!ingress_lb_already_matches(&ing, &addr, ports_http_https()));
    }

    #[test]
    fn lb_already_matches_returns_false_when_status_empty() {
        let ing = Ingress {
            status: None,
            ..Default::default()
        };
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr, ports_none()));
    }

    // ── build_ingress_status_patch ────────────────────────────────────────────

    #[test]
    fn patch_includes_http_and_https_ports_for_ip() {
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        let patch = build_ingress_status_patch(&addr, ports_http_https());
        let entry = &patch["status"]["loadBalancer"]["ingress"][0];
        assert_eq!(entry["ip"], "203.0.113.1");
        let ports = entry["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0]["port"], 80);
        assert_eq!(ports[0]["protocol"], "TCP");
        assert_eq!(ports[1]["port"], 443);
        assert_eq!(ports[1]["protocol"], "TCP");
    }

    #[test]
    fn patch_includes_http_port_only() {
        let addr = StatusAddress::Ip("10.0.0.1".parse().unwrap());
        let patch = build_ingress_status_patch(&addr, ports_http_only());
        let ports = patch["status"]["loadBalancer"]["ingress"][0]["ports"]
            .as_array()
            .unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0]["port"], 80);
    }

    #[test]
    fn patch_omits_ports_key_when_none_configured() {
        let addr = StatusAddress::Ip("10.0.0.1".parse().unwrap());
        let patch = build_ingress_status_patch(&addr, ports_none());
        let entry = &patch["status"]["loadBalancer"]["ingress"][0];
        assert!(entry.get("ports").is_none() || entry["ports"].is_null());
    }

    #[test]
    fn patch_uses_ip_field_for_ip_address() {
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        let patch = build_ingress_status_patch(&addr, ports_none());
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
        let patch = build_ingress_status_patch(&addr, ports_none());
        assert_eq!(
            patch,
            serde_json::json!({
                "status": { "loadBalancer": { "ingress": [{ "hostname": "coxswain.example.com" }] } }
            })
        );
    }

    #[test]
    fn patch_is_valid_json_for_ip() {
        let addr = StatusAddress::Ip("10.0.0.1".parse().unwrap());
        let patch = build_ingress_status_patch(&addr, ports_none());
        let entry = &patch["status"]["loadBalancer"]["ingress"][0];
        assert_eq!(entry["ip"], "10.0.0.1");
        assert!(entry.get("hostname").is_none() || entry["hostname"].is_null());
    }

    #[test]
    fn patch_is_valid_json_for_hostname() {
        let addr = StatusAddress::Hostname("lb.example.com".into());
        let patch = build_ingress_status_patch(&addr, ports_none());
        let entry = &patch["status"]["loadBalancer"]["ingress"][0];
        assert_eq!(entry["hostname"], "lb.example.com");
        assert!(entry.get("ip").is_none() || entry["ip"].is_null());
    }
}
