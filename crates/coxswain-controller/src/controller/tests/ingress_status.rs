use super::super::config::StatusAddress;
use super::super::ingress_status::{build_ingress_status_patch, ingress_lb_already_matches};
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
