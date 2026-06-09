use super::super::conditions::{
    filter_owned_parent_refs, gateway_accepted, gateway_class_accepted, gateway_programmed,
    has_condition, http_route_programmed,
};
use super::super::ingress_status::{build_ingress_status_patch, ingress_lb_already_matches};
use super::super::{ControllerConfig, StatusAddress};
use crate::gw_types::HttpRoute;
use coxswain_core::ownership::ObjectKey;
use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassStatus};
use gateway_api::apis::standard::gateways::{Gateway, GatewayStatus};
use gateway_api::apis::standard::httproutes::{
    HttpRouteParentRefs, HttpRouteStatus, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::api::networking::v1::{
    IngressLoadBalancerIngress, IngressLoadBalancerStatus, IngressStatus,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use std::collections::HashSet;

fn stub_condition(
    type_: &str,
    status: &str,
) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
    k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: String::new(),
        message: String::new(),
        observed_generation: None,
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
    }
}

fn owned(pairs: &[(&str, &str)]) -> HashSet<ObjectKey> {
    pairs
        .iter()
        .map(|(ns, name)| ObjectKey::new(*ns, *name))
        .collect()
}

#[test]
fn has_condition_returns_true_when_present_and_true() {
    let conds = vec![stub_condition("Programmed", "True")];
    assert!(has_condition(Some(&conds), "Programmed"));
}

#[test]
fn has_condition_returns_false_when_absent() {
    let conds = vec![stub_condition("Accepted", "True")];
    assert!(!has_condition(Some(&conds), "Programmed"));
}

#[test]
fn has_condition_returns_false_when_not_true() {
    let conds = vec![stub_condition("Programmed", "False")];
    assert!(!has_condition(Some(&conds), "Programmed"));
}

#[test]
fn gateway_class_accepted_when_condition_present() {
    let gc = GatewayClass {
        status: Some(GatewayClassStatus {
            conditions: Some(vec![stub_condition("Accepted", "True")]),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(gateway_class_accepted(&gc));
}

#[test]
fn gateway_class_not_accepted_when_no_status() {
    let gc = GatewayClass {
        status: None,
        ..Default::default()
    };
    assert!(!gateway_class_accepted(&gc));
}

#[test]
fn http_route_programmed_for_matching_controller_and_owned_parent() {
    let set = owned(&[("default", "gw")]);
    let route = HttpRoute {
        metadata: kube::api::ObjectMeta {
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        status: Some(HttpRouteStatus {
            parents: vec![HttpRouteStatusParents {
                controller_name: "my-controller".to_string(),
                conditions: vec![
                    stub_condition("Programmed", "True"),
                    stub_condition("ResolvedRefs", "True"),
                ],
                parent_ref: HttpRouteStatusParentsParentRef {
                    name: "gw".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
            }],
        }),
        ..Default::default()
    };
    assert!(http_route_programmed(&route, "my-controller", &set));
}

#[test]
fn http_route_not_programmed_for_different_controller() {
    let set = owned(&[("default", "gw")]);
    let route = HttpRoute {
        metadata: kube::api::ObjectMeta {
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        status: Some(HttpRouteStatus {
            parents: vec![HttpRouteStatusParents {
                controller_name: "other-controller".to_string(),
                conditions: vec![stub_condition("Programmed", "True")],
                parent_ref: HttpRouteStatusParentsParentRef {
                    name: "gw".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
            }],
        }),
        ..Default::default()
    };
    assert!(!http_route_programmed(&route, "my-controller", &set));
}

#[test]
fn http_route_not_programmed_when_parent_not_owned() {
    let set = owned(&[("default", "gw")]);
    let route = HttpRoute {
        metadata: kube::api::ObjectMeta {
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        status: Some(HttpRouteStatus {
            parents: vec![HttpRouteStatusParents {
                controller_name: "my-controller".to_string(),
                conditions: vec![stub_condition("Programmed", "True")],
                parent_ref: HttpRouteStatusParentsParentRef {
                    name: "envoy-gateway".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
            }],
        }),
        ..Default::default()
    };
    assert!(!http_route_programmed(&route, "my-controller", &set));
}

#[test]
fn filter_owned_parent_refs_keeps_owned_only() {
    let set = owned(&[("default", "gw")]);
    let refs = vec![
        HttpRouteParentRefs {
            name: "gw".to_string(),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        HttpRouteParentRefs {
            name: "envoy-gw".to_string(),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
    ];
    let filtered = filter_owned_parent_refs(&refs, "default", &set);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "gw");
}

#[test]
fn filter_owned_parent_refs_returns_empty_when_none_owned() {
    let set = owned(&[("default", "gw")]);
    let refs = vec![HttpRouteParentRefs {
        name: "foreign-gw".to_string(),
        namespace: Some("default".to_string()),
        ..Default::default()
    }];
    let filtered = filter_owned_parent_refs(&refs, "default", &set);
    assert!(filtered.is_empty());
}

#[test]
fn filter_owned_parent_refs_applies_default_namespace() {
    let set = owned(&[("apps", "gw")]);
    let refs = vec![HttpRouteParentRefs {
        name: "gw".to_string(),
        namespace: None,
        ..Default::default()
    }];
    let filtered = filter_owned_parent_refs(&refs, "apps", &set);
    assert_eq!(filtered.len(), 1);
}

#[test]
fn gateway_accepted_true_when_condition_present() {
    let gw = Gateway {
        status: Some(GatewayStatus {
            conditions: Some(vec![stub_condition("Accepted", "True")]),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(gateway_accepted(&gw));
}

#[test]
fn gateway_accepted_false_when_no_status() {
    let gw = Gateway {
        status: None,
        ..Default::default()
    };
    assert!(!gateway_accepted(&gw));
}

#[test]
fn gateway_accepted_false_when_status_is_false() {
    let gw = Gateway {
        status: Some(GatewayStatus {
            conditions: Some(vec![stub_condition("Accepted", "False")]),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(!gateway_accepted(&gw));
}

#[test]
fn gateway_programmed_true_when_condition_present() {
    let gw = Gateway {
        status: Some(GatewayStatus {
            conditions: Some(vec![stub_condition("Programmed", "True")]),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(gateway_programmed(&gw));
}

#[test]
fn gateway_programmed_false_when_absent() {
    let gw = Gateway {
        status: Some(GatewayStatus {
            conditions: Some(vec![stub_condition("Accepted", "True")]),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(!gateway_programmed(&gw));
}

#[test]
fn gateway_programmed_false_when_no_status() {
    let gw = Gateway {
        status: None,
        ..Default::default()
    };
    assert!(!gateway_programmed(&gw));
}

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

#[test]
fn controller_config_parses_ip_address() {
    use crate::controller::LeaseSettings;
    use crate::ingress::IngressPorts;
    use std::time::Duration;
    let cfg = ControllerConfig::new(
        "ctrl".into(),
        "pod".into(),
        "ns".into(),
        LeaseSettings::new(Duration::from_secs(15), Duration::from_secs(5)),
        None,
        Some("203.0.113.1".into()),
        IngressPorts::new(Some(80), Some(443)),
    )
    .unwrap();
    assert!(matches!(cfg.status_address, Some(StatusAddress::Ip(_))));
}

#[test]
fn controller_config_parses_hostname() {
    use crate::controller::LeaseSettings;
    use crate::ingress::IngressPorts;
    use std::time::Duration;
    let cfg = ControllerConfig::new(
        "ctrl".into(),
        "pod".into(),
        "ns".into(),
        LeaseSettings::new(Duration::from_secs(15), Duration::from_secs(5)),
        None,
        Some("coxswain.example.com".into()),
        IngressPorts::new(Some(80), Some(443)),
    )
    .unwrap();
    assert!(matches!(
        cfg.status_address,
        Some(StatusAddress::Hostname(_))
    ));
}

#[test]
fn controller_config_rejects_empty_status_address() {
    use crate::controller::LeaseSettings;
    use crate::ingress::IngressPorts;
    use std::time::Duration;
    let result = ControllerConfig::new(
        "ctrl".into(),
        "pod".into(),
        "ns".into(),
        LeaseSettings::new(Duration::from_secs(15), Duration::from_secs(5)),
        None,
        Some("   ".into()),
        IngressPorts::new(Some(80), Some(443)),
    );
    assert!(result.is_err());
}

#[test]
fn controller_config_none_address_is_ok() {
    use crate::controller::LeaseSettings;
    use crate::ingress::IngressPorts;
    use std::time::Duration;
    let cfg = ControllerConfig::new(
        "ctrl".into(),
        "pod".into(),
        "ns".into(),
        LeaseSettings::new(Duration::from_secs(15), Duration::from_secs(5)),
        None,
        None,
        IngressPorts::new(Some(80), Some(443)),
    )
    .unwrap();
    assert!(cfg.status_address.is_none());
}
