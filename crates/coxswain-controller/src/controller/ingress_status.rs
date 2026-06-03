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
