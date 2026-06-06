use crate::endpoints;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::IngressServiceBackend;
use kube::runtime::reflector;

/// Resolves a backend port to its numeric value.
///
/// Tries `port.number` first; when absent, looks up `port.name` in the
/// Service store. Emits a warning and returns `None` when the name is set
/// but the Service is missing or has no matching port.
pub(super) fn resolve_backend_port(
    ns: &str,
    svc: &IngressServiceBackend,
    services: &reflector::Store<Service>,
) -> Option<i32> {
    let port = svc.port.as_ref()?;
    if let Some(n) = port.number {
        return Some(n);
    }
    let name = port.name.as_deref()?;
    let resolved = endpoints::port_for_name(ns, &svc.name, name, services);
    if resolved.is_none() {
        tracing::warn!(
            namespace = %ns,
            service = %svc.name,
            port_name = %name,
            "Ingress backend references unknown named port on Service — skipping"
        );
    }
    resolved
}
