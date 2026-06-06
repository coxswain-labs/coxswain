//! Gateway API reconciler: routes `HTTPRoute` and `Gateway` resources into the
//! routing table and TLS store.

mod bindings;
mod filters;
mod hostnames;
mod reconcile;
mod status;
mod timeouts;

pub use bindings::ListenerBinding;
pub(crate) use hostnames::hostnames_intersect;

#[cfg(test)]
mod tests;

use crate::gw_types::HttpRoute;
use crate::gw_types::v::gateways::Gateway;
use crate::tls::HttpRouteHealthMap;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::ReferenceGrantKey;
use k8s_openapi::api::core::v1::Service;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;

pub struct GatewayApiReconciler;

impl GatewayApiReconciler {
    pub fn compute_route_health(
        routes: &[Arc<HttpRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<ObjectKey>,
        backend_grants: &HashSet<ReferenceGrantKey>,
        service_store: &reflector::Store<Service>,
    ) -> HttpRouteHealthMap {
        status::compute_route_health(
            routes,
            gateways,
            owned_gateways,
            backend_grants,
            service_store,
        )
    }
}
