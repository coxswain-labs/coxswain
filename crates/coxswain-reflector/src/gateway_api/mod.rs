//! Gateway API reconciler: routes `HTTPRoute` and `Gateway` resources into the
//! routing table and TLS store.

mod backend_tls;
mod bindings;
mod filters;
mod hostnames;
mod reconcile;
mod status;
mod timeouts;

pub use backend_tls::{BackendTlsIndex, build_backend_tls_index};
pub use bindings::ListenerBinding;
pub(crate) use hostnames::hostnames_intersect;
pub use reconcile::RouteResolution;

#[cfg(test)]
mod tests;

use crate::gw_types::HttpRoute;
use crate::gw_types::v::gateways::Gateway;
use crate::tls::{BackendTlsPolicyHealthMap, HttpRouteHealthMap};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::ReferenceGrantKey;
use k8s_openapi::api::core::v1::Service;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;

/// Zero-sized handle namespacing the Gateway API reconciliation entry points.
///
/// The actual translation logic lives in submodules ([`backend_tls`],
/// [`reconcile`], [`status`]); this struct exposes the surfaces that consumers
/// (the [`crate::reconciler::Reconciler`] rebuild loop, the controller crate's
/// status writer) call into.
pub struct GatewayApiReconciler;

impl GatewayApiReconciler {
    /// Compute per-(route, parent) `Accepted` + `ResolvedRefs` health from
    /// the current snapshot of reflector stores.
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

    /// Compute per-policy health from the pre-built index and the policy reflector.
    pub fn compute_policy_health(
        index: &BackendTlsIndex,
        policies: &kube::runtime::reflector::Store<crate::gw_types::BackendTlsPolicy>,
        routes: &[Arc<HttpRoute>],
        owned_gateways: &HashSet<ObjectKey>,
    ) -> BackendTlsPolicyHealthMap {
        backend_tls::compute_policy_health(index, policies, routes, owned_gateways)
    }
}
