//! Gateway API reconciler: routes `HTTPRoute`, `GRPCRoute`, and `Gateway` resources into the
//! routing table and TLS store.

mod backend_tls;
mod bindings;
mod filters;
mod grpc_reconcile;
mod grpc_status;
mod hostnames;
mod reconcile;
mod status;
mod timeouts;

pub use backend_tls::{BackendTlsIndex, build_backend_tls_index};
pub use bindings::ListenerBinding;
pub use grpc_reconcile::GrpcRouteResolution;
pub(crate) use hostnames::hostnames_intersect;
pub use reconcile::RouteResolution;

#[cfg(test)]
mod tests;

use crate::gw_types::v::gateways::Gateway;
use crate::gw_types::{GrpcRoute, HttpRoute};
use crate::tls::{BackendTlsPolicyHealthMap, HttpRouteHealthMap};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::ReferenceGrantKey;
use k8s_openapi::api::core::v1::Service;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;

/// Zero-sized handle namespacing the Gateway API reconciliation entry points for `HTTPRoute`.
///
/// The actual translation logic lives in submodules ([`backend_tls`],
/// [`reconcile`], [`status`]); this struct exposes the surfaces that consumers
/// (the [`crate::reconciler::SharedProxyReconciler`] rebuild loop, the controller crate's
/// status writer) call into.
#[non_exhaustive]
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

/// Zero-sized handle namespacing the `GRPCRoute` reconciliation entry points.
///
/// Parallel sibling to [`GatewayApiReconciler`] — not a trait, not a generic, just a second
/// concrete handle. Both feed the same [`coxswain_core::routing::GatewayRoutingTableBuilder`].
#[non_exhaustive]
pub struct GrpcRouteReconciler;

impl GrpcRouteReconciler {
    /// Install a `GRPCRoute`'s rules into the shared routing-table builder.
    ///
    /// Translates `spec.rules[].matches.method` (service/method) to HTTP path patterns
    /// (`/{service}/{method}`), resolves backends via `endpoints::resolve`, and installs
    /// routes into the same builder that [`GatewayApiReconciler::reconcile`] uses.
    ///
    /// # Errors
    ///
    /// This function is infallible; routing errors (missing backends, invalid refs) are
    /// reported as warn-log entries and produce 500/503 error routes.
    pub fn reconcile(
        route: &GrpcRoute,
        slices: &reflector::Store<k8s_openapi::api::discovery::v1::EndpointSlice>,
        services: &reflector::Store<Service>,
        owned_gateways: &HashSet<ObjectKey>,
        grants: &HashSet<ReferenceGrantKey>,
        resolution: GrpcRouteResolution<'_>,
        builder: &mut coxswain_core::routing::GatewayRoutingTableBuilder,
    ) {
        grpc_reconcile::reconcile(
            route,
            slices,
            services,
            owned_gateways,
            grants,
            resolution,
            builder,
        )
    }

    /// Compute per-(route, parent) `Accepted` + `ResolvedRefs` health for `GRPCRoute`s.
    ///
    /// Returns an [`HttpRouteHealthMap`] keyed by [`crate::keys::RouteParentKey`] — the map
    /// type is kind-neutral. Use a **separate** `SharedHttpRouteHealth` instance for grpc health
    /// to avoid `RouteParentKey` collisions with HTTPRoute health (same key shape, different kind).
    pub fn compute_route_health(
        routes: &[Arc<GrpcRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<ObjectKey>,
        backend_grants: &HashSet<ReferenceGrantKey>,
        service_store: &reflector::Store<Service>,
    ) -> HttpRouteHealthMap {
        grpc_status::compute_route_health(
            routes,
            gateways,
            owned_gateways,
            backend_grants,
            service_store,
        )
    }
}
