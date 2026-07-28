//! Gateway API reconciler: routes `HTTPRoute`, `GRPCRoute`, and `Gateway` resources into the
//! routing table and TLS store.

pub(crate) mod backend_client_cert;
mod backend_policy;
mod backend_tls;
mod bindings;
mod client_traffic_policy;
pub(crate) mod compression;
pub(crate) mod external_auth;
mod filters;
pub(crate) mod frontend_tls;
mod grpc_reconcile;
mod grpc_status;
mod hostnames;
pub(crate) mod ip_access_control;
pub(crate) mod jwt_auth;
pub(crate) mod rate_limit;
mod reconcile;
mod reconcile_tls;
pub(crate) mod retry;
mod route_status;
mod status;
mod tcp_status;
mod timeouts;
mod tls_status;
mod udp_status;

pub use backend_policy::{BackendPolicyIndex, ResolvedBackendPolicy, build_backend_policy_index};
pub use backend_tls::{BackendTlsIndex, build_backend_tls_index};
pub use bindings::ListenerBinding;
pub(crate) use bindings::{
    compute_grpc_listener_bindings, compute_listener_bindings, parent_listener_source,
};
pub use client_traffic_policy::{
    ClientTrafficPolicyIndex, effective_proxy_config, resolve_client_traffic_policies,
};
pub use external_auth::{ExternalAuthGatewayIndex, resolve_gateway_policies};
pub use grpc_reconcile::GrpcRouteResolution;
pub(crate) use grpc_reconcile::route_fingerprint as grpc_route_fingerprint;
pub(crate) use hostnames::hostnames_intersect;
pub use reconcile::RouteResolution;
pub(crate) use reconcile::route_fingerprint as http_route_fingerprint;
pub(crate) use reconcile_tls::GatewayTlsTarget;
pub(crate) use route_status::{RefValidationStores, RouteLike};

/// API group for the coxswain-proprietary `ExtensionRef` CRDs (`RateLimit`,
/// `IpAccessControl`, `BasicAuth`, `RequestSizeLimit`, `Compression`,
/// `PathRewriteRegex`, `JwtAuth`). Single source of truth for the `ExtensionRef.group`
/// dispatch — a stray literal that misspells this silently disables a filter.
/// `pub(crate)` so [`crate::reference_grants`] (BasicAuth secret grants, same
/// group) shares this one definition rather than keeping its own copy.
pub(crate) const COXSWAIN_GROUP: &str = "gateway.coxswain-labs.dev";

/// Coxswain `ExtensionRef` kinds `HTTPRoute`'s filter translator resolves.
///
/// Single source of truth for two independent questions that must never
/// disagree: `filters::build_filters`'s "does enforcement know this kind"
/// check, and `status::has_unsupported_filter`'s "does `Accepted` accept this
/// kind" check. Before #690 these were two hand-maintained literal lists that
/// drifted — enforcement supported 5 kinds status silently reported as
/// `Accepted=False/UnsupportedValue` forever. A kind added here is
/// automatically recognized by both; a kind resolved by neither by construction.
pub(crate) const HTTP_ROUTE_EXTENSION_KINDS: &[&str] = &[
    "RateLimit",
    "IpAccessControl",
    "BasicAuth",
    "RequestSizeLimit",
    "Compression",
    "ExternalAuth",
    "RetryPolicy",
    "JwtAuth",
    "PathRewriteRegex",
];

/// [`HTTP_ROUTE_EXTENSION_KINDS`]'s `GRPCRoute` counterpart — the narrower set
/// `grpc_reconcile`'s filter translator resolves, shared with
/// `grpc_status::has_unsupported_filter` (#690). `PathRewriteRegex` is
/// meaningless for gRPC (the path *is* the `/{service}/{method}` RPC
/// address); `BasicAuth`/`Compression`/`RequestSizeLimit` are HTTP-only idioms
/// (see `grpc_reconcile`'s module doc for the per-kind rationale).
pub(crate) const GRPC_ROUTE_EXTENSION_KINDS: &[&str] =
    &["RateLimit", "IpAccessControl", "RetryPolicy", "JwtAuth"];

/// Whether `(group, kind)` is an `ExtensionRef` HTTPRoute's filter translator
/// resolves. The **only** place that decision is made — `filters::build_filters`'s
/// enforcement guard and `status::has_unsupported_filter`'s `Accepted` guard both
/// call this function rather than re-deriving the check, so a bug in the check
/// itself (not just a stale kind list) can't diverge between the two call sites
/// either (#690).
pub(crate) fn http_extension_kind_supported(group: &str, kind: &str) -> bool {
    group == COXSWAIN_GROUP && HTTP_ROUTE_EXTENSION_KINDS.contains(&kind)
}

/// [`http_extension_kind_supported`]'s `GRPCRoute` counterpart, backed by
/// [`GRPC_ROUTE_EXTENSION_KINDS`].
pub(crate) fn grpc_extension_kind_supported(group: &str, kind: &str) -> bool {
    group == COXSWAIN_GROUP && GRPC_ROUTE_EXTENSION_KINDS.contains(&kind)
}

#[cfg(test)]
mod tests;

use crate::MergedStore;
use crate::gw_types::v::gateways::Gateway;
use crate::gw_types::{GrpcRoute, HttpRoute, TcpRoute, TlsRoute, UdpRoute};
use crate::status::{BackendTlsPolicyStatusMap, RouteStatusMap};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::ReferenceGrantKey;
use k8s_openapi::api::core::v1::Service;
use std::collections::HashSet;
use std::sync::Arc;

/// Zero-sized handle namespacing the Gateway API reconciliation entry points for `HTTPRoute`.
///
/// The actual translation logic lives in submodules (`backend_tls`,
/// `reconcile`, `status`); this struct exposes the surfaces that consumers
/// (the [`crate::reconciler::SharedProxyReconciler`] rebuild loop, the controller crate's
/// status writer) call into.
pub struct GatewayApiReconciler;

impl GatewayApiReconciler {
    /// Compute per-(route, parent) `Accepted` + `ResolvedRefs` status from
    /// the current snapshot of reflector stores.
    pub(crate) fn compute_route_health(
        routes: &[Arc<HttpRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<ObjectKey>,
        effective: &std::collections::HashMap<
            ObjectKey,
            crate::reconciler::listener_merge::EffectiveGateway,
        >,
        backend_grants: &HashSet<ReferenceGrantKey>,
        stores: &route_status::RefValidationStores<'_>,
    ) -> RouteStatusMap {
        route_status::compute_route_health(
            routes,
            gateways,
            owned_gateways,
            effective,
            backend_grants,
            stores,
            "HTTPRoute",
        )
    }

    /// Compute per-policy status from the pre-built index and the policy reflector.
    pub fn compute_policy_health(
        index: &BackendTlsIndex,
        policies: &MergedStore<crate::gw_types::BackendTlsPolicy>,
        routes: &[Arc<HttpRoute>],
        owned_gateways: &HashSet<ObjectKey>,
    ) -> BackendTlsPolicyStatusMap {
        backend_tls::compute_policy_health(index, policies, routes, owned_gateways)
    }
}

/// Zero-sized handle namespacing the `GRPCRoute` reconciliation entry points.
///
/// Parallel sibling to [`GatewayApiReconciler`] — not a trait, not a generic, just a second
/// concrete handle. Both feed the same [`coxswain_core::routing::GatewayRoutingTableBuilder`].
pub struct GrpcRouteReconciler;

impl GrpcRouteReconciler {
    /// Install a `GRPCRoute`'s rules into the shared routing-table builder.
    ///
    /// Translates `spec.rules[].matches.method` (service/method) to HTTP path patterns
    /// (`/{service}/{method}`), resolves backends via the reflector's
    /// [`crate::endpoints::pool::EndpointCache`], and installs routes into the same
    /// builder that [`GatewayApiReconciler::reconcile`] uses.
    ///
    /// # Errors
    ///
    /// This function is infallible; routing errors (missing backends, invalid refs) are
    /// reported as warn-log entries and produce 500/503 error routes.
    pub fn reconcile(
        route: &GrpcRoute,
        endpoint_cache: &crate::endpoints::pool::EndpointCache,
        services: &MergedStore<Service>,
        owned_gateways: &HashSet<ObjectKey>,
        grants: &HashSet<ReferenceGrantKey>,
        resolution: GrpcRouteResolution<'_>,
        builder: &mut coxswain_core::routing::GatewayRoutingTableBuilder,
    ) {
        grpc_reconcile::reconcile(
            route,
            endpoint_cache,
            services,
            owned_gateways,
            grants,
            resolution,
            builder,
        )
    }

    /// Compute per-(route, parent) `Accepted` + `ResolvedRefs` status for `GRPCRoute`s.
    ///
    /// Returns a [`RouteStatusMap`] keyed by [`crate::keys::RouteParentKey`] — the map
    /// type is kind-neutral. Use a **separate** `RouteStatusHandle` instance for GRPCRoute status
    /// to avoid `RouteParentKey` collisions with HTTPRoute status (same key shape, different kind).
    pub(crate) fn compute_route_health(
        routes: &[Arc<GrpcRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<ObjectKey>,
        effective: &std::collections::HashMap<
            ObjectKey,
            crate::reconciler::listener_merge::EffectiveGateway,
        >,
        backend_grants: &HashSet<ReferenceGrantKey>,
        stores: &route_status::RefValidationStores<'_>,
    ) -> RouteStatusMap {
        route_status::compute_route_health(
            routes,
            gateways,
            owned_gateways,
            effective,
            backend_grants,
            stores,
            "GRPCRoute",
        )
    }
}

/// Zero-sized handle namespacing the `TLSRoute` reconciliation entry points.
///
/// Parallel sibling to [`GatewayApiReconciler`] and [`GrpcRouteReconciler`] — not a trait,
/// not a generic, just a concrete handle. Consumes only protocol-filtered listeners
/// (`protocol: TLS, tls.mode: Passthrough`).
pub struct TlsRouteReconciler;

impl TlsRouteReconciler {
    /// Compute per-(route, parent) `Accepted` + `ResolvedRefs` status for `TLSRoute`s.
    ///
    /// Only `protocol: TLS` listeners are considered — routes attached to HTTP/HTTPS
    /// listeners receive `Accepted=False, NotAllowedByListeners`. Use a **separate**
    /// [`crate::status::RouteStatusHandle`] instance to avoid key collisions with
    /// HTTP/GRPC route status (same key shape, different kind).
    pub(crate) fn compute_route_health(
        routes: &[Arc<TlsRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<ObjectKey>,
        effective: &std::collections::HashMap<
            ObjectKey,
            crate::reconciler::listener_merge::EffectiveGateway,
        >,
        backend_grants: &HashSet<ReferenceGrantKey>,
        stores: &route_status::RefValidationStores<'_>,
    ) -> RouteStatusMap {
        route_status::compute_route_health(
            routes,
            gateways,
            owned_gateways,
            effective,
            backend_grants,
            stores,
            "TLSRoute",
        )
    }
}

/// Zero-sized handle namespacing the `TCPRoute` reconciliation entry points.
///
/// Parallel sibling to [`TlsRouteReconciler`] — not a trait, not a generic, just a concrete
/// handle. Consumes only protocol-filtered listeners (`protocol: TCP`). Unlike `TLSRoute`
/// there is no passthrough/terminate mode split and no SNI/hostname dimension.
pub struct TcpRouteReconciler;

impl TcpRouteReconciler {
    /// Compute per-(route, parent) `Accepted` + `ResolvedRefs` status for `TCPRoute`s.
    ///
    /// Only `protocol: TCP` listeners are considered — routes attached to any other
    /// protocol listener receive `Accepted=False, NotAllowedByListeners`. Use a **separate**
    /// [`crate::status::RouteStatusHandle`] instance to avoid key collisions with other
    /// route kinds' status (same key shape, different kind).
    pub(crate) fn compute_route_health(
        routes: &[Arc<TcpRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<ObjectKey>,
        effective: &std::collections::HashMap<
            ObjectKey,
            crate::reconciler::listener_merge::EffectiveGateway,
        >,
        backend_grants: &HashSet<ReferenceGrantKey>,
        stores: &route_status::RefValidationStores<'_>,
    ) -> RouteStatusMap {
        route_status::compute_route_health(
            routes,
            gateways,
            owned_gateways,
            effective,
            backend_grants,
            stores,
            "TCPRoute",
        )
    }
}

/// Zero-sized handle namespacing the `UDPRoute` reconciliation entry points.
///
/// Parallel sibling to [`TcpRouteReconciler`] — not a trait, not a generic, just a concrete
/// handle. Consumes only protocol-filtered listeners (`protocol: UDP`). Like `TCPRoute`
/// there is no passthrough/terminate mode split and no SNI/hostname dimension.
pub struct UdpRouteReconciler;

impl UdpRouteReconciler {
    /// Compute per-(route, parent) `Accepted` + `ResolvedRefs` status for `UDPRoute`s.
    ///
    /// Only `protocol: UDP` listeners are considered — routes attached to any other
    /// protocol listener receive `Accepted=False, NotAllowedByListeners`. Use a **separate**
    /// [`crate::status::RouteStatusHandle`] instance to avoid key collisions with other
    /// route kinds' status (same key shape, different kind).
    pub(crate) fn compute_route_health(
        routes: &[Arc<UdpRoute>],
        gateways: &[Arc<Gateway>],
        owned_gateways: &HashSet<ObjectKey>,
        effective: &std::collections::HashMap<
            ObjectKey,
            crate::reconciler::listener_merge::EffectiveGateway,
        >,
        backend_grants: &HashSet<ReferenceGrantKey>,
        stores: &route_status::RefValidationStores<'_>,
    ) -> RouteStatusMap {
        route_status::compute_route_health(
            routes,
            gateways,
            owned_gateways,
            effective,
            backend_grants,
            stores,
            "UDPRoute",
        )
    }
}
