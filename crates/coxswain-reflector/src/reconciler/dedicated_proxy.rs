//! Dedicated-proxy reconciler: scoped to a single named Gateway.
//!
//! `serve proxy --gateway` runs an instance of this reconciler. Unlike
//! [`super::SharedProxyReconciler`], the data plane built here serves traffic
//! for exactly one Gateway — identified by `--gateway-name` and
//! `--gateway-namespace`. The routing-table-build step filters the cluster's
//! HTTPRoutes down to those that attach to the target Gateway via `parentRef`
//! (the existing [`coxswain_core::ownership::parent_ref_owned`] check); the
//! existing [`crate::gateway_api::GatewayApiReconciler::reconcile`] then
//! follows backendRefs and ReferenceGrants unchanged.
//!
//! ## Differences from `SharedProxyReconciler`
//!
//! - No `Ingress` or `IngressClass` reflectors: dedicated mode is Gateway-only.
//! - No cluster-summary output: the controller pod's `/cluster` endpoint
//!   aggregates Gateways from a separate cluster-wide watch.
//! - `owned_gateways` is narrowed at the rebuild step to the singleton
//!   `{(gateway_namespace, gateway_name)}` whenever that Gateway is owned by
//!   this controller. Routes whose `parentRef` points elsewhere are filtered
//!   out at the same routing-table-build step the shared pool uses.
//!
//! ## Deferred to Step 10 of the architecture plan (per-Gateway-proxy RBAC)
//!
//! The architecture plan ultimately wants per-Gateway proxies running with
//! reads narrowed to only the namespaces they touch — for blast-radius and
//! least-privilege reasons. The current acceptance criterion for Step 7 is
//! only "same RBAC profile as shared-proxy SA" (cluster-wide reads, zero
//! writes), so this reconciler watches resources cluster-wide today. The
//! per-namespace reflector machinery that pairs with Step 10's RoleBinding
//! reconciliation is a follow-up; the [`DedicatedConfig::allow_cluster_wide_route_read`]
//! and [`DedicatedConfig::allow_cluster_wide_namespace_read`] knobs are
//! plumbed through now (CLI / future CRD) so the RBAC opt-in path is
//! visible to operators before the runtime narrowing lands. When a Gateway
//! listener declares `allowedRoutes.namespaces.from: All` or `Selector` and
//! the corresponding opt-in is false, the reconciler logs a warning at
//! startup; full listener-level refusal (an `Accepted=false` condition) is
//! also deferred until Step 10, when the refusal has runtime teeth.

use super::shared_proxy::{
    Ownership, ReconcilerHealth, ReflectorEffects, ReflectorStores, build_gateway_routes,
    build_tls, compute_ownership, count_attached_routes, flatten_grants, spawn_reflector,
};
use crate::gateway_api::build_backend_tls_index;
use crate::gw_types::BackendTlsPolicy;
use crate::gw_types::HttpRoute;
use crate::gw_types::v::gatewayclasses::GatewayClass;
use crate::gw_types::v::gateways::Gateway;
use crate::gw_types::v::referencegrants::ReferenceGrant;
use crate::k8s_utils::scoped_api;
use crate::tls::{
    SharedBackendTlsPolicyHealth, SharedGatewayListenerHealth, SharedHttpRouteHealth,
};
use async_trait::async_trait;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_core::routing::SharedGatewayRoutingTable;
use coxswain_core::tls::SharedTlsStore;
use k8s_openapi::api::core::v1::{ConfigMap, Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::{
    Client,
    api::Api,
    runtime::{reflector, watcher},
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinSet;

/// Configuration for a [`DedicatedProxyReconciler`].
///
/// Constructed by the bin layer from `--gateway-name` / `--gateway-namespace`
/// plus the two RBAC opt-in flags. The opt-in flags are forwarded into the
/// reconciler so that the eventual Step 10 narrowing of per-NS reflectors can
/// read them from the same place the listener-refusal logic will.
#[non_exhaustive]
pub struct DedicatedConfig {
    /// `GatewayClass`/`HTTPRoute` `controllerName` claim — same as the shared
    /// reconciler, used to filter to coxswain-owned resources.
    pub controller_name: String,
    /// Name of the Gateway this proxy is dedicated to.
    pub gateway_name: String,
    /// Namespace of the Gateway this proxy is dedicated to.
    pub gateway_namespace: String,
    /// Permit cluster-wide HTTPRoute reads for listeners with
    /// `allowedRoutes.namespaces.from: All`. Defaults to `false`; when the
    /// target Gateway has such a listener and the flag is `false`, the
    /// reconciler logs a warning at startup (full listener-level refusal lands
    /// in Step 10 alongside the per-NS RBAC narrowing).
    pub allow_cluster_wide_route_read: bool,
    /// Permit cluster-wide Namespace reads for listeners with
    /// `allowedRoutes.namespaces.from: Selector`. Same shape as
    /// `allow_cluster_wide_route_read`: warned-on now, enforced in Step 10.
    pub allow_cluster_wide_namespace_read: bool,
}

impl DedicatedConfig {
    /// Build a [`DedicatedConfig`] with both opt-in flags defaulted to `false`.
    #[must_use]
    pub fn new(
        controller_name: impl Into<String>,
        gateway_name: impl Into<String>,
        gateway_namespace: impl Into<String>,
    ) -> Self {
        Self {
            controller_name: controller_name.into(),
            gateway_name: gateway_name.into(),
            gateway_namespace: gateway_namespace.into(),
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
        }
    }

    /// Returns the [`ObjectKey`] of the target Gateway.
    #[must_use]
    pub fn target(&self) -> ObjectKey {
        ObjectKey::new(self.gateway_namespace.clone(), self.gateway_name.clone())
    }
}

/// The `Shared<T>` outputs the [`DedicatedProxyReconciler`] writes into on
/// each rebuild.
///
/// Narrower than [`super::ReconcilerOutputs`]: dedicated mode does not build
/// the Ingress routing table (no `IngressProxy` is registered in this pod) and
/// does not emit a cluster summary (that's the controller's `/cluster`
/// endpoint's job).
#[non_exhaustive]
pub struct DedicatedOutputs {
    /// Gateway-API-flavored routing table snapshot, updated on every successful
    /// build.
    pub gateway_routes: SharedGatewayRoutingTable,
    /// TLS certificate store snapshot, updated whenever the target Gateway's
    /// referenced `kubernetes.io/tls` Secrets change.
    pub tls: SharedTlsStore,
    /// Per-listener Gateway health for the target Gateway. Consumed by
    /// `HotReloader` (port discovery on the dedicated pod) and exposed via
    /// `/status`.
    pub tls_health: SharedGatewayListenerHealth,
}

impl DedicatedOutputs {
    /// Construct a [`DedicatedOutputs`] from its shared handles.
    #[must_use]
    pub fn new(
        gateway_routes: SharedGatewayRoutingTable,
        tls: SharedTlsStore,
        tls_health: SharedGatewayListenerHealth,
    ) -> Self {
        Self {
            gateway_routes,
            tls,
            tls_health,
        }
    }
}

/// Pingora background service that maintains reflector-backed stores scoped to
/// one Gateway and rebuilds that Gateway's routing table whenever any of them
/// change.
///
/// Mirrors [`super::SharedProxyReconciler`]'s debounce + rebuild pipeline but
/// filters at the routing-table-build step to the target Gateway only and
/// skips the Ingress code paths entirely.
pub struct DedicatedProxyReconciler {
    config: DedicatedConfig,
    outputs: DedicatedOutputs,
    owned_gateways: OwnedGateways,
    route_health: SharedHttpRouteHealth,
    policy_health: SharedBackendTlsPolicyHealth,
    health: ReconcilerHealth,
}

impl DedicatedProxyReconciler {
    /// Construct a new dedicated reconciler (does not start the watch loop).
    #[must_use]
    pub fn new(
        config: DedicatedConfig,
        outputs: DedicatedOutputs,
        owned_gateways: OwnedGateways,
        health: ReconcilerHealth,
    ) -> Self {
        Self {
            config,
            outputs,
            owned_gateways,
            route_health: SharedHttpRouteHealth::new(),
            policy_health: SharedBackendTlsPolicyHealth::new(),
            health,
        }
    }

    /// Returns the shared route-health handle. Exposed for symmetry with
    /// [`super::SharedProxyReconciler::route_health`]; in dedicated mode the
    /// controller pod's status writer is the one consumer and runs out of
    /// process — this handle is only really useful for tests.
    #[must_use]
    pub fn route_health(&self) -> SharedHttpRouteHealth {
        self.route_health.clone()
    }

    /// Returns the shared policy-health handle. Same shape as
    /// [`Self::route_health`].
    #[must_use]
    pub fn policy_health(&self) -> SharedBackendTlsPolicyHealth {
        self.policy_health.clone()
    }
}

#[async_trait]
impl BackgroundService for DedicatedProxyReconciler {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to initialise Kubernetes client; dedicated reconciler will not run");
                return;
            }
        };
        let mut set = spawn_dedicated_tasks(client, self).await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                res = set.join_next() => match res {
                    Some(Ok(())) => tracing::warn!("DedicatedProxyReconciler task exited unexpectedly"),
                    Some(Err(e)) => tracing::error!(error = %e, "DedicatedProxyReconciler task panicked"),
                    None => break,
                },
            }
        }
    }
}

/// Spawn the cluster-wide reflectors and the debounced rebuild loop.
///
/// Watch shape today (intentionally cluster-wide for Step 7; per-namespace
/// narrowing is paired with Step 10's RBAC reconciliation): same set of
/// resources as the shared proxy except `Ingress` and `IngressClass`, which
/// are never relevant to a per-Gateway proxy.
async fn spawn_dedicated_tasks(client: Client, rec: &DedicatedProxyReconciler) -> JoinSet<()> {
    let (route_reader, route_writer) = reflector::store::<HttpRoute>();
    let (gateway_reader, gateway_writer) = reflector::store::<Gateway>();
    let (gateway_class_reader, gateway_class_writer) = reflector::store::<GatewayClass>();
    let (slice_reader, slice_writer) = reflector::store::<EndpointSlice>();
    let (grant_reader, grant_writer) = reflector::store::<ReferenceGrant>();
    let (secret_reader, secret_writer) = reflector::store::<Secret>();
    let (service_reader, service_writer) = reflector::store::<Service>();
    let (policy_reader, policy_writer) = reflector::store::<BackendTlsPolicy>();
    let (configmap_reader, configmap_writer) = reflector::store::<ConfigMap>();
    // The Ingress / IngressClass reflectors are deliberately not constructed.
    // Their stores still need to exist because `build_gateway_routes` reads
    // through a `ReflectorStores` borrow that names them — we hand it empty
    // stores that will stay empty for the lifetime of this reconciler.
    let (ingress_reader, _ingress_writer) =
        reflector::store::<k8s_openapi::api::networking::v1::Ingress>();
    let (ingress_class_reader, _ingress_class_writer) =
        reflector::store::<k8s_openapi::api::networking::v1::IngressClass>();

    let notify = Arc::new(Notify::new());
    let mut set = JoinSet::new();
    let controller_health = &rec.health.controller;

    // Cluster-wide watches: identical RBAC profile to the shared-proxy SA.
    // See the module header for the rationale.
    spawn_reflector(
        &mut set,
        route_writer,
        Api::<HttpRoute>::all(client.clone()),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "httproute"),
        "HttpRoute",
    );
    spawn_reflector(
        &mut set,
        gateway_writer,
        Api::<Gateway>::all(client.clone()),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "gateway"),
        "Gateway",
    );
    spawn_reflector(
        &mut set,
        gateway_class_writer,
        Api::<GatewayClass>::all(client.clone()),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "gateway_class"),
        "GatewayClass",
    );
    spawn_reflector(
        &mut set,
        slice_writer,
        scoped_api::<EndpointSlice>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "endpoint_slice"),
        "EndpointSlice",
    );
    spawn_reflector(
        &mut set,
        grant_writer,
        scoped_api::<ReferenceGrant>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "reference_grant"),
        "ReferenceGrant",
    );
    spawn_reflector(
        &mut set,
        secret_writer,
        scoped_api::<Secret>(client.clone(), None),
        watcher::Config::default().fields("type=kubernetes.io/tls"),
        ReflectorEffects::new(&notify, controller_health, "secret"),
        "Secret",
    );
    spawn_reflector(
        &mut set,
        service_writer,
        scoped_api::<Service>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "service"),
        "Service",
    );
    spawn_reflector(
        &mut set,
        policy_writer,
        scoped_api::<BackendTlsPolicy>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "backend_tls_policy"),
        "BackendTlsPolicy",
    );
    spawn_reflector(
        &mut set,
        configmap_writer,
        scoped_api::<ConfigMap>(client, None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "config_map"),
        "ConfigMap",
    );
    // The dedicated reconciler skips Ingress / IngressClass — but those
    // subsystem checks were registered for the shared-proxy case. Flip them
    // ready immediately so `/readyz` doesn't stay 503 forever.
    controller_health.ready("ingress");
    controller_health.ready("ingress_class");

    let controller_name = rec.config.controller_name.clone();
    let target = rec.config.target();
    let allow_cluster_wide_route_read = rec.config.allow_cluster_wide_route_read;
    let allow_cluster_wide_namespace_read = rec.config.allow_cluster_wide_namespace_read;
    let gateway_routes = rec.outputs.gateway_routes.clone();
    let tls = rec.outputs.tls.clone();
    let tls_health = rec.outputs.tls_health.clone();
    let route_health = rec.route_health.clone();
    let policy_health = rec.policy_health.clone();
    let owned_gateways_handle = rec.owned_gateways.clone();
    let controller_health_for_loop = controller_health.clone();
    let proxy_health_for_loop = rec.health.proxy.clone();

    set.spawn(async move {
        let mut routing_table_published = false;
        let mut listener_warning_logged = false;
        loop {
            notify.notified().await;
            loop {
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(500)) => break,
                }
            }
            let stores = ReflectorStores {
                routes: &route_reader,
                ingresses: &ingress_reader,
                ingress_classes: &ingress_class_reader,
                gateways: &gateway_reader,
                gateway_classes: &gateway_class_reader,
                slices: &slice_reader,
                services: &service_reader,
                grants: &grant_reader,
                secrets: &secret_reader,
                policies: &policy_reader,
                configmaps: &configmap_reader,
            };
            let published = rebuild_dedicated(
                &stores,
                &controller_name,
                &target,
                allow_cluster_wide_route_read,
                allow_cluster_wide_namespace_read,
                &mut listener_warning_logged,
                &owned_gateways_handle,
                &gateway_routes,
                &tls,
                &tls_health,
                &route_health,
                &policy_health,
            );
            if published && !routing_table_published {
                controller_health_for_loop.ready("routing_table_built");
                proxy_health_for_loop.ready("routing_table_loaded");
                routing_table_published = true;
            }
        }
    });

    set
}

/// One rebuild iteration for the dedicated reconciler.
///
/// Returns `true` if the Gateway routing table was published (i.e. the build
/// succeeded). The shared-proxy variant also waits for Ingress to publish;
/// dedicated mode only has one table.
#[allow(clippy::too_many_arguments)]
fn rebuild_dedicated(
    stores: &ReflectorStores<'_>,
    controller_name: &str,
    target: &ObjectKey,
    allow_cluster_wide_route_read: bool,
    allow_cluster_wide_namespace_read: bool,
    listener_warning_logged: &mut bool,
    owned_gateways_handle: &OwnedGateways,
    gateway_routes: &SharedGatewayRoutingTable,
    tls: &SharedTlsStore,
    tls_health: &SharedGatewayListenerHealth,
    route_health: &SharedHttpRouteHealth,
    policy_health: &SharedBackendTlsPolicyHealth,
) -> bool {
    let routes = stores.routes.state();
    let (
        owned_ingress_classes,
        owned_default_ingress_class,
        owned_gateway_classes,
        cluster_owned_gateways,
    ) = compute_ownership(
        stores.ingress_classes,
        stores.gateway_classes,
        stores.gateways,
        controller_name,
        // Pass a throwaway handle: we publish the narrowed singleton below
        // ourselves so `controller_name` filtering doesn't leak the rest of
        // the cluster's Gateways into the dedicated pod's owned set.
        &OwnedGateways::new(),
    );

    // Narrow to the singleton {target} — only if our controller actually owns
    // it. If the target Gateway isn't owned by this controller_name, the set
    // is empty and no routes will be emitted.
    let owned_gateways: HashSet<ObjectKey> = if cluster_owned_gateways.contains(target) {
        std::iter::once(target.clone()).collect()
    } else {
        tracing::warn!(
            gateway = %format!("{}/{}", target.ns, target.name),
            controller_name,
            "Target Gateway is not owned by this controller_name (or does not exist); routing table will be empty"
        );
        HashSet::new()
    };
    owned_gateways_handle.store(Arc::new(owned_gateways.clone()));

    if !*listener_warning_logged {
        warn_on_unsupported_listener_modes(
            stores,
            target,
            allow_cluster_wide_route_read,
            allow_cluster_wide_namespace_read,
        );
        *listener_warning_logged = true;
    }

    let (backend_grants, cert_grants) = flatten_grants(&stores.grants.state());

    let (policy_index, mut policy_health_map) =
        build_backend_tls_index(stores.policies, stores.configmaps, stores.services);

    let ownership = Ownership {
        ingress_classes: &owned_ingress_classes,
        default_ingress_class: owned_default_ingress_class.as_deref(),
        gateways: &owned_gateways,
        gateway_classes: &owned_gateway_classes,
        backend_grants: &backend_grants,
        cert_grants: &cert_grants,
        policy_index: &policy_index,
    };

    let routes_published = build_gateway_routes(stores, &routes, &ownership, gateway_routes);

    let ingresses: Vec<Arc<k8s_openapi::api::networking::v1::Ingress>> = Vec::new();
    let mut gateway_tls_health = build_tls(stores, &ingresses, &ownership, tls);
    count_attached_routes(&routes, &owned_gateways, &mut gateway_tls_health);
    tls_health.store_and_notify(gateway_tls_health);

    let gateways = stores.gateways.state();
    let route_health_map = crate::gateway_api::GatewayApiReconciler::compute_route_health(
        &routes,
        &gateways,
        &owned_gateways,
        &backend_grants,
        stores.services,
    );
    route_health.store_and_notify(route_health_map);

    let ancestor_health = crate::gateway_api::GatewayApiReconciler::compute_policy_health(
        &policy_index,
        stores.policies,
        &routes,
        &owned_gateways,
    );
    for (key, ah) in ancestor_health {
        let entry = policy_health_map.entry(key).or_default();
        entry.ancestors = ah.ancestors;
    }
    policy_health.store_and_notify(policy_health_map);

    routes_published
}

/// Log a warning the first time we observe the target Gateway with a listener
/// declaring `allowedRoutes.namespaces.from: All` or `Selector` while the
/// corresponding opt-in flag is false.
///
/// Full listener-level refusal (an `Accepted=false` listener condition) lands
/// in Step 10 alongside the per-namespace RBAC narrowing — at that point the
/// refusal has runtime teeth. Today the watches are cluster-wide regardless,
/// so an unconsented mode would not actually leak more than the shared-proxy
/// SA already does; the warning is a forward-compatibility breadcrumb.
fn warn_on_unsupported_listener_modes(
    stores: &ReflectorStores<'_>,
    target: &ObjectKey,
    allow_cluster_wide_route_read: bool,
    allow_cluster_wide_namespace_read: bool,
) {
    use crate::gw_types::v::gateways::GatewayListenersAllowedRoutesNamespacesFrom as From;

    for gw in stores.gateways.state() {
        let ns = gw.metadata.namespace.clone().unwrap_or_default();
        let name = gw.metadata.name.clone().unwrap_or_default();
        if !(ns == target.ns && name == target.name) {
            continue;
        }
        for listener in &gw.spec.listeners {
            let Some(allowed) = listener.allowed_routes.as_ref() else {
                continue;
            };
            let Some(ns_spec) = allowed.namespaces.as_ref() else {
                continue;
            };
            match ns_spec.from {
                Some(From::All) if !allow_cluster_wide_route_read => {
                    tracing::warn!(
                        gateway = %format!("{ns}/{name}"),
                        listener = %listener.name,
                        "Listener uses allowedRoutes.namespaces.from=All but \
                         --allow-cluster-wide-route-read is false; cluster-wide \
                         HTTPRoute reads are still in effect today (Step 7), \
                         but Step 10 will refuse this listener via an \
                         Accepted=false condition unless the opt-in is set"
                    );
                }
                Some(From::Selector) if !allow_cluster_wide_namespace_read => {
                    tracing::warn!(
                        gateway = %format!("{ns}/{name}"),
                        listener = %listener.name,
                        "Listener uses allowedRoutes.namespaces.from=Selector but \
                         --allow-cluster-wide-namespace-read is false; cluster-wide \
                         Namespace reads are still in effect today (Step 7), \
                         but Step 10 will refuse this listener via an \
                         Accepted=false condition unless the opt-in is set"
                    );
                }
                _ => {}
            }
        }
    }
}
