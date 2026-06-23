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
//! ## Watch scope (#209, Step 10)
//!
//! Two modes:
//!
//! - **Per-namespace (production)** — when
//!   [`DedicatedConfig::watch_namespaces`] is non-empty, one reflector is
//!   spawned per (resource, namespace) pair for the namespaced resources the
//!   proxy needs reads on. The list is rendered by the controller from the
//!   Gateway's desired-namespace set and matches the per-namespace
//!   `RoleBinding`s the controller has provisioned (#209). On this path the
//!   `GatewayClass` watch is **dropped entirely** — the controller is the
//!   authority on "this Gateway is dedicated and mine", and the proxy reads
//!   its target Gateway's class name directly from the Gateway object
//!   (avoiding the cluster-scoped RBAC the watch would otherwise require).
//! - **Cluster-wide (legacy / test)** — when `watch_namespaces` is empty,
//!   reflectors run cluster-wide as in #208. Kept for tests and for the
//!   transitional half-functional state from #208; production rollouts
//!   always pass a list.
//!
//! The `allow_cluster_wide_route_read` flag switches the `HTTPRoute` reflector
//! from per-namespace to cluster-wide on the per-namespace path so that
//! listeners with `allowedRoutes.namespaces.from: All` or `from: Selector`
//! see routes from all namespaces (#229).

use super::shared_proxy::{
    Ownership, ReconcilerHealth, ReflectorEffects, ReflectorStores, build_gateway_routes,
    build_tls, compute_ownership, count_attached_routes, spawn_reflector,
};
use crate::gateway_api::build_backend_tls_index;
use crate::gw_types::BackendTlsPolicy;
use crate::gw_types::HttpRoute;
use crate::gw_types::v::gatewayclasses::GatewayClass;
use crate::gw_types::v::gateways::Gateway;
use crate::gw_types::v::referencegrants::ReferenceGrant;
use crate::k8s_utils::scoped_api;
use crate::reference_grants::flatten_grants;
use crate::tls::{
    SharedBackendTlsPolicyHealth, SharedGatewayListenerHealth, SharedHttpRouteHealth,
};
use async_trait::async_trait;
use coxswain_core::crd::RateLimit;
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
/// plus the two cluster-wide read flags. The flags are derived by the
/// controller from the Gateway's `allowedRoutes.namespaces.from` field and
/// rendered into the Deployment's container args (#229).
#[non_exhaustive]
pub struct DedicatedConfig {
    /// `GatewayClass`/`HTTPRoute` `controllerName` claim — same as the shared
    /// reconciler, used to filter to coxswain-owned resources.
    pub controller_name: String,
    /// Name of the Gateway this proxy is dedicated to.
    pub gateway_name: String,
    /// Namespace of the Gateway this proxy is dedicated to.
    pub gateway_namespace: String,
    /// Spawn a cluster-wide `HTTPRoute` reflector so routes from all
    /// namespaces are visible. Set when any listener has
    /// `allowedRoutes.namespaces.from: All` or `from: Selector`.
    pub allow_cluster_wide_route_read: bool,
    /// Permit cluster-wide `Namespace` reads. Set when any listener has
    /// `allowedRoutes.namespaces.from: Selector` (needed for future
    /// namespace-selector evaluation).
    pub allow_cluster_wide_namespace_read: bool,
    /// Namespaces the proxy is permitted to watch backend resources in.
    ///
    /// Populated by the bin layer from `--proxy-watch-namespaces` (rendered
    /// by the controller from the Gateway's desired-namespace set). The list
    /// always includes the target Gateway's own namespace and every namespace
    /// the Gateway's HTTPRoutes' backendRefs resolve into (via
    /// `ReferenceGrant`). Empty list means the dedicated reconciler falls back
    /// to cluster-wide watches — only used by the legacy half-functional
    /// state from #208; production rollouts always pass a list.
    pub watch_namespaces: Vec<String>,
}

impl DedicatedConfig {
    /// Build a [`DedicatedConfig`] with both opt-in flags defaulted to `false`
    /// and an empty `watch_namespaces` (falls back to cluster-wide watches —
    /// only suitable for tests and the legacy half-functional state).
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
            watch_namespaces: Vec::new(),
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
#[non_exhaustive]
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

/// Dispatch to the per-namespace or cluster-wide reflector setup depending on
/// whether the controller passed a `--proxy-watch-namespaces` list (#209).
async fn spawn_dedicated_tasks(client: Client, rec: &DedicatedProxyReconciler) -> JoinSet<()> {
    if rec.config.watch_namespaces.is_empty() {
        tracing::warn!(
            "DedicatedProxyReconciler running with no --proxy-watch-namespaces — \
             falling back to cluster-wide watches (legacy / test mode). Production \
             rollouts must pass a list so RBAC narrowing is enforced."
        );
        spawn_cluster_wide_tasks(client, rec).await
    } else {
        spawn_per_namespace_tasks(client, rec).await
    }
}

/// Spawn the cluster-wide reflectors and the debounced rebuild loop.
///
/// Watch shape: same set of resources as the shared proxy except `Ingress`
/// and `IngressClass`, which are never relevant to a per-Gateway proxy. This
/// path requires cluster-wide RBAC; it survives only as a fallback for tests
/// and the transitional half-functional state from #208.
async fn spawn_cluster_wide_tasks(client: Client, rec: &DedicatedProxyReconciler) -> JoinSet<()> {
    let (route_reader, route_writer) = reflector::store::<HttpRoute>();
    let (gateway_reader, gateway_writer) = reflector::store::<Gateway>();
    let (gateway_class_reader, gateway_class_writer) = reflector::store::<GatewayClass>();
    let (slice_reader, slice_writer) = reflector::store::<EndpointSlice>();
    let (grant_reader, grant_writer) = reflector::store::<ReferenceGrant>();
    let (secret_reader, secret_writer) = reflector::store::<Secret>();
    let (service_reader, service_writer) = reflector::store::<Service>();
    let (policy_reader, policy_writer) = reflector::store::<BackendTlsPolicy>();
    let (configmap_reader, configmap_writer) = reflector::store::<ConfigMap>();
    let (rate_limit_reader, rate_limit_writer) = reflector::store::<RateLimit>();
    // The Ingress / IngressClass reflectors are deliberately not constructed.
    // Their stores still need to exist because `build_gateway_routes` reads
    // through a `ReflectorStores` borrow that names them — we hand it empty
    // stores that will stay empty for the lifetime of this reconciler.
    let (ingress_reader, _ingress_writer) =
        reflector::store::<k8s_openapi::api::networking::v1::Ingress>();
    let (ingress_class_reader, _ingress_class_writer) =
        reflector::store::<k8s_openapi::api::networking::v1::IngressClass>();
    let (ingress_class_params_reader, _ingress_class_params_writer) =
        reflector::store::<coxswain_core::crd::CoxswainIngressClassParameters>();

    let notify = Arc::new(Notify::new());
    let mut set = JoinSet::new();
    let controller_health = &rec.health.controller;
    let metrics = crate::ReflectorMetrics::new(crate::MetricsPrefix::Proxy);

    // Cluster-wide watches: identical RBAC profile to the shared-proxy SA.
    // See the module header for the rationale.
    spawn_reflector(
        &mut set,
        route_writer,
        Api::<HttpRoute>::all(client.clone()),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "httproute", metrics),
        "HttpRoute",
    );
    spawn_reflector(
        &mut set,
        gateway_writer,
        Api::<Gateway>::all(client.clone()),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "gateway", metrics),
        "Gateway",
    );
    spawn_reflector(
        &mut set,
        gateway_class_writer,
        Api::<GatewayClass>::all(client.clone()),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "gateway_class", metrics),
        "GatewayClass",
    );
    spawn_reflector(
        &mut set,
        slice_writer,
        scoped_api::<EndpointSlice>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "endpoint_slice", metrics),
        "EndpointSlice",
    );
    spawn_reflector(
        &mut set,
        grant_writer,
        scoped_api::<ReferenceGrant>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "reference_grant", metrics),
        "ReferenceGrant",
    );
    spawn_reflector(
        &mut set,
        secret_writer,
        scoped_api::<Secret>(client.clone(), None),
        watcher::Config::default().fields("type=kubernetes.io/tls"),
        ReflectorEffects::new(&notify, controller_health, "secret", metrics),
        "Secret",
    );
    spawn_reflector(
        &mut set,
        service_writer,
        scoped_api::<Service>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "service", metrics),
        "Service",
    );
    spawn_reflector(
        &mut set,
        policy_writer,
        scoped_api::<BackendTlsPolicy>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "backend_tls_policy", metrics),
        "BackendTlsPolicy",
    );
    spawn_reflector(
        &mut set,
        configmap_writer,
        scoped_api::<ConfigMap>(client.clone(), None),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "config_map", metrics),
        "ConfigMap",
    );
    spawn_reflector(
        &mut set,
        rate_limit_writer,
        Api::<RateLimit>::all(client),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, controller_health, "rate_limit", metrics),
        "RateLimit",
    );
    // The dedicated reconciler skips Ingress / IngressClass / the Ingress-class
    // params CR — but those subsystem checks were registered for the
    // shared-proxy case. Flip them ready immediately so `/readyz` doesn't stay
    // 503 forever.
    controller_health.ready("ingress");
    controller_health.ready("ingress_class");
    controller_health.ready("ingress_class_parameters");

    let controller_name = rec.config.controller_name.clone();
    let target = rec.config.target();
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
        loop {
            notify.notified().await;
            loop {
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(500)) => break,
                }
            }
            // Dedicated proxy is Gateway-API-only; Ingress auth is not processed
            // here.  An empty store satisfies the ReflectorStores contract for
            // both htpasswd (auth_secrets) and client-cert CA (auth_tls_secrets).
            let empty_auth_secrets =
                kube::runtime::reflector::store::Writer::<Secret>::default().as_reader();
            let stores = ReflectorStores {
                routes: &route_reader,
                ingresses: &ingress_reader,
                ingress_classes: &ingress_class_reader,
                ingress_class_parameters: &ingress_class_params_reader,
                gateways: &gateway_reader,
                gateway_classes: &gateway_class_reader,
                slices: &slice_reader,
                services: &service_reader,
                grants: &grant_reader,
                secrets: &secret_reader,
                auth_secrets: &empty_auth_secrets,
                auth_tls_secrets: &empty_auth_secrets,
                policies: &policy_reader,
                configmaps: &configmap_reader,
                rate_limits: &rate_limit_reader,
            };
            let rebuild_start = std::time::Instant::now();
            let target_spec = DedicatedRebuildTarget {
                controller_name: &controller_name,
                target: &target,
            };
            let outputs = DedicatedRebuildOutputs {
                owned_gateways_handle: &owned_gateways_handle,
                gateway_routes: &gateway_routes,
                tls: &tls,
                tls_health: &tls_health,
                route_health: &route_health,
                policy_health: &policy_health,
            };
            let published = rebuild_dedicated(&stores, &target_spec, &outputs);
            metrics.observe_rebuild(
                rebuild_start.elapsed(),
                if published { "ok" } else { "error" },
            );
            let snapshot = gateway_routes.load();
            metrics.set_routing_table(snapshot.host_count(), 0, snapshot.host_count());
            let tls_snapshot = tls.load();
            let (exact, wildcard, default) = tls_snapshot.cert_counts();
            let expiries = tls_snapshot.expiries();
            metrics.set_tls(exact, wildcard, default, &expiries);
            if published && !routing_table_published {
                controller_health_for_loop.ready("routing_table_built");
                proxy_health_for_loop.ready("routing_table_loaded");
                routing_table_published = true;
            }
        }
    });

    set
}

/// Identity of the target Gateway for a dedicated-mode rebuild.
pub(super) struct DedicatedRebuildTarget<'a> {
    /// `GatewayClass.spec.controllerName` claim — filters owned resources.
    pub(super) controller_name: &'a str,
    /// Single Gateway this dedicated proxy serves.
    pub(super) target: &'a ObjectKey,
}

/// Shared output handles a dedicated-mode rebuild publishes into. Grouped to
/// keep the rebuild function under the 7-arg threshold per workspace policy.
pub(super) struct DedicatedRebuildOutputs<'a> {
    /// Owned-gateways set, narrowed to the singleton target by the rebuild.
    pub(super) owned_gateways_handle: &'a OwnedGateways,
    /// Gateway-flavored routing table the rebuild publishes.
    pub(super) gateway_routes: &'a SharedGatewayRoutingTable,
    /// TLS cert store the rebuild publishes.
    pub(super) tls: &'a SharedTlsStore,
    /// Per-listener TLS-resolution health.
    pub(super) tls_health: &'a SharedGatewayListenerHealth,
    /// Per-route health.
    pub(super) route_health: &'a SharedHttpRouteHealth,
    /// Per-policy health.
    pub(super) policy_health: &'a SharedBackendTlsPolicyHealth,
}

/// One rebuild iteration for the dedicated reconciler.
///
/// Returns `true` if the Gateway routing table was published (i.e. the build
/// succeeded). The shared-proxy variant also waits for Ingress to publish;
/// dedicated mode only has one table.
fn rebuild_dedicated(
    stores: &ReflectorStores<'_>,
    target_spec: &DedicatedRebuildTarget<'_>,
    outputs: &DedicatedRebuildOutputs<'_>,
) -> bool {
    let DedicatedRebuildTarget {
        controller_name,
        target,
    } = *target_spec;
    let DedicatedRebuildOutputs {
        owned_gateways_handle,
        gateway_routes,
        tls,
        tls_health,
        route_health,
        policy_health,
    } = *outputs;
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

    // `skip_cut_over = false`: the dedicated proxy serves the cut-over Gateway.
    let routes_published = build_gateway_routes(stores, &routes, &ownership, gateway_routes, false);

    let ingresses: Vec<Arc<k8s_openapi::api::networking::v1::Ingress>> = Vec::new();
    // `skip_cut_over = false`: the dedicated proxy's whole job is serving the
    // cut-over Gateway. The shared-pool filter would drop our listener.
    let mut gateway_tls_health = build_tls(stores, &ingresses, &ownership, tls, false);
    count_attached_routes(&routes, &owned_gateways, &mut gateway_tls_health);
    // Merge only THIS Gateway's listener health into the shared cell: the
    // shared-pool reconciler and the other dedicated reconcilers publish into
    // the same cell, so a full replace would transiently drop their entries and
    // make their proxies unbind their listeners (#423 dedicated bind→remove).
    tls_health.update_scoped(gateway_tls_health, |k| k == target);

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

/// Per-namespace reflector spawn + debounced rebuild loop (#209, #229).
///
/// One reflector per (resource, namespace) for the namespaced resources the
/// dedicated proxy reads. The list comes from
/// [`DedicatedConfig::watch_namespaces`], which the controller renders from
/// the Gateway's desired-namespace set so the proxy's watches and the
/// per-namespace `RoleBinding`s the controller has provisioned stay in sync.
///
/// When `allow_cluster_wide_route_read` is true (any listener has
/// `allowedRoutes.namespaces.from: All` or `from: Selector`), a single
/// cluster-wide `HTTPRoute` reflector replaces the per-namespace one so
/// routes from all namespaces are visible.
///
/// The `GatewayClass` watch is deliberately omitted on this path: the
/// controller is the source of truth for "this Gateway is dedicated and
/// mine", and the rebuild reads the target Gateway's class name directly
/// from the Gateway object instead.
async fn spawn_per_namespace_tasks(client: Client, rec: &DedicatedProxyReconciler) -> JoinSet<()> {
    let namespaces = rec.config.watch_namespaces.clone();
    let gateway_namespace = rec.config.gateway_namespace.clone();
    let allow_cluster_wide_route_read = rec.config.allow_cluster_wide_route_read;

    // Per-resource Vec<Store<T>>; index parallel to the namespace iteration
    // order. Aggregated on each rebuild tick by `aggregate_into_store`.
    let mut route_readers: Vec<reflector::Store<HttpRoute>> = Vec::new();
    let mut gateway_readers: Vec<reflector::Store<Gateway>> = Vec::new();
    let mut slice_readers: Vec<reflector::Store<EndpointSlice>> = Vec::new();
    let mut grant_readers: Vec<reflector::Store<ReferenceGrant>> = Vec::new();
    let mut secret_readers: Vec<reflector::Store<Secret>> = Vec::new();
    let mut service_readers: Vec<reflector::Store<Service>> = Vec::new();
    let mut policy_readers: Vec<reflector::Store<BackendTlsPolicy>> = Vec::new();
    let mut configmap_readers: Vec<reflector::Store<ConfigMap>> = Vec::new();
    let mut rate_limit_readers: Vec<reflector::Store<RateLimit>> = Vec::new();

    let notify = Arc::new(Notify::new());
    let mut set = JoinSet::new();
    let controller_health = &rec.health.controller;
    let metrics = crate::ReflectorMetrics::new(crate::MetricsPrefix::Proxy);

    for ns in &namespaces {
        // Gateway: only watched in the target Gateway's own namespace. Other
        // namespaces in `watch_namespaces` are backend namespaces where we
        // don't expect any Gateway we care about. Skipping them saves a
        // small amount of RBAC + memory and matches operator intent.
        if ns == &gateway_namespace {
            let (gateway_reader, gateway_writer) = reflector::store::<Gateway>();
            spawn_reflector(
                &mut set,
                gateway_writer,
                scoped_api::<Gateway>(client.clone(), Some(ns)),
                watcher::Config::default(),
                ReflectorEffects::new(&notify, controller_health, "gateway", metrics),
                "Gateway",
            );
            gateway_readers.push(gateway_reader);

            // HTTPRoute: cluster-wide when any listener has from: All or
            // from: Selector; otherwise per-namespace (Gateway's own namespace
            // covers all from: Same routes, which is the default).
            if !allow_cluster_wide_route_read {
                let (route_reader, route_writer) = reflector::store::<HttpRoute>();
                spawn_reflector(
                    &mut set,
                    route_writer,
                    scoped_api::<HttpRoute>(client.clone(), Some(ns)),
                    watcher::Config::default(),
                    ReflectorEffects::new(&notify, controller_health, "httproute", metrics),
                    "HttpRoute",
                );
                route_readers.push(route_reader);
            }
        }

        // Cluster-wide HTTPRoute reflector: spawned once when any listener
        // declares from: All or from: Selector so routes from all namespaces
        // are visible to the routing table builder.
        if allow_cluster_wide_route_read {
            let (route_reader, route_writer) = reflector::store::<HttpRoute>();
            spawn_reflector(
                &mut set,
                route_writer,
                Api::<HttpRoute>::all(client.clone()),
                watcher::Config::default(),
                ReflectorEffects::new(&notify, controller_health, "httproute", metrics),
                "HttpRoute (cluster-wide)",
            );
            route_readers.push(route_reader);
        }

        // The six backend-resource types — watched in every namespace in
        // `watch_namespaces`. Includes the Gateway's own namespace (covers
        // same-ns backends and listener TLS Secrets) plus every backend
        // namespace expanded by `desired_namespaces_for_gateway`.
        let (slice_reader, slice_writer) = reflector::store::<EndpointSlice>();
        spawn_reflector(
            &mut set,
            slice_writer,
            scoped_api::<EndpointSlice>(client.clone(), Some(ns)),
            watcher::Config::default(),
            ReflectorEffects::new(&notify, controller_health, "endpoint_slice", metrics),
            "EndpointSlice",
        );
        slice_readers.push(slice_reader);

        let (grant_reader, grant_writer) = reflector::store::<ReferenceGrant>();
        spawn_reflector(
            &mut set,
            grant_writer,
            scoped_api::<ReferenceGrant>(client.clone(), Some(ns)),
            watcher::Config::default(),
            ReflectorEffects::new(&notify, controller_health, "reference_grant", metrics),
            "ReferenceGrant",
        );
        grant_readers.push(grant_reader);

        let (secret_reader, secret_writer) = reflector::store::<Secret>();
        spawn_reflector(
            &mut set,
            secret_writer,
            scoped_api::<Secret>(client.clone(), Some(ns)),
            watcher::Config::default().fields("type=kubernetes.io/tls"),
            ReflectorEffects::new(&notify, controller_health, "secret", metrics),
            "Secret",
        );
        secret_readers.push(secret_reader);

        let (service_reader, service_writer) = reflector::store::<Service>();
        spawn_reflector(
            &mut set,
            service_writer,
            scoped_api::<Service>(client.clone(), Some(ns)),
            watcher::Config::default(),
            ReflectorEffects::new(&notify, controller_health, "service", metrics),
            "Service",
        );
        service_readers.push(service_reader);

        let (policy_reader, policy_writer) = reflector::store::<BackendTlsPolicy>();
        spawn_reflector(
            &mut set,
            policy_writer,
            scoped_api::<BackendTlsPolicy>(client.clone(), Some(ns)),
            watcher::Config::default(),
            ReflectorEffects::new(&notify, controller_health, "backend_tls_policy", metrics),
            "BackendTlsPolicy",
        );
        policy_readers.push(policy_reader);

        let (configmap_reader, configmap_writer) = reflector::store::<ConfigMap>();
        spawn_reflector(
            &mut set,
            configmap_writer,
            scoped_api::<ConfigMap>(client.clone(), Some(ns)),
            watcher::Config::default(),
            ReflectorEffects::new(&notify, controller_health, "config_map", metrics),
            "ConfigMap",
        );
        configmap_readers.push(configmap_reader);

        let (rate_limit_reader, rate_limit_writer) = reflector::store::<RateLimit>();
        spawn_reflector(
            &mut set,
            rate_limit_writer,
            scoped_api::<RateLimit>(client.clone(), Some(ns)),
            watcher::Config::default(),
            ReflectorEffects::new(&notify, controller_health, "rate_limit", metrics),
            "RateLimit",
        );
        rate_limit_readers.push(rate_limit_reader);
    }

    // Empty placeholder stores for resources the dedicated path never
    // watches: Ingress / IngressClass (no Ingress in dedicated mode) and
    // GatewayClass (we read class info directly from the Gateway, see the
    // module header). They satisfy `ReflectorStores`'s `&Store<T>` borrow.
    let (ingress_reader, _) = reflector::store::<k8s_openapi::api::networking::v1::Ingress>();
    let (ingress_class_reader, _) =
        reflector::store::<k8s_openapi::api::networking::v1::IngressClass>();
    let (ingress_class_params_reader, _) =
        reflector::store::<coxswain_core::crd::CoxswainIngressClassParameters>();
    let (gateway_class_reader, _) = reflector::store::<GatewayClass>();

    // Flip the "we don't watch this" subsystem checks Ready immediately so
    // `/readyz` doesn't get stuck on them.
    controller_health.ready("ingress");
    controller_health.ready("ingress_class");
    controller_health.ready("ingress_class_parameters");
    controller_health.ready("gateway_class");

    let controller_name = rec.config.controller_name.clone();
    let target = rec.config.target();
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
        loop {
            notify.notified().await;
            loop {
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(500)) => break,
                }
            }
            // Snapshot every per-namespace store into a single aggregated
            // Store for this rebuild iteration. The aggregated stores live
            // for the duration of the rebuild; ReflectorStores borrows
            // references into them.
            let routes_aggr = aggregate_into_store(&route_readers);
            let gateways_aggr = aggregate_into_store(&gateway_readers);
            let slices_aggr = aggregate_into_store(&slice_readers);
            let grants_aggr = aggregate_into_store(&grant_readers);
            let secrets_aggr = aggregate_into_store(&secret_readers);
            let services_aggr = aggregate_into_store(&service_readers);
            let policies_aggr = aggregate_into_store(&policy_readers);
            let configmaps_aggr = aggregate_into_store(&configmap_readers);
            let rate_limits_aggr = aggregate_into_store(&rate_limit_readers);

            // Dedicated proxy is Gateway-API-only; Ingress auth is not processed
            // here.  An empty store satisfies the ReflectorStores contract for
            // both htpasswd (auth_secrets) and client-cert CA (auth_tls_secrets).
            let empty_auth_secrets =
                kube::runtime::reflector::store::Writer::<Secret>::default().as_reader();
            let stores = ReflectorStores {
                routes: &routes_aggr,
                ingresses: &ingress_reader,
                ingress_classes: &ingress_class_reader,
                ingress_class_parameters: &ingress_class_params_reader,
                gateways: &gateways_aggr,
                gateway_classes: &gateway_class_reader,
                slices: &slices_aggr,
                services: &services_aggr,
                grants: &grants_aggr,
                secrets: &secrets_aggr,
                auth_secrets: &empty_auth_secrets,
                auth_tls_secrets: &empty_auth_secrets,
                policies: &policies_aggr,
                configmaps: &configmaps_aggr,
                rate_limits: &rate_limits_aggr,
            };
            let rebuild_start = std::time::Instant::now();
            let target_spec = DedicatedRebuildTarget {
                controller_name: &controller_name,
                target: &target,
            };
            let outputs = DedicatedRebuildOutputs {
                owned_gateways_handle: &owned_gateways_handle,
                gateway_routes: &gateway_routes,
                tls: &tls,
                tls_health: &tls_health,
                route_health: &route_health,
                policy_health: &policy_health,
            };
            let published = rebuild_dedicated_narrow(&stores, &target_spec, &outputs);
            metrics.observe_rebuild(
                rebuild_start.elapsed(),
                if published { "ok" } else { "error" },
            );
            let snapshot = gateway_routes.load();
            metrics.set_routing_table(snapshot.host_count(), 0, snapshot.host_count());
            let tls_snapshot = tls.load();
            let (exact, wildcard, default) = tls_snapshot.cert_counts();
            let expiries = tls_snapshot.expiries();
            metrics.set_tls(exact, wildcard, default, &expiries);
            if published && !routing_table_published {
                controller_health_for_loop.ready("routing_table_built");
                proxy_health_for_loop.ready("routing_table_loaded");
                routing_table_published = true;
            }
        }
    });

    set
}

/// Snapshot every per-namespace `Store<T>`'s state into one aggregated
/// `Store<T>` for a single rebuild iteration.
///
/// Cost: O(total objects across all per-ns stores). For the scale the
/// dedicated proxy targets (a few namespaces × a few dozen objects each)
/// this is microseconds and runs at most every 500 ms (rebuild debounce).
///
/// The aggregation is necessary because kube-rs's reflector machinery binds
/// one `Store` to one `Writer`; we can't share a single `Store` across
/// multiple per-namespace reflectors without their `Init` lifecycle steps
/// clobbering each other's buffers. The aggregated store is discarded after
/// the rebuild; the per-namespace stores remain authoritative.
fn aggregate_into_store<T>(stores: &[reflector::Store<T>]) -> reflector::Store<T>
where
    T: kube::Resource + Clone + 'static,
    T::DynamicType: Default + Eq + std::hash::Hash + Clone,
{
    let (reader, mut writer) = reflector::store::<T>();
    writer.apply_watcher_event(&watcher::Event::Init);
    for store in stores {
        for obj in store.state() {
            writer.apply_watcher_event(&watcher::Event::InitApply((*obj).clone()));
        }
    }
    writer.apply_watcher_event(&watcher::Event::InitDone);
    reader
}

/// Narrow rebuild for the per-namespace path. Bypasses
/// [`compute_ownership`] (which scans the `GatewayClass` store to determine
/// which Gateways are ours) and constructs `owned_gateways` /
/// `owned_gateway_classes` directly from the target Gateway in the
/// aggregated store.
fn rebuild_dedicated_narrow(
    stores: &ReflectorStores<'_>,
    target_spec: &DedicatedRebuildTarget<'_>,
    outputs: &DedicatedRebuildOutputs<'_>,
) -> bool {
    let DedicatedRebuildTarget {
        controller_name,
        target,
    } = *target_spec;
    let DedicatedRebuildOutputs {
        owned_gateways_handle,
        gateway_routes,
        tls,
        tls_health,
        route_health,
        policy_health,
    } = *outputs;
    let routes = stores.routes.state();
    let gateways = stores.gateways.state();

    // Find the target Gateway in the aggregated store and pull its class
    // name. Without a `GatewayClass` watch we can't verify the class's
    // `controllerName` claim — the controller already did that check before
    // provisioning us. The proxy trusts the controller's decision and only
    // serves traffic for its configured target.
    let target_gw = gateways.iter().find(|g| {
        g.metadata.namespace.as_deref() == Some(target.ns.as_str())
            && g.metadata.name.as_deref() == Some(target.name.as_str())
    });
    let (owned_gateways, owned_gateway_classes) = match target_gw {
        Some(gw) => {
            let mut classes = HashSet::with_capacity(1);
            classes.insert(gw.spec.gateway_class_name.clone());
            let mut gws = HashSet::with_capacity(1);
            gws.insert(target.clone());
            (gws, classes)
        }
        None => {
            tracing::warn!(
                gateway = %format!("{}/{}", target.ns, target.name),
                controller_name,
                "Target Gateway not yet visible in the per-namespace watch; routing table will be empty until it appears"
            );
            (HashSet::new(), HashSet::new())
        }
    };
    owned_gateways_handle.store(Arc::new(owned_gateways.clone()));

    let (backend_grants, cert_grants) = flatten_grants(&stores.grants.state());

    let (policy_index, mut policy_health_map) =
        build_backend_tls_index(stores.policies, stores.configmaps, stores.services);

    let owned_ingress_classes: HashSet<String> = HashSet::new();
    let ownership = Ownership {
        ingress_classes: &owned_ingress_classes,
        default_ingress_class: None,
        gateways: &owned_gateways,
        gateway_classes: &owned_gateway_classes,
        backend_grants: &backend_grants,
        cert_grants: &cert_grants,
        policy_index: &policy_index,
    };

    // `skip_cut_over = false`: the dedicated proxy serves the cut-over Gateway.
    let routes_published = build_gateway_routes(stores, &routes, &ownership, gateway_routes, false);

    let ingresses: Vec<Arc<k8s_openapi::api::networking::v1::Ingress>> = Vec::new();
    // `skip_cut_over = false`: the dedicated proxy's whole job is serving the
    // cut-over Gateway. The shared-pool filter would drop our listener.
    let mut gateway_tls_health = build_tls(stores, &ingresses, &ownership, tls, false);
    count_attached_routes(&routes, &owned_gateways, &mut gateway_tls_health);
    // Merge only THIS Gateway's listener health into the shared cell: the
    // shared-pool reconciler and the other dedicated reconcilers publish into
    // the same cell, so a full replace would transiently drop their entries and
    // make their proxies unbind their listeners (#423 dedicated bind→remove).
    tls_health.update_scoped(gateway_tls_health, |k| k == target);

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

#[cfg(test)]
mod tests {
    use crate::DedicatedConfig;
    use coxswain_core::ownership::ObjectKey;
    use std::collections::HashSet;

    #[test]
    fn target_returns_namespaced_object_key() {
        let cfg = DedicatedConfig::new("coxswain-labs.dev/gateway-controller", "my-gw", "tenant-a");
        assert_eq!(
            cfg.target(),
            ObjectKey::new("tenant-a".to_string(), "my-gw".to_string())
        );
    }

    #[test]
    fn new_defaults_opt_ins_to_false() {
        let cfg = DedicatedConfig::new("c", "n", "ns");
        assert!(!cfg.allow_cluster_wide_route_read);
        assert!(!cfg.allow_cluster_wide_namespace_read);
    }

    #[test]
    fn opt_in_flags_settable() {
        let mut cfg = DedicatedConfig::new("c", "n", "ns");
        cfg.allow_cluster_wide_route_read = true;
        cfg.allow_cluster_wide_namespace_read = true;
        assert!(cfg.allow_cluster_wide_route_read);
        assert!(cfg.allow_cluster_wide_namespace_read);
    }

    /// Reproduce the singleton-narrowing logic from `rebuild_dedicated` against
    /// a synthetic ownership set. This is what guarantees acceptance criterion
    /// "HTTPRoute attached to a different Gateway (ignored)": the dedicated
    /// reconciler only includes the target Gateway in `owned_gateways`, so any
    /// HTTPRoute whose `parentRef` points elsewhere is silently dropped by the
    /// existing `parent_ref_owned` check that the routing-table build pipeline
    /// already calls.
    #[test]
    fn narrow_to_singleton_keeps_target_when_owned() {
        let target = ObjectKey::new("tenant-a", "my-gw");
        let cluster_owned: HashSet<ObjectKey> = [
            target.clone(),
            ObjectKey::new("tenant-b", "their-gw"),
            ObjectKey::new("tenant-c", "another-gw"),
        ]
        .into_iter()
        .collect();

        let narrowed: HashSet<ObjectKey> = if cluster_owned.contains(&target) {
            std::iter::once(target.clone()).collect()
        } else {
            HashSet::new()
        };

        assert_eq!(narrowed.len(), 1);
        assert!(narrowed.contains(&target));
        assert!(!narrowed.contains(&ObjectKey::new("tenant-b", "their-gw")));
    }

    /// When the target Gateway is not owned by this controller (e.g. its
    /// GatewayClass is claimed by a different controller), the dedicated
    /// reconciler returns an empty owned-set and the routing table will publish
    /// empty — no routes attach.
    #[test]
    fn narrow_to_singleton_empty_when_target_not_owned() {
        let target = ObjectKey::new("tenant-a", "my-gw");
        let cluster_owned: HashSet<ObjectKey> = [
            ObjectKey::new("tenant-b", "their-gw"),
            ObjectKey::new("tenant-c", "another-gw"),
        ]
        .into_iter()
        .collect();

        let narrowed: HashSet<ObjectKey> = if cluster_owned.contains(&target) {
            std::iter::once(target.clone()).collect()
        } else {
            HashSet::new()
        };

        assert!(narrowed.is_empty());
    }
}
