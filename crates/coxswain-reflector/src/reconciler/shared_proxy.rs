//! Shared-proxy reconciler: cluster-wide watches feeding the shared-pool data
//! plane (`serve proxy --shared` and `serve dev`).
//!
//! Owns the debounced watch + rebuild pipeline that turns reflector snapshots
//! into the full set of outputs the shared pool needs: Ingress + Gateway
//! routing tables, the TLS cert store, the per-listener health map (consumed
//! by `HotReloader`), the per-route and per-policy health maps (consumed by
//! the controller's status writer in `dev` mode), and the cluster summary.
//!
//! Sibling reconcilers in this module narrow the scope:
//!
//! - `DedicatedProxyReconciler` (Step 7) — one Gateway, dynamic per-namespace
//!   reflectors.
//! - `ControllerReconciler` (Step 7) — cluster-wide watches but no routing
//!   tables or TLS store; status-only output set.

use crate::cluster::{ClusterSummaryInputs, build_cluster_summary};
use crate::gateway_api::hostnames_intersect;
use crate::gateway_api::{
    BackendTlsIndex, GatewayApiReconciler, ListenerBinding, build_backend_tls_index,
};
use crate::gw_types::BackendTlsPolicy;
use crate::gw_types::HttpRoute;
use crate::gw_types::v::gatewayclasses::GatewayClass;
use crate::gw_types::v::gateways::Gateway;
use crate::gw_types::v::referencegrants::ReferenceGrant;
use crate::k8s_utils::scoped_api;
use crate::keys::ListenerKey;
use crate::reference_grants::{GrantSet, flatten_grants};
use crate::tls::{
    GatewayListenerHealth, SharedBackendTlsPolicyHealth, SharedGatewayListenerHealth,
    SharedHttpRouteHealth,
};
use crate::{
    endpoints,
    ingress::{IngressPorts, IngressReconciler},
};
use async_trait::async_trait;
use coxswain_core::cluster::SharedClusterSummary;
use coxswain_core::health::SubsystemHandle;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_core::routing::{
    BackendGroup, GatewayRoutingTableBuilder, IngressRoutingTableBuilder, RouteEntry, RoutingTable,
    RoutingTableBuilder, SharedGatewayRoutingTable, SharedIngressRoutingTable,
};
use coxswain_core::shared::Shared;
use coxswain_core::tls::{SharedTlsStore, TlsStoreBuilder};
use futures::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::{
    Client,
    api::Api,
    runtime::{WatchStreamExt, reflector, watcher},
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::task::JoinSet;

/// Error returned when parsing `--ingress-default-backend`.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum IngressDefaultBackendParseError {
    /// No `:` separator found; expected `<namespace>/<service>:<port>`.
    #[error("missing port; expected <namespace>/<service>:<port>")]
    MissingPort,
    /// No `/` separator found before the port; expected `<namespace>/<service>:<port>`.
    #[error("missing namespace; expected <namespace>/<service>:<port>")]
    MissingNamespace,
    /// Port substring is not a valid integer.
    #[error("invalid port '{0}'; expected an integer")]
    InvalidPort(String),
    /// Namespace or service name is empty after parsing.
    #[error("namespace and service name must not be empty")]
    EmptyComponent,
}

/// A parsed reference to the controller-wide ingress default backend service.
///
/// Set via `--ingress-default-backend=<namespace>/<service>:<port>`.
/// Implements [`std::str::FromStr`]; parsing errors are reported as
/// [`IngressDefaultBackendParseError`].
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct IngressDefaultBackend {
    /// Kubernetes namespace of the backend service.
    pub namespace: String,
    /// Name of the backend service.
    pub name: String,
    /// Service port number.
    pub port: i32,
}

impl std::str::FromStr for IngressDefaultBackend {
    type Err = IngressDefaultBackendParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns_name, port_str) = s
            .rsplit_once(':')
            .ok_or(IngressDefaultBackendParseError::MissingPort)?;
        let (namespace, name) = ns_name
            .split_once('/')
            .ok_or(IngressDefaultBackendParseError::MissingNamespace)?;
        let port: i32 = port_str
            .parse()
            .map_err(|_| IngressDefaultBackendParseError::InvalidPort(port_str.to_owned()))?;
        if namespace.is_empty() || name.is_empty() {
            return Err(IngressDefaultBackendParseError::EmptyComponent);
        }
        Ok(IngressDefaultBackend {
            namespace: namespace.to_string(),
            name: name.to_string(),
            port,
        })
    }
}

/// Optional configuration for a [`SharedProxyReconciler`].
#[non_exhaustive]
pub struct ReconcilerOptions {
    /// When set, scope namespaced watches to this namespace. When `None`, watch cluster-wide.
    pub watch_namespace: Option<String>,
    /// Controller-wide default backend for Ingress traffic with no matching rule.
    pub ingress_default_backend: Option<IngressDefaultBackend>,
    /// Ports on which Ingress routes are served.
    pub ingress_ports: IngressPorts,
    /// Pod role driving the metric-prefix selection (`coxswain_proxy_*` vs
    /// `coxswain_controller_*`). Default [`MetricsPrefix::Proxy`].
    pub metrics_prefix: crate::MetricsPrefix,
}

impl Default for ReconcilerOptions {
    fn default() -> Self {
        Self {
            watch_namespace: None,
            ingress_default_backend: None,
            ingress_ports: IngressPorts::default(),
            metrics_prefix: crate::MetricsPrefix::Proxy,
        }
    }
}

/// Health-registry handles consumed by the [`SharedProxyReconciler`].
///
/// Each reflector flips a per-source check on `controller` to `Ready` once it
/// has emitted its first `InitDone` (the authoritative "initial sync complete"
/// signal). After the first successful routing-table publish, the reconciler
/// also flips `controller.routing_table_built` and `proxy.routing_table_loaded`.
#[non_exhaustive]
pub struct ReconcilerHealth {
    /// Handle for the `controller` subsystem (per-reflector + `routing_table_built`).
    pub controller: SubsystemHandle,
    /// Handle for the `proxy` subsystem (`routing_table_loaded`).
    pub proxy: SubsystemHandle,
}

impl ReconcilerHealth {
    /// Construct a `ReconcilerHealth` from the two subsystem handles.
    #[must_use]
    pub fn new(controller: SubsystemHandle, proxy: SubsystemHandle) -> Self {
        Self { controller, proxy }
    }
}

/// Pingora background service that maintains reflector-backed stores for
/// `HTTPRoute`, `Ingress`, `IngressClass`, `Gateway`, `GatewayClass`,
/// `BackendTLSPolicy`, `ConfigMap`, and `EndpointSlice`, and rebuilds the routing
/// table whenever any of them change — with a 500 ms trailing-edge debounce to
/// coalesce burst updates (e.g. rolling deploys).
#[non_exhaustive]
pub struct SharedProxyReconciler {
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    tls: SharedTlsStore,
    tls_health: SharedGatewayListenerHealth,
    cluster_summary: SharedClusterSummary,
    route_health: SharedHttpRouteHealth,
    policy_health: SharedBackendTlsPolicyHealth,
    owned_gateways: OwnedGateways,
    leader: Arc<AtomicBool>,
    health: ReconcilerHealth,
    controller_name: String,
    opts: ReconcilerOptions,
}

/// The `Shared<T>` outputs the [`SharedProxyReconciler`] writes into on each rebuild.
///
/// Bundling them lets [`SharedProxyReconciler::new`] stay under the workspace
/// `clippy::too_many_arguments` threshold; callers pass one
/// `ReconcilerOutputs` struct instead of several positional handles.
#[non_exhaustive]
pub struct ReconcilerOutputs {
    /// Ingress-flavored routing table snapshot, updated on every successful Ingress build.
    pub ingress_routes: SharedIngressRoutingTable,
    /// Gateway-API-flavored routing table snapshot, updated on every successful Gateway build.
    pub gateway_routes: SharedGatewayRoutingTable,
    /// TLS certificate store snapshot, updated whenever a `kubernetes.io/tls` Secret changes.
    pub tls: SharedTlsStore,
    /// Per-listener Gateway health used by status writes and the hot-reloader.
    pub tls_health: SharedGatewayListenerHealth,
    /// Cluster aggregate (per-Gateway / per-Ingress summary) consumed by the
    /// controller's `/cluster` admin endpoint. Updated on every rebuild.
    pub cluster_summary: SharedClusterSummary,
}

impl ReconcilerOutputs {
    /// Construct a `ReconcilerOutputs` bundle from its shared handles.
    #[must_use]
    pub fn new(
        ingress_routes: SharedIngressRoutingTable,
        gateway_routes: SharedGatewayRoutingTable,
        tls: SharedTlsStore,
        tls_health: SharedGatewayListenerHealth,
        cluster_summary: SharedClusterSummary,
    ) -> Self {
        Self {
            ingress_routes,
            gateway_routes,
            tls,
            tls_health,
            cluster_summary,
        }
    }
}

impl SharedProxyReconciler {
    /// Construct a new reconciler (does not start the watch loop).
    ///
    /// `leader` is the shared leader-election flag the controller pod owns; the
    /// proxy pod passes a fresh `Arc::new(AtomicBool::new(false))` since it never
    /// holds a lease. The reconciler reads it once per rebuild to populate
    /// [`coxswain_core::cluster::ControllerSummary::leader`].
    pub fn new(
        outputs: ReconcilerOutputs,
        owned_gateways: OwnedGateways,
        leader: Arc<AtomicBool>,
        health: ReconcilerHealth,
        controller_name: String,
        opts: ReconcilerOptions,
    ) -> Self {
        let ReconcilerOutputs {
            ingress_routes,
            gateway_routes,
            tls,
            tls_health,
            cluster_summary,
        } = outputs;
        Self {
            ingress_routes,
            gateway_routes,
            tls,
            tls_health,
            cluster_summary,
            route_health: SharedHttpRouteHealth::new(),
            policy_health: SharedBackendTlsPolicyHealth::new(),
            owned_gateways,
            leader,
            health,
            controller_name,
            opts,
        }
    }

    /// Returns the shared route health handle so other services (e.g. the Controller)
    /// can subscribe to updates published by this reconciler.
    pub fn route_health(&self) -> SharedHttpRouteHealth {
        self.route_health.clone()
    }

    /// Returns the shared `BackendTLSPolicy` health handle so the Controller can
    /// write `status.ancestors[]` when leader.
    pub fn policy_health(&self) -> SharedBackendTlsPolicyHealth {
        self.policy_health.clone()
    }
}

struct ReconcilerConfig {
    controller_name: String,
    watch_namespace: Option<String>,
    ingress_default_backend: Option<IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    metrics: crate::ReflectorMetrics,
}

pub(super) struct ReflectorStores<'a> {
    pub(super) routes: &'a reflector::Store<HttpRoute>,
    pub(super) ingresses: &'a reflector::Store<Ingress>,
    pub(super) ingress_classes: &'a reflector::Store<IngressClass>,
    pub(super) gateways: &'a reflector::Store<Gateway>,
    pub(super) gateway_classes: &'a reflector::Store<GatewayClass>,
    pub(super) slices: &'a reflector::Store<EndpointSlice>,
    pub(super) services: &'a reflector::Store<Service>,
    pub(super) grants: &'a reflector::Store<ReferenceGrant>,
    pub(super) secrets: &'a reflector::Store<Secret>,
    /// `BackendTLSPolicy` resources in scope (namespaced per `watch_namespace`).
    pub(super) policies: &'a reflector::Store<BackendTlsPolicy>,
    /// All ConfigMaps in scope — used to resolve `caCertificateRefs`.
    /// Unlike the `Secret` reflector (which uses a type= field selector), ConfigMaps
    /// have no equivalent filter; all CMs in scope are watched. A follow-up will
    /// switch to per-policy informers to bound memory use in large clusters.
    pub(super) configmaps: &'a reflector::Store<ConfigMap>,
}

struct SharedOutputs<'a> {
    ingress_routes: &'a SharedIngressRoutingTable,
    gateway_routes: &'a SharedGatewayRoutingTable,
    tls: &'a SharedTlsStore,
    tls_health: &'a SharedGatewayListenerHealth,
    cluster_summary: &'a SharedClusterSummary,
    route_health: &'a SharedHttpRouteHealth,
    policy_health: &'a SharedBackendTlsPolicyHealth,
}

pub(super) struct Ownership<'a> {
    pub(super) ingress_classes: &'a HashSet<String>,
    pub(super) default_ingress_class: Option<&'a str>,
    pub(super) gateways: &'a HashSet<ObjectKey>,
    pub(super) gateway_classes: &'a HashSet<String>,
    pub(super) backend_grants: &'a GrantSet,
    pub(super) cert_grants: &'a GrantSet,
    /// Per-(Service, port) `BackendTLSPolicy` lookup table, built before this
    /// `Ownership` is constructed. Carried alongside ownership data because
    /// `build_routes` and the per-route `reconcile` both need it on the same
    /// borrow pass — folding it in here keeps the function arities clippy-clean.
    pub(super) policy_index: &'a BackendTlsIndex,
}

/// Per-reflector side-effect channels: rebuild notification, readiness flip,
/// and metric observation.
///
/// Grouped so [`spawn_reflector`] stays under `clippy::too_many_arguments`.
pub(super) struct ReflectorEffects {
    notify: Arc<Notify>,
    controller_health: SubsystemHandle,
    /// Health-check name to flip Ready on first `Event::InitDone`. Also used
    /// as the `kind` metric label for `watch_events_total` / `watch_errors_total`.
    check: &'static str,
    metrics: crate::ReflectorMetrics,
}

impl ReflectorEffects {
    pub(super) fn new(
        notify: &Arc<Notify>,
        health: &SubsystemHandle,
        check: &'static str,
        metrics: crate::ReflectorMetrics,
    ) -> Self {
        Self {
            notify: Arc::clone(notify),
            controller_health: health.clone(),
            check,
            metrics,
        }
    }
}

pub(super) fn spawn_reflector<T>(
    set: &mut JoinSet<()>,
    writer: reflector::store::Writer<T>,
    api: Api<T>,
    config: watcher::Config,
    effects: ReflectorEffects,
    label: &'static str,
) where
    T: kube::Resource
        + serde::de::DeserializeOwned
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    T::DynamicType: Default + Clone + std::hash::Hash + Eq + Send + Sync + 'static,
{
    let ReflectorEffects {
        notify,
        controller_health,
        check,
        metrics,
    } = effects;
    set.spawn(async move {
        let stream = reflector::reflector(writer, watcher(api, config).default_backoff());
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(watcher::Event::InitDone) => {
                    notify.notify_one();
                    controller_health.ready(check);
                    metrics.observe_watch_event(check, "init_done");
                }
                Ok(watcher::Event::Apply(_)) => {
                    notify.notify_one();
                    metrics.observe_watch_event(check, "apply");
                }
                Ok(watcher::Event::Delete(_)) => {
                    notify.notify_one();
                    metrics.observe_watch_event(check, "delete");
                }
                Ok(_) => {
                    notify.notify_one();
                    metrics.observe_watch_event(check, "restart");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "{label} reflector error");
                    metrics.observe_watch_error(check);
                }
            }
        }
    });
}

#[async_trait]
impl BackgroundService for SharedProxyReconciler {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to initialise Kubernetes client; reconciler will not run");
                return;
            }
        };
        let config = ReconcilerConfig {
            controller_name: self.controller_name.clone(),
            watch_namespace: self.opts.watch_namespace.clone(),
            ingress_default_backend: self.opts.ingress_default_backend.clone(),
            ingress_ports: self.opts.ingress_ports,
            metrics: crate::ReflectorMetrics::new(self.opts.metrics_prefix),
        };
        let handles = SharedHandles {
            ingress_routes: self.ingress_routes.clone(),
            gateway_routes: self.gateway_routes.clone(),
            tls: self.tls.clone(),
            tls_health: self.tls_health.clone(),
            cluster_summary: self.cluster_summary.clone(),
            route_health: self.route_health.clone(),
            policy_health: self.policy_health.clone(),
            owned_gateways: self.owned_gateways.clone(),
            leader: Arc::clone(&self.leader),
            controller_health: self.health.controller.clone(),
            proxy_health: self.health.proxy.clone(),
        };
        let mut set = spawn_tasks(client, handles, config).await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                res = set.join_next() => match res {
                    Some(Ok(())) => tracing::warn!("SharedProxyReconciler task exited unexpectedly"),
                    Some(Err(e)) => tracing::error!(error = %e, "SharedProxyReconciler task panicked"),
                    None => break,
                },
            }
        }
    }
}

/// Owned bundle of shared state handles consumed by [`spawn_tasks`].
///
/// Groups every cross-task handle the reconciler clones into its background work
/// so the function stays under the `clippy::too_many_arguments` threshold.
struct SharedHandles {
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    tls: SharedTlsStore,
    tls_health: SharedGatewayListenerHealth,
    cluster_summary: SharedClusterSummary,
    route_health: SharedHttpRouteHealth,
    policy_health: SharedBackendTlsPolicyHealth,
    owned_gateways: OwnedGateways,
    leader: Arc<AtomicBool>,
    controller_health: SubsystemHandle,
    proxy_health: SubsystemHandle,
}

async fn spawn_tasks(
    client: Client,
    handles: SharedHandles,
    config: ReconcilerConfig,
) -> JoinSet<()> {
    let SharedHandles {
        ingress_routes,
        gateway_routes,
        tls,
        tls_health,
        cluster_summary,
        route_health,
        policy_health,
        owned_gateways,
        leader,
        controller_health,
        proxy_health,
    } = handles;
    let ReconcilerConfig {
        controller_name,
        watch_namespace,
        ingress_default_backend,
        ingress_ports,
        metrics,
    } = config;
    let (route_reader, route_writer) = reflector::store::<HttpRoute>();
    let (ingress_reader, ingress_writer) = reflector::store::<Ingress>();
    let (class_reader, class_writer) = reflector::store::<IngressClass>();
    let (gateway_reader, gateway_writer) = reflector::store::<Gateway>();
    let (gateway_class_reader, gateway_class_writer) = reflector::store::<GatewayClass>();
    let (slice_reader, slice_writer) = reflector::store::<EndpointSlice>();
    let (grant_reader, grant_writer) = reflector::store::<ReferenceGrant>();
    let (secret_reader, secret_writer) = reflector::store::<Secret>();
    let (service_reader, service_writer) = reflector::store::<Service>();
    let (policy_reader, policy_writer) = reflector::store::<BackendTlsPolicy>();
    let (configmap_reader, configmap_writer) = reflector::store::<ConfigMap>();
    let notify = Arc::new(Notify::new());
    let mut set = JoinSet::new();
    let ns = watch_namespace.as_deref();

    spawn_reflector(
        &mut set,
        route_writer,
        scoped_api::<HttpRoute>(client.clone(), ns),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "httproute", metrics),
        "HttpRoute",
    );
    spawn_reflector(
        &mut set,
        ingress_writer,
        scoped_api::<Ingress>(client.clone(), ns),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "ingress", metrics),
        "Ingress",
    );
    spawn_reflector(
        &mut set,
        class_writer,
        Api::<IngressClass>::all(client.clone()),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "ingress_class", metrics),
        "IngressClass",
    );
    spawn_reflector(
        &mut set,
        gateway_writer,
        scoped_api::<Gateway>(client.clone(), ns),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "gateway", metrics),
        "Gateway",
    );
    spawn_reflector(
        &mut set,
        gateway_class_writer,
        Api::<GatewayClass>::all(client.clone()),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "gateway_class", metrics),
        "GatewayClass",
    );
    spawn_reflector(
        &mut set,
        slice_writer,
        scoped_api::<EndpointSlice>(client.clone(), ns),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "endpoint_slice", metrics),
        "EndpointSlice",
    );
    spawn_reflector(
        &mut set,
        grant_writer,
        scoped_api::<ReferenceGrant>(client.clone(), ns),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "reference_grant", metrics),
        "ReferenceGrant",
    );
    // Field-selector scoped to `type=kubernetes.io/tls` to avoid pulling every Secret into memory.
    spawn_reflector(
        &mut set,
        secret_writer,
        scoped_api::<Secret>(client.clone(), ns),
        watcher::Config::default().fields("type=kubernetes.io/tls"),
        ReflectorEffects::new(&notify, &controller_health, "secret", metrics),
        "Secret",
    );
    // Used to resolve targetPort for backends where servicePort ≠ targetPort.
    spawn_reflector(
        &mut set,
        service_writer,
        scoped_api::<Service>(client.clone(), ns),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "service", metrics),
        "Service",
    );
    spawn_reflector(
        &mut set,
        policy_writer,
        scoped_api::<BackendTlsPolicy>(client.clone(), ns),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "backend_tls_policy", metrics),
        "BackendTlsPolicy",
    );
    // ConfigMaps have no type= field selector equivalent; all CMs in scope are
    // watched so BackendTLSPolicy caCertificateRefs can be resolved. A follow-up
    // will switch to per-policy informers to bound memory use in large clusters.
    spawn_reflector(
        &mut set,
        configmap_writer,
        scoped_api::<ConfigMap>(client, ns),
        watcher::Config::default(),
        ReflectorEffects::new(&notify, &controller_health, "config_map", metrics),
        "ConfigMap",
    );

    // --- Trailing-edge debounce + rebuild ---
    //
    // Waits for the first notification, then races subsequent notifications
    // against a 500 ms timer. Each new notification resets the timer. When
    // the timer expires uninterrupted, the full routing table is rebuilt from
    // the current store snapshots — never from the API server.
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
            let stores = ReflectorStores {
                routes: &route_reader,
                ingresses: &ingress_reader,
                ingress_classes: &class_reader,
                gateways: &gateway_reader,
                gateway_classes: &gateway_class_reader,
                slices: &slice_reader,
                services: &service_reader,
                grants: &grant_reader,
                secrets: &secret_reader,
                policies: &policy_reader,
                configmaps: &configmap_reader,
            };
            let outputs = SharedOutputs {
                ingress_routes: &ingress_routes,
                gateway_routes: &gateway_routes,
                tls: &tls,
                tls_health: &tls_health,
                cluster_summary: &cluster_summary,
                route_health: &route_health,
                policy_health: &policy_health,
            };
            let rebuild_start = std::time::Instant::now();
            let published = rebuild(
                &stores,
                &controller_name,
                &owned_gateways,
                ingress_default_backend.as_ref(),
                ingress_ports,
                leader.load(Ordering::Acquire),
                &outputs,
            );
            metrics.observe_rebuild(
                rebuild_start.elapsed(),
                if published { "ok" } else { "error" },
            );
            // Mirror the routing-table size gauges from the published snapshots.
            // Loads via `Shared::load()` are atomic and cheap.
            let ing_snapshot = outputs.ingress_routes.load();
            let gw_snapshot = outputs.gateway_routes.load();
            metrics.set_routing_table(
                ing_snapshot.host_count() + gw_snapshot.host_count(),
                ing_snapshot.host_count(),
                gw_snapshot.host_count(),
            );
            let tls_snapshot = outputs.tls.load();
            let (exact, wildcard, default) = tls_snapshot.cert_counts();
            let expiries = tls_snapshot.expiries();
            metrics.set_tls(exact, wildcard, default, &expiries);
            // First successful publish: flip the readiness checks that gate
            // `/readyz` on having an honest routing table. Subsequent rebuilds
            // do not re-touch the checks — `Ready` is idempotent and there is
            // no transient state we want to flag here.
            if published && !routing_table_published {
                controller_health.ready("routing_table_built");
                proxy_health.ready("routing_table_loaded");
                routing_table_published = true;
            }
        }
    });

    set
}

/// Returns `true` if a new routing table was published (the rebuild succeeded).
/// Used by the debounce loop to flip the first-publish readiness checks once.
fn rebuild(
    stores: &ReflectorStores<'_>,
    controller_name: &str,
    owned_gateways_handle: &OwnedGateways,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    leader: bool,
    outputs: &SharedOutputs<'_>,
) -> bool {
    let routes = stores.routes.state();
    let ingresses = stores.ingresses.state();

    let (owned_ingress_classes, owned_default_ingress_class, owned_gateway_classes, owned_gateways) =
        compute_ownership(
            stores.ingress_classes,
            stores.gateway_classes,
            stores.gateways,
            controller_name,
            owned_gateways_handle,
        );

    let (backend_grants, cert_grants) = flatten_grants(&stores.grants.state());

    tracing::debug!(
        http_routes = routes.len(),
        ingresses = ingresses.len(),
        owned_ingress_classes = owned_ingress_classes.len(),
        owned_gateways = owned_gateways.len(),
        "Rebuilding routing table"
    );

    // `policy_index` is built first because `Ownership` now carries a borrow of it.
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

    let routes_published = build_routes(
        stores,
        &routes,
        &ingresses,
        &ownership,
        ingress_default_backend,
        ingress_ports,
        outputs,
    );

    let mut gateway_tls_health = build_tls(stores, &ingresses, &ownership, outputs.tls, true);

    count_attached_routes(&routes, &owned_gateways, &mut gateway_tls_health);

    let gateways = stores.gateways.state();
    // Publish the cluster summary while we still have access to gateway_tls_health
    // (it's moved into `tls_health.store_and_notify` next). Reads from already-
    // materialised state: nothing kube-side, no allocations beyond the summary.
    outputs
        .cluster_summary
        .store(Arc::new(build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &owned_gateways,
            owned_ingress_classes: &owned_ingress_classes,
            default_ingress_class: owned_default_ingress_class.as_deref(),
            gateway_tls_health: &gateway_tls_health,
            leader,
        })));

    outputs.tls_health.store_and_notify(gateway_tls_health);

    let route_health_map = GatewayApiReconciler::compute_route_health(
        &routes,
        &gateways,
        &owned_gateways,
        &backend_grants,
        stores.services,
    );
    outputs.route_health.store_and_notify(route_health_map);

    // Compute per-policy ancestor lists and merge with the validity health from index build.
    let ancestor_health = GatewayApiReconciler::compute_policy_health(
        &policy_index,
        stores.policies,
        &routes,
        &owned_gateways,
    );
    for (key, ah) in ancestor_health {
        let entry = policy_health_map.entry(key).or_default();
        entry.ancestors = ah.ancestors;
    }
    outputs.policy_health.store_and_notify(policy_health_map);

    routes_published
}

/// Compute which IngressClasses, GatewayClasses, and Gateways are owned by this controller.
/// Publishes the owned-gateways snapshot to `owned_gateways_handle` as a side effect.
/// The fourth element of the returned tuple is the name of the owned default IngressClass (if any).
pub(super) fn compute_ownership(
    class_store: &reflector::Store<IngressClass>,
    gateway_class_store: &reflector::Store<GatewayClass>,
    gateway_store: &reflector::Store<Gateway>,
    controller_name: &str,
    owned_gateways_handle: &OwnedGateways,
) -> (
    HashSet<String>,
    Option<String>,
    HashSet<String>,
    HashSet<ObjectKey>,
) {
    let owned_class_objs: Vec<_> = class_store
        .state()
        .into_iter()
        .filter(|ic| {
            ic.spec.as_ref().and_then(|s| s.controller.as_deref()) == Some(controller_name)
        })
        .collect();

    let owned_ingress_classes: HashSet<String> = owned_class_objs
        .iter()
        .filter_map(|ic| ic.metadata.name.clone())
        .collect();

    let mut defaults: Vec<String> = owned_class_objs
        .iter()
        .filter(|ic| crate::ingress::is_default_ingress_class(ic))
        .filter_map(|ic| ic.metadata.name.clone())
        .collect();
    defaults.sort();
    if defaults.len() > 1 {
        tracing::warn!(
            ?defaults,
            "Multiple owned IngressClasses annotated as default; using lexicographically lowest"
        );
    }
    let owned_default_ingress_class = defaults.into_iter().next();

    let owned_gateway_classes: HashSet<String> = gateway_class_store
        .state()
        .into_iter()
        .filter(|gc| gc.spec.controller_name == controller_name)
        .filter_map(|gc| gc.metadata.name.clone())
        .collect();

    let owned_gateways: HashSet<ObjectKey> = gateway_store
        .state()
        .into_iter()
        .filter(|g| owned_gateway_classes.contains(&g.spec.gateway_class_name))
        // Exclude Gateways that have been cut over to a dedicated proxy
        // (#210). The dedicated pool's data plane serves them now; the
        // shared pool must drop them from its routing table.
        .filter(|g| !gateway_is_cut_over(g))
        .filter_map(|g| {
            let ns = g.metadata.namespace.clone()?;
            let name = g.metadata.name.clone()?;
            Some(ObjectKey::new(ns, name))
        })
        .collect();

    owned_gateways_handle.store(Arc::new(owned_gateways.clone()));
    (
        owned_ingress_classes,
        owned_default_ingress_class,
        owned_gateway_classes,
        owned_gateways,
    )
}

/// Build and publish the Ingress and Gateway routing tables from their
/// respective source resources.
///
/// Two independent build pipelines run, each with its own typed builder. The
/// two `Shared` outputs are swapped independently: a failure in one cannot
/// disrupt or partially clear the other. Returns `true` only when BOTH builds
/// publish successfully — the proxy is not considered "fully synchronised"
/// until each table has had at least one honest publish.
fn build_routes(
    stores: &ReflectorStores<'_>,
    routes: &[Arc<HttpRoute>],
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    outputs: &SharedOutputs<'_>,
) -> bool {
    let gateway_published =
        build_gateway_routes(stores, routes, ownership, outputs.gateway_routes, true);
    let ingress_published = build_ingress_routes(
        stores,
        ingresses,
        ownership,
        ingress_default_backend,
        ingress_ports,
        outputs.ingress_routes,
    );
    gateway_published && ingress_published
}

/// Build the Gateway-API routing table from `HTTPRoute` resources and publish
/// it to `shared`. Returns `true` if the publish succeeded.
/// `skip_cut_over` drops cut-over Gateways from the listener-info map —
/// correct for the *shared* reconciler (those listeners bind on the dedicated
/// proxy instead). The dedicated reconciler must pass `false`: its target
/// Gateway IS the cut-over Gateway, and filtering it leaves the dedicated
/// subprocess with no listener_info and no resolvable routes.
pub(super) fn build_gateway_routes(
    stores: &ReflectorStores<'_>,
    routes: &[Arc<HttpRoute>],
    ownership: &Ownership<'_>,
    shared: &SharedGatewayRoutingTable,
    skip_cut_over: bool,
) -> bool {
    // Precompute ListenerKey → (hostname, port) from all owned gateway
    // listeners.
    let listener_info: HashMap<ListenerKey, ListenerBinding> = stores
        .gateways
        .state()
        .into_iter()
        .filter(|g| {
            ownership
                .gateway_classes
                .contains(&g.spec.gateway_class_name)
        })
        .filter(|g| !(skip_cut_over && gateway_is_cut_over(g)))
        .flat_map(|g| {
            let ns = g.metadata.namespace.clone().unwrap_or_default();
            let name = g.metadata.name.clone().unwrap_or_default();
            g.spec.listeners.clone().into_iter().map(move |l| {
                let key = ListenerKey::new(ns.clone(), name.clone(), l.name);
                let binding = ListenerBinding {
                    hostname: l.hostname.unwrap_or_default(),
                    port: l.port as u16,
                };
                (key, binding)
            })
        })
        .collect();

    let mut builder = GatewayRoutingTableBuilder::new();
    for route in routes {
        GatewayApiReconciler::reconcile(
            route,
            stores.slices,
            stores.services,
            ownership.gateways,
            ownership.backend_grants,
            crate::gateway_api::RouteResolution {
                listener_info: &listener_info,
                policy_index: ownership.policy_index,
            },
            &mut builder,
        );
    }

    publish_routes(
        shared,
        builder,
        "gateway",
        routes.len(),
        ownership.gateways.len(),
    )
}

/// Build the Ingress routing table from `Ingress` resources (plus the
/// controller-wide default backend, if configured) and publish it to `shared`.
/// Returns `true` if the publish succeeded.
fn build_ingress_routes(
    stores: &ReflectorStores<'_>,
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    shared: &SharedIngressRoutingTable,
) -> bool {
    let mut builder = IngressRoutingTableBuilder::new();
    for ingress in ingresses {
        IngressReconciler::reconcile(
            ingress,
            stores.slices,
            stores.services,
            ownership.ingress_classes,
            ownership.default_ingress_class,
            ingress_ports,
            &mut builder,
        );
    }

    // Install the controller-wide default backend on the catchall for each configured
    // Ingress port. Per-Ingress defaults always win because they are installed on the
    // host router (matched first).
    if let Some(db) = ingress_default_backend {
        let resolved = endpoints::resolve(
            &db.namespace,
            &db.name,
            db.port,
            stores.slices,
            stores.services,
        );
        if resolved.addrs.is_empty() {
            tracing::warn!(
                svc = %format!("{}/{}", db.namespace, db.name),
                "No ready endpoints for --ingress-default-backend — skipping"
            );
        } else {
            let protocol = resolved.app_protocol;
            let group = Arc::new(
                BackendGroup::new(format!("{}/{}", db.namespace, db.name), resolved.addrs)
                    .with_protocol(protocol),
            );
            let svc_id = format!("{}/{}", db.namespace, db.name);
            // Distinct kind prefix so the controller-wide `--ingress-default-backend`
            // doesn't collide with any specific Ingress's `spec.defaultBackend`
            // (which uses `ingress/<ns>/<name>:default`).
            let metric_route_id: Arc<str> = Arc::from(format!(
                "ingress-default-backend/{}/{}",
                db.namespace, db.name
            ));
            for port in [ingress_ports.http, ingress_ports.https]
                .into_iter()
                .flatten()
            {
                let e = Arc::new(
                    RouteEntry::path_only(Arc::clone(&group), svc_id.clone(), None)
                        .with_path_pattern(Arc::from("/"))
                        .with_metric_route_id(Arc::clone(&metric_route_id)),
                );
                builder.for_port(port).catchall().add_prefix_route("/", e);
            }
        }
    }

    publish_routes(
        shared,
        builder,
        "ingress",
        ingresses.len(),
        ownership.ingress_classes.len(),
    )
}

/// Generic publish step: compile a builder, log conflicts, swap the snapshot.
///
/// Returns `true` if the build succeeded; `false` leaves the previous snapshot
/// in place and lets the failure surface in logs without taking the proxy down.
fn publish_routes<K>(
    shared: &Shared<RoutingTable<K>>,
    builder: RoutingTableBuilder<K>,
    table_label: &'static str,
    source_count: usize,
    owned_owner_count: usize,
) -> bool {
    match builder.build() {
        Ok(table) => {
            for c in table.conflicts() {
                tracing::warn!(
                    port = c.port,
                    host = %c.host,
                    path = %c.path,
                    kind = c.kind.as_str(),
                    rejected_group = %c.rejected_group,
                    table = table_label,
                    "Route conflict: path already claimed by an earlier rule — ignoring"
                );
            }
            shared.store(Arc::new(table));
            tracing::info!(
                table = table_label,
                sources = source_count,
                owners = owned_owner_count,
                "Routing table rebuilt"
            );
            true
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                table = table_label,
                "Routing table build failed — retaining previous table"
            );
            false
        }
    }
}

/// Build and publish the TLS cert store; returns per-gateway listener health for further use.
/// Build the per-Gateway TLS listener health map plus update the shared TLS
/// cert store.
///
/// `skip_cut_over` drops Gateways whose `DedicatedProxyReady=True` condition
/// matches their current generation — appropriate for the *shared* reconciler
/// (the shared pool yields these listeners to the dedicated proxy that owns
/// them). The dedicated reconciler must pass `false`: the Gateway it serves
/// IS the cut-over Gateway, and skipping it leaves the dedicated subprocess
/// with no listener specs and no bound listener.
pub(super) fn build_tls(
    stores: &ReflectorStores<'_>,
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    tls_shared: &SharedTlsStore,
    skip_cut_over: bool,
) -> HashMap<ObjectKey, GatewayListenerHealth> {
    let mut tls_builder = TlsStoreBuilder::new();
    for ingress in ingresses {
        IngressReconciler::reconcile_tls(
            ingress,
            stores.secrets,
            ownership.ingress_classes,
            ownership.default_ingress_class,
            &mut tls_builder,
        );
    }

    let mut gateway_tls_health: HashMap<ObjectKey, GatewayListenerHealth> = HashMap::new();
    for gw in stores.gateways.state() {
        if !ownership
            .gateway_classes
            .contains(&gw.spec.gateway_class_name)
        {
            continue;
        }
        // Cut-over Gateways (#210) don't contribute TLS certs to the shared
        // store — the dedicated proxy terminates their TLS instead. The
        // dedicated reconciler passes `skip_cut_over = false` because its
        // target Gateway IS cut over and it must still bind its listener.
        if skip_cut_over && gateway_is_cut_over(&gw) {
            continue;
        }
        let ns = gw.metadata.namespace.clone().unwrap_or_default();
        let name = gw.metadata.name.clone().unwrap_or_default();
        let health = GatewayApiReconciler::reconcile_tls(
            &gw,
            stores.secrets,
            ownership.cert_grants,
            &mut tls_builder,
        );
        gateway_tls_health.insert(ObjectKey::new(ns, name), health);
    }

    let tls_store = tls_builder.build();
    let certs = tls_store.cert_count();
    let current = tls_shared.load();
    if *current != tls_store {
        tracing::debug!(certs, "TLS cert store swapped");
        tls_shared.store(Arc::new(tls_store));
    } else {
        tracing::trace!(certs, "TLS cert store unchanged, skip swap");
    }

    gateway_tls_health
}

/// Returns true iff the Gateway has been cut over to a dedicated proxy and
/// the shared pool should not serve its routes (#210).
///
/// "Cut over" means the controller's provisioning operator (#208 + #210) has
/// published `gateway.coxswain-labs.dev/DedicatedProxyReady=True` with an
/// `observed_generation` that reflects the Gateway's current spec
/// generation. The generation guard prevents a stale True condition (from
/// before a spec change that may have demoted the Gateway out of dedicated
/// mode) from incorrectly filtering the Gateway out — the operator must
/// observe the new generation and re-publish the condition before the
/// shared pool drops it again.
pub(super) fn gateway_is_cut_over(gw: &Gateway) -> bool {
    const CONDITION_TYPE: &str = "gateway.coxswain-labs.dev/DedicatedProxyReady";
    let expected_gen = gw.metadata.generation.unwrap_or(0);
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == CONDITION_TYPE))
        .is_some_and(|c| c.status == "True" && c.observed_generation.unwrap_or(0) >= expected_gen)
}

/// Increment `attached_routes` counters for each gateway listener whose hostname
/// intersects with the route's hostnames. Only owned gateways are counted.
pub(super) fn count_attached_routes(
    routes: &[Arc<HttpRoute>],
    owned_gateways: &HashSet<ObjectKey>,
    gateway_tls_health: &mut HashMap<ObjectKey, GatewayListenerHealth>,
) {
    for route in routes {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_hostnames: Vec<&str> = route
            .spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();

        for pr in route.spec.parent_refs.as_deref().unwrap_or(&[]) {
            let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
            let gw_name = pr.name.as_str();
            let key = ObjectKey::new(gw_ns, gw_name);
            if !owned_gateways.contains(&key) {
                continue;
            }
            if let Some(health) = gateway_tls_health.get_mut(&key) {
                let pr_port = pr.port.map(|p| p as u16);
                if let Some(sn) = pr.section_name.as_deref() {
                    let Some(info) = health.listeners.get_mut(sn) else {
                        continue;
                    };
                    if gw_ns != route_ns && !info.allows_all_namespaces {
                        continue;
                    }
                    if let Some(port) = pr_port
                        && info.port != port
                    {
                        continue;
                    }
                    if hostnames_intersect(&route_hostnames, &info.hostname) {
                        info.attached_routes += 1;
                    }
                } else {
                    let listener_names: Vec<String> = health.listeners.keys().cloned().collect();
                    for ln in listener_names {
                        let Some(info) = health.listeners.get_mut(&ln) else {
                            continue;
                        };
                        if let Some(p) = pr_port
                            && info.port != p
                        {
                            continue;
                        }
                        if gw_ns != route_ns && !info.allows_all_namespaces {
                            continue;
                        }
                        if hostnames_intersect(&route_hostnames, &info.hostname) {
                            info.attached_routes += 1;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::gateway_is_cut_over;
    use crate::gw_types::v::gateways::{Gateway, GatewayStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
    use kube::api::ObjectMeta;

    fn cond(type_: &str, status: &str, observed_gen: i64) -> Condition {
        Condition {
            type_: type_.into(),
            status: status.into(),
            reason: "x".into(),
            message: String::new(),
            observed_generation: Some(observed_gen),
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
        }
    }

    fn gw(generation: i64, conditions: Vec<Condition>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some("gw".into()),
                namespace: Some("ns".into()),
                generation: Some(generation),
                ..Default::default()
            },
            spec: Default::default(),
            status: Some(GatewayStatus {
                conditions: Some(conditions),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn no_status_means_not_cut_over() {
        let gw = Gateway {
            metadata: ObjectMeta {
                name: Some("gw".into()),
                namespace: Some("ns".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: Default::default(),
            status: None,
        };
        assert!(!gateway_is_cut_over(&gw));
    }

    #[test]
    fn no_dedicated_proxy_ready_condition_means_not_cut_over() {
        let gw = gw(1, vec![cond("Accepted", "True", 1)]);
        assert!(!gateway_is_cut_over(&gw));
    }

    #[test]
    fn dedicated_proxy_ready_false_means_not_cut_over() {
        let gw = gw(
            1,
            vec![cond(
                "gateway.coxswain-labs.dev/DedicatedProxyReady",
                "False",
                1,
            )],
        );
        assert!(!gateway_is_cut_over(&gw));
    }

    #[test]
    fn dedicated_proxy_ready_true_with_current_gen_means_cut_over() {
        let gw = gw(
            2,
            vec![cond(
                "gateway.coxswain-labs.dev/DedicatedProxyReady",
                "True",
                2,
            )],
        );
        assert!(gateway_is_cut_over(&gw));
    }

    #[test]
    fn stale_true_condition_does_not_cut_over() {
        // metadata.generation=2 but condition observed gen=1 → the condition
        // reflects an older spec; do not filter the Gateway out until the
        // operator has re-published the condition against the new spec.
        let gw = gw(
            2,
            vec![cond(
                "gateway.coxswain-labs.dev/DedicatedProxyReady",
                "True",
                1,
            )],
        );
        assert!(!gateway_is_cut_over(&gw));
    }

    use crate::reconciler::{IngressDefaultBackend, IngressDefaultBackendParseError};

    #[test]
    fn happy_path() {
        let b: IngressDefaultBackend = "default/echo:80".parse().unwrap();
        assert_eq!(b.namespace, "default");
        assert_eq!(b.name, "echo");
        assert_eq!(b.port, 80);
    }

    #[test]
    fn missing_colon_returns_missing_port() {
        let err = "default/echo".parse::<IngressDefaultBackend>().unwrap_err();
        assert!(matches!(err, IngressDefaultBackendParseError::MissingPort));
    }

    #[test]
    fn missing_slash_returns_missing_namespace() {
        let err = "defaultecho:80"
            .parse::<IngressDefaultBackend>()
            .unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::MissingNamespace
        ));
    }

    #[test]
    fn empty_namespace_returns_empty_component() {
        let err = "/echo:80".parse::<IngressDefaultBackend>().unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::EmptyComponent
        ));
    }

    #[test]
    fn empty_name_returns_empty_component() {
        let err = "default/:80".parse::<IngressDefaultBackend>().unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::EmptyComponent
        ));
    }

    #[test]
    fn non_numeric_port_returns_invalid_port() {
        let err = "default/echo:abc"
            .parse::<IngressDefaultBackend>()
            .unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::InvalidPort(s) if s == "abc"
        ));
    }

    #[test]
    fn port_overflow_returns_invalid_port() {
        let err = "default/echo:2147483648"
            .parse::<IngressDefaultBackend>()
            .unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::InvalidPort(_)
        ));
    }

    #[test]
    fn colon_in_service_name_uses_last_colon_as_port_separator() {
        // rsplit_once(':') splits on the last colon; "ns/svc:extra:80" → ns_name="ns/svc:extra", port=80
        let b: IngressDefaultBackend = "ns/svc:extra:80".parse().unwrap();
        assert_eq!(b.namespace, "ns");
        assert_eq!(b.name, "svc:extra");
        assert_eq!(b.port, 80);
    }
}
