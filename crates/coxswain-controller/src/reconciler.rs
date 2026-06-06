//! Debounced reconciler: watches all Kubernetes resources and rebuilds the routing
//! and TLS tables whenever any of them change.

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
use crate::tls::{
    GatewayListenerHealth, SharedBackendTlsPolicyHealth, SharedGatewayListenerHealth,
    SharedHttpRouteHealth,
};
use crate::{
    endpoints,
    ingress::{IngressPorts, IngressReconciler},
};
use async_trait::async_trait;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_core::reference_grants::ReferenceGrantKey;
use coxswain_core::routing::{BackendGroup, RouteEntry, RoutingTableBuilder, SharedRoutingTable};
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
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::task::JoinSet;

/// Error returned when parsing `--ingress-default-backend`.
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

/// Optional configuration for a [`Reconciler`].
#[non_exhaustive]
#[derive(Default)]
pub struct ReconcilerOptions {
    /// When set, scope namespaced watches to this namespace. When `None`, watch cluster-wide.
    pub watch_namespace: Option<String>,
    /// Controller-wide default backend for Ingress traffic with no matching rule.
    pub ingress_default_backend: Option<IngressDefaultBackend>,
    /// Ports on which Ingress routes are served.
    pub ingress_ports: IngressPorts,
}

/// Pingora background service that maintains reflector-backed stores for
/// `HTTPRoute`, `Ingress`, `IngressClass`, `Gateway`, `GatewayClass`,
/// `BackendTLSPolicy`, `ConfigMap`, and `EndpointSlice`, and rebuilds the routing
/// table whenever any of them change — with a 500 ms trailing-edge debounce to
/// coalesce burst updates (e.g. rolling deploys).
pub struct Reconciler {
    routes: SharedRoutingTable,
    tls: SharedTlsStore,
    tls_health: SharedGatewayListenerHealth,
    route_health: SharedHttpRouteHealth,
    policy_health: SharedBackendTlsPolicyHealth,
    owned_gateways: OwnedGateways,
    controller_name: String,
    opts: ReconcilerOptions,
}

impl Reconciler {
    /// Construct a new reconciler (does not start the watch loop).
    pub fn new(
        routes: SharedRoutingTable,
        tls: SharedTlsStore,
        tls_health: SharedGatewayListenerHealth,
        owned_gateways: OwnedGateways,
        controller_name: String,
        opts: ReconcilerOptions,
    ) -> Self {
        Self {
            routes,
            tls,
            tls_health,
            route_health: SharedHttpRouteHealth::new(),
            policy_health: SharedBackendTlsPolicyHealth::new(),
            owned_gateways,
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
}

struct ReflectorStores<'a> {
    routes: &'a reflector::Store<HttpRoute>,
    ingresses: &'a reflector::Store<Ingress>,
    ingress_classes: &'a reflector::Store<IngressClass>,
    gateways: &'a reflector::Store<Gateway>,
    gateway_classes: &'a reflector::Store<GatewayClass>,
    slices: &'a reflector::Store<EndpointSlice>,
    services: &'a reflector::Store<Service>,
    grants: &'a reflector::Store<ReferenceGrant>,
    secrets: &'a reflector::Store<Secret>,
    /// `BackendTLSPolicy` resources in scope (namespaced per `watch_namespace`).
    policies: &'a reflector::Store<BackendTlsPolicy>,
    /// All ConfigMaps in scope — used to resolve `caCertificateRefs`.
    /// Unlike the `Secret` reflector (which uses a type= field selector), ConfigMaps
    /// have no equivalent filter; all CMs in scope are watched. A follow-up will
    /// switch to per-policy informers to bound memory use in large clusters.
    configmaps: &'a reflector::Store<ConfigMap>,
}

struct SharedOutputs<'a> {
    routes: &'a SharedRoutingTable,
    tls: &'a SharedTlsStore,
    tls_health: &'a SharedGatewayListenerHealth,
    route_health: &'a SharedHttpRouteHealth,
    policy_health: &'a SharedBackendTlsPolicyHealth,
}

struct Ownership<'a> {
    ingress_classes: &'a HashSet<String>,
    default_ingress_class: Option<&'a str>,
    gateways: &'a HashSet<ObjectKey>,
    gateway_classes: &'a HashSet<String>,
    backend_grants: &'a GrantSet,
    cert_grants: &'a GrantSet,
}

fn spawn_reflector<T>(
    set: &mut JoinSet<()>,
    writer: reflector::store::Writer<T>,
    api: Api<T>,
    config: watcher::Config,
    notify: Arc<Notify>,
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
    set.spawn(async move {
        let stream = reflector::reflector(writer, watcher(api, config).default_backoff());
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(_) => notify.notify_one(),
                Err(e) => tracing::warn!(error = %e, "{label} reflector error"),
            }
        }
    });
}

#[async_trait]
impl BackgroundService for Reconciler {
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
        };
        let mut set = spawn_tasks(
            client,
            self.routes.clone(),
            self.tls.clone(),
            self.tls_health.clone(),
            self.route_health.clone(),
            self.policy_health.clone(),
            self.owned_gateways.clone(),
            config,
        )
        .await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                res = set.join_next() => match res {
                    Some(Ok(())) => tracing::warn!("Reconciler task exited unexpectedly"),
                    Some(Err(e)) => tracing::error!(error = %e, "Reconciler task panicked"),
                    None => break,
                },
            }
        }
    }
}

async fn spawn_tasks(
    client: Client,
    routes: SharedRoutingTable,
    tls: SharedTlsStore,
    tls_health: SharedGatewayListenerHealth,
    route_health: SharedHttpRouteHealth,
    policy_health: SharedBackendTlsPolicyHealth,
    owned_gateways: OwnedGateways,
    config: ReconcilerConfig,
) -> JoinSet<()> {
    let ReconcilerConfig {
        controller_name,
        watch_namespace,
        ingress_default_backend,
        ingress_ports,
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
        Arc::clone(&notify),
        "HttpRoute",
    );
    spawn_reflector(
        &mut set,
        ingress_writer,
        scoped_api::<Ingress>(client.clone(), ns),
        watcher::Config::default(),
        Arc::clone(&notify),
        "Ingress",
    );
    spawn_reflector(
        &mut set,
        class_writer,
        Api::<IngressClass>::all(client.clone()),
        watcher::Config::default(),
        Arc::clone(&notify),
        "IngressClass",
    );
    spawn_reflector(
        &mut set,
        gateway_writer,
        scoped_api::<Gateway>(client.clone(), ns),
        watcher::Config::default(),
        Arc::clone(&notify),
        "Gateway",
    );
    spawn_reflector(
        &mut set,
        gateway_class_writer,
        Api::<GatewayClass>::all(client.clone()),
        watcher::Config::default(),
        Arc::clone(&notify),
        "GatewayClass",
    );
    spawn_reflector(
        &mut set,
        slice_writer,
        scoped_api::<EndpointSlice>(client.clone(), ns),
        watcher::Config::default(),
        Arc::clone(&notify),
        "EndpointSlice",
    );
    spawn_reflector(
        &mut set,
        grant_writer,
        scoped_api::<ReferenceGrant>(client.clone(), ns),
        watcher::Config::default(),
        Arc::clone(&notify),
        "ReferenceGrant",
    );
    // Field-selector scoped to `type=kubernetes.io/tls` to avoid pulling every Secret into memory.
    spawn_reflector(
        &mut set,
        secret_writer,
        scoped_api::<Secret>(client.clone(), ns),
        watcher::Config::default().fields("type=kubernetes.io/tls"),
        Arc::clone(&notify),
        "Secret",
    );
    // Used to resolve targetPort for backends where servicePort ≠ targetPort.
    spawn_reflector(
        &mut set,
        service_writer,
        scoped_api::<Service>(client.clone(), ns),
        watcher::Config::default(),
        Arc::clone(&notify),
        "Service",
    );
    spawn_reflector(
        &mut set,
        policy_writer,
        scoped_api::<BackendTlsPolicy>(client.clone(), ns),
        watcher::Config::default(),
        Arc::clone(&notify),
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
        Arc::clone(&notify),
        "ConfigMap",
    );

    // --- Trailing-edge debounce + rebuild ---
    //
    // Waits for the first notification, then races subsequent notifications
    // against a 500 ms timer. Each new notification resets the timer. When
    // the timer expires uninterrupted, the full routing table is rebuilt from
    // the current store snapshots — never from the API server.
    set.spawn(async move {
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
                routes: &routes,
                tls: &tls,
                tls_health: &tls_health,
                route_health: &route_health,
                policy_health: &policy_health,
            };
            rebuild(
                &stores,
                &controller_name,
                &owned_gateways,
                ingress_default_backend.as_ref(),
                ingress_ports,
                &outputs,
            );
        }
    });

    set
}

fn rebuild(
    stores: &ReflectorStores<'_>,
    controller_name: &str,
    owned_gateways_handle: &OwnedGateways,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    outputs: &SharedOutputs<'_>,
) {
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

    let ownership = Ownership {
        ingress_classes: &owned_ingress_classes,
        default_ingress_class: owned_default_ingress_class.as_deref(),
        gateways: &owned_gateways,
        gateway_classes: &owned_gateway_classes,
        backend_grants: &backend_grants,
        cert_grants: &cert_grants,
    };

    let (policy_index, mut policy_health_map) =
        build_backend_tls_index(stores.policies, stores.configmaps);

    build_routes(
        stores,
        &routes,
        &ingresses,
        &ownership,
        ingress_default_backend,
        ingress_ports,
        &policy_index,
        outputs.routes,
    );

    let mut gateway_tls_health = build_tls(stores, &ingresses, &ownership, outputs.tls);

    count_attached_routes(&routes, &owned_gateways, &mut gateway_tls_health);
    outputs.tls_health.store_and_notify(gateway_tls_health);

    let gateways = stores.gateways.state();
    let route_health_map = GatewayApiReconciler::compute_route_health(
        &routes,
        &gateways,
        &owned_gateways,
        &backend_grants,
        stores.services,
    );
    outputs.route_health.store_and_notify(route_health_map);

    // Compute per-policy ancestor lists and merge with the validity health from index build.
    let ancestor_health =
        GatewayApiReconciler::compute_policy_health(&policy_index, &routes, &owned_gateways);
    for (key, ah) in ancestor_health {
        let entry = policy_health_map.entry(key).or_default();
        entry.ancestors = ah.ancestors;
    }
    outputs.policy_health.store_and_notify(policy_health_map);
}

/// Compute which IngressClasses, GatewayClasses, and Gateways are owned by this controller.
/// Publishes the owned-gateways snapshot to `owned_gateways_handle` as a side effect.
/// The fourth element of the returned tuple is the name of the owned default IngressClass (if any).
fn compute_ownership(
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

type GrantSet = HashSet<ReferenceGrantKey>;

/// Flatten `ReferenceGrant` objects into two O(1) sets for cross-namespace ref checks:
/// - `backend_grants`: HTTPRoute → Service (used by `GatewayApiReconciler::reconcile`)
/// - `cert_grants`: Gateway → Secret (used by `GatewayApiReconciler::reconcile_tls`)
fn flatten_grants(grants: &[Arc<ReferenceGrant>]) -> (GrantSet, GrantSet) {
    fn flatten(grants: &[Arc<ReferenceGrant>], from_kind: &str, to_kind: &str) -> GrantSet {
        grants
            .iter()
            .filter_map(|grant| {
                let to_ns = grant.metadata.namespace.clone()?;
                Some((grant, to_ns))
            })
            .flat_map(|(grant, to_ns)| {
                let from_entries: Vec<_> = grant
                    .spec
                    .from
                    .iter()
                    .filter(|f| f.group == "gateway.networking.k8s.io" && f.kind == from_kind)
                    .map(|f| f.namespace.clone())
                    .collect();
                let to_entries: Vec<_> = grant
                    .spec
                    .to
                    .iter()
                    .filter(|t| (t.group.is_empty() || t.group == "core") && t.kind == to_kind)
                    .map(|t| t.name.clone())
                    .collect();
                from_entries.into_iter().flat_map(move |from_ns| {
                    let to_ns = to_ns.clone();
                    to_entries
                        .clone()
                        .into_iter()
                        .map(move |to_name| match to_name {
                            Some(name) => {
                                ReferenceGrantKey::specific(from_ns.clone(), to_ns.clone(), name)
                            }
                            None => ReferenceGrantKey::wildcard(from_ns.clone(), to_ns.clone()),
                        })
                })
            })
            .collect()
    }

    let backend_grants = flatten(grants, "HTTPRoute", "Service");
    let cert_grants = flatten(grants, "Gateway", "Secret");
    (backend_grants, cert_grants)
}

/// Build and publish the routing table from HTTPRoutes and Ingresses.
fn build_routes(
    stores: &ReflectorStores<'_>,
    routes: &[Arc<HttpRoute>],
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    policy_index: &BackendTlsIndex,
    shared: &SharedRoutingTable,
) {
    // Precompute ListenerKey → (hostname, port) from all owned gateway listeners.
    let listener_info: HashMap<ListenerKey, ListenerBinding> = stores
        .gateways
        .state()
        .into_iter()
        .filter(|g| {
            ownership
                .gateway_classes
                .contains(&g.spec.gateway_class_name)
        })
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

    let mut builder = RoutingTableBuilder::new();
    for route in routes {
        GatewayApiReconciler::reconcile(
            route,
            stores.slices,
            stores.services,
            ownership.gateways,
            ownership.backend_grants,
            &listener_info,
            policy_index,
            &mut builder,
        );
    }
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
            for port in [ingress_ports.http, ingress_ports.https]
                .into_iter()
                .flatten()
            {
                let e = Arc::new(RouteEntry::path_only(
                    Arc::clone(&group),
                    svc_id.clone(),
                    None,
                ));
                builder.for_port(port).catchall().add_prefix_route("/", e);
            }
        }
    }

    match builder.build() {
        Ok(table) => {
            for c in table.conflicts() {
                tracing::warn!(
                    port = c.port,
                    host = %c.host,
                    path = %c.path,
                    kind = c.kind.as_str(),
                    rejected_group = %c.rejected_group,
                    "Route conflict: path already claimed by an earlier rule — ignoring"
                );
            }
            shared.store(Arc::new(table));
            tracing::info!(
                http_routes = routes.len(),
                ingresses = ingresses.len(),
                owned_ingress_classes = ownership.ingress_classes.len(),
                owned_gateways = ownership.gateways.len(),
                "Routing table rebuilt"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Routing table build failed — retaining previous table");
        }
    }
}

/// Build and publish the TLS cert store; returns per-gateway listener health for further use.
fn build_tls(
    stores: &ReflectorStores<'_>,
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    tls_shared: &SharedTlsStore,
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

/// Increment `attached_routes` counters for each gateway listener whose hostname
/// intersects with the route's hostnames. Only owned gateways are counted.
fn count_attached_routes(
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
