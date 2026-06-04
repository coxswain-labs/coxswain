use crate::gateway_api::hostnames_intersect;
use crate::keys::ListenerKey;
use crate::tls::{GatewayListenerHealth, SharedGatewayListenerHealth, SharedHttpRouteHealth};
use crate::{endpoints, gateway_api::GatewayApiReconciler, ingress::IngressReconciler};
use async_trait::async_trait;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_core::reference_grants::ReferenceGrantKey;
use coxswain_core::routing::{RouteEntry, RoutingTableBuilder, SharedRoutingTable, Upstream};
use coxswain_core::tls::{SharedTlsStore, TlsStoreBuilder};
use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use gateway_api::apis::standard::referencegrants::ReferenceGrant;
use k8s_openapi::api::core::v1::{Secret, Service};
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
use tokio::sync::Notify;
use tokio::task::JoinSet;

/// A parsed reference to the controller-wide ingress default backend service.
/// Set via `--ingress-default-backend=<namespace>/<service>:<port>`.
#[derive(Clone, Debug)]
pub struct IngressDefaultBackend {
    pub namespace: String,
    pub name: String,
    pub port: i32,
}

impl std::str::FromStr for IngressDefaultBackend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns_name, port_str) = s.rsplit_once(':').ok_or_else(|| {
            format!("missing port in '{s}'; expected <namespace>/<service>:<port>")
        })?;
        let (namespace, name) = ns_name.split_once('/').ok_or_else(|| {
            format!("missing namespace in '{s}'; expected <namespace>/<service>:<port>")
        })?;
        let port: i32 = port_str
            .parse()
            .map_err(|_| format!("invalid port '{port_str}'; expected an integer"))?;
        if namespace.is_empty() || name.is_empty() {
            return Err(format!(
                "namespace and service name must not be empty in '{s}'"
            ));
        }
        Ok(IngressDefaultBackend {
            namespace: namespace.to_string(),
            name: name.to_string(),
            port,
        })
    }
}

/// Pingora background service that maintains reflector-backed stores for
/// `HTTPRoute`, `Ingress`, `IngressClass`, `Gateway`, `GatewayClass`, and
/// `EndpointSlice`, and rebuilds the routing table whenever any of them change
/// — with a 500 ms trailing-edge debounce to coalesce burst updates (e.g.
/// rolling deploys).
pub struct Reconciler {
    routes: SharedRoutingTable,
    tls: SharedTlsStore,
    tls_health: SharedGatewayListenerHealth,
    route_health: SharedHttpRouteHealth,
    owned_gateways: OwnedGateways,
    controller_name: String,
    /// When set, scope namespaced watches to this namespace. When `None`, watch cluster-wide.
    watch_namespace: Option<String>,
    ingress_default_backend: Option<IngressDefaultBackend>,
}

impl Reconciler {
    pub fn new(
        routes: SharedRoutingTable,
        tls: SharedTlsStore,
        tls_health: SharedGatewayListenerHealth,
        owned_gateways: OwnedGateways,
        controller_name: String,
        watch_namespace: Option<String>,
        ingress_default_backend: Option<IngressDefaultBackend>,
    ) -> Self {
        Self {
            routes,
            tls,
            tls_health,
            route_health: SharedHttpRouteHealth::new(),
            owned_gateways,
            controller_name,
            watch_namespace,
            ingress_default_backend,
        }
    }

    /// Returns the shared route health handle so other services (e.g. the Controller)
    /// can subscribe to updates published by this reconciler.
    pub fn route_health(&self) -> SharedHttpRouteHealth {
        self.route_health.clone()
    }
}

struct ReconcilerConfig {
    controller_name: String,
    watch_namespace: Option<String>,
    ingress_default_backend: Option<IngressDefaultBackend>,
}

fn scoped_api<T>(client: Client, ns: Option<&str>) -> Api<T>
where
    T: kube::Resource<Scope = kube::core::NamespaceResourceScope>,
    T::DynamicType: Default,
{
    match ns {
        Some(ns) => Api::namespaced(client, ns),
        None => Api::all(client),
    }
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
        let client = Client::try_default()
            .await
            .expect("K8s client for reconciler");
        let config = ReconcilerConfig {
            controller_name: self.controller_name.clone(),
            watch_namespace: self.watch_namespace.clone(),
            ingress_default_backend: self.ingress_default_backend.clone(),
        };
        let mut set = spawn_tasks(
            client,
            self.routes.clone(),
            self.tls.clone(),
            self.tls_health.clone(),
            self.route_health.clone(),
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
    owned_gateways: OwnedGateways,
    config: ReconcilerConfig,
) -> JoinSet<()> {
    let ReconcilerConfig {
        controller_name,
        watch_namespace,
        ingress_default_backend,
    } = config;
    let (route_reader, route_writer) = reflector::store::<HTTPRoute>();
    let (ingress_reader, ingress_writer) = reflector::store::<Ingress>();
    let (class_reader, class_writer) = reflector::store::<IngressClass>();
    let (gateway_reader, gateway_writer) = reflector::store::<Gateway>();
    let (gateway_class_reader, gateway_class_writer) = reflector::store::<GatewayClass>();
    let (slice_reader, slice_writer) = reflector::store::<EndpointSlice>();
    let (grant_reader, grant_writer) = reflector::store::<ReferenceGrant>();
    let (secret_reader, secret_writer) = reflector::store::<Secret>();
    let (service_reader, service_writer) = reflector::store::<Service>();
    let notify = Arc::new(Notify::new());
    let mut set = JoinSet::new();
    let ns = watch_namespace.as_deref();

    spawn_reflector(
        &mut set,
        route_writer,
        scoped_api::<HTTPRoute>(client.clone(), ns),
        watcher::Config::default(),
        Arc::clone(&notify),
        "HTTPRoute",
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
        scoped_api::<Service>(client, ns),
        watcher::Config::default(),
        Arc::clone(&notify),
        "Service",
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
            rebuild(
                &route_reader,
                &ingress_reader,
                &class_reader,
                &gateway_reader,
                &gateway_class_reader,
                &slice_reader,
                &service_reader,
                &grant_reader,
                &secret_reader,
                &controller_name,
                &owned_gateways,
                ingress_default_backend.as_ref(),
                &routes,
                &tls,
                &tls_health,
                &route_health,
            );
        }
    });

    set
}

#[allow(clippy::too_many_arguments)]
fn rebuild(
    route_store: &reflector::Store<HTTPRoute>,
    ingress_store: &reflector::Store<Ingress>,
    class_store: &reflector::Store<IngressClass>,
    gateway_store: &reflector::Store<Gateway>,
    gateway_class_store: &reflector::Store<GatewayClass>,
    slice_store: &reflector::Store<EndpointSlice>,
    service_store: &reflector::Store<Service>,
    grant_store: &reflector::Store<ReferenceGrant>,
    secret_store: &reflector::Store<Secret>,
    controller_name: &str,
    owned_gateways_handle: &OwnedGateways,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    shared: &SharedRoutingTable,
    tls_shared: &SharedTlsStore,
    tls_health_shared: &SharedGatewayListenerHealth,
    route_health_shared: &SharedHttpRouteHealth,
) {
    let routes = route_store.state();
    let ingresses = ingress_store.state();

    let (owned_ingress_classes, owned_default_ingress_class, owned_gateway_classes, owned_gateways) =
        compute_ownership(
            class_store,
            gateway_class_store,
            gateway_store,
            controller_name,
            owned_gateways_handle,
        );

    let (backend_grants, cert_grants) = flatten_grants(&grant_store.state());

    tracing::debug!(
        http_routes = routes.len(),
        ingresses = ingresses.len(),
        owned_ingress_classes = owned_ingress_classes.len(),
        owned_gateways = owned_gateways.len(),
        "Rebuilding routing table"
    );

    build_routes(
        &routes,
        &ingresses,
        &owned_ingress_classes,
        owned_default_ingress_class.as_deref(),
        &owned_gateways,
        &backend_grants,
        gateway_store,
        &owned_gateway_classes,
        slice_store,
        service_store,
        ingress_default_backend,
        shared,
    );

    let mut gateway_tls_health = build_tls(
        &ingresses,
        gateway_store,
        &owned_gateway_classes,
        &owned_ingress_classes,
        owned_default_ingress_class.as_deref(),
        &cert_grants,
        secret_store,
        tls_shared,
    );

    count_attached_routes(&routes, &owned_gateways, &mut gateway_tls_health);
    tls_health_shared.store_and_notify(gateway_tls_health);

    let gateways = gateway_store.state();
    let route_health_map = GatewayApiReconciler::compute_route_health(
        &routes,
        &gateways,
        &owned_gateways,
        &backend_grants,
        service_store,
    );
    route_health_shared.store_and_notify(route_health_map);
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
#[allow(clippy::too_many_arguments)]
fn build_routes(
    routes: &[Arc<HTTPRoute>],
    ingresses: &[Arc<Ingress>],
    owned_ingress_classes: &HashSet<String>,
    owned_default_ingress_class: Option<&str>,
    owned_gateways: &HashSet<ObjectKey>,
    backend_grants: &GrantSet,
    gateway_store: &reflector::Store<Gateway>,
    owned_gateway_classes: &HashSet<String>,
    slice_store: &reflector::Store<EndpointSlice>,
    service_store: &reflector::Store<Service>,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    shared: &SharedRoutingTable,
) {
    // Precompute ListenerKey → hostname so reconcile() can scope routes without
    // spec.hostnames to their parent listener's hostname.
    let listener_hostname_map: HashMap<ListenerKey, String> = gateway_store
        .state()
        .into_iter()
        .filter(|g| owned_gateway_classes.contains(&g.spec.gateway_class_name))
        .flat_map(|g| {
            let ns = g.metadata.namespace.clone().unwrap_or_default();
            let name = g.metadata.name.clone().unwrap_or_default();
            g.spec
                .listeners
                .iter()
                .map(|l| {
                    (
                        ListenerKey::new(ns.clone(), name.clone(), l.name.clone()),
                        l.hostname.clone().unwrap_or_default(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let mut builder = RoutingTableBuilder::new();
    for route in routes {
        GatewayApiReconciler::reconcile(
            route,
            slice_store,
            service_store,
            owned_gateways,
            backend_grants,
            &listener_hostname_map,
            &mut builder,
        );
    }
    for ingress in ingresses {
        IngressReconciler::reconcile(
            ingress,
            slice_store,
            service_store,
            owned_ingress_classes,
            owned_default_ingress_class,
            &mut builder,
        );
    }

    // Install the controller-wide default backend on the global catchall. Thanks to
    // the catchall fall-through in RoutingTable::route, this also serves path-misses
    // on hosts that did not declare their own spec.defaultBackend. Per-Ingress defaults
    // always win because they are installed on the host router (matched first).
    if let Some(db) = ingress_default_backend {
        let addrs =
            endpoints::resolve(&db.namespace, &db.name, db.port, slice_store, service_store);
        if addrs.is_empty() {
            tracing::warn!(
                svc = %format!("{}/{}", db.namespace, db.name),
                "No ready endpoints for --ingress-default-backend — skipping"
            );
        } else {
            let upstream = Arc::new(Upstream::new(
                format!("{}/{}", db.namespace, db.name),
                addrs,
            ));
            let e = Arc::new(RouteEntry::path_only(
                upstream,
                format!("{}/{}", db.namespace, db.name),
                None,
            ));
            builder.catchall().add_prefix_route("/", e);
        }
    }

    match builder.build() {
        Ok(table) => {
            for c in table.conflicts() {
                tracing::warn!(
                    host = %c.host,
                    path = %c.path,
                    kind = c.kind.as_str(),
                    rejected_upstream = %c.rejected_upstream,
                    "Route conflict: path already claimed by an earlier rule — ignoring"
                );
            }
            shared.store(Arc::new(table));
            tracing::info!(
                http_routes = routes.len(),
                ingresses = ingresses.len(),
                owned_ingress_classes = owned_ingress_classes.len(),
                owned_gateways = owned_gateways.len(),
                "Routing table rebuilt"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Routing table build failed — retaining previous table");
        }
    }
}

/// Build and publish the TLS cert store; returns per-gateway listener health for further use.
#[allow(clippy::too_many_arguments)]
fn build_tls(
    ingresses: &[Arc<Ingress>],
    gateway_store: &reflector::Store<Gateway>,
    owned_gateway_classes: &HashSet<String>,
    owned_ingress_classes: &HashSet<String>,
    owned_default_ingress_class: Option<&str>,
    cert_grants: &GrantSet,
    secret_store: &reflector::Store<Secret>,
    tls_shared: &SharedTlsStore,
) -> HashMap<ObjectKey, GatewayListenerHealth> {
    let mut tls_builder = TlsStoreBuilder::new();
    for ingress in ingresses {
        IngressReconciler::reconcile_tls(
            ingress,
            secret_store,
            owned_ingress_classes,
            owned_default_ingress_class,
            &mut tls_builder,
        );
    }

    let mut gateway_tls_health: HashMap<ObjectKey, GatewayListenerHealth> = HashMap::new();
    for gw in gateway_store.state() {
        if !owned_gateway_classes.contains(&gw.spec.gateway_class_name) {
            continue;
        }
        let ns = gw.metadata.namespace.clone().unwrap_or_default();
        let name = gw.metadata.name.clone().unwrap_or_default();
        let health =
            GatewayApiReconciler::reconcile_tls(&gw, secret_store, cert_grants, &mut tls_builder);
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
    routes: &[Arc<HTTPRoute>],
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
                    let allows_all = health
                        .listener_allows_all_namespaces
                        .get(sn)
                        .copied()
                        .unwrap_or(false);
                    if gw_ns != route_ns && !allows_all {
                        continue;
                    }
                    if let Some(port) = pr_port
                        && health.listener_ports.get(sn).copied().unwrap_or(0) != port
                    {
                        continue;
                    }
                    if let Some(listener_hn) = health.listener_hostnames.get(sn)
                        && hostnames_intersect(&route_hostnames, listener_hn)
                    {
                        *health.attached_routes.entry(sn.to_string()).or_insert(0) += 1;
                    }
                } else {
                    let listeners: Vec<(String, String, bool)> = health
                        .listener_hostnames
                        .iter()
                        .filter_map(|(n, hn)| {
                            if let Some(p) = pr_port
                                && health.listener_ports.get(n).copied().unwrap_or(0) != p
                            {
                                return None;
                            }
                            let allows = health
                                .listener_allows_all_namespaces
                                .get(n)
                                .copied()
                                .unwrap_or(false);
                            Some((n.clone(), hn.clone(), allows))
                        })
                        .collect();
                    for (ln, listener_hn, allows_all) in listeners {
                        if gw_ns != route_ns && !allows_all {
                            continue;
                        }
                        if hostnames_intersect(&route_hostnames, &listener_hn) {
                            *health.attached_routes.entry(ln).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }
}
