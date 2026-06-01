use crate::{endpoints, gateway_api::GatewayApiReconciler, ingress::IngressReconciler};
use async_trait::async_trait;
use coxswain_core::ownership::OwnedGateways;
use coxswain_core::routing::{RouteEntry, RoutingTableBuilder, SharedRoutingTable, Upstream};
use coxswain_core::tls::{SharedTlsStore, TlsStoreBuilder};
use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use gateway_api::apis::standard::referencegrants::ReferenceGrant;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::{
    Client,
    api::Api,
    runtime::{WatchStreamExt, reflector, watcher},
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashSet;
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
        owned_gateways: OwnedGateways,
        controller_name: String,
        watch_namespace: Option<String>,
        ingress_default_backend: Option<IngressDefaultBackend>,
    ) -> Self {
        Self {
            routes,
            tls,
            owned_gateways,
            controller_name,
            watch_namespace,
            ingress_default_backend,
        }
    }
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

#[async_trait]
impl BackgroundService for Reconciler {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let client = Client::try_default()
            .await
            .expect("K8s client for reconciler");
        let mut set = spawn_tasks(
            client,
            self.routes.clone(),
            self.tls.clone(),
            self.owned_gateways.clone(),
            self.controller_name.clone(),
            self.watch_namespace.clone(),
            self.ingress_default_backend.clone(),
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
    owned_gateways: OwnedGateways,
    controller_name: String,
    watch_namespace: Option<String>,
    ingress_default_backend: Option<IngressDefaultBackend>,
) -> JoinSet<()> {
    let (route_reader, route_writer) = reflector::store::<HTTPRoute>();
    let (ingress_reader, ingress_writer) = reflector::store::<Ingress>();
    let (class_reader, class_writer) = reflector::store::<IngressClass>();
    let (gateway_reader, gateway_writer) = reflector::store::<Gateway>();
    let (gateway_class_reader, gateway_class_writer) = reflector::store::<GatewayClass>();
    let (slice_reader, slice_writer) = reflector::store::<EndpointSlice>();
    let (grant_reader, grant_writer) = reflector::store::<ReferenceGrant>();
    let (secret_reader, secret_writer) = reflector::store::<Secret>();
    let notify = Arc::new(Notify::new());
    let mut set = JoinSet::new();

    // --- HTTPRoute reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        let client = client.clone();
        let ns = watch_namespace.clone();
        async move {
            let stream = reflector::reflector(
                route_writer,
                watcher(
                    scoped_api::<HTTPRoute>(client, ns.as_deref()),
                    watcher::Config::default(),
                )
                .default_backoff(),
            );
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(_) => notify.notify_one(),
                    Err(e) => tracing::warn!(error = %e, "HTTPRoute reflector error"),
                }
            }
        }
    });

    // --- Ingress reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        let client = client.clone();
        let ns = watch_namespace.clone();
        async move {
            let stream = reflector::reflector(
                ingress_writer,
                watcher(
                    scoped_api::<Ingress>(client, ns.as_deref()),
                    watcher::Config::default(),
                )
                .default_backoff(),
            );
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(_) => notify.notify_one(),
                    Err(e) => tracing::warn!(error = %e, "Ingress reflector error"),
                }
            }
        }
    });

    // --- IngressClass reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        let client = client.clone();
        async move {
            let stream = reflector::reflector(
                class_writer,
                watcher(Api::<IngressClass>::all(client), watcher::Config::default())
                    .default_backoff(),
            );
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(_) => notify.notify_one(),
                    Err(e) => tracing::warn!(error = %e, "IngressClass reflector error"),
                }
            }
        }
    });

    // --- Gateway reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        let client = client.clone();
        let ns = watch_namespace.clone();
        async move {
            let stream = reflector::reflector(
                gateway_writer,
                watcher(
                    scoped_api::<Gateway>(client, ns.as_deref()),
                    watcher::Config::default(),
                )
                .default_backoff(),
            );
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(_) => notify.notify_one(),
                    Err(e) => tracing::warn!(error = %e, "Gateway reflector error"),
                }
            }
        }
    });

    // --- GatewayClass reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        let client = client.clone();
        async move {
            let stream = reflector::reflector(
                gateway_class_writer,
                watcher(Api::<GatewayClass>::all(client), watcher::Config::default())
                    .default_backoff(),
            );
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(_) => notify.notify_one(),
                    Err(e) => tracing::warn!(error = %e, "GatewayClass reflector error"),
                }
            }
        }
    });

    // --- EndpointSlice reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        let client = client.clone();
        let ns = watch_namespace.clone();
        async move {
            let stream = reflector::reflector(
                slice_writer,
                watcher(
                    scoped_api::<EndpointSlice>(client, ns.as_deref()),
                    watcher::Config::default(),
                )
                .default_backoff(),
            );
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(_) => notify.notify_one(),
                    Err(e) => tracing::warn!(error = %e, "EndpointSlice reflector error"),
                }
            }
        }
    });

    // --- ReferenceGrant reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        let client = client.clone();
        let ns = watch_namespace.clone();
        async move {
            let stream = reflector::reflector(
                grant_writer,
                watcher(
                    scoped_api::<ReferenceGrant>(client, ns.as_deref()),
                    watcher::Config::default(),
                )
                .default_backoff(),
            );
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(_) => notify.notify_one(),
                    Err(e) => tracing::warn!(error = %e, "ReferenceGrant reflector error"),
                }
            }
        }
    });

    // --- Secret reflector (TLS certs only) ---
    //
    // Field-selector scoped to `type=kubernetes.io/tls` to avoid pulling every
    // Secret in the cluster into memory.
    set.spawn({
        let notify = Arc::clone(&notify);
        let ns = watch_namespace;
        async move {
            let stream = reflector::reflector(
                secret_writer,
                watcher(
                    scoped_api::<Secret>(client, ns.as_deref()),
                    watcher::Config::default().fields("type=kubernetes.io/tls"),
                )
                .default_backoff(),
            );
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(_) => notify.notify_one(),
                    Err(e) => tracing::warn!(error = %e, "Secret reflector error"),
                }
            }
        }
    });

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
                &grant_reader,
                &secret_reader,
                &controller_name,
                &owned_gateways,
                ingress_default_backend.as_ref(),
                &routes,
                &tls,
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
    grant_store: &reflector::Store<ReferenceGrant>,
    secret_store: &reflector::Store<Secret>,
    controller_name: &str,
    owned_gateways_handle: &OwnedGateways,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    shared: &SharedRoutingTable,
    tls_shared: &SharedTlsStore,
) {
    let routes = route_store.state();
    let ingresses = ingress_store.state();

    let owned_ingress_classes: HashSet<String> = class_store
        .state()
        .into_iter()
        .filter(|ic| {
            ic.spec.as_ref().and_then(|s| s.controller.as_deref()) == Some(controller_name)
        })
        .filter_map(|ic| ic.metadata.name.clone())
        .collect();

    let owned_gateway_classes: HashSet<String> = gateway_class_store
        .state()
        .into_iter()
        .filter(|gc| gc.spec.controller_name == controller_name)
        .filter_map(|gc| gc.metadata.name.clone())
        .collect();

    let owned_gateways: HashSet<(String, String)> = gateway_store
        .state()
        .into_iter()
        .filter(|g| owned_gateway_classes.contains(&g.spec.gateway_class_name))
        .filter_map(|g| {
            let ns = g.metadata.namespace.clone()?;
            let name = g.metadata.name.clone()?;
            Some((ns, name))
        })
        .collect();

    // Publish the owned-gateways snapshot so the controller can filter status writes.
    owned_gateways_handle.store(owned_gateways.clone());

    // Flatten ReferenceGrant objects into a (from_ns, to_ns, Option<to_name>) set for
    // O(1) cross-namespace backend-ref checks in GatewayApiReconciler. Only grants that
    // permit HTTPRoute → Service cross-namespace refs are included.
    let backend_grants: HashSet<(String, String, Option<String>)> = grant_store
        .state()
        .into_iter()
        .filter_map(|grant| {
            let to_ns = grant.metadata.namespace.clone()?;
            Some((grant, to_ns))
        })
        .flat_map(|(grant, to_ns)| {
            let from_entries: Vec<_> = grant
                .spec
                .from
                .iter()
                .filter(|f| f.group == "gateway.networking.k8s.io" && f.kind == "HTTPRoute")
                .map(|f| f.namespace.clone())
                .collect();
            let to_entries: Vec<_> = grant
                .spec
                .to
                .iter()
                .filter(|t| (t.group.is_empty() || t.group == "core") && t.kind == "Service")
                .map(|t| t.name.clone())
                .collect();
            from_entries.into_iter().flat_map(move |from_ns| {
                let to_ns = to_ns.clone();
                to_entries
                    .clone()
                    .into_iter()
                    .map(move |to_name| (from_ns.clone(), to_ns.clone(), to_name))
            })
        })
        .collect();

    tracing::debug!(
        http_routes = routes.len(),
        ingresses = ingresses.len(),
        owned_ingress_classes = owned_ingress_classes.len(),
        owned_gateways = owned_gateways.len(),
        "Rebuilding routing table"
    );
    let mut builder = RoutingTableBuilder::new();
    for route in &routes {
        GatewayApiReconciler::reconcile(
            route,
            slice_store,
            &owned_gateways,
            &backend_grants,
            &mut builder,
        );
    }
    for ingress in &ingresses {
        IngressReconciler::reconcile(ingress, slice_store, &owned_ingress_classes, &mut builder);
    }

    // Install the controller-wide default backend on the global catchall. Thanks to
    // the catchall fall-through in RoutingTable::route, this also serves path-misses
    // on hosts that did not declare their own spec.defaultBackend. Per-Ingress defaults
    // always win because they are installed on the host router (matched first).
    if let Some(db) = ingress_default_backend {
        let addrs = endpoints::resolve(&db.namespace, &db.name, db.port, slice_store);
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

    // Build and publish the TLS cert store independently of the route table.
    let mut tls_builder = TlsStoreBuilder::new();
    for ingress in &ingresses {
        IngressReconciler::reconcile_tls(
            ingress,
            secret_store,
            &owned_ingress_classes,
            &mut tls_builder,
        );
    }
    let tls_store = tls_builder.build();
    tracing::debug!(certs = tls_store.cert_count(), "TLS cert store rebuilt");
    tls_shared.store(Arc::new(tls_store));
}
