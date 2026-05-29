use crate::{gateway_api::GatewayApiReconciler, ingress::IngressReconciler};
use async_trait::async_trait;
use coxswain_core::routing::{RoutingTableBuilder, SharedRoutingTable};
use futures::StreamExt;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{
    Client,
    api::Api,
    runtime::{WatchStreamExt, reflector, watcher},
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinSet;

/// Pingora background service that maintains reflector-backed stores for
/// `HTTPRoute`, `Ingress`, and `EndpointSlice`, and rebuilds the routing
/// table whenever any of them change — with a 500 ms trailing-edge debounce
/// to coalesce burst updates (e.g. rolling deploys).
pub struct ReconcilerService {
    routes: SharedRoutingTable,
}

impl ReconcilerService {
    pub fn new(routes: SharedRoutingTable) -> Self {
        Self { routes }
    }
}

#[async_trait]
impl BackgroundService for ReconcilerService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let client = Client::try_default()
            .await
            .expect("K8s client for reconciler");
        let mut set = spawn_tasks(client, self.routes.clone()).await;
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

async fn spawn_tasks(client: Client, routes: SharedRoutingTable) -> JoinSet<()> {
    let (route_reader, route_writer) = reflector::store::<HTTPRoute>();
    let (ingress_reader, ingress_writer) = reflector::store::<Ingress>();
    let (slice_reader, slice_writer) = reflector::store::<EndpointSlice>();
    let notify = Arc::new(Notify::new());
    let mut set = JoinSet::new();

    // --- HTTPRoute reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        let client = client.clone();
        async move {
            let stream = reflector::reflector(
                route_writer,
                watcher(Api::<HTTPRoute>::all(client), watcher::Config::default())
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
        async move {
            let stream = reflector::reflector(
                ingress_writer,
                watcher(Api::<Ingress>::all(client), watcher::Config::default()).default_backoff(),
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

    // --- EndpointSlice reflector ---
    set.spawn({
        let notify = Arc::clone(&notify);
        async move {
            let stream = reflector::reflector(
                slice_writer,
                watcher(
                    Api::<EndpointSlice>::all(client),
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
            rebuild(&route_reader, &ingress_reader, &slice_reader, &routes);
        }
    });

    set
}

fn rebuild(
    route_store: &reflector::Store<HTTPRoute>,
    ingress_store: &reflector::Store<Ingress>,
    slice_store: &reflector::Store<EndpointSlice>,
    shared: &SharedRoutingTable,
) {
    let routes = route_store.state();
    let ingresses = ingress_store.state();
    tracing::debug!(http_routes = routes.len(), ingresses = ingresses.len(), "Rebuilding routing table");
    let mut builder = RoutingTableBuilder::new();
    for route in &routes {
        GatewayApiReconciler::reconcile(route, slice_store, &mut builder);
    }
    for ingress in &ingresses {
        IngressReconciler::reconcile(ingress, slice_store, &mut builder);
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
                "Routing table rebuilt"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Routing table build failed — retaining previous table");
        }
    }
}
