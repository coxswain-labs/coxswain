use crate::gateway_api::GatewayApiTranslator;
use crate::ingress::IngressTranslator;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use coxswain_core::routing::RoutingTable;
use futures::StreamExt;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{
    Client,
    api::Api,
    runtime::{WatchStreamExt, watcher},
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::sync::Arc;

pub struct Controller {
    shared_routes: Arc<ArcSwap<RoutingTable>>,
}

impl Controller {
    pub fn new(shared_routes: Arc<ArcSwap<RoutingTable>>) -> Self {
        Self { shared_routes }
    }

    async fn start_watcher_loop(&self, mut shutdown: ShutdownWatch) {
        let client = Client::try_default()
            .await
            .expect("Failed to init K8s client");

        let ingress_watcher = watcher(
            Api::<Ingress>::all(client.clone()),
            watcher::Config::default(),
        )
        .default_backoff();
        let route_watcher = watcher(
            Api::<HTTPRoute>::all(client.clone()),
            watcher::Config::default(),
        )
        .default_backoff();

        tokio::pin!(ingress_watcher);
        tokio::pin!(route_watcher);

        println!("Coxswain control plane streams active.");

        loop {
            tokio::select! {
                Some(event) = ingress_watcher.next() => {
                    if let Ok(e) = event {
                        let mut table_clone = (**self.shared_routes.load()).clone();
                        IngressTranslator::translate(e, &mut table_clone);
                        self.shared_routes.store(Arc::new(table_clone));
                    }
                }
                Some(event) = route_watcher.next() => {
                    if let Ok(e) = event {
                        let mut table_clone = (**self.shared_routes.load()).clone();
                        GatewayApiTranslator::translate(e, &mut table_clone);
                        self.shared_routes.store(Arc::new(table_clone));
                    }
                }
                _ = shutdown.changed() => {
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl BackgroundService for Controller {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.start_watcher_loop(shutdown).await;
    }
}
