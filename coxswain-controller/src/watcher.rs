use crate::gateway_api::GatewayApiTranslator;
use crate::ingress::IngressTranslator;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use coxswain_core::routing::RoutingTable;
use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
    runtime::{WatchStreamExt, watcher},
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct Controller {
    shared_routes: Arc<ArcSwap<RoutingTable>>,
    synced: Arc<AtomicBool>,
    controller_name: String,
}

impl Controller {
    pub fn new(
        shared_routes: Arc<ArcSwap<RoutingTable>>,
        synced: Arc<AtomicBool>,
        controller_name: String,
    ) -> Self {
        Self { shared_routes, synced, controller_name }
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
        let gateway_class_watcher = watcher(
            Api::<GatewayClass>::all(client.clone()),
            watcher::Config::default(),
        )
        .default_backoff();

        tokio::pin!(ingress_watcher);
        tokio::pin!(route_watcher);
        tokio::pin!(gateway_class_watcher);

        tracing::info!("Watch streams active");

        loop {
            tokio::select! {
                Some(event) = ingress_watcher.next() => {
                    match event {
                        Ok(watcher::Event::InitDone) => {
                            self.synced.store(true, Ordering::Release);
                            tracing::info!("Ingress initial sync complete");
                        }
                        Ok(e) => {
                            let mut table = (**self.shared_routes.load()).clone();
                            IngressTranslator::translate(e, &mut table);
                            self.shared_routes.store(Arc::new(table));
                        }
                        Err(e) => tracing::warn!(error = %e, "Ingress watch error"),
                    }
                }
                Some(event) = route_watcher.next() => {
                    match event {
                        Ok(watcher::Event::InitDone) => {
                            self.synced.store(true, Ordering::Release);
                            tracing::info!("HTTPRoute initial sync complete");
                        }
                        Ok(e) => {
                            let mut table = (**self.shared_routes.load()).clone();
                            GatewayApiTranslator::translate(e, &mut table);
                            self.shared_routes.store(Arc::new(table));
                        }
                        Err(e) => tracing::warn!(error = %e, "HTTPRoute watch error — Gateway API CRDs may not be installed"),
                    }
                }
                Some(event) = gateway_class_watcher.next() => {
                    match event {
                        Ok(watcher::Event::Apply(gc) | watcher::Event::InitApply(gc)) => {
                            let name = gc.metadata.name.clone().unwrap_or_default();
                            if gc.spec.controller_name == self.controller_name {
                                let generation = gc.metadata.generation.unwrap_or(0);
                                Self::accept_gateway_class(&client, &name, generation).await;
                            } else {
                                tracing::debug!(
                                    name,
                                    controller_name = %gc.spec.controller_name,
                                    "Ignoring GatewayClass — controller name does not match"
                                );
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "GatewayClass watch error"),
                    }
                }
                _ = shutdown.changed() => {
                    break;
                }
            }
        }
    }

    async fn accept_gateway_class(client: &Client, name: &str, generation: i64) {
        let api: Api<GatewayClass> = Api::all(client.clone());
        let now = Time(k8s_openapi::jiff::Timestamp::now());
        let condition = Condition {
            type_: "Accepted".to_string(),
            status: "True".to_string(),
            reason: "Accepted".to_string(),
            message: String::new(),
            observed_generation: Some(generation),
            last_transition_time: now,
        };
        let patch = serde_json::json!({ "status": { "conditions": [condition] } });
        match api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch)).await {
            Ok(_) => tracing::info!(name, "GatewayClass accepted"),
            Err(e) => tracing::warn!(name, error = %e, "Failed to patch GatewayClass status"),
        }
    }
}

#[async_trait]
impl BackgroundService for Controller {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.start_watcher_loop(shutdown).await;
    }
}
