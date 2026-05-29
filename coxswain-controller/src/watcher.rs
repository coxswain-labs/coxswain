use crate::gateway_api::GatewayApiTranslator;
use crate::ingress::IngressTranslator;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use coxswain_core::routing::RoutingTable;
use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
    runtime::{WatchStreamExt, watcher},
};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn has_condition(conditions: Option<&[Condition]>, type_: &str) -> bool {
    conditions
        .map(|conds| conds.iter().any(|c| c.type_ == type_ && c.status == "True"))
        .unwrap_or(false)
}

fn gateway_class_accepted(gc: &GatewayClass) -> bool {
    has_condition(
        gc.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Accepted",
    )
}

fn httproute_programmed(route: &HTTPRoute, controller_name: &str) -> bool {
    route
        .status
        .as_ref()
        .map(|s| {
            s.parents.iter().any(|p| {
                p.controller_name == controller_name
                    && has_condition(Some(p.conditions.as_slice()), "Programmed")
            })
        })
        .unwrap_or(false)
}

pub struct Controller {
    shared_routes: Arc<ArcSwap<RoutingTable>>,
    synced: Arc<AtomicBool>,
    leader: Arc<AtomicBool>,
    controller_name: String,
    pod_name: String,
    pod_namespace: String,
}

impl Controller {
    pub fn new(
        shared_routes: Arc<ArcSwap<RoutingTable>>,
        synced: Arc<AtomicBool>,
        leader: Arc<AtomicBool>,
        controller_name: String,
        pod_name: String,
        pod_namespace: String,
    ) -> Self {
        Self {
            shared_routes,
            synced,
            leader,
            controller_name,
            pod_name,
            pod_namespace,
        }
    }

    async fn start_watcher_loop(&self, mut shutdown: ShutdownWatch) {
        let client = Client::try_default()
            .await
            .expect("Failed to init K8s client");

        let lease_lock = LeaseLock::new(
            client.clone(),
            &self.pod_namespace,
            LeaseLockParams {
                holder_id: self.pod_name.clone(),
                lease_name: "coxswain-leader-lock".to_string(),
                lease_ttl: Duration::from_secs(15),
            },
        );

        // Acquire leadership before the event loop so that InitApply events
        // during the initial list are processed with the correct leader state.
        let mut is_leader = Self::try_renew(&lease_lock, &self.pod_name).await;
        self.leader.store(is_leader, Ordering::Release);

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

        // Renew every 5 seconds (≤ 1/3 of the 15s TTL).
        // interval_at delays the first tick so we don't double-acquire immediately.
        let mut renewal_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(5),
            Duration::from_secs(5),
        );

        tracing::info!(pod = %self.pod_name, is_leader, "Watch streams active");

        loop {
            tokio::select! {
                _ = renewal_interval.tick() => {
                    let leading = Self::try_renew(&lease_lock, &self.pod_name).await;
                    if leading != is_leader {
                        if leading {
                            tracing::info!(pod = %self.pod_name, "Acquired leadership");
                        } else {
                            tracing::info!(pod = %self.pod_name, "Lost leadership");
                        }
                        is_leader = leading;
                        self.leader.store(is_leader, Ordering::Release);
                    }
                }

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
                        Ok(watcher::Event::Apply(route) | watcher::Event::InitApply(route)) => {
                            // All replicas update the local data plane unconditionally.
                            let mut table = (**self.shared_routes.load()).clone();
                            GatewayApiTranslator::apply(&route, &mut table);
                            self.shared_routes.store(Arc::new(table));
                            // Only the leader writes status back to the API server.
                            if is_leader && !httproute_programmed(&route, &self.controller_name) {
                                Self::mark_httproute_programmed(
                                    &client,
                                    &route,
                                    &self.controller_name,
                                )
                                .await;
                            } else if !is_leader {
                                tracing::debug!("Skipping status update: replica is standby");
                            }
                        }
                        Ok(e) => {
                            let mut table = (**self.shared_routes.load()).clone();
                            GatewayApiTranslator::translate(e, &mut table);
                            self.shared_routes.store(Arc::new(table));
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "HTTPRoute watch error — Gateway API CRDs may not be installed"
                        ),
                    }
                }

                Some(event) = gateway_class_watcher.next() => {
                    match event {
                        Ok(watcher::Event::Apply(gc) | watcher::Event::InitApply(gc)) => {
                            let name = gc.metadata.name.clone().unwrap_or_default();
                            if gc.spec.controller_name == self.controller_name {
                                if is_leader && !gateway_class_accepted(&gc) {
                                    let generation = gc.metadata.generation.unwrap_or(0);
                                    Self::accept_gateway_class(&client, &name, generation).await;
                                } else if !is_leader {
                                    tracing::debug!("Skipping status update: replica is standby");
                                }
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
                    if is_leader {
                        match lease_lock.step_down().await {
                            Ok(()) => tracing::info!(pod = %self.pod_name, "Stepped down from leadership"),
                            // Already lost the lease by the time we tried to release it — fine.
                            Err(kube_leader_election::Error::ReleaseLockWhenNotLeading { .. }) => {}
                            Err(e) => tracing::warn!(error = %e, "Failed to step down from leadership"),
                        }
                    }
                    break;
                }
            }
        }
    }

    async fn try_renew(lease_lock: &LeaseLock, pod_name: &str) -> bool {
        match lease_lock.try_acquire_or_renew().await {
            Ok(LeaseLockResult::Acquired(_)) => true,
            Ok(LeaseLockResult::NotAcquired(_)) => false,
            Err(e) => {
                tracing::warn!(pod = %pod_name, error = %e, "Lease operation failed, assuming standby");
                false
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
        match api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => tracing::info!(name, "GatewayClass accepted"),
            Err(e) => tracing::warn!(name, error = %e, "Failed to patch GatewayClass status"),
        }
    }

    async fn mark_httproute_programmed(client: &Client, route: &HTTPRoute, controller_name: &str) {
        let name = match route.metadata.name.as_deref() {
            Some(n) => n,
            None => return,
        };
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let parent_refs = match route.spec.parent_refs.as_deref() {
            Some(refs) if !refs.is_empty() => refs,
            _ => return,
        };

        let api: Api<HTTPRoute> = Api::namespaced(client.clone(), ns);
        let now = Time(k8s_openapi::jiff::Timestamp::now());
        let observed_gen = route.metadata.generation.unwrap_or(0);

        let accepted = Condition {
            type_: "Accepted".to_string(),
            status: "True".to_string(),
            reason: "Accepted".to_string(),
            message: String::new(),
            observed_generation: Some(observed_gen),
            last_transition_time: now.clone(),
        };
        let programmed = Condition {
            type_: "Programmed".to_string(),
            status: "True".to_string(),
            reason: "Programmed".to_string(),
            message: String::new(),
            observed_generation: Some(observed_gen),
            last_transition_time: now,
        };

        let parents: Vec<HttpRouteStatusParents> = parent_refs
            .iter()
            .map(|p| HttpRouteStatusParents {
                controller_name: controller_name.to_string(),
                parent_ref: HttpRouteStatusParentsParentRef {
                    group: p.group.clone(),
                    kind: p.kind.clone(),
                    name: p.name.clone(),
                    namespace: p.namespace.clone(),
                    port: p.port,
                    section_name: p.section_name.clone(),
                },
                conditions: vec![accepted.clone(), programmed.clone()],
            })
            .collect();

        let patch = serde_json::json!({ "status": { "parents": parents } });
        match api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => tracing::info!(name, ns, "HTTPRoute programmed"),
            Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch HTTPRoute status"),
        }
    }
}

#[async_trait]
impl BackgroundService for Controller {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.start_watcher_loop(shutdown).await;
    }
}
