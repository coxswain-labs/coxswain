use async_trait::async_trait;
use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
};
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

const LEASE_NAME: &str = "coxswain-leader-lock";

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

fn http_route_programmed(route: &HTTPRoute, controller_name: &str) -> bool {
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

fn make_condition(type_: &str, reason: &str, generation: i64, now: Time) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: "True".to_string(),
        reason: reason.to_string(),
        message: String::new(),
        observed_generation: Some(generation),
        last_transition_time: now,
    }
}

/// Kubernetes watch loop responsible for leader election and writing status
/// conditions back to `HTTPRoute` and `GatewayClass` resources.
///
/// Only the active leader patches resource status; standby replicas track
/// the election result and skip all writes to avoid feedback loops.
pub struct Controller {
    synced: Arc<AtomicBool>,
    leader: Arc<AtomicBool>,
    controller_name: String,
    pod_name: String,
    pod_namespace: String,
}

impl Controller {
    pub fn new(
        synced: Arc<AtomicBool>,
        leader: Arc<AtomicBool>,
        controller_name: String,
        pod_name: String,
        pod_namespace: String,
    ) -> Self {
        Self {
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
                lease_name: LEASE_NAME.to_string(),
                lease_ttl: Duration::from_secs(15),
            },
        );

        // Acquire leadership before the event loop so that InitApply events
        // during the initial list are processed with the correct leader state.
        let mut is_leader = Self::try_renew(&lease_lock, &self.pod_name).await;
        self.leader.store(is_leader, Ordering::Release);

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

                Some(event) = route_watcher.next() => {
                    match event {
                        Ok(watcher::Event::InitDone) => {
                            self.synced.store(true, Ordering::Release);
                            tracing::info!("HTTPRoute initial sync complete");
                        }
                        Ok(watcher::Event::Apply(route) | watcher::Event::InitApply(route)) => {
                            // Only the leader writes status back to the API server.
                            if is_leader && !http_route_programmed(&route, &self.controller_name) {
                                Self::mark_http_route_programmed(
                                    &client,
                                    &route,
                                    &self.controller_name,
                                )
                                .await;
                            } else if !is_leader {
                                tracing::debug!("Skipping status update: replica is standby");
                            }
                        }
                        Ok(_) => {}
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
        let condition = make_condition("Accepted", "Accepted", generation, Time(k8s_openapi::jiff::Timestamp::now()));
        let patch = serde_json::json!({ "status": { "conditions": [condition] } });
        match api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => tracing::info!(name, "GatewayClass accepted"),
            Err(e) => tracing::warn!(name, error = %e, "Failed to patch GatewayClass status"),
        }
    }

    async fn mark_http_route_programmed(client: &Client, route: &HTTPRoute, controller_name: &str) {
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

        let accepted = make_condition("Accepted", "Accepted", observed_gen, now.clone());
        let programmed = make_condition("Programmed", "Programmed", observed_gen, now);

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

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassStatus};
    use gateway_api::apis::standard::httproutes::{
        HTTPRoute, HttpRouteStatus, HttpRouteStatusParents,
    };

    fn stub_condition(type_: &str, status: &str) -> Condition {
        Condition {
            type_: type_.to_string(),
            status: status.to_string(),
            reason: String::new(),
            message: String::new(),
            observed_generation: None,
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
        }
    }

    #[test]
    fn has_condition_returns_true_when_present_and_true() {
        let conds = vec![stub_condition("Programmed", "True")];
        assert!(has_condition(Some(&conds), "Programmed"));
    }

    #[test]
    fn has_condition_returns_false_when_absent() {
        let conds = vec![stub_condition("Accepted", "True")];
        assert!(!has_condition(Some(&conds), "Programmed"));
    }

    #[test]
    fn has_condition_returns_false_when_not_true() {
        let conds = vec![stub_condition("Programmed", "False")];
        assert!(!has_condition(Some(&conds), "Programmed"));
    }

    #[test]
    fn gateway_class_accepted_when_condition_present() {
        let gc = GatewayClass {
            status: Some(GatewayClassStatus {
                conditions: Some(vec![stub_condition("Accepted", "True")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(gateway_class_accepted(&gc));
    }

    #[test]
    fn gateway_class_not_accepted_when_no_status() {
        let gc = GatewayClass { status: None, ..Default::default() };
        assert!(!gateway_class_accepted(&gc));
    }

    #[test]
    fn http_route_programmed_for_matching_controller() {
        let route = HTTPRoute {
            status: Some(HttpRouteStatus {
                parents: vec![HttpRouteStatusParents {
                    controller_name: "my-controller".to_string(),
                    conditions: vec![stub_condition("Programmed", "True")],
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        assert!(http_route_programmed(&route, "my-controller"));
    }

    #[test]
    fn http_route_not_programmed_for_different_controller() {
        let route = HTTPRoute {
            status: Some(HttpRouteStatus {
                parents: vec![HttpRouteStatusParents {
                    controller_name: "other-controller".to_string(),
                    conditions: vec![stub_condition("Programmed", "True")],
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        assert!(!http_route_programmed(&route, "my-controller"));
    }
}
