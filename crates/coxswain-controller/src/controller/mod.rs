use crate::gw_types::HttpRoute;
use crate::gw_types::v::gatewayclasses::GatewayClass;
use crate::gw_types::v::gateways::Gateway;
use crate::tls::{GatewayListenerHealth, SharedGatewayListenerHealth, SharedHttpRouteHealth};
use async_trait::async_trait;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use futures::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{
    Client,
    api::Api,
    runtime::{WatchStreamExt, watcher},
};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod conditions;
mod config;
mod gateway_class_status;
mod gateway_events;
mod gateway_status;
mod gatewayclass_events;
mod ingress_events;
mod ingress_status;
mod route_events;

pub use config::{ControllerConfig, ControllerConfigError, StatusAddress};

use conditions::{gateway_accepted, http_route_programmed};
use gateway_class_status::gateway_class_needs_status_patch;
use gateway_status::gateway_needs_status_patch;
use ingress_status::ingress_lb_already_matches;

use crate::k8s_utils::scoped_api;

const LEASE_NAME: &str = "coxswain-leader-lock";

/// Kubernetes watch loop for leader election and writing status conditions
/// back to `HTTPRoute`, `Gateway`, and `GatewayClass` resources.
pub struct Controller {
    synced: Arc<AtomicBool>,
    leader: Arc<AtomicBool>,
    owned_gateways: OwnedGateways,
    tls_health: SharedGatewayListenerHealth,
    route_health: SharedHttpRouteHealth,
    config: ControllerConfig,
}

impl Controller {
    pub fn new(
        synced: Arc<AtomicBool>,
        leader: Arc<AtomicBool>,
        owned_gateways: OwnedGateways,
        tls_health: SharedGatewayListenerHealth,
        route_health: SharedHttpRouteHealth,
        config: ControllerConfig,
    ) -> Self {
        Self {
            synced,
            leader,
            owned_gateways,
            tls_health,
            route_health,
            config,
        }
    }

    async fn start_watcher_loop(&self, mut shutdown: ShutdownWatch) {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to initialise Kubernetes client; controller will not run");
                return;
            }
        };

        let lease_lock = LeaseLock::new(
            client.clone(),
            &self.config.pod_namespace,
            LeaseLockParams {
                holder_id: self.config.pod_name.clone(),
                lease_name: LEASE_NAME.to_string(),
                lease_ttl: self.config.lease_ttl,
            },
        );

        // Acquire leadership before the event loop so that InitApply events
        // during the initial list are processed with the correct leader state.
        let mut is_leader = Self::try_renew(&lease_lock, &self.config.pod_name).await;
        self.leader.store(is_leader, Ordering::Release);

        let route_watcher = watcher(
            scoped_api::<HttpRoute>(client.clone(), self.config.watch_namespace.as_deref()),
            watcher::Config::default(),
        )
        .default_backoff();
        let gateway_class_watcher = watcher(
            Api::<GatewayClass>::all(client.clone()),
            watcher::Config::default(),
        )
        .default_backoff();
        let gateway_watcher = watcher(
            scoped_api::<Gateway>(client.clone(), self.config.watch_namespace.as_deref()),
            watcher::Config::default(),
        )
        .default_backoff();
        let ingress_class_watcher = watcher(
            Api::<k8s_openapi::api::networking::v1::IngressClass>::all(client.clone()),
            watcher::Config::default(),
        )
        .default_backoff();
        let ingress_watcher = watcher(
            scoped_api::<Ingress>(client.clone(), self.config.watch_namespace.as_deref()),
            watcher::Config::default(),
        )
        .default_backoff();

        tokio::pin!(route_watcher);
        tokio::pin!(gateway_class_watcher);
        tokio::pin!(gateway_watcher);
        tokio::pin!(ingress_class_watcher);
        tokio::pin!(ingress_watcher);

        // Names of GatewayClass resources whose controllerName matches ours.
        let mut owned_gateway_classes: HashSet<String> = HashSet::new();

        // Names of IngressClass resources whose spec.controller matches ours.
        let mut owned_ingress_classes: HashSet<String> = HashSet::new();

        // Subset of owned IngressClasses annotated `is-default-class: "true"`.
        let mut owned_default_ingress_classes: HashSet<String> = HashSet::new();

        // Local cache of known Gateway objects.
        let mut known_gateways: HashMap<ObjectKey, Gateway> = HashMap::new();

        // Local cache of known HTTPRoute objects.
        let mut known_routes: HashMap<ObjectKey, HttpRoute> = HashMap::new();

        // interval_at delays the first tick so we don't double-acquire immediately.
        let mut renewal_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + self.config.lease_renew_interval,
            self.config.lease_renew_interval,
        );

        tracing::info!(pod = %self.config.pod_name, is_leader, "Watch streams active");

        loop {
            tokio::select! {
                _ = renewal_interval.tick() => {
                    let leading = Self::try_renew(&lease_lock, &self.config.pod_name).await;
                    if leading != is_leader {
                        if leading {
                            tracing::info!(pod = %self.config.pod_name, "Acquired leadership");
                        } else {
                            tracing::info!(pod = %self.config.pod_name, "Lost leadership");
                        }
                        is_leader = leading;
                        self.leader.store(is_leader, Ordering::Release);
                    }
                }

                Some(event) = route_watcher.next() => {
                    match event {
                        Ok(watcher::Event::InitDone) => {
                            self.synced.store(true, Ordering::Release);
                            tracing::info!("HttpRoute initial sync complete");
                        }
                        Ok(watcher::Event::Apply(route) | watcher::Event::InitApply(route)) => {
                            let ns = route.metadata.namespace.clone().unwrap_or_default();
                            let name = route.metadata.name.clone().unwrap_or_default();
                            known_routes.insert(ObjectKey::new(ns, name), route.clone());
                            let owned = self.owned_gateways.load();
                            if is_leader
                                && !http_route_programmed(
                                    &route,
                                    &self.config.controller_name,
                                    &owned,
                                )
                            {
                                let rh = self.route_health.load();
                                route_events::mark_http_route_programmed(
                                    &client,
                                    &route,
                                    &self.config.controller_name,
                                    &owned,
                                    &rh,
                                )
                                .await;
                            }
                        }
                        Ok(watcher::Event::Delete(route)) => {
                            let ns = route.metadata.namespace.clone().unwrap_or_default();
                            let name = route.metadata.name.clone().unwrap_or_default();
                            known_routes.remove(&ObjectKey::new(ns, name));
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(
                            error = %e,
                            "HttpRoute watch error — Gateway API CRDs may not be installed"
                        ),
                    }
                }

                Some(event) = gateway_class_watcher.next() => {
                    match event {
                        Ok(watcher::Event::Apply(gc) | watcher::Event::InitApply(gc)) => {
                            let name = gc.metadata.name.clone().unwrap_or_default();
                            if gc.spec.controller_name == self.config.controller_name {
                                owned_gateway_classes.insert(name.clone());
                                if is_leader && gateway_class_needs_status_patch(&gc) {
                                    let Some(generation) = gc.metadata.generation else {
                                        tracing::warn!(name, "Skipping GatewayClass status patch: metadata.generation is unset");
                                        continue;
                                    };
                                    gatewayclass_events::patch_gateway_class_status(&client, &name, generation).await;
                                }
                            } else {
                                tracing::debug!(
                                    name,
                                    controller_name = %gc.spec.controller_name,
                                    "Ignoring GatewayClass — controller name does not match"
                                );
                            }
                        }
                        Ok(watcher::Event::Delete(gc)) => {
                            let name = gc.metadata.name.clone().unwrap_or_default();
                            if gc.spec.controller_name == self.config.controller_name {
                                owned_gateway_classes.remove(&name);
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "GatewayClass watch error"),
                    }
                }

                Some(event) = gateway_watcher.next() => {
                    match event {
                        Ok(watcher::Event::Apply(gw) | watcher::Event::InitApply(gw)) => {
                            let class_name = gw.spec.gateway_class_name.as_str();
                            if !owned_gateway_classes.contains(class_name) {
                                tracing::debug!(
                                    name = gw.metadata.name.as_deref().unwrap_or(""),
                                    class_name,
                                    "Ignoring Gateway — GatewayClass not managed by us"
                                );
                                continue;
                            }
                            let ns = gw.metadata.namespace.clone().unwrap_or_default();
                            let name = gw.metadata.name.clone().unwrap_or_default();
                            known_gateways.insert(ObjectKey::new(ns, name), gw.clone());

                            let synced = self.synced.load(Ordering::Acquire);
                            if is_leader && synced {
                                let health_map = self.tls_health.load();
                                let key = ObjectKey::new(
                                    gw.metadata.namespace.clone().unwrap_or_default(),
                                    gw.metadata.name.clone().unwrap_or_default(),
                                );
                                let health = health_map
                                    .get(&key)
                                    .cloned()
                                    .unwrap_or_default();
                                if gateway_needs_status_patch(&gw, &health) {
                                    gateway_events::patch_gateway_status(&client, &gw, &health, self.config.status_address.as_ref()).await;
                                }
                            } else if is_leader && !gateway_accepted(&gw) {
                                // Before synced: only ensure Accepted is set; defer Programmed.
                                let empty_health = GatewayListenerHealth::default();
                                if gateway_needs_status_patch(&gw, &empty_health) {
                                    gateway_events::patch_gateway_status(&client, &gw, &empty_health, self.config.status_address.as_ref()).await;
                                }
                            }
                        }
                        Ok(watcher::Event::Delete(gw)) => {
                            let ns = gw.metadata.namespace.clone().unwrap_or_default();
                            let name = gw.metadata.name.clone().unwrap_or_default();
                            known_gateways.remove(&ObjectKey::new(ns, name));
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "Gateway watch error"),
                    }
                }

                _ = self.tls_health.notified() => {
                    if !is_leader || !self.synced.load(Ordering::Acquire) {
                        continue;
                    }
                    let health_map = self.tls_health.load();
                    for (key, gw) in &known_gateways {
                        if !owned_gateway_classes.contains(&gw.spec.gateway_class_name) {
                            continue;
                        }
                        let health = health_map
                            .get(key)
                            .cloned()
                            .unwrap_or_default();
                        if gateway_needs_status_patch(gw, &health) {
                            gateway_events::patch_gateway_status(&client, gw, &health, self.config.status_address.as_ref()).await;
                        }
                    }
                }

                _ = self.route_health.notified() => {
                    if !is_leader {
                        continue;
                    }
                    let owned = self.owned_gateways.load();
                    let rh = self.route_health.load();
                    for route in known_routes.values() {
                        route_events::mark_http_route_programmed(
                            &client,
                            route,
                            &self.config.controller_name,
                            &owned,
                            &rh,
                        )
                        .await;
                    }
                }

                Some(event) = ingress_class_watcher.next() => {
                    match event {
                        Ok(watcher::Event::Apply(ic) | watcher::Event::InitApply(ic)) => {
                            let name = ic.metadata.name.clone().unwrap_or_default();
                            let is_owned = ic.spec.as_ref().and_then(|s| s.controller.as_deref())
                                == Some(self.config.controller_name.as_str());
                            let is_default = crate::ingress::is_default_ingress_class(&ic);
                            if is_owned {
                                owned_ingress_classes.insert(name.clone());
                            } else {
                                owned_ingress_classes.remove(&name);
                            }
                            if is_owned && is_default {
                                owned_default_ingress_classes.insert(name);
                            } else {
                                owned_default_ingress_classes.remove(&name);
                            }
                        }
                        Ok(watcher::Event::Delete(ic)) => {
                            let name = ic.metadata.name.clone().unwrap_or_default();
                            owned_ingress_classes.remove(&name);
                            owned_default_ingress_classes.remove(&name);
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "IngressClass watch error"),
                    }
                }

                Some(event) = ingress_watcher.next() => {
                    if let Some(addr) = &self.config.status_address {
                        match event {
                            Ok(watcher::Event::Apply(ing) | watcher::Event::InitApply(ing)) => {
                                let owned = match crate::ingress::claimed_ingress_class(&ing) {
                                    Some(c) => owned_ingress_classes.contains(c),
                                    None => !owned_default_ingress_classes.is_empty(),
                                };
                                if is_leader && owned && !ingress_lb_already_matches(&ing, addr) {
                                    ingress_events::patch_ingress_status(&client, &ing, addr).await;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!(error = %e, "Ingress watch error"),
                        }
                    }
                }

                _ = shutdown.changed() => {
                    if is_leader {
                        match lease_lock.step_down().await {
                            Ok(()) => tracing::info!(pod = %self.config.pod_name, "Stepped down from leadership"),
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
}

#[async_trait]
impl BackgroundService for Controller {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.start_watcher_loop(shutdown).await;
    }
}

#[cfg(test)]
mod tests {
    use super::conditions::{
        filter_owned_parent_refs, gateway_accepted, gateway_class_accepted, gateway_programmed,
        has_condition, http_route_programmed,
    };
    use super::ingress_status::{build_ingress_status_patch, ingress_lb_already_matches};
    use super::*;
    use crate::gw_types::HttpRoute;
    use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassStatus};
    use gateway_api::apis::standard::gateways::{Gateway, GatewayStatus};
    use gateway_api::apis::standard::httproutes::{
        HttpRouteParentRefs, HttpRouteStatus, HttpRouteStatusParents,
        HttpRouteStatusParentsParentRef,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    fn stub_condition(
        type_: &str,
        status: &str,
    ) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
            type_: type_.to_string(),
            status: status.to_string(),
            reason: String::new(),
            message: String::new(),
            observed_generation: None,
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
        }
    }

    fn owned(pairs: &[(&str, &str)]) -> HashSet<ObjectKey> {
        pairs
            .iter()
            .map(|(ns, name)| ObjectKey::new(*ns, *name))
            .collect()
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
        let gc = GatewayClass {
            status: None,
            ..Default::default()
        };
        assert!(!gateway_class_accepted(&gc));
    }

    #[test]
    fn http_route_programmed_for_matching_controller_and_owned_parent() {
        let set = owned(&[("default", "gw")]);
        let route = HttpRoute {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            status: Some(HttpRouteStatus {
                parents: vec![HttpRouteStatusParents {
                    controller_name: "my-controller".to_string(),
                    conditions: vec![
                        stub_condition("Programmed", "True"),
                        stub_condition("ResolvedRefs", "True"),
                    ],
                    parent_ref: HttpRouteStatusParentsParentRef {
                        name: "gw".to_string(),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    },
                }],
            }),
            ..Default::default()
        };
        assert!(http_route_programmed(&route, "my-controller", &set));
    }

    #[test]
    fn http_route_not_programmed_for_different_controller() {
        let set = owned(&[("default", "gw")]);
        let route = HttpRoute {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            status: Some(HttpRouteStatus {
                parents: vec![HttpRouteStatusParents {
                    controller_name: "other-controller".to_string(),
                    conditions: vec![stub_condition("Programmed", "True")],
                    parent_ref: HttpRouteStatusParentsParentRef {
                        name: "gw".to_string(),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    },
                }],
            }),
            ..Default::default()
        };
        assert!(!http_route_programmed(&route, "my-controller", &set));
    }

    #[test]
    fn http_route_not_programmed_when_parent_not_owned() {
        let set = owned(&[("default", "gw")]);
        let route = HttpRoute {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            status: Some(HttpRouteStatus {
                parents: vec![HttpRouteStatusParents {
                    controller_name: "my-controller".to_string(),
                    conditions: vec![stub_condition("Programmed", "True")],
                    parent_ref: HttpRouteStatusParentsParentRef {
                        name: "envoy-gateway".to_string(),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    },
                }],
            }),
            ..Default::default()
        };
        assert!(!http_route_programmed(&route, "my-controller", &set));
    }

    #[test]
    fn filter_owned_parent_refs_keeps_owned_only() {
        let set = owned(&[("default", "gw")]);
        let refs = vec![
            HttpRouteParentRefs {
                name: "gw".to_string(),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            HttpRouteParentRefs {
                name: "envoy-gw".to_string(),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
        ];
        let filtered = filter_owned_parent_refs(&refs, "default", &set);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "gw");
    }

    #[test]
    fn filter_owned_parent_refs_returns_empty_when_none_owned() {
        let set = owned(&[("default", "gw")]);
        let refs = vec![HttpRouteParentRefs {
            name: "foreign-gw".to_string(),
            namespace: Some("default".to_string()),
            ..Default::default()
        }];
        let filtered = filter_owned_parent_refs(&refs, "default", &set);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_owned_parent_refs_applies_default_namespace() {
        let set = owned(&[("apps", "gw")]);
        let refs = vec![HttpRouteParentRefs {
            name: "gw".to_string(),
            namespace: None,
            ..Default::default()
        }];
        let filtered = filter_owned_parent_refs(&refs, "apps", &set);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn gateway_accepted_true_when_condition_present() {
        let gw = Gateway {
            status: Some(GatewayStatus {
                conditions: Some(vec![stub_condition("Accepted", "True")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(gateway_accepted(&gw));
    }

    #[test]
    fn gateway_accepted_false_when_no_status() {
        let gw = Gateway {
            status: None,
            ..Default::default()
        };
        assert!(!gateway_accepted(&gw));
    }

    #[test]
    fn gateway_accepted_false_when_status_is_false() {
        let gw = Gateway {
            status: Some(GatewayStatus {
                conditions: Some(vec![stub_condition("Accepted", "False")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!gateway_accepted(&gw));
    }

    #[test]
    fn gateway_programmed_true_when_condition_present() {
        let gw = Gateway {
            status: Some(GatewayStatus {
                conditions: Some(vec![stub_condition("Programmed", "True")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(gateway_programmed(&gw));
    }

    #[test]
    fn gateway_programmed_false_when_absent() {
        let gw = Gateway {
            status: Some(GatewayStatus {
                conditions: Some(vec![stub_condition("Accepted", "True")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!gateway_programmed(&gw));
    }

    #[test]
    fn gateway_programmed_false_when_no_status() {
        let gw = Gateway {
            status: None,
            ..Default::default()
        };
        assert!(!gateway_programmed(&gw));
    }

    use k8s_openapi::api::networking::v1::{
        IngressLoadBalancerIngress, IngressLoadBalancerStatus, IngressStatus,
    };

    fn ingress_with_lb(ip: Option<&str>, hostname: Option<&str>) -> Ingress {
        Ingress {
            status: Some(IngressStatus {
                load_balancer: Some(IngressLoadBalancerStatus {
                    ingress: Some(vec![IngressLoadBalancerIngress {
                        ip: ip.map(str::to_string),
                        hostname: hostname.map(str::to_string),
                        ..Default::default()
                    }]),
                }),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn patch_uses_ip_field_for_ip_address() {
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        let patch = build_ingress_status_patch(&addr);
        assert_eq!(
            patch,
            serde_json::json!({
                "status": { "loadBalancer": { "ingress": [{ "ip": "203.0.113.1" }] } }
            })
        );
    }

    #[test]
    fn patch_uses_hostname_field_for_hostname() {
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        let patch = build_ingress_status_patch(&addr);
        assert_eq!(
            patch,
            serde_json::json!({
                "status": { "loadBalancer": { "ingress": [{ "hostname": "coxswain.example.com" }] } }
            })
        );
    }

    #[test]
    fn lb_already_matches_returns_true_when_ip_equal() {
        let ing = ingress_with_lb(Some("203.0.113.1"), None);
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_returns_false_when_ip_differs() {
        let ing = ingress_with_lb(Some("10.0.0.1"), None);
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_returns_true_when_hostname_equal() {
        let ing = ingress_with_lb(None, Some("coxswain.example.com"));
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        assert!(ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_returns_false_when_hostname_differs() {
        let ing = ingress_with_lb(None, Some("other.example.com"));
        let addr = StatusAddress::Hostname("coxswain.example.com".into());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn lb_already_matches_returns_false_when_status_empty() {
        let ing = Ingress {
            status: None,
            ..Default::default()
        };
        let addr = StatusAddress::Ip("203.0.113.1".parse().unwrap());
        assert!(!ingress_lb_already_matches(&ing, &addr));
    }

    #[test]
    fn controller_config_parses_ip_address() {
        use std::time::Duration;
        let cfg = ControllerConfig::new(
            "ctrl".into(),
            "pod".into(),
            "ns".into(),
            Duration::from_secs(15),
            Duration::from_secs(5),
            None,
            Some("203.0.113.1".into()),
        )
        .unwrap();
        assert!(matches!(cfg.status_address, Some(StatusAddress::Ip(_))));
    }

    #[test]
    fn controller_config_parses_hostname() {
        use std::time::Duration;
        let cfg = ControllerConfig::new(
            "ctrl".into(),
            "pod".into(),
            "ns".into(),
            Duration::from_secs(15),
            Duration::from_secs(5),
            None,
            Some("coxswain.example.com".into()),
        )
        .unwrap();
        assert!(matches!(
            cfg.status_address,
            Some(StatusAddress::Hostname(_))
        ));
    }

    #[test]
    fn controller_config_rejects_empty_status_address() {
        use std::time::Duration;
        let result = ControllerConfig::new(
            "ctrl".into(),
            "pod".into(),
            "ns".into(),
            Duration::from_secs(15),
            Duration::from_secs(5),
            None,
            Some("   ".into()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn controller_config_none_address_is_ok() {
        use std::time::Duration;
        let cfg = ControllerConfig::new(
            "ctrl".into(),
            "pod".into(),
            "ns".into(),
            Duration::from_secs(15),
            Duration::from_secs(5),
            None,
            None,
        )
        .unwrap();
        assert!(cfg.status_address.is_none());
    }
}
