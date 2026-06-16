//! Leader-elected status writer: watches resource events and patches Gateway API
//! status conditions back to the Kubernetes API server.

use async_trait::async_trait;
use coxswain_core::health::HealthRegistry;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::gw_types::{BackendTlsPolicy, HttpRoute};
use coxswain_reflector::tls::{
    GatewayListenerHealth, SharedBackendTlsPolicyHealth, SharedGatewayListenerHealth,
    SharedHttpRouteHealth,
};
use futures::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{
    Client,
    api::{Api, ListParams},
    runtime::{WatchStreamExt, watcher},
};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

mod backend_tls_events;
mod conditions;
mod config;
mod gateway_class_events;
mod gateway_class_status;
mod gateway_events;
mod gateway_status;
mod ingress_events;
mod ingress_status;
mod route_events;

pub use config::{ControllerConfig, ControllerConfigError, LeaseSettings, StatusAddress};

use conditions::{gateway_accepted, http_route_programmed};
use gateway_class_status::gateway_class_needs_status_patch;
use gateway_status::gateway_needs_status_patch;
use ingress_status::ingress_lb_already_matches;

use coxswain_reflector::k8s_utils::scoped_api;

const LEASE_NAME: &str = "coxswain-leader-lock";

/// Cadence of the Gateway status resync backstop.
///
/// The cold-start GatewayClass-ordering race is eliminated at the source by
/// priming the ownership sets before the watch loop (see
/// [`Controller::list_owned_gateway_classes`]), and leadership/class-ownership
/// transitions trigger immediate event-driven re-drives. This tick covers the
/// one precondition transition that is *not* cleanly observable as an event:
/// the `controller` subsystem becoming ready. The reflector wakes this writer
/// (`tls_health` change) from *inside* its rebuild, but flips
/// `routing_table_built` ready only *after* the rebuild returns — so a writer
/// woken by that notify can still read `ready=false`, and on a quiet cluster no
/// further notify follows. The periodic re-drive closes that window. The scan
/// is in-memory and only patches when a Gateway's status is actually stale
/// ([`gateway_needs_status_patch`]), so a steady-state tick is read-only.
///
/// Interim: the v0.3 migration to a `Controller` work-queue makes this
/// unnecessary — "not ready yet" becomes a native requeue.
const STATUS_RESYNC_INTERVAL: Duration = Duration::from_secs(10);

/// Kubernetes watch loop for leader election and writing status conditions
/// back to `HTTPRoute`, `Gateway`, `GatewayClass`, and `BackendTLSPolicy` resources.
#[non_exhaustive]
pub struct Controller {
    health: HealthRegistry,
    leader: Arc<AtomicBool>,
    owned_gateways: OwnedGateways,
    tls_health: SharedGatewayListenerHealth,
    route_health: SharedHttpRouteHealth,
    policy_health: SharedBackendTlsPolicyHealth,
    config: ControllerConfig,
}

impl Controller {
    /// Construct a new controller instance (does not start the watch loop).
    pub fn new(
        health: HealthRegistry,
        leader: Arc<AtomicBool>,
        owned_gateways: OwnedGateways,
        tls_health: SharedGatewayListenerHealth,
        route_health: SharedHttpRouteHealth,
        policy_health: SharedBackendTlsPolicyHealth,
        config: ControllerConfig,
    ) -> Self {
        Self {
            health,
            leader,
            owned_gateways,
            tls_health,
            route_health,
            policy_health,
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
                lease_ttl: self.config.lease.ttl,
            },
        );

        // Acquire leadership before the event loop so that InitApply events
        // during the initial list are processed with the correct leader state.
        let mut is_leader = Self::try_renew(&lease_lock, &self.config.pod_name).await;
        self.leader.store(is_leader, Ordering::Release);
        crate::metrics::leader().set(i64::from(is_leader));

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
        let policy_watcher = watcher(
            scoped_api::<BackendTlsPolicy>(client.clone(), self.config.watch_namespace.as_deref()),
            watcher::Config::default(),
        )
        .default_backoff();

        tokio::pin!(route_watcher);
        tokio::pin!(gateway_class_watcher);
        tokio::pin!(gateway_watcher);
        tokio::pin!(ingress_class_watcher);
        tokio::pin!(ingress_watcher);
        tokio::pin!(policy_watcher);

        // Class-ownership sets, primed by an explicit LIST before the watch loop
        // processes any dependent resource. The Gateway/Ingress handlers gate on
        // these sets; the class watchers are *independent* streams, so without
        // priming a Gateway's `InitApply` can be processed before its
        // GatewayClass's on a cold start, dropping the Gateway until the next
        // relist. Priming makes "the owning class is known" a precondition that
        // holds before the first dependent event — eliminating that ordering
        // race at the source. Watch events keep the sets current thereafter; a
        // list error is non-fatal (the watcher backfill + resync still converge).
        //
        // `owned_gateway_classes`: GatewayClasses whose controllerName is ours.
        // `owned_dedicated_gateway_classes`: the subset whose `spec.parametersRef`
        //   targets `CoxswainGatewayParameters` — every Gateway in such a class
        //   is dedicated-mode, its status written by the operator in
        //   `crate::operator::status`, not this writer (tracked, not re-derived
        //   per event, so the Gateway dispatch needn't re-snapshot the class).
        let (mut owned_gateway_classes, mut owned_dedicated_gateway_classes) =
            self.list_owned_gateway_classes(&client).await;

        // `owned_ingress_classes`: IngressClasses whose spec.controller is ours.
        // `owned_default_ingress_classes`: the subset annotated the default class.
        let (mut owned_ingress_classes, mut owned_default_ingress_classes) =
            self.list_owned_ingress_classes(&client).await;

        // Local cache of known Gateway objects.
        let mut known_gateways: HashMap<ObjectKey, Gateway> = HashMap::new();

        // Local cache of known HTTPRoute objects.
        let mut known_routes: HashMap<ObjectKey, HttpRoute> = HashMap::new();

        // Local cache of known BackendTLSPolicy objects.
        let mut known_policies: HashMap<ObjectKey, BackendTlsPolicy> = HashMap::new();

        // interval_at delays the first tick so we don't double-acquire immediately.
        let mut renewal_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + self.config.lease.renew_interval,
            self.config.lease.renew_interval,
        );

        // Backstop resync of cached Gateways. Catches the cold-start case where a
        // Gateway's watch event was consumed before its preconditions were met
        // (see `STATUS_RESYNC_INTERVAL`); a no-op in steady state.
        let mut resync_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + STATUS_RESYNC_INTERVAL,
            STATUS_RESYNC_INTERVAL,
        );

        // Subscribe to the three health channels. Each `watch::Receiver` tracks its
        // own last-seen generation; a `changed().await` future that is cancelled by
        // `select!` simply re-checks the generation on the next poll, so wake-ups
        // cannot be lost across cancellation. (Compare with `Notify`, which drops
        // wakes delivered while no waiter is registered.)
        let mut tls_health_rx = self.tls_health.subscribe();
        let mut route_health_rx = self.route_health.subscribe();
        let mut policy_health_rx = self.policy_health.subscribe();

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
                        crate::metrics::leader().set(i64::from(is_leader));
                        crate::metrics::leader_transitions_total().inc();
                        if is_leader {
                            // Gateways observed during the pre-leadership window had
                            // their watch event consumed while status writes were
                            // gated off. Re-drive now so they don't wait for a relist.
                            self.resync_gateways(
                                &client,
                                &known_gateways,
                                &owned_gateway_classes,
                                &owned_dedicated_gateway_classes,
                            )
                            .await;
                        }
                    }
                }

                _ = resync_interval.tick() => {
                    if is_leader {
                        self.resync_gateways(
                            &client,
                            &known_gateways,
                            &owned_gateway_classes,
                            &owned_dedicated_gateway_classes,
                        )
                        .await;
                    }
                }

                Some(event) = route_watcher.next() => {
                    match event {
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
                                if class_has_coxswain_params_ref(&gc) {
                                    owned_dedicated_gateway_classes.insert(name.clone());
                                } else {
                                    owned_dedicated_gateway_classes.remove(&name);
                                }
                                if is_leader {
                                    // This class is now owned; re-drive any cached
                                    // Gateway whose InitApply was processed and
                                    // skipped before the class was known (cold-start
                                    // ordering race between the two watch streams).
                                    self.resync_gateways(
                                        &client,
                                        &known_gateways,
                                        &owned_gateway_classes,
                                        &owned_dedicated_gateway_classes,
                                    )
                                    .await;
                                }
                                if is_leader && gateway_class_needs_status_patch(&gc) {
                                    let Some(generation) = gc.metadata.generation else {
                                        tracing::warn!(name, "Skipping GatewayClass status patch: metadata.generation is unset");
                                        continue;
                                    };
                                    gateway_class_events::patch_gateway_class_status(&client, &name, generation).await;
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
                                owned_dedicated_gateway_classes.remove(&name);
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "GatewayClass watch error"),
                    }
                }

                Some(event) = gateway_watcher.next() => {
                    match event {
                        Ok(watcher::Event::Apply(gw) | watcher::Event::InitApply(gw)) => {
                            // Cache unconditionally, before any ownership gate. The
                            // GatewayClass watcher is an independent stream, so on a
                            // cold start this Gateway's InitApply can arrive before
                            // its class is known; caching here (not after the gate)
                            // lets a later resync reconcile it once the class is
                            // owned, instead of stranding it until the next relist.
                            let ns = gw.metadata.namespace.clone().unwrap_or_default();
                            let name = gw.metadata.name.clone().unwrap_or_default();
                            known_gateways
                                .insert(ObjectKey::new(ns, name), gw.clone());

                            let class_name = gw.spec.gateway_class_name.as_str();
                            if !owned_gateway_classes.contains(class_name) {
                                tracing::debug!(
                                    name = gw.metadata.name.as_deref().unwrap_or(""),
                                    class_name,
                                    "Ignoring Gateway status — GatewayClass not managed by us (cached for resync)"
                                );
                                continue;
                            }

                            // Skip dedicated-mode Gateways — the operator in
                            // `crate::operator::status` is their sole status
                            // writer (#211). The two writers would otherwise
                            // race on `Gateway.status.conditions` and produce
                            // a flapping `Programmed` reason during the
                            // initial reconcile window.
                            if is_dedicated_mode(&gw, &owned_dedicated_gateway_classes) {
                                tracing::debug!(
                                    name = gw.metadata.name.as_deref().unwrap_or(""),
                                    class_name,
                                    "Skipping Gateway status — dedicated mode (operator owns status)"
                                );
                                continue;
                            }

                            let controller_ready = self.health.is_subsystem_ready("controller");
                            if is_leader && controller_ready {
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
                                    gateway_events::patch_gateway_status(&client, &gw, &health, self.config.status_address.as_ref(), self.config.ingress_ports).await;
                                }
                            } else if is_leader && !gateway_accepted(&gw) {
                                // Before synced: only ensure Accepted is set; defer Programmed.
                                let empty_health = GatewayListenerHealth::default();
                                if gateway_needs_status_patch(&gw, &empty_health) {
                                    gateway_events::patch_gateway_status(&client, &gw, &empty_health, self.config.status_address.as_ref(), self.config.ingress_ports).await;
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

                _ = tls_health_rx.changed() => {
                    if is_leader {
                        self.resync_gateways(
                            &client,
                            &known_gateways,
                            &owned_gateway_classes,
                            &owned_dedicated_gateway_classes,
                        )
                        .await;
                    }
                }

                _ = route_health_rx.changed() => {
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
                            let is_default = coxswain_reflector::ingress::is_default_ingress_class(&ic);
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
                                let owned = match coxswain_reflector::ingress::claimed_ingress_class(&ing) {
                                    Some(c) => owned_ingress_classes.contains(c),
                                    None => !owned_default_ingress_classes.is_empty(),
                                };
                                if is_leader && owned && !ingress_lb_already_matches(&ing, addr, self.config.ingress_ports) {
                                    ingress_events::patch_ingress_status(&client, &ing, addr, self.config.ingress_ports).await;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!(error = %e, "Ingress watch error"),
                        }
                    }
                }

                Some(event) = policy_watcher.next() => {
                    match event {
                        Ok(watcher::Event::Apply(p) | watcher::Event::InitApply(p)) => {
                            let ns = p.metadata.namespace.clone().unwrap_or_default();
                            let name = p.metadata.name.clone().unwrap_or_default();
                            known_policies.insert(ObjectKey::new(ns, name), p.clone());
                            if is_leader {
                                let ph = self.policy_health.load();
                                backend_tls_events::patch_backend_tls_policy_status(
                                    &client,
                                    &p,
                                    &self.config.controller_name,
                                    &ph,
                                )
                                .await;
                            }
                        }
                        Ok(watcher::Event::Delete(p)) => {
                            let ns = p.metadata.namespace.clone().unwrap_or_default();
                            let name = p.metadata.name.clone().unwrap_or_default();
                            known_policies.remove(&ObjectKey::new(ns, name));
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "BackendTLSPolicy watch error"),
                    }
                }

                _ = policy_health_rx.changed() => {
                    if !is_leader {
                        continue;
                    }
                    let ph = self.policy_health.load();
                    for policy in known_policies.values() {
                        backend_tls_events::patch_backend_tls_policy_status(
                            &client,
                            policy,
                            &self.config.controller_name,
                            &ph,
                        )
                        .await;
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

    /// List GatewayClasses once and return `(owned, owned_dedicated)` ownership
    /// sets, mirroring the classification the gateway_class watcher applies per
    /// event.
    ///
    /// Called once before the watch loop so the Gateway handler never observes a
    /// Gateway before its owning class is known (the cold-start ordering race
    /// between the two independent watch streams). A list error is non-fatal:
    /// the GatewayClass watcher's `InitApply` backfill re-populates the sets and
    /// the resync backstop re-drives any Gateway that was skipped meanwhile, so
    /// startup degrades to the pre-priming behaviour rather than failing.
    async fn list_owned_gateway_classes(
        &self,
        client: &Client,
    ) -> (HashSet<String>, HashSet<String>) {
        let mut owned = HashSet::new();
        let mut dedicated = HashSet::new();
        match Api::<GatewayClass>::all(client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(list) => {
                for gc in list {
                    if gc.spec.controller_name != self.config.controller_name {
                        continue;
                    }
                    let name = gc.metadata.name.clone().unwrap_or_default();
                    if class_has_coxswain_params_ref(&gc) {
                        dedicated.insert(name.clone());
                    }
                    owned.insert(name);
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "Failed to prime GatewayClass ownership; relying on watch backfill + resync"
            ),
        }
        (owned, dedicated)
    }

    /// List IngressClasses once and return `(owned, owned_default)` ownership
    /// sets, mirroring the classification the ingress_class watcher applies per
    /// event. See [`Self::list_owned_gateway_classes`] for why this is primed
    /// before the watch loop and why a list error is non-fatal.
    async fn list_owned_ingress_classes(
        &self,
        client: &Client,
    ) -> (HashSet<String>, HashSet<String>) {
        use k8s_openapi::api::networking::v1::IngressClass;
        let mut owned = HashSet::new();
        let mut default = HashSet::new();
        match Api::<IngressClass>::all(client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(list) => {
                for ic in list {
                    let is_owned = ic.spec.as_ref().and_then(|s| s.controller.as_deref())
                        == Some(self.config.controller_name.as_str());
                    if !is_owned {
                        continue;
                    }
                    let name = ic.metadata.name.clone().unwrap_or_default();
                    if coxswain_reflector::ingress::is_default_ingress_class(&ic) {
                        default.insert(name.clone());
                    }
                    owned.insert(name);
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "Failed to prime IngressClass ownership; relying on watch backfill + resync"
            ),
        }
        (owned, default)
    }

    /// Re-reconcile every cached Gateway whose `GatewayClass` we own, patching
    /// status where it is stale.
    ///
    /// A Gateway's watch event can be consumed before its status can be written —
    /// the owning `GatewayClass` may not yet be observed (the two watch streams
    /// race on a cold start), or the `controller` subsystem may not yet be ready.
    /// The event is not redelivered until the next watcher relist (minutes), so
    /// the Gateway would otherwise carry stale status for that whole window. This
    /// re-drives the in-memory cache when a precondition transitions true
    /// (leadership acquired, class becomes owned, listener health changes) and on
    /// a periodic backstop tick, bounding recovery to event/tick latency.
    ///
    /// The caller is responsible for the leadership gate; this is a no-op until
    /// the `controller` subsystem is ready, because a `Programmed` condition
    /// requires a synced data plane. Dedicated-mode Gateways are skipped — the
    /// operator in [`crate::operator::status`] is their sole status writer (#211).
    async fn resync_gateways(
        &self,
        client: &Client,
        known_gateways: &HashMap<ObjectKey, Gateway>,
        owned_gateway_classes: &HashSet<String>,
        owned_dedicated_gateway_classes: &HashSet<String>,
    ) {
        if !self.health.is_subsystem_ready("controller") {
            return;
        }
        let health_map = self.tls_health.load();
        for (key, gw) in known_gateways {
            if !owned_gateway_classes.contains(&gw.spec.gateway_class_name) {
                continue;
            }
            if is_dedicated_mode(gw, owned_dedicated_gateway_classes) {
                continue;
            }
            let health = health_map.get(key).cloned().unwrap_or_default();
            if gateway_needs_status_patch(gw, &health) {
                gateway_events::patch_gateway_status(
                    client,
                    gw,
                    &health,
                    self.config.status_address.as_ref(),
                    self.config.ingress_ports,
                )
                .await;
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

/// CRD group hosting [`coxswain_core::crd::CoxswainGatewayParameters`]. A
/// `parametersRef` with this group + matching kind marks a Gateway (or its
/// GatewayClass) as dedicated-mode, which the shared-pool status writer
/// must skip (#211).
const COXSWAIN_PARAMS_GROUP: &str = "gateway.coxswain-labs.dev";
/// CRD kind for the dedicated-mode parameters CRD.
const COXSWAIN_PARAMS_KIND: &str = "CoxswainGatewayParameters";

/// Returns true iff the GatewayClass's `parametersRef` targets
/// `CoxswainGatewayParameters`. The presence of the reference is the
/// dedicated-mode opt-in signal — we do not resolve the target here, because
/// even an unresolvable reference is the operator's case (the
/// `InvalidParameters` Gateway condition).
fn class_has_coxswain_params_ref(gc: &GatewayClass) -> bool {
    gc.spec
        .parameters_ref
        .as_ref()
        .is_some_and(|r| r.group == COXSWAIN_PARAMS_GROUP && r.kind == COXSWAIN_PARAMS_KIND)
}

/// Same predicate, applied to the Gateway's own
/// `spec.infrastructure.parametersRef`. Either reference triggers
/// dedicated mode.
fn gateway_has_coxswain_params_ref(gw: &Gateway) -> bool {
    gw.spec
        .infrastructure
        .as_ref()
        .and_then(|i| i.parameters_ref.as_ref())
        .is_some_and(|r| r.group == COXSWAIN_PARAMS_GROUP && r.kind == COXSWAIN_PARAMS_KIND)
}

/// Returns true iff the Gateway is in dedicated mode and therefore must NOT
/// have its `status` patched by the shared-pool writer. The check is purely
/// derived from already-watched specs (no resolve, no shared state) so the
/// dispatch is race-free with respect to the operator.
fn is_dedicated_mode(gw: &Gateway, owned_dedicated_classes: &HashSet<String>) -> bool {
    gateway_has_coxswain_params_ref(gw)
        || owned_dedicated_classes.contains(gw.spec.gateway_class_name.as_str())
}
