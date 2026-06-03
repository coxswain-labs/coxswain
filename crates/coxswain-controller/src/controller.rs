use crate::tls::{
    GatewayListenerHealth, HttpRouteHealthMap, ListenerTlsOutcome, RouteParentHealth,
    SharedGatewayListenerHealth, SharedHttpRouteHealth,
};
use async_trait::async_trait;
use coxswain_core::ownership::{self, OwnedGateways};
use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayListeners, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteParentRefs, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
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
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const LEASE_NAME: &str = "coxswain-leader-lock";

/// The external address written to `Ingress.status.loadBalancer.ingress[0]`
/// and `Gateway.status.addresses[0]`.
///
/// Parsed from `--status-address` at startup: if the value is a valid
/// `IpAddr` it becomes `Ip`, otherwise it is treated as a DNS hostname.
pub enum StatusAddress {
    Ip(IpAddr),
    Hostname(String),
}

/// Configuration for the leader-election controller.
///
/// Validated on construction: `lease_renew_interval * 3` must not exceed `lease_ttl`,
/// which keeps the renewal rate safely below the threshold where a live leader could
/// be evicted by a standby.
pub struct ControllerConfig {
    pub controller_name: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub lease_ttl: Duration,
    pub lease_renew_interval: Duration,
    /// When set, scope namespaced watches to this namespace. When `None`, watch cluster-wide.
    pub watch_namespace: Option<String>,
    /// When set, the leader writes this address to every owned
    /// `Ingress.status.loadBalancer.ingress[0]` and `Gateway.status.addresses[0]`
    /// after each watch event.
    pub status_address: Option<StatusAddress>,
}

impl ControllerConfig {
    pub fn new(
        controller_name: String,
        pod_name: String,
        pod_namespace: String,
        lease_ttl: Duration,
        lease_renew_interval: Duration,
        watch_namespace: Option<String>,
        status_address: Option<String>,
    ) -> Result<Self, String> {
        if lease_renew_interval * 3 > lease_ttl {
            return Err(format!(
                "lease_renew_interval ({lease_renew_interval:?}) must be at most \
                 1/3 of lease_ttl ({lease_ttl:?})"
            ));
        }
        let status_address = status_address
            .map(|s| {
                let s = s.trim().to_string();
                if s.is_empty() {
                    return Err("status_address must not be empty".to_string());
                }
                match s.parse::<IpAddr>() {
                    Ok(ip) => Ok(StatusAddress::Ip(ip)),
                    Err(_) => Ok(StatusAddress::Hostname(s)),
                }
            })
            .transpose()?;
        Ok(Self {
            controller_name,
            pod_name,
            pod_namespace,
            lease_ttl,
            lease_renew_interval,
            watch_namespace,
            status_address,
        })
    }
}

fn ingress_lb_already_matches(ingress: &Ingress, addr: &StatusAddress) -> bool {
    let entry = ingress
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_deref())
        .and_then(|entries| entries.first());
    match (entry, addr) {
        (Some(e), StatusAddress::Ip(ip)) => e.ip.as_deref() == Some(&ip.to_string()),
        (Some(e), StatusAddress::Hostname(h)) => e.hostname.as_deref() == Some(h.as_str()),
        (None, _) => false,
    }
}

fn build_ingress_status_patch(addr: &StatusAddress) -> serde_json::Value {
    let entry = match addr {
        StatusAddress::Ip(ip) => serde_json::json!({ "ip": ip.to_string() }),
        StatusAddress::Hostname(h) => serde_json::json!({ "hostname": h }),
    };
    serde_json::json!({ "status": { "loadBalancer": { "ingress": [entry] } } })
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

fn has_condition(conditions: Option<&[Condition]>, type_: &str) -> bool {
    conditions
        .map(|conds| conds.iter().any(|c| c.type_ == type_ && c.status == "True"))
        .unwrap_or(false)
}

fn gateway_class_accepted(gc: &GatewayClass) -> bool {
    let generation = gc.metadata.generation.unwrap_or(0);
    gc.status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .map(|conds| {
            conds.iter().any(|c| {
                c.type_ == "Accepted"
                    && c.status == "True"
                    && c.observed_generation.unwrap_or(0) >= generation
            })
        })
        .unwrap_or(false)
}

fn gateway_accepted(gw: &Gateway) -> bool {
    has_condition(
        gw.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Accepted",
    )
}

fn gateway_programmed(gw: &Gateway) -> bool {
    has_condition(
        gw.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Programmed",
    )
}

/// Returns true when the Gateway's current status does not yet reflect the desired
/// state computed from `health`. Prevents redundant patches and watch-feedback loops.
fn gateway_needs_status_patch(gw: &Gateway, health: &GatewayListenerHealth) -> bool {
    if !gateway_accepted(gw) {
        return true;
    }
    // Gateway-level Programmed is always True once accepted.
    if !gateway_programmed(gw) {
        return true;
    }
    // Check per-listener count matches spec.
    let current_listener_count = gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_deref())
        .map(|l| l.len())
        .unwrap_or(0);
    if current_listener_count != gw.spec.listeners.len() {
        return true;
    }
    // Check each listener's ResolvedRefs condition matches desired health.
    let current_listeners = gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_ref())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    for listener in &gw.spec.listeners {
        let (has_invalid_kinds, _) = listener_route_kind_info(listener);
        let desired_healthy = !has_invalid_kinds
            && health
                .by_listener
                .get(&listener.name)
                .map(|o| o.is_healthy())
                .unwrap_or(true);
        let current_listener = current_listeners.iter().find(|sl| sl.name == listener.name);
        let current_resolved = current_listener
            .map(|sl| has_condition(Some(sl.conditions.as_slice()), "ResolvedRefs"))
            .unwrap_or(false);
        if desired_healthy != current_resolved {
            return true;
        }
        let desired_attached = health
            .attached_routes
            .get(&listener.name)
            .copied()
            .unwrap_or(0);
        let current_attached = current_listener.map(|sl| sl.attached_routes).unwrap_or(0);
        if desired_attached != current_attached {
            return true;
        }
    }
    false
}

fn http_route_programmed(
    route: &HTTPRoute,
    controller_name: &str,
    owned_gateways: &HashSet<(String, String)>,
) -> bool {
    let default_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let expected_gen = route.metadata.generation.unwrap_or(0);
    route
        .status
        .as_ref()
        .map(|s| {
            s.parents.iter().any(|p| {
                p.controller_name == controller_name
                    && p.conditions.iter().any(|c| {
                        c.type_ == "Programmed"
                            && c.observed_generation.unwrap_or(0) >= expected_gen
                    })
                    && p.conditions.iter().any(|c| {
                        c.type_ == "ResolvedRefs"
                            && c.observed_generation.unwrap_or(0) >= expected_gen
                    })
                    && ownership::parent_ref_owned(
                        p.parent_ref.group.as_deref(),
                        p.parent_ref.kind.as_deref(),
                        p.parent_ref.namespace.as_deref(),
                        &p.parent_ref.name,
                        default_ns,
                        owned_gateways,
                    )
            })
        })
        .unwrap_or(false)
}

fn make_condition(
    type_: &str,
    status: &str,
    reason: &str,
    message: &str,
    generation: i64,
    now: Time,
) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: Some(generation),
        last_transition_time: now,
    }
}

/// Returns the subset of `parent_refs` that point to a Coxswain-managed Gateway.
fn filter_owned_parent_refs(
    parent_refs: &[HttpRouteParentRefs],
    default_ns: &str,
    owned_gateways: &HashSet<(String, String)>,
) -> Vec<HttpRouteParentRefs> {
    parent_refs
        .iter()
        .filter(|p| {
            ownership::parent_ref_owned(
                p.group.as_deref(),
                p.kind.as_deref(),
                p.namespace.as_deref(),
                &p.name,
                default_ns,
                owned_gateways,
            )
        })
        .cloned()
        .collect()
}

/// Returns `(has_any_invalid, supported_kinds)` for a listener's `allowedRoutes.kinds`.
///
/// - `has_any_invalid`: true if any listed kind is not supported by this controller.
///   When true, `ResolvedRefs: False, reason: InvalidRouteKinds` must be set.
/// - `supported_kinds`: intersection of the listed kinds with what we support (currently
///   only `HTTPRoute`). Empty list when all listed kinds are unsupported. When
///   `allowedRoutes.kinds` is absent or empty, returns `[HTTPRoute]` with `has_any_invalid=false`.
fn listener_route_kind_info(
    listener: &GatewayListeners,
) -> (bool, Vec<GatewayStatusListenersSupportedKinds>) {
    const HTTP_ROUTE_GROUP: &str = "gateway.networking.k8s.io";
    let http_route_kind = || GatewayStatusListenersSupportedKinds {
        group: Some(HTTP_ROUTE_GROUP.to_string()),
        kind: "HTTPRoute".to_string(),
    };
    let allowed = match listener
        .allowed_routes
        .as_ref()
        .and_then(|ar| ar.kinds.as_deref())
    {
        Some(k) if !k.is_empty() => k,
        _ => return (false, vec![http_route_kind()]),
    };
    let mut has_invalid = false;
    let mut includes_http_route = false;
    for k in allowed {
        let is_http_route = k.kind == "HTTPRoute"
            && k.group
                .as_deref()
                .is_none_or(|g| g.is_empty() || g == HTTP_ROUTE_GROUP);
        if is_http_route {
            includes_http_route = true;
        } else {
            has_invalid = true;
        }
    }
    let supported = if includes_http_route {
        vec![http_route_kind()]
    } else {
        vec![]
    };
    (has_invalid, supported)
}

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
        let client = Client::try_default()
            .await
            .expect("Failed to init K8s client");

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
            scoped_api::<HTTPRoute>(client.clone(), self.config.watch_namespace.as_deref()),
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
        // Populated from the gateway_class_watcher arm so we can quickly decide
        // whether an incoming Gateway event belongs to us without relying on the
        // reconciler's debounced owned_gateways snapshot.
        let mut owned_gateway_classes: HashSet<String> = HashSet::new();

        // Names of IngressClass resources whose spec.controller matches ours.
        // Populated from the ingress_class_watcher arm; used to skip Ingress
        // status patches for Ingresses not managed by this controller.
        let mut owned_ingress_classes: HashSet<String> = HashSet::new();

        // Local cache of known Gateway objects, keyed by (namespace, name).
        // Updated on Apply/InitApply/Delete events so the status_recompute arm
        // can iterate all managed Gateways without needing a separate reflector store.
        let mut known_gateways: HashMap<(String, String), Gateway> = HashMap::new();

        // Local cache of known HTTPRoute objects, keyed by (namespace, name).
        // Updated on Apply/InitApply/Delete events so the route_health.notified() arm
        // can re-patch routes when backend health changes after the initial patch.
        let mut known_routes: HashMap<(String, String), HTTPRoute> = HashMap::new();

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
                            tracing::info!("HTTPRoute initial sync complete");
                        }
                        Ok(watcher::Event::Apply(route) | watcher::Event::InitApply(route)) => {
                            let ns = route.metadata.namespace.clone().unwrap_or_default();
                            let name = route.metadata.name.clone().unwrap_or_default();
                            known_routes.insert((ns, name), route.clone());
                            let owned = self.owned_gateways.load();
                            if is_leader
                                && !http_route_programmed(
                                    &route,
                                    &self.config.controller_name,
                                    &owned,
                                )
                            {
                                let rh = self.route_health.load();
                                Self::mark_http_route_programmed(
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
                            known_routes.remove(&(ns, name));
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
                            if gc.spec.controller_name == self.config.controller_name {
                                owned_gateway_classes.insert(name.clone());
                                if is_leader && !gateway_class_accepted(&gc) {
                                    let generation = gc.metadata.generation.unwrap_or(0);
                                    Self::accept_gateway_class(&client, &name, generation).await;
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
                            known_gateways.insert((ns, name), gw.clone());

                            let synced = self.synced.load(Ordering::Acquire);
                            if is_leader && synced {
                                let health_map = self.tls_health.load();
                                let key = (
                                    gw.metadata.namespace.clone().unwrap_or_default(),
                                    gw.metadata.name.clone().unwrap_or_default(),
                                );
                                let health = health_map
                                    .get(&key)
                                    .cloned()
                                    .unwrap_or_default();
                                if gateway_needs_status_patch(&gw, &health) {
                                    Self::patch_gateway_status(&client, &gw, &health, self.config.status_address.as_ref()).await;
                                }
                            } else if is_leader && !gateway_accepted(&gw) {
                                // Before synced: only ensure Accepted is set; defer Programmed.
                                let empty_health = GatewayListenerHealth::default();
                                if gateway_needs_status_patch(&gw, &empty_health) {
                                    Self::patch_gateway_status(&client, &gw, &empty_health, self.config.status_address.as_ref()).await;
                                }
                            }
                        }
                        Ok(watcher::Event::Delete(gw)) => {
                            let ns = gw.metadata.namespace.clone().unwrap_or_default();
                            let name = gw.metadata.name.clone().unwrap_or_default();
                            known_gateways.remove(&(ns, name));
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
                    for ((ns, name), gw) in &known_gateways {
                        if !owned_gateway_classes.contains(&gw.spec.gateway_class_name) {
                            continue;
                        }
                        let health = health_map
                            .get(&(ns.clone(), name.clone()))
                            .cloned()
                            .unwrap_or_default();
                        if gateway_needs_status_patch(gw, &health) {
                            Self::patch_gateway_status(&client, gw, &health, self.config.status_address.as_ref()).await;
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
                        Self::mark_http_route_programmed(
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
                            if ic.spec.as_ref().and_then(|s| s.controller.as_deref())
                                == Some(self.config.controller_name.as_str())
                            {
                                owned_ingress_classes.insert(name);
                            } else {
                                owned_ingress_classes.remove(&name);
                            }
                        }
                        Ok(watcher::Event::Delete(ic)) => {
                            let name = ic.metadata.name.clone().unwrap_or_default();
                            owned_ingress_classes.remove(&name);
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "IngressClass watch error"),
                    }
                }

                Some(event) = ingress_watcher.next() => {
                    if let Some(addr) = &self.config.status_address {
                        match event {
                            Ok(watcher::Event::Apply(ing) | watcher::Event::InitApply(ing)) => {
                                let class = crate::ingress::claimed_ingress_class(&ing);
                                let owned = class.is_some_and(|c| owned_ingress_classes.contains(c));
                                if is_leader && owned && !ingress_lb_already_matches(&ing, addr) {
                                    Self::patch_ingress_status(&client, &ing, addr).await;
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
        let condition = make_condition(
            "Accepted",
            "True",
            "Accepted",
            "",
            generation,
            Time(k8s_openapi::jiff::Timestamp::now()),
        );
        let patch = serde_json::json!({ "status": { "conditions": [condition] } });
        match api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => tracing::info!(name, "GatewayClass accepted"),
            Err(e) => tracing::warn!(name, error = %e, "Failed to patch GatewayClass status"),
        }
    }

    // Single patch call sets all Gateway conditions, listener statuses, and addresses at once.
    // A JSON merge patch replaces the entire conditions array, so splitting calls
    // would cause conditions to toggle in a watch-feedback loop.
    async fn patch_gateway_status(
        client: &Client,
        gw: &Gateway,
        health: &GatewayListenerHealth,
        addr: Option<&StatusAddress>,
    ) {
        let name = match gw.metadata.name.as_deref() {
            Some(n) => n,
            None => return,
        };
        let ns = gw.metadata.namespace.as_deref().unwrap_or("default");
        let generation = gw.metadata.generation.unwrap_or(0);
        let api: Api<Gateway> = Api::namespaced(client.clone(), ns);
        let now = Time(k8s_openapi::jiff::Timestamp::now());
        let patch = Self::build_gateway_status_patch(gw, health, generation, &now, addr);
        match api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => tracing::info!(name, ns, "Gateway status patched"),
            Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch Gateway status"),
        }
    }

    fn build_gateway_status_patch(
        gw: &Gateway,
        health: &GatewayListenerHealth,
        generation: i64,
        now: &Time,
        addr: Option<&StatusAddress>,
    ) -> serde_json::Value {
        // Gateway-level Programmed is always True once the controller has processed the
        // Gateway. Per-listener conditions (ListenerConditionProgrammed, ResolvedRefs)
        // express individual listener health. This matches what the conformance suite
        // expects: the setup waits for Programmed=True on all Gateways, including ones
        // with invalid TLS refs, and the per-listener tests check listener conditions.
        let (prog_status, prog_reason, prog_message) = ("True", "Programmed", "");

        let conditions = vec![
            make_condition("Accepted", "True", "Accepted", "", generation, now.clone()),
            make_condition(
                "Programmed",
                prog_status,
                prog_reason,
                prog_message,
                generation,
                now.clone(),
            ),
        ];

        // Build per-listener status entries.
        let listener_statuses: Vec<GatewayStatusListeners> = gw
            .spec
            .listeners
            .iter()
            .map(|l| {
                let outcome = health
                    .by_listener
                    .get(&l.name)
                    .cloned()
                    .unwrap_or(ListenerTlsOutcome::NotApplicable);
                let (has_invalid_kinds, supported_kinds_list) = listener_route_kind_info(l);
                let (resolved_refs_status, resolved_refs_reason, resolved_refs_msg) =
                    if has_invalid_kinds {
                        (
                            "False",
                            "InvalidRouteKinds",
                            "One or more specified route kinds are not supported by this implementation",
                        )
                    } else if outcome.is_healthy() {
                        ("True", "ResolvedRefs", "")
                    } else {
                        ("False", outcome.reason(), outcome.message())
                    };
                let (listener_prog_status, listener_prog_reason, listener_prog_msg) =
                    if outcome.is_healthy() {
                        ("True", "Programmed", "")
                    } else {
                        ("False", outcome.reason(), outcome.message())
                    };
                let attached = health.attached_routes.get(&l.name).copied().unwrap_or(0);
                tracing::debug!(
                    listener = %l.name,
                    resolved_refs = resolved_refs_status,
                    programmed = listener_prog_status,
                    attached_routes = attached,
                    supported_kinds = supported_kinds_list.len(),
                    "Listener status"
                );
                let listener_conditions = vec![
                    make_condition("Accepted", "True", "Accepted", "", generation, now.clone()),
                    make_condition(
                        "ResolvedRefs",
                        resolved_refs_status,
                        resolved_refs_reason,
                        resolved_refs_msg,
                        generation,
                        now.clone(),
                    ),
                    make_condition(
                        "Programmed",
                        listener_prog_status,
                        listener_prog_reason,
                        listener_prog_msg,
                        generation,
                        now.clone(),
                    ),
                ];
                GatewayStatusListeners {
                    name: l.name.clone(),
                    attached_routes: attached,
                    supported_kinds: Some(supported_kinds_list),
                    conditions: listener_conditions,
                }
            })
            .collect();

        let mut patch = serde_json::json!({
            "status": {
                "conditions": conditions,
                "listeners": listener_statuses,
            }
        });
        if let Some(addr) = addr {
            let (type_str, value_str) = match addr {
                StatusAddress::Ip(ip) => ("IPAddress", ip.to_string()),
                StatusAddress::Hostname(h) => ("Hostname", h.clone()),
            };
            patch["status"]["addresses"] = serde_json::json!([{
                "type": type_str,
                "value": value_str,
            }]);
        }
        patch
    }

    async fn mark_http_route_programmed(
        client: &Client,
        route: &HTTPRoute,
        controller_name: &str,
        owned_gateways: &HashSet<(String, String)>,
        route_health: &HttpRouteHealthMap,
    ) {
        let name = match route.metadata.name.as_deref() {
            Some(n) => n,
            None => return,
        };
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let parent_refs = match route.spec.parent_refs.as_deref() {
            Some(refs) if !refs.is_empty() => refs,
            _ => return,
        };

        let owned_refs = filter_owned_parent_refs(parent_refs, ns, owned_gateways);
        if owned_refs.is_empty() {
            tracing::debug!(name, ns, "Skipping status patch — no owned parentRefs");
            return;
        }

        let api: Api<HTTPRoute> = Api::namespaced(client.clone(), ns);
        let now = Time(k8s_openapi::jiff::Timestamp::now());
        let observed_gen = route.metadata.generation.unwrap_or(0);

        let default_health = RouteParentHealth::default();
        let parents: Vec<HttpRouteStatusParents> = owned_refs
            .iter()
            .map(|p| {
                let gw_ns = p.namespace.as_deref().unwrap_or(ns);
                let section = p.section_name.as_deref().unwrap_or("").to_string();
                let health_key = (
                    ns.to_string(),
                    name.to_string(),
                    gw_ns.to_string(),
                    p.name.clone(),
                    section,
                );
                let health = route_health.get(&health_key).unwrap_or(&default_health);

                let (acc_status, acc_reason) = if health.accepted {
                    ("True", health.accepted_reason)
                } else {
                    ("False", health.accepted_reason)
                };
                let (res_status, res_reason) = if health.resolved_refs {
                    ("True", health.resolved_refs_reason)
                } else {
                    ("False", health.resolved_refs_reason)
                };
                let (prog_status, prog_reason) = if health.accepted {
                    ("True", "Programmed")
                } else {
                    ("False", health.accepted_reason)
                };

                let accepted_cond = make_condition(
                    "Accepted",
                    acc_status,
                    acc_reason,
                    "",
                    observed_gen,
                    now.clone(),
                );
                let programmed_cond = make_condition(
                    "Programmed",
                    prog_status,
                    prog_reason,
                    "",
                    observed_gen,
                    now.clone(),
                );
                let resolved_refs_cond = make_condition(
                    "ResolvedRefs",
                    res_status,
                    res_reason,
                    "",
                    observed_gen,
                    now.clone(),
                );

                HttpRouteStatusParents {
                    controller_name: controller_name.to_string(),
                    parent_ref: HttpRouteStatusParentsParentRef {
                        group: p.group.clone(),
                        kind: p.kind.clone(),
                        name: p.name.clone(),
                        namespace: p.namespace.clone(),
                        port: p.port,
                        section_name: p.section_name.clone(),
                    },
                    conditions: vec![accepted_cond, programmed_cond, resolved_refs_cond],
                }
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

    async fn patch_ingress_status(client: &Client, ingress: &Ingress, addr: &StatusAddress) {
        let name = match ingress.metadata.name.as_deref() {
            Some(n) => n,
            None => return,
        };
        let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
        let api: Api<Ingress> = Api::namespaced(client.clone(), ns);
        let patch = build_ingress_status_patch(addr);
        match api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => tracing::info!(name, ns, "Ingress loadBalancer status patched"),
            Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch Ingress status"),
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
    use gateway_api::apis::standard::gateways::{Gateway, GatewayStatus};
    use gateway_api::apis::standard::httproutes::{
        HTTPRoute, HttpRouteParentRefs, HttpRouteStatus, HttpRouteStatusParents,
        HttpRouteStatusParentsParentRef,
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

    fn owned(pairs: &[(&str, &str)]) -> HashSet<(String, String)> {
        pairs
            .iter()
            .map(|(ns, name)| (ns.to_string(), name.to_string()))
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
        let route = HTTPRoute {
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
        let route = HTTPRoute {
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
        let route = HTTPRoute {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            status: Some(HttpRouteStatus {
                parents: vec![HttpRouteStatusParents {
                    controller_name: "my-controller".to_string(),
                    conditions: vec![stub_condition("Programmed", "True")],
                    parent_ref: HttpRouteStatusParentsParentRef {
                        name: "envoy-gateway".to_string(), // not in owned set
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    },
                }],
            }),
            ..Default::default()
        };
        assert!(!http_route_programmed(&route, "my-controller", &set));
    }

    // --- filter_owned_parent_refs tests ---

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
        // Gateway is in "apps" namespace; parentRef omits namespace field.
        let set = owned(&[("apps", "gw")]);
        let refs = vec![HttpRouteParentRefs {
            name: "gw".to_string(),
            namespace: None, // should default to the route's namespace "apps"
            ..Default::default()
        }];
        let filtered = filter_owned_parent_refs(&refs, "apps", &set);
        assert_eq!(filtered.len(), 1);
    }

    // --- gateway_accepted tests ---

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

    // --- gateway_programmed tests ---

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

    // --- StatusAddress helpers ---

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
