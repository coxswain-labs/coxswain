//! Leader-elected status writer: a set of kube `Controller` work-queues that
//! patch Gateway API status conditions back to the API server.
//!
//! One reconcile path per primary resource (`Gateway`, `GatewayClass`,
//! `HTTPRoute`, `Ingress`, `BackendTLSPolicy`), each driven by the reflector's
//! **shared** informers (`StatusSubscriptions`) rather than its own duplicate
//! watches (#347). Every reconcile reads ownership/state from the synced
//! reflector stores at reconcile time, so there is no cross-stream ordering
//! race: a Gateway observed before its `GatewayClass` simply reconciles to
//! `await_change` and is re-driven by the `GatewayClass → Gateway` secondary
//! watch once the class lands. "Not leader" / "data plane not yet synced"
//! become native `Action::requeue`s, not dropped events.
//!
//! Leader election (the `Lease` renewal loop) lives in this same background
//! service; the shared `leader` flag gates every reconcile and is the one
//! truth-source the dedicated-mode operator also reads.

use async_trait::async_trait;
use coxswain_core::Shared;
use coxswain_core::crd::client_traffic_policy::ClientTrafficPolicy;
use coxswain_core::crd::coxswain_backend_policy::CoxswainBackendPolicy;
use coxswain_core::crd::coxswain_external_auth::CoxswainExternalAuth;
use coxswain_core::health::HealthRegistry;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_reflector::gw_types::ListenerSet;
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::gw_types::{
    BackendTlsPolicy, GrpcRoute, HttpRoute, TcpRoute, TlsRoute, UdpRoute,
};
use coxswain_reflector::status::{
    GatewayListenerStatus, SharedBackendTlsPolicyStatus, SharedClientTrafficPolicyStatus,
    SharedCoxswainBackendPolicyStatus, SharedCoxswainExternalAuthStatus,
    SharedGatewayListenerStatus, SharedRouteStatus,
};
use coxswain_reflector::{IngressEvent, StatusSubscriptions};
use futures::StreamExt;
use futures::channel::mpsc::{self, UnboundedSender};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::{
    Client, Resource as _,
    runtime::{
        controller::{Action, Controller as KubeController},
        reflector::ObjectRef,
    },
};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::task::JoinSet;

mod backend_tls_events;
mod client_traffic_policy_events;
mod conditions;
mod config;
mod coxswain_backend_policy_events;
mod coxswain_external_auth_events;
mod gateway_class_events;
mod gateway_class_status;
mod gateway_events;
mod gateway_status;
mod grpc_route_events;
mod ingress_event_recorder;
mod ingress_events;
mod ingress_status;
mod leader_label;
mod listenerset_events;
mod listenerset_status;
mod route_events;
mod tcp_route_events;
mod tls_route_events;
mod udp_route_events;

pub use config::{ControllerConfig, ControllerConfigError, LeaseSettings, StatusAddress};

use conditions::{gateway_accepted, gateway_programmed_at_current_gen};
use gateway_class_status::gateway_class_needs_status_patch;
use gateway_status::gateway_needs_status_patch;
use ingress_status::ingress_lb_already_matches;

const LEASE_NAME: &str = "coxswain-leader-lock";

/// Re-queue interval for a reconcile that ran on a non-leader pod. Long enough
/// not to hot-spin, short enough that leader promotion translates into action
/// promptly (the lease TTL defaults to 15 s).
const NON_LEADER_REQUEUE: Duration = Duration::from_secs(20);

/// Re-queue interval after a reconcile error (none of the status helpers
/// currently surface one, so this is a backstop for the framework's error
/// policy).
const ERROR_REQUEUE: Duration = Duration::from_secs(15);

/// Re-queue interval while a Gateway's `Programmed` condition is deferred
/// because the `controller` subsystem has not finished its first data-plane
/// rebuild. Replaces the old `STATUS_RESYNC_INTERVAL` backstop: instead of a
/// process-wide periodic scan, only the Gateways actually waiting on readiness
/// requeue, and only until the subsystem flips ready (then the `listener_status`
/// re-drive and normal events take over). Also the sampling cadence for the
/// #531 bind+ack gate opening (snapshot acks deliberately don't re-drive the
/// queue). Do NOT shorten below 2 s: every held-Pending patch is a Gateway
/// event that re-triggers the operator and the VIP pass, and a 1 s cadence
/// was observed outpacing store convergence on CI — feeding reconcile storms
/// instead of converging faster.
const DEFERRED_PROGRAMMED_REQUEUE: Duration = Duration::from_secs(2);

/// Requeue cadence for a Gateway whose status settled `AddressNotUsable` (#558).
/// The negative is legitimate at patch time, but its inputs — the VIP Service
/// binding and the operator's `vip_failures` snapshot — converge asynchronously
/// on the VIP reconciler's trigger/15 s-resync cadence and fire no Gateway
/// event, so `await_change` would strand a stale negative (the
/// `GatewayStaticAddresses` conformance flake). Matches the VIP resync interval:
/// one writer pass per VIP pass is enough to observe any repair.
const SETTLED_NEGATIVE_REQUEUE: Duration = Duration::from_secs(15);

/// The three reflector-published health channels the status reconcilers read
/// (a `.load()` snapshot per reconcile) and subscribe to (to re-drive the
/// affected work-queue when a TLS-resolution / route-health / policy-health
/// outcome flips).
// intentionally open: field-literal constructed in crate::spawn_status_writer.
pub struct StatusChannels {
    /// Per-listener Gateway TLS health.
    pub tls: SharedGatewayListenerStatus,
    /// Per-HTTPRoute Accepted/ResolvedRefs health.
    pub route: SharedRouteStatus,
    /// Per-GRPCRoute Accepted/ResolvedRefs health.
    ///
    /// Separate from `route` — `RouteParentKey` is kind-neutral and an HTTPRoute + GRPCRoute
    /// with the same name/ns/gateway would collide in one map.
    pub grpc_route: SharedRouteStatus,
    /// Per-TLSRoute Accepted/ResolvedRefs health.
    ///
    /// Separate from `route` and `grpc_route` for the same kind-neutrality reason.
    pub tls_route: SharedRouteStatus,
    /// Per-TCPRoute Accepted/ResolvedRefs health.
    ///
    /// Separate from the other route-kind channels for the same kind-neutrality reason.
    pub tcp_route: SharedRouteStatus,
    /// Per-UDPRoute Accepted/ResolvedRefs health.
    ///
    /// Separate from the other route-kind channels for the same kind-neutrality reason.
    pub udp_route: SharedRouteStatus,
    /// Per-`BackendTLSPolicy` ancestor health.
    pub policy: SharedBackendTlsPolicyStatus,
    /// Per-`ClientTrafficPolicy` ancestor health (#327).
    pub ctp: SharedClientTrafficPolicyStatus,
    /// Per-`CoxswainBackendPolicy` ancestor health (#354).
    pub cbp: SharedCoxswainBackendPolicyStatus,
    /// Per-`CoxswainExternalAuth` ancestor health (#23).
    pub external_auth: SharedCoxswainExternalAuthStatus,
}

/// Leader-elected status writer. Registered as a Pingora `BackgroundService`
/// next to the reflector (whose shared informers it consumes) in
/// `serve controller`.
#[non_exhaustive]
pub struct Controller {
    health: HealthRegistry,
    leader: Arc<AtomicBool>,
    owned_gateways: OwnedGateways,
    channels: StatusChannels,
    config: ControllerConfig,
    /// Shared-informer subscriptions handed over by the reflector; taken once
    /// in `start` (the handles are independent broadcast subscribers and must
    /// not be left undrained, which would back-pressure the stores).
    subscriptions: parking_lot::Mutex<Option<StatusSubscriptions>>,
    /// Ingress diagnostic event channel. Taken once in `start` and driven by
    /// [`ingress_event_recorder::run`]. `None` in test / dev configurations
    /// that do not wire up an `ingress_event_tx` on the reconciler.
    ingress_event_rx: parking_lot::Mutex<Option<tokio::sync::mpsc::Receiver<IngressEvent>>>,
    /// Shared-mode Gateways whose static-address VIP provisioning has
    /// definitively failed (#533), published by the operator's VIP reconciler.
    /// Read to distinguish a settled `AddressNotUsable` from a still-provisioning
    /// Gateway (held `Pending`). Empty when unset (dev/in-process).
    vip_failures: Shared<HashSet<ObjectKey>>,
    /// Publishes leadership to the discovery server's stream gate and the
    /// operator's promotion re-drive (#531). `None` in tests; the bin always
    /// wires it. The lease loop is the single sender.
    leadership_watch: Option<tokio::sync::watch::Sender<bool>>,
    /// Connected-proxy registry (bound-port reports) read by the shared-mode
    /// `Programmed` readiness gate (#531). `None` (tests/dev) disables the
    /// gate — today's address-only convergence behaviour.
    node_registry: Option<coxswain_core::node_registry::SharedNodeRegistry>,
    /// Per-Gateway publish-sequence index (#531). Paired with `node_registry`:
    /// the ack half of the `Programmed` gate — every connected shared-pool
    /// node must have Ack'd a snapshot containing the Gateway's current
    /// generation, not merely have its ports bound (pre-bound ports satisfy
    /// the bind gate instantly while the config is still propagating).
    publish_index: Option<coxswain_core::publish_index::SharedGatewayPublishIndex>,
}

impl Controller {
    /// Construct a new status writer (does not start the work-queues).
    pub fn new(
        health: HealthRegistry,
        leader: Arc<AtomicBool>,
        owned_gateways: OwnedGateways,
        channels: StatusChannels,
        subscriptions: StatusSubscriptions,
        config: ControllerConfig,
        ingress_event_rx: Option<tokio::sync::mpsc::Receiver<IngressEvent>>,
    ) -> Self {
        Self {
            health,
            leader,
            owned_gateways,
            channels,
            config,
            subscriptions: parking_lot::Mutex::new(Some(subscriptions)),
            ingress_event_rx: parking_lot::Mutex::new(ingress_event_rx),
            vip_failures: Shared::new(),
            leadership_watch: None,
            node_registry: None,
            publish_index: None,
        }
    }

    /// Share the operator VIP reconciler's definitively-failed static-address set
    /// (#533) so a Gateway still provisioning its VIP is held `Pending` rather
    /// than briefly reporting a settled `AddressNotUsable`.
    #[must_use]
    pub fn with_vip_failures(mut self, vip_failures: Shared<HashSet<ObjectKey>>) -> Self {
        self.vip_failures = vip_failures;
        self
    }

    /// Publish leadership over a watch channel (#531).
    ///
    /// The bin hands the receiver ends to the discovery server (stream gate)
    /// and the operator (promotion re-drive). Initialized `false` by the
    /// creator, so the discovery server starts gated-closed on every replica
    /// and opens on first promotion — no startup-order dependency.
    #[must_use]
    pub fn with_leadership_watch(mut self, tx: tokio::sync::watch::Sender<bool>) -> Self {
        self.leadership_watch = Some(tx);
        self
    }

    /// Wire the connected-proxy registry so shared-mode Gateways gate
    /// `Programmed=True` on every connected shared-pool proxy having bound
    /// their VIP internal ports (#531).
    #[must_use]
    pub fn with_node_registry(
        mut self,
        registry: coxswain_core::node_registry::SharedNodeRegistry,
    ) -> Self {
        self.node_registry = Some(registry);
        self
    }

    /// Wire the reflector's per-Gateway publish-sequence index (#531) so the
    /// shared-mode `Programmed` gate also requires every connected proxy to
    /// have Ack'd a snapshot containing the Gateway's current generation.
    #[must_use]
    pub fn with_publish_index(
        mut self,
        index: coxswain_core::publish_index::SharedGatewayPublishIndex,
    ) -> Self {
        self.publish_index = Some(index);
        self
    }

    /// Publish a leadership state to the watch (no-op when unwired).
    fn publish_leadership(&self, leading: bool) {
        if let Some(tx) = &self.leadership_watch {
            let _ = tx.send(leading);
        }
    }

    async fn run_controllers(&self, mut shutdown: ShutdownWatch) {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to initialise Kubernetes client; controller will not run");
                return;
            }
        };
        // `client` is moved into ReconcileContext below; the leader-label task
        // and the shutdown-time unlabel need their own handle.
        let client_for_label = client.clone();

        let lease_lock = LeaseLock::new(
            client.clone(),
            &self.config.pod_namespace,
            LeaseLockParams {
                holder_id: self.config.pod_name.clone(),
                lease_name: LEASE_NAME.to_string(),
                lease_ttl: self.config.lease.ttl,
            },
        );

        // Acquire leadership before building the work-queues so the initial
        // reconcile burst (driven by the shared informers' InitApply) runs with
        // the correct leader state.
        let mut lease_state =
            LeadershipState::new(self.config.lease.ttl, self.config.lease.renew_interval);
        let renew_bound = self.config.lease.renew_interval;
        let mut is_leader = lease_state.observe(
            Self::try_renew(&lease_lock, &self.config.pod_name, renew_bound).await,
            tokio::time::Instant::now(),
        );
        self.leader.store(is_leader, Ordering::Release);
        crate::metrics::leader().set(i64::from(is_leader));
        self.publish_leadership(is_leader);

        let subs = self
            .subscriptions
            .lock()
            .take()
            .unwrap_or_else(|| panic!("invariant: status subscriptions taken twice"));
        let StatusSubscriptions {
            gateways,
            gateway_classes,
            routes,
            grpc_routes,
            ingresses,
            ingress_classes,
            policies,
            tls_routes,
            tcp_routes,
            udp_routes,
            listener_sets,
            client_traffic_policies,
            coxswain_backend_policies,
            coxswain_external_auths,
            ..
        } = subs;

        // Readers for ownership lookups + secondary mappers. Captured before the
        // handles are consumed as work-queue triggers; an independent secondary
        // subscriber for the Gateway controller's GatewayClass watch is cloned
        // off the GatewayClass handle.
        let gateways_reader = gateways.reader();
        let gateway_classes_reader = gateway_classes.reader();
        let routes_reader = routes.reader();
        let grpc_routes_reader = grpc_routes.reader();
        let tls_routes_reader = tls_routes.reader();
        let tcp_routes_reader = tcp_routes.reader();
        let udp_routes_reader = udp_routes.reader();
        let ingresses_reader = ingresses.reader();
        let ingress_classes_reader = ingress_classes.reader();
        let policies_reader = policies.reader();
        let listener_sets_reader = listener_sets.reader();
        let ctps_reader = client_traffic_policies.reader();
        let cbps_reader = coxswain_backend_policies.reader();
        let external_auths_reader = coxswain_external_auths.reader();
        let gateway_classes_for_gateways = gateway_classes.clone();
        let gateways_for_listener_sets = gateways.clone();

        let ctx = Arc::new(ReconcileContext {
            client,
            leader: Arc::clone(&self.leader),
            health: self.health.clone(),
            controller_name: self.config.controller_name.clone(),
            status_address: self.config.status_address.clone(),
            shared_vip_addressing: self.config.shared_vip_addressing,
            controller_namespace: self.config.pod_namespace.clone(),
            ingress_ports: self.config.ingress_ports,
            owned_gateways: self.owned_gateways.clone(),
            listener_status: self.channels.tls.clone(),
            route_status: self.channels.route.clone(),
            grpc_route_status: self.channels.grpc_route.clone(),
            tls_route_status: self.channels.tls_route.clone(),
            tcp_route_status: self.channels.tcp_route.clone(),
            udp_route_status: self.channels.udp_route.clone(),
            policy_status: self.channels.policy.clone(),
            ctp_status: self.channels.ctp.clone(),
            cbp_status: self.channels.cbp.clone(),
            external_auth_status: self.channels.external_auth.clone(),
            gateway_classes: gateway_classes_reader,
            ingress_classes: ingress_classes_reader,
            gateways: gateways_reader.clone(),
            vip_failures: self.vip_failures.clone(),
            node_registry: self.node_registry.clone(),
            publish_index: self.publish_index.clone(),
        });

        // One re-drive channel per work-queue. Each is fed by the relevant
        // health forwarder (TLS → Gateway, route → HTTPRoute, policy →
        // BackendTLSPolicy) and by leader-promotion (all five). `reconcile_all_on`
        // re-reconciles every object currently in that controller's store; the
        // per-resource idempotency gates absorb the duplicates.
        let (gw_tx, gw_rx) = mpsc::unbounded::<()>();
        let (gc_tx, gc_rx) = mpsc::unbounded::<()>();
        let (route_tx, route_rx) = mpsc::unbounded::<()>();
        let (grpc_route_tx, grpc_route_rx) = mpsc::unbounded::<()>();
        let (tls_route_tx, tls_route_rx) = mpsc::unbounded::<()>();
        let (tcp_route_tx, tcp_route_rx) = mpsc::unbounded::<()>();
        let (udp_route_tx, udp_route_rx) = mpsc::unbounded::<()>();
        let (ing_tx, ing_rx) = mpsc::unbounded::<()>();
        let (pol_tx, pol_rx) = mpsc::unbounded::<()>();
        let (ls_tx, ls_rx) = mpsc::unbounded::<()>();
        let (ctp_tx, ctp_rx) = mpsc::unbounded::<()>();
        let (cbp_tx, cbp_rx) = mpsc::unbounded::<()>();
        let (ea_tx, ea_rx) = mpsc::unbounded::<()>();
        let leadership_txs = vec![
            gw_tx.clone(),
            gc_tx.clone(),
            route_tx.clone(),
            grpc_route_tx.clone(),
            tls_route_tx.clone(),
            tcp_route_tx.clone(),
            udp_route_tx.clone(),
            ing_tx.clone(),
            pol_tx.clone(),
            ls_tx.clone(),
            ctp_tx.clone(),
            cbp_tx.clone(),
            ea_tx.clone(),
        ];

        let mut tasks = JoinSet::new();

        // Discovery leader label (#531): converged by its own task off the
        // leadership watch — label I/O (own-pod PATCH, promotion LIST + strip
        // PATCHes) must never sit on the lease renewal path, where a stalled
        // apiserver call would erode the renew-before-TTL fencing margin. The
        // startup leadership value was published above, so the task's first
        // convergence pass covers the crashed-prior-incarnation stale label.
        if let Some(tx) = &self.leadership_watch {
            tasks.spawn(leader_label::run(
                leader_label::LeaderLabel::new(
                    client_for_label.clone(),
                    &self.config.pod_namespace,
                    self.config.pod_name.clone(),
                ),
                tx.subscribe(),
            ));
        }

        // Ingress diagnostic event recorder: receives route-conflict and
        // annotation-parse-failure events from the reconciler and emits
        // Kubernetes Warning Events on the affected Ingress objects.
        if let Some(rx) = self.ingress_event_rx.lock().take() {
            let reporter = kube::runtime::events::Reporter {
                controller: self.config.controller_name.clone(),
                instance: Some(self.config.pod_name.clone()),
            };
            tasks.spawn(ingress_event_recorder::run(
                ctx.client.clone(),
                reporter,
                rx,
            ));
        }

        // Health → work-queue forwarders. Each bridges a `watch::Receiver<u64>`
        // (Send, !Sync) onto the `mpsc::Unbounded` stream `reconcile_all_on`
        // wants, dropping the initial value so a fresh subscription does not
        // spuriously re-drive before any health flip occurs.
        spawn_health_forwarder(&mut tasks, self.channels.tls.subscribe(), gw_tx.clone());
        // Proxy-pool readiness (#531): a shared-pool node connecting,
        // disconnecting, or changing its bound-port report re-drives every
        // Gateway so `Programmed` flips promptly once the pool binds — the 2 s
        // deferred requeue is only the backstop.
        if let Some(registry) = &self.node_registry {
            spawn_health_forwarder(&mut tasks, registry.subscribe(), gw_tx);
        }
        spawn_health_forwarder(&mut tasks, self.channels.route.subscribe(), route_tx);
        spawn_health_forwarder(
            &mut tasks,
            self.channels.grpc_route.subscribe(),
            grpc_route_tx,
        );
        spawn_health_forwarder(
            &mut tasks,
            self.channels.tls_route.subscribe(),
            tls_route_tx,
        );
        spawn_health_forwarder(
            &mut tasks,
            self.channels.tcp_route.subscribe(),
            tcp_route_tx,
        );
        spawn_health_forwarder(
            &mut tasks,
            self.channels.udp_route.subscribe(),
            udp_route_tx,
        );
        spawn_health_forwarder(&mut tasks, self.channels.policy.subscribe(), pol_tx);
        spawn_health_forwarder(&mut tasks, self.channels.ctp.subscribe(), ctp_tx);
        spawn_health_forwarder(&mut tasks, self.channels.cbp.subscribe(), cbp_tx);
        spawn_health_forwarder(&mut tasks, self.channels.external_auth.subscribe(), ea_tx);
        // GEP-1713: a TLS-health flip changes which listeners (incl. ListenerSet
        // ones) are programmed, so re-drive ListenerSet status off the same channel.
        spawn_health_forwarder(&mut tasks, self.channels.tls.subscribe(), ls_tx);

        // --- Gateway: primary Gateway, secondary GatewayClass → Gateways in
        // that class, re-driven on TLS-health flips + promotion. ---
        let gateway_ctrl = KubeController::for_shared_stream(gateways, gateways_reader.clone())
            .watches_shared_stream(gateway_classes_for_gateways, {
                let gw_store = gateways_reader.clone();
                move |gc: Arc<GatewayClass>| -> Vec<ObjectRef<Gateway>> {
                    let Some(class_name) = gc.meta().name.clone() else {
                        return Vec::new();
                    };
                    gw_store
                        .state()
                        .into_iter()
                        .filter(|gw| gw.spec.gateway_class_name == class_name)
                        .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                        .collect()
                }
            })
            .reconcile_all_on(gw_rx)
            .run(reconcile_gateway, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, gateway_ctrl, "Gateway");

        // --- ListenerSet: primary ListenerSet, secondary Gateway → its
        // ListenerSets (a parent allowedListeners/listeners edit re-drives the
        // attached ListenerSets), re-driven on TLS-health flips + promotion
        // (GEP-1713). ---
        let listenerset_ctrl =
            KubeController::for_shared_stream(listener_sets, listener_sets_reader.clone())
                .watches_shared_stream(gateways_for_listener_sets, {
                    let ls_store = listener_sets_reader.clone();
                    move |gw: Arc<Gateway>| -> Vec<ObjectRef<ListenerSet>> {
                        let gw_ns = gw.meta().namespace.clone().unwrap_or_default();
                        let gw_name = gw.meta().name.clone().unwrap_or_default();
                        ls_store
                            .state()
                            .into_iter()
                            .filter(|ls| {
                                let ls_ns = ls.meta().namespace.clone().unwrap_or_default();
                                let pr = &ls.spec.parent_ref;
                                let pns = pr.namespace.clone().unwrap_or(ls_ns);
                                pns == gw_ns && pr.name == gw_name
                            })
                            .map(|ls| ObjectRef::from_obj(ls.as_ref()))
                            .collect()
                    }
                })
                .reconcile_all_on(ls_rx)
                .run(reconcile_listenerset, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, listenerset_ctrl, "ListenerSet");

        // --- GatewayClass: primary only; re-driven on promotion. ---
        let gateway_class_ctrl =
            KubeController::for_shared_stream(gateway_classes, ctx.gateway_classes.clone())
                .reconcile_all_on(gc_rx)
                .run(reconcile_gateway_class, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, gateway_class_ctrl, "GatewayClass");

        // --- HTTPRoute: primary only; re-driven on route-health flips +
        // promotion. ---
        let route_ctrl = KubeController::for_shared_stream(routes, routes_reader)
            .reconcile_all_on(route_rx)
            .run(reconcile_route, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, route_ctrl, "HTTPRoute");

        // --- GRPCRoute: primary only; re-driven on grpc-route-health flips +
        // promotion. Sibling to HTTPRoute, feeds the same gateway routing table
        // via a parallel reconcile path.
        let grpc_route_ctrl = KubeController::for_shared_stream(grpc_routes, grpc_routes_reader)
            .reconcile_all_on(grpc_route_rx)
            .run(reconcile_grpc_route, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, grpc_route_ctrl, "GRPCRoute");

        // --- TLSRoute: primary only; re-driven on tls-route-health flips +
        // promotion. Handles SNI-passthrough routes bound to TLS/Passthrough listeners.
        let tls_route_ctrl = KubeController::for_shared_stream(tls_routes, tls_routes_reader)
            .reconcile_all_on(tls_route_rx)
            .run(reconcile_tls_route, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, tls_route_ctrl, "TLSRoute");

        // --- TCPRoute: primary only; re-driven on tcp-route-health flips +
        // promotion. Handles raw-TCP routes bound to protocol:TCP listeners.
        let tcp_route_ctrl = KubeController::for_shared_stream(tcp_routes, tcp_routes_reader)
            .reconcile_all_on(tcp_route_rx)
            .run(reconcile_tcp_route, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, tcp_route_ctrl, "TCPRoute");

        // --- UDPRoute: primary only; re-driven on udp-route-health flips +
        // promotion. Handles datagram routes bound to protocol:UDP listeners.
        let udp_route_ctrl = KubeController::for_shared_stream(udp_routes, udp_routes_reader)
            .reconcile_all_on(udp_route_rx)
            .run(reconcile_udp_route, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, udp_route_ctrl, "UDPRoute");

        // --- Ingress: primary Ingress, secondary IngressClass → all Ingresses
        // (ownership re-checked per reconcile); re-driven on promotion. ---
        let ingress_ctrl = KubeController::for_shared_stream(ingresses, ingresses_reader.clone())
            .watches_shared_stream(ingress_classes, {
                let ing_store = ingresses_reader.clone();
                move |_ic: Arc<IngressClass>| -> Vec<ObjectRef<Ingress>> {
                    ing_store
                        .state()
                        .into_iter()
                        .map(|ing| ObjectRef::from_obj(ing.as_ref()))
                        .collect()
                }
            })
            .reconcile_all_on(ing_rx)
            .run(reconcile_ingress, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, ingress_ctrl, "Ingress");

        // --- BackendTLSPolicy: primary only; re-driven on policy-health flips +
        // promotion. ---
        let policy_ctrl = KubeController::for_shared_stream(policies, policies_reader)
            .reconcile_all_on(pol_rx)
            .run(reconcile_policy, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, policy_ctrl, "BackendTLSPolicy");

        // --- ClientTrafficPolicy: primary only; re-driven on ctp-health flips +
        // promotion (#327). ---
        let ctp_ctrl = KubeController::for_shared_stream(client_traffic_policies, ctps_reader)
            .reconcile_all_on(ctp_rx)
            .run(reconcile_ctp, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, ctp_ctrl, "ClientTrafficPolicy");

        // --- CoxswainBackendPolicy: primary only; re-driven on cbp-health flips +
        // promotion (#354). ---
        let cbp_ctrl = KubeController::for_shared_stream(coxswain_backend_policies, cbps_reader)
            .reconcile_all_on(cbp_rx)
            .run(reconcile_cbp, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, cbp_ctrl, "CoxswainBackendPolicy");

        // --- CoxswainExternalAuth: primary only; re-driven on external-auth-health
        // flips + promotion (#23). ---
        let ea_ctrl =
            KubeController::for_shared_stream(coxswain_external_auths, external_auths_reader)
                .reconcile_all_on(ea_rx)
                .run(reconcile_external_auth, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, ea_ctrl, "CoxswainExternalAuth");

        tracing::info!(pod = %self.config.pod_name, is_leader, "Status-writer work-queues active");

        let mut renewal_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + self.config.lease.renew_interval,
            self.config.lease.renew_interval,
        );

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if is_leader {
                        // Publish the demotion FIRST so the discovery server
                        // terminates its streams while this process can still
                        // flush them — proxies redial and land on the next
                        // leader instead of waiting out TCP death (#531). The
                        // label task sees the same flip and unlabels; a
                        // bounded best-effort unlabel here covers the case
                        // where task teardown wins that race.
                        self.publish_leadership(false);
                        let mut label = leader_label::LeaderLabel::new(
                            client_for_label.clone(),
                            &self.config.pod_namespace,
                            self.config.pod_name.clone(),
                        );
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            label.ensure(false),
                        )
                        .await;
                        match lease_lock.step_down().await {
                            Ok(()) => tracing::info!(pod = %self.config.pod_name, "Stepped down from leadership"),
                            Err(kube_leader_election::Error::ReleaseLockWhenNotLeading { .. }) => {}
                            Err(e) => tracing::warn!(error = %e, "Failed to step down from leadership"),
                        }
                    }
                    break;
                }
                _ = renewal_interval.tick() => {
                    let leading = lease_state.observe(
                        Self::try_renew(&lease_lock, &self.config.pod_name, renew_bound).await,
                        tokio::time::Instant::now(),
                    );
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
                        self.publish_leadership(is_leader);
                        if is_leader {
                            // Promotion: re-drive every work-queue so Gateways /
                            // routes / policies observed while we were standby
                            // (their status writes gated off) are reconciled now,
                            // not at the next watch event.
                            for tx in &leadership_txs {
                                let _ = tx.unbounded_send(());
                            }
                        }
                    }
                }
                res = tasks.join_next() => {
                    match res {
                        Some(Ok(())) => tracing::warn!("status-writer: a background task exited unexpectedly"),
                        Some(Err(e)) => tracing::error!(error = %e, "status-writer: a background task panicked"),
                        None => break,
                    }
                }
            }
        }
        tasks.shutdown().await;
    }

    /// One lease acquire/renew attempt, bounded to `bound` wall-clock time.
    ///
    /// The bound matters for fencing: an unbounded kube call can hang for its
    /// full client timeout (30 s+) during an apiserver partition, freezing the
    /// renewal loop while the lease expires under us. Bounding each attempt to
    /// one renew interval keeps [`LeadershipState`]'s wall-clock demotion
    /// deadline observable in time.
    async fn try_renew(lease_lock: &LeaseLock, pod_name: &str, bound: Duration) -> RenewOutcome {
        match tokio::time::timeout(bound, lease_lock.try_acquire_or_renew()).await {
            Ok(Ok(LeaseLockResult::Acquired(_))) => RenewOutcome::Leading,
            Ok(Ok(LeaseLockResult::NotAcquired(_))) => RenewOutcome::Standby,
            Ok(Err(e)) => {
                tracing::warn!(pod = %pod_name, error = %e, "Lease operation failed");
                RenewOutcome::RenewError
            }
            Err(_) => {
                tracing::warn!(pod = %pod_name, bound = ?bound, "Lease operation timed out");
                RenewOutcome::RenewError
            }
        }
    }
}

/// One lease-loop observation, as [`LeadershipState`]'s input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RenewOutcome {
    /// The lease is held (acquired or renewed) by this replica.
    Leading,
    /// Another replica positively holds the lease.
    Standby,
    /// The lease operation failed (apiserver blip, timeout) — the lease's true
    /// state is unknown.
    RenewError,
}

/// Pure leadership decision state: tolerates transient renew errors while
/// leading, bounded by a **wall-clock** deadline inside the lease TTL.
///
/// A single failed renew does NOT demote: the lease is still validly held
/// server-side (nobody else can acquire it before the TTL expires), so
/// dropping leadership on one apiserver blip trades a real 5-10 s writer
/// outage + full re-drive burst against no split-brain benefit. But the
/// tolerance must be measured in elapsed time since the last *successful*
/// renew, never in error counts: a slow-failing call (bounded by
/// [`Controller::try_renew`]'s timeout, but still real time) would otherwise
/// stretch a "two errors" budget past the TTL while another replica
/// legitimately acquires the expired lease. Demotion fires once
/// `ttl - renew_interval` has elapsed since the last confirmed hold — one
/// renew interval of fencing margin before the lease can be stolen. A
/// positive `Standby` observation always demotes immediately, and errors
/// never promote a standby.
struct LeadershipState {
    is_leader: bool,
    /// Instant of the last successful acquire/renew; `None` while standby.
    last_confirmed: Option<tokio::time::Instant>,
    /// Elapsed-time budget after which errors demote: `ttl - renew_interval`.
    error_deadline: Duration,
}

impl LeadershipState {
    fn new(ttl: Duration, renew_interval: Duration) -> Self {
        // Floor at one renew interval so degenerate settings (ttl == renew)
        // demote on the first error rather than never tolerating anything —
        // and never underflow to a zero deadline that demotes spuriously.
        let error_deadline = ttl
            .saturating_sub(renew_interval)
            .max(renew_interval.min(ttl));
        Self {
            is_leader: false,
            last_confirmed: None,
            error_deadline,
        }
    }

    /// Fold one renew observation at `now`; returns the resulting leadership.
    fn observe(&mut self, outcome: RenewOutcome, now: tokio::time::Instant) -> bool {
        match outcome {
            RenewOutcome::Leading => {
                self.is_leader = true;
                self.last_confirmed = Some(now);
            }
            RenewOutcome::Standby => {
                self.is_leader = false;
                self.last_confirmed = None;
            }
            RenewOutcome::RenewError => {
                if self.is_leader {
                    // `last_confirmed` is always Some while leading; a missing
                    // value fails safe (demote).
                    let held_for = self
                        .last_confirmed
                        .map_or(self.error_deadline, |t| now.duration_since(t));
                    if held_for >= self.error_deadline {
                        tracing::warn!(
                            held_for = ?held_for,
                            deadline = ?self.error_deadline,
                            "renew-error budget exhausted; demoting before the lease TTL can expire"
                        );
                        self.is_leader = false;
                        self.last_confirmed = None;
                    }
                }
                // A standby stays standby on errors: never promote blind.
            }
        }
        self.is_leader
    }
}

#[async_trait]
impl BackgroundService for Controller {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.run_controllers(shutdown).await;
    }
}

/// Bridge a health `watch::Receiver<u64>` onto an `mpsc` `()` stream feeding a
/// work-queue's `reconcile_all_on`. The initial value is dropped via
/// `borrow_and_update` so a fresh subscription does not fire a spurious
/// re-drive before any health flip.
fn spawn_health_forwarder(
    tasks: &mut JoinSet<()>,
    mut rx: tokio::sync::watch::Receiver<u64>,
    tx: UnboundedSender<()>,
) {
    tasks.spawn(async move {
        let _ = rx.borrow_and_update();
        while rx.changed().await.is_ok() {
            if tx.unbounded_send(()).is_err() {
                break;
            }
        }
    });
}

/// Drain a kube `Controller::run` stream, logging reconcile errors. The stream
/// owns the work-queue; dropping it would stop reconciliation, so it is kept
/// running until the service shuts down (which aborts the `JoinSet`).
fn spawn_controller_stream<K>(
    tasks: &mut JoinSet<()>,
    stream: impl futures::Stream<
        Item = Result<
            (ObjectRef<K>, Action),
            kube::runtime::controller::Error<Infallible, kube::runtime::watcher::Error>,
        >,
    > + Send
    + 'static,
    label: &'static str,
) where
    K: kube::Resource + 'static,
{
    tasks.spawn(async move {
        tokio::pin!(stream);
        while let Some(res) = stream.next().await {
            if let Err(e) = res {
                tracing::debug!(controller = label, error = %e, "status-writer: controller stream error");
            }
        }
        tracing::warn!(controller = label, "status-writer: controller stream ended");
    });
}

/// State shared across every reconcile invocation of all five work-queues.
struct ReconcileContext {
    client: Client,
    leader: Arc<AtomicBool>,
    health: HealthRegistry,
    controller_name: String,
    status_address: Option<StatusAddress>,
    /// Whether shared-mode per-Gateway VIP addressing is enabled (#472). Gates
    /// the per-reconcile VIP Service lookup so a feature-off install does zero
    /// extra apiserver GETs.
    shared_vip_addressing: bool,
    /// Controller namespace — where shared-mode VIP Services live (#472), so the
    /// status writer can resolve a Gateway's own address from there.
    controller_namespace: String,
    ingress_ports: coxswain_reflector::ingress::IngressPorts,
    owned_gateways: OwnedGateways,
    listener_status: SharedGatewayListenerStatus,
    route_status: SharedRouteStatus,
    grpc_route_status: SharedRouteStatus,
    tls_route_status: SharedRouteStatus,
    tcp_route_status: SharedRouteStatus,
    udp_route_status: SharedRouteStatus,
    policy_status: SharedBackendTlsPolicyStatus,
    ctp_status: SharedClientTrafficPolicyStatus,
    cbp_status: SharedCoxswainBackendPolicyStatus,
    external_auth_status: SharedCoxswainExternalAuthStatus,
    /// Synced GatewayClass store, read for Gateway ownership at reconcile time.
    gateway_classes: kube::runtime::reflector::Store<GatewayClass>,
    /// Synced IngressClass store, read for Ingress ownership at reconcile time.
    ingress_classes: kube::runtime::reflector::Store<IngressClass>,
    /// Synced Gateway store, read by the ListenerSet reconciler to resolve a
    /// ListenerSet's parent Gateway and its ownership/mode (GEP-1713).
    gateways: kube::runtime::reflector::Store<Gateway>,
    /// Definitively-failed static-address VIP set (#533), published by the
    /// operator VIP reconciler; read to hold a still-provisioning Gateway at
    /// `Pending` instead of a premature `AddressNotUsable`.
    vip_failures: Shared<HashSet<ObjectKey>>,
    /// Connected-proxy registry with per-node bound-port reports (#531). Read
    /// by the shared-Gateway reconcile to gate `Programmed=True` on every
    /// connected shared-pool node having bound the Gateway's VIP internal
    /// ports. `None` disables the gate (tests / dev).
    node_registry: Option<coxswain_core::node_registry::SharedNodeRegistry>,
    /// Per-Gateway publish-sequence index (#531): the ack half of the
    /// `Programmed` gate. `None` disables it (tests / dev).
    publish_index: Option<coxswain_core::publish_index::SharedGatewayPublishIndex>,
}

/// Error policy shared by every work-queue. The status reconcilers are
/// infallible ([`Infallible`]) — every fallible patch is a fire-and-forget log
/// inside the `*_events` helpers — so this is never invoked; it exists only to
/// satisfy `Controller::run`.
fn error_policy<K>(_obj: Arc<K>, _err: &Infallible, _ctx: Arc<ReconcileContext>) -> Action {
    Action::requeue(ERROR_REQUEUE)
}

/// Last-moment leadership re-check before a status write (#531 HA rider).
///
/// The entry check at the top of each reconcile can be stale by the entire
/// reconcile body (including apiserver GETs); re-checking immediately before
/// the patch narrows the stale-leader double-writer window from
/// `renew_interval + reconcile duration` to one patch RTT. The residual window
/// (fence → apiserver processing) is accepted last-write-wins: both writers
/// compute from warm identical stores, so the racing content is near-identical
/// and the next watch event re-converges it.
fn leader_write_fence(ctx: &ReconcileContext) -> bool {
    let leading = ctx.leader.load(Ordering::Acquire);
    if !leading {
        tracing::debug!("write fence: leadership lost mid-reconcile; skipping status patch");
    }
    leading
}

async fn reconcile_gateway(
    gw: Arc<Gateway>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_gateway_inner(&gw, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_gateway_inner(gw: &Gateway, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }

    // Ownership is read from the synced GatewayClass store at reconcile time —
    // never from a sibling handler's cache — so the cold-start ordering race
    // cannot recur. An un-owned (or not-yet-observed) class yields
    // `await_change`; the GatewayClass → Gateway secondary watch re-drives this
    // Gateway once its class lands.
    let classes = ctx.gateway_classes.state();
    let (owned, owned_dedicated) = classify_gateway_classes(&classes, &ctx.controller_name);
    let class_name = gw.spec.gateway_class_name.as_str();
    if !owned.contains(class_name) {
        return Action::await_change();
    }
    // Dedicated-mode Gateways are the operator's to write (#211); skipping here
    // keeps the two writers from racing on `status.conditions`.
    if is_dedicated_mode(gw, &owned_dedicated) {
        return Action::await_change();
    }

    // Shared-mode Gateways advertise their OWN per-Gateway VIP Service address
    // (#472) — see [`select_shared_gateway_address`] for the state→address map.
    let vip = resolve_shared_vip_address(
        &ctx.client,
        gw,
        &ctx.controller_namespace,
        ctx.shared_vip_addressing,
    )
    .await;
    let owned_status_addr = select_shared_gateway_address(
        &vip.address,
        ctx.shared_vip_addressing,
        ctx.status_address.as_ref(),
    );

    // GatewayStaticAddresses (#260): validate any requested `spec.addresses`
    // against the address coxswain actually advertises/bound. The advertised
    // address (`owned_status_addr`) is what the VIP reconciler tried to honor, so
    // a requested address is usable iff it equals it. `legacy_addr` keeps the
    // pre-#260 single-address behaviour for Gateways with no static request.
    let resolved: Vec<_> = owned_status_addr
        .as_ref()
        .map(status_address_to_typed)
        .into_iter()
        .collect();
    let mut static_outcome = crate::status_common::addresses::evaluate_static_addresses(
        gw.spec.addresses.as_deref().unwrap_or_default(),
        &resolved,
    );
    // GatewayInvalidParametersRef (#517): dedicated Gateways already returned
    // above via `is_dedicated_mode`, so any `spec.infrastructure.parametersRef`
    // still present here targets a kind this shared-pool writer does not
    // support → `Accepted=False, reason=InvalidParameters`. Existence of the ref
    // is the whole signal; the target is never resolved.
    let params_ref_unsupported = gw
        .spec
        .infrastructure
        .as_ref()
        .and_then(|i| i.parameters_ref.as_ref())
        .is_some();

    // The per-Gateway VIP Service and its LoadBalancer IP are provisioned
    // asynchronously by the separate `run_vip_reconciler` task, which fires no
    // Gateway event — so a shared Gateway reconciled before its own VIP resolves
    // must REQUEUE (not `await_change`) or `status.addresses` would stay stale
    // until an unrelated Gateway edit. Only a `Resolved` own-VIP is terminal.
    let awaiting_own_vip =
        ctx.shared_vip_addressing && !matches!(vip.address, VipAddress::Resolved(_));

    let key = ObjectKey::new(
        gw.metadata.namespace.clone().unwrap_or_default(),
        gw.metadata.name.clone().unwrap_or_default(),
    );

    // Hold an unconfirmed `AddressNotUsable` at `Pending` (#533, #558). An
    // empty `resolved` set (VIP mid-provisioning) — or a resolved-but-stale
    // address observed mid-repin (the operator deletes + defer-recreates the
    // VIP Service to repin a clusterIP) — reports `AddressNotUsable`, yet is
    // indistinguishable from a genuinely unusable request. Settle the negative
    // only on one of the two authorities `should_hold_pending` checks: a
    // definitive `vip_failures` entry, or a partial match proving the VIP
    // reconciler already honored the request as far as it can. Otherwise
    // downgrade the override so the convergence gate holds `Programmed` at
    // `gen-1` and the 2 s requeue keeps polling until the repin lands —
    // settling here went quiet (`await_change`) with a stale negative the VIP
    // reconciler never re-drives (the `GatewayStaticAddresses` flake, #558).
    if static_outcome.should_hold_pending(
        awaiting_own_vip,
        ctx.vip_failures.load().contains(&key),
        ctx.shared_vip_addressing,
    ) {
        static_outcome.hold_pending_address();
    }

    // Anti-flap latch first (#533, #531): once the Gateway is Programmed at
    // its live generation, convergence is settled — VIP re-resolution and pool
    // churn (rollouts, leader failover emptying the registry) must never flap
    // an established `Programmed=True` back to `Pending`; only a spec change
    // (new generation) re-arms the gate. Latch-first also skips the registry
    // query for the steady-state majority of reconciles.
    let latched = gateway_programmed_at_current_gen(gw);

    // Latched address preservation (#531): the latch keeps `Programmed=True`
    // through a transiently-unresolved VIP (the operator deletes + recreates
    // the Service to repin a requested clusterIP; an LB re-assigns), but the
    // static-address patch path rewrites `status.addresses` from the current
    // resolution — publishing `Programmed=True` with an EMPTY address set, an
    // inconsistent state the conformance `GatewayStaticAddresses` fetch races
    // into. While latched-True with no settled negative, keep the currently
    // published addresses instead of wiping them: a *real* address change
    // arrives with a generation bump, which re-arms the gate (`latched` goes
    // false) and traverses the `Pending` hold, never this branch.
    if latched
        && static_outcome.feature_engaged
        && static_outcome.programmed_override.is_none()
        && static_outcome.status_addresses.is_empty()
    {
        static_outcome.status_addresses = current_status_typed_addresses(gw);
    }

    // Proxy-pool readiness gate (#531), two halves:
    //
    //  * Bind: every connected shared-pool proxy node must have reported the
    //    VIP's internal ports bound — otherwise `Programmed=True` races real
    //    traffic into a not-yet-listening port.
    //  * Ack: every connected node must have Ack'd a snapshot containing this
    //    Gateway's current generation (publish-sequence comparison). Bind
    //    alone is instantly true when the ports were already bound for other
    //    Gateways while this Gateway's routes/cert config is still
    //    propagating — the `GatewayFrontendClientCertificateValidation` race.
    //
    // All-connected-nodes quorum: the VIP load-balances across every pool
    // member, so one stale pod means real connections can black-hole or serve
    // pre-update config. Zero connected nodes fails closed; a Gateway not yet
    // stamped by the reflector (or stamped at an older generation) fails
    // closed too.
    let (proxies_bound, proxy_pending_detail) = match &ctx.node_registry {
        Some(registry) if ctx.shared_vip_addressing && !latched => {
            let ports_bound = registry.all_shared_nodes_bound(&vip.internal_ports);
            let snapshot_acked = match &ctx.publish_index {
                Some(index) => index.get(&key).is_some_and(|stamp| {
                    stamp.generation >= gw.metadata.generation.unwrap_or(0)
                        && registry.all_shared_nodes_acked(stamp.seq)
                }),
                None => true,
            };
            let bound = ports_bound && snapshot_acked;
            // Snapshot clone only on the held path, where the pending
            // message needs the per-node view.
            let detail = (!bound && !awaiting_own_vip).then(|| {
                if ports_bound {
                    format!(
                        "waiting for all connected shared proxies to apply the routing \
                         snapshot containing generation {}",
                        gw.metadata.generation.unwrap_or(0)
                    )
                } else {
                    proxy_bind_pending_detail(&registry.load(), &vip.internal_ports)
                }
            });
            (bound, detail)
        }
        // Latched, no registry (tests / dev), or per-Gateway addressing off
        // (no internal ports to await): the gate is inert.
        _ => (true, None),
    };

    // Convergence gate (#533, #531): a shared-mode Gateway is fully converged
    // for its current generation only once its own VIP address has resolved
    // AND the shared pool has bound its internal ports. Until then the status
    // patch holds `Programmed` at `False/Pending` with its `observedGeneration`
    // below the current generation, so a one-shot "conditions are latest" check
    // keeps waiting and never observes `Programmed` claiming generation N while
    // the address is unresolved or the data plane dark; the same patch that
    // flips `Programmed=True@N` also publishes the address.
    //
    // Structural backstop for the same invariant in the other direction: a
    // static-address Gateway with no settled negative and NOTHING to publish
    // in `status.addresses` (nothing resolved now, nothing preserved from the
    // latch) must never surface `Programmed=True` with an empty address set —
    // whatever transient produced that combination (VIP churn mid-repin, a
    // stale object), hold `Pending` and requeue instead.
    let publishable_addresses = !static_outcome.feature_engaged
        || static_outcome.programmed_override.is_some()
        || !static_outcome.status_addresses.is_empty();
    let converged = (latched || (!awaiting_own_vip && proxies_bound)) && publishable_addresses;

    let decision = gateway_status::SharedAddressDecision {
        legacy_addr: owned_status_addr,
        static_outcome,
        params_ref_unsupported,
        converged,
        pending_detail: proxy_pending_detail,
    };

    if ctx.health.is_subsystem_ready("controller") {
        let health_map = ctx.listener_status.load();
        let health = health_map.get(&key).cloned().unwrap_or_default();
        if gateway_needs_status_patch(gw, &health, &decision) && leader_write_fence(ctx) {
            gateway_events::patch_gateway_status(
                &ctx.client,
                gw,
                &health,
                &decision,
                ctx.ingress_ports,
            )
            .await;
        }
        // Requeue until fully converged so `Programmed` lands promptly once the
        // VIP resolves AND the proxy acks, rather than waiting for an unrelated
        // Gateway event. A *settled* `AddressNotUsable` is converged for patch
        // purposes but must never go fully quiet (#558): its inputs (the VIP
        // Service binding, the `vip_failures` snapshot) converge on the VIP
        // reconciler's own cadence and fire no Gateway event, so an
        // `await_change` here would strand a stale negative until an unrelated
        // event. Slow-requeue as the self-heal backstop instead.
        if !converged {
            Action::requeue(DEFERRED_PROGRAMMED_REQUEUE)
        } else if decision.static_outcome.is_address_not_usable() {
            Action::requeue(SETTLED_NEGATIVE_REQUEUE)
        } else {
            Action::await_change()
        }
    } else if !gateway_accepted(gw) {
        // Before the data plane is synced, write the minimal Accepted-oriented
        // status and requeue to revisit `Programmed` once ready. This requeue
        // replaces the old process-wide resync backstop.
        let empty_status = GatewayListenerStatus::default();
        if gateway_needs_status_patch(gw, &empty_status, &decision) && leader_write_fence(ctx) {
            gateway_events::patch_gateway_status(
                &ctx.client,
                gw,
                &empty_status,
                &decision,
                ctx.ingress_ports,
            )
            .await;
        }
        Action::requeue(DEFERRED_PROGRAMMED_REQUEUE)
    } else {
        // Accepted already set, but the subsystem is not ready yet: revisit
        // shortly so `Programmed` lands without waiting for the next event.
        Action::requeue(DEFERRED_PROGRAMMED_REQUEUE)
    }
}

/// Map a shared Gateway's VIP state to the address it should advertise (#472).
///
/// The subtle case is `NotProvisioned`. When per-Gateway addressing is ON, the
/// global `--status-address` points at the shared proxy's fixed `80`/`443`,
/// which post-#472 serve **Ingress only** — a Gateway that advertised it would
/// send its own clients to the Ingress listener (404/reset). So a shared Gateway
/// must NEVER fall back to the global address: it reports no address (and the
/// caller requeues via `awaiting_own_vip`) until its own VIP is provisioned and
/// resolved. The global address is the Gateway's address only when the feature
/// is OFF — the legacy single-shared-IP model where every Gateway shares it.
///
/// `Pending` (Service exists, address not yet assigned) always reports `None`:
/// wait for the real VIP rather than mask it with anything else.
fn select_shared_gateway_address(
    vip: &VipAddress,
    shared_vip_addressing: bool,
    global_status_address: Option<&StatusAddress>,
) -> Option<StatusAddress> {
    match vip {
        VipAddress::Resolved(a) => Some(a.clone()),
        VipAddress::Pending => None,
        VipAddress::NotProvisioned if shared_vip_addressing => None,
        VipAddress::NotProvisioned => global_status_address.cloned(),
    }
}

/// Provisioning/address state of a shared-mode Gateway's own VIP Service (#472).
///
/// Distinguishing `Pending` from `NotProvisioned` is what stops a
/// provisioned-but-address-pending VIP from being masked by the global
/// `--status-address`: the caller reports no address for `Pending`, but the
/// global address for `NotProvisioned`.
enum VipAddress {
    /// No VIP Service exists — feature off, or not yet provisioned at all
    /// (Service 404), or a transient API error (degrade to the global address).
    NotProvisioned,
    /// The VIP Service exists but has no externally-reachable address yet
    /// (e.g. LoadBalancer IP still pending), or is NodePort/unknown-typed.
    Pending,
    /// The VIP Service has a resolved address.
    Resolved(StatusAddress),
}

/// A shared Gateway's VIP resolution: address state plus the VIP Service's
/// internal `targetPort`s (#531).
///
/// The `targetPort`s are the controller-allocated internal ports the shared
/// pool binds for this Gateway — read back from the same Service GET that
/// resolves the address, so the `Programmed` bind gate compares against the
/// single-writer VIP reconciler's authoritative allocation (never watch-lagged
/// reflector state). By construction the set excludes Ingress ports and
/// includes ListenerSet-merged listeners.
struct SharedVip {
    address: VipAddress,
    /// Empty when the Service does not exist, the feature is off, or the
    /// lookup failed — states in which the address term of the convergence
    /// gate already holds `Pending`.
    internal_ports: std::collections::BTreeSet<u16>,
}

impl SharedVip {
    /// No VIP Service observed (feature off, 404, or lookup error): the
    /// address degrades per [`VipAddress::NotProvisioned`] and there are no
    /// internal ports to gate on.
    fn not_provisioned() -> Self {
        Self {
            address: VipAddress::NotProvisioned,
            internal_ports: std::collections::BTreeSet::new(),
        }
    }
}

/// Read a shared-mode Gateway's own VIP Service and classify its address state.
///
/// Best-effort: a 404 (no Service) and any API error both map to
/// [`VipAddress::NotProvisioned`] so a transient apiserver hiccup degrades to
/// the global address rather than dropping the Gateway's address. Gated on
/// `enabled` so a feature-off install issues no apiserver GET at all.
async fn resolve_shared_vip_address(
    client: &kube::Client,
    gw: &Gateway,
    controller_namespace: &str,
    enabled: bool,
) -> SharedVip {
    use k8s_openapi::api::core::v1::Service;
    if !enabled {
        return SharedVip::not_provisioned();
    }
    let (Some(ns), Some(gw_name)) = (
        gw.metadata.namespace.as_deref(),
        gw.metadata.name.as_deref(),
    ) else {
        return SharedVip::not_provisioned();
    };
    // The VIP Service lives in the controller namespace (with the shared proxy
    // pod) under a namespace-qualified name (#472).
    let svc_name = crate::operator::render::shared_gateway_service_name(ns, gw_name);
    let api: kube::Api<Service> = kube::Api::namespaced(client.clone(), controller_namespace);
    match api.get_opt(&svc_name).await {
        Ok(Some(svc)) => {
            let address = match service_vip_address(&svc) {
                Some(addr) => VipAddress::Resolved(addr),
                None => VipAddress::Pending,
            };
            SharedVip {
                address,
                internal_ports: service_internal_ports(&svc),
            }
        }
        Ok(None) => SharedVip::not_provisioned(),
        Err(e) => {
            tracing::debug!(
                gateway = %format!("{ns}/{gw_name}"),
                error = %e,
                "shared VIP Service lookup failed; using global status address"
            );
            SharedVip::not_provisioned()
        }
    }
}

/// Extract a VIP Service's internal `targetPort`s — the ports the shared pool
/// must bind for this Gateway (#531). Named `targetPort`s (`IntOrString::
/// String`) cannot occur on VIP Services (the reconciler renders numeric
/// allocations) and are skipped defensively.
fn service_internal_ports(
    svc: &k8s_openapi::api::core::v1::Service,
) -> std::collections::BTreeSet<u16> {
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    svc.spec
        .as_ref()
        .and_then(|s| s.ports.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|p| match &p.target_port {
            Some(IntOrString::Int(i)) => u16::try_from(*i).ok(),
            _ => None,
        })
        .collect()
}

/// Render the `Programmed=False/Pending` message for the proxy-pool bind gate
/// (#531): who the Gateway is waiting on. Message-only — never part of the
/// patch-staleness comparison.
fn proxy_bind_pending_detail(
    snapshot: &coxswain_core::node_registry::NodeRegistry,
    required: &std::collections::BTreeSet<u16>,
) -> String {
    use coxswain_core::node_registry::NodeScope;
    let shared: Vec<_> = snapshot
        .nodes
        .values()
        .filter(|e| e.scope == NodeScope::SharedPool)
        .collect();
    if shared.is_empty() {
        return "no shared proxy nodes connected; waiting for the pool before \
                declaring the Gateway programmed"
            .to_owned();
    }
    let unbound = shared
        .iter()
        .filter(|e| {
            !e.bound_ports
                .as_ref()
                .is_some_and(|bound| required.is_subset(bound))
        })
        .count();
    let ports: Vec<String> = required.iter().map(u16::to_string).collect();
    format!(
        "waiting for {unbound}/{} connected shared proxy node(s) to bind internal port(s) [{}]",
        shared.len(),
        ports.join(", ")
    )
}

/// Convert a [`StatusAddress`] (the address coxswain advertises for a Gateway)
/// into the type-tagged form the static-address validator compares against (#260).
fn status_address_to_typed(addr: &StatusAddress) -> crate::status_common::addresses::TypedAddress {
    use crate::status_common::addresses::{SupportedAddressType, TypedAddress};
    match addr {
        StatusAddress::Ip(ip) => TypedAddress::new(SupportedAddressType::IpAddress, ip.to_string()),
        StatusAddress::Hostname(h) => TypedAddress::new(SupportedAddressType::Hostname, h.clone()),
    }
}

/// The Gateway's currently-published `status.addresses`, re-parsed into the
/// typed form (#531 latched address preservation). Entries with an
/// unrecognised type tag are dropped — only coxswain writes this field, and
/// it only writes the two supported types.
fn current_status_typed_addresses(
    gw: &Gateway,
) -> Vec<crate::status_common::addresses::TypedAddress> {
    use crate::status_common::addresses::{SupportedAddressType, TypedAddress};
    gw.status
        .as_ref()
        .and_then(|s| s.addresses.as_ref())
        .map(|addrs| {
            addrs
                .iter()
                .filter_map(|a| {
                    let type_ = match a.r#type.as_deref() {
                        Some("IPAddress") => SupportedAddressType::IpAddress,
                        Some("Hostname") => SupportedAddressType::Hostname,
                        _ => return None,
                    };
                    Some(TypedAddress::new(type_, a.value.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Derive a single [`StatusAddress`] from a VIP Service by its type:
/// `LoadBalancer` ingress (IP preferred, else hostname) or `ClusterIP`.
/// `NodePort`/unknown yields `None` (node-IP resolution lives on the dedicated
/// path, which has a Node store; the shared status writer falls back instead).
fn service_vip_address(svc: &k8s_openapi::api::core::v1::Service) -> Option<StatusAddress> {
    use std::net::IpAddr;
    let spec = svc.spec.as_ref()?;
    match spec.type_.as_deref() {
        Some("LoadBalancer") => {
            let ingress = svc
                .status
                .as_ref()?
                .load_balancer
                .as_ref()?
                .ingress
                .as_ref()?;
            ingress.iter().find_map(|e| {
                if let Some(ip) = e.ip.as_deref().filter(|s| !s.is_empty()) {
                    ip.parse::<IpAddr>().ok().map(StatusAddress::Ip)
                } else {
                    e.hostname
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .map(|h| StatusAddress::Hostname(h.to_string()))
                }
            })
        }
        Some("ClusterIP") | Some("") | None => spec
            .cluster_ip
            .as_deref()
            .filter(|s| !s.is_empty() && *s != "None")
            .and_then(|s| s.parse::<IpAddr>().ok())
            .map(StatusAddress::Ip),
        _ => None,
    }
}

async fn reconcile_listenerset(
    ls: Arc<ListenerSet>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_listenerset_inner(&ls, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

/// GEP-1713: write `ListenerSet.status`. Resolves the ListenerSet's parent Gateway
/// and writes status only when this controller manages it (owned class) and it
/// runs on the shared pool — a dedicated-mode Gateway (and its ListenerSets) is
/// the operator's to write, mirroring [`reconcile_gateway_inner`]'s split.
async fn reconcile_listenerset_inner(ls: &ListenerSet, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }

    let ls_ns = ls.metadata.namespace.as_deref().unwrap_or("default");
    let parent = &ls.spec.parent_ref;
    let parent_ns = parent.namespace.as_deref().unwrap_or(ls_ns);
    let parent_key = ObjectKey::new(parent_ns, parent.name.as_str());

    // Resolve the parent Gateway from the synced store (O(1)). Absent → not yet
    // observed; the Gateway → ListenerSet secondary watch re-drives this once it lands.
    let parent_ref = ObjectRef::<Gateway>::new(parent.name.as_str()).within(parent_ns);
    let Some(parent_gw) = ctx.gateways.get(&parent_ref) else {
        return Action::await_change();
    };

    let classes = ctx.gateway_classes.state();
    let (owned, owned_dedicated) = classify_gateway_classes(&classes, &ctx.controller_name);
    if !owned.contains(parent_gw.spec.gateway_class_name.as_str()) {
        return Action::await_change();
    }
    if is_dedicated_mode(&parent_gw, &owned_dedicated) {
        return Action::await_change();
    }

    if !ctx.health.is_subsystem_ready("controller") {
        // Defer until the data plane has computed listener status; requeue rather
        // than await_change so a fresh ListenerSet doesn't stall until an
        // unrelated edit (mirrors the Gateway path's deferred-Programmed requeue).
        return Action::requeue(DEFERRED_PROGRAMMED_REQUEUE);
    }

    let health_map = ctx.listener_status.load();
    let parent_health = health_map.get(&parent_key);
    let accepted = listenerset_status::listenerset_accepted(ls, parent_health);
    if listenerset_status::listenerset_needs_status_patch(
        ls,
        parent_health,
        accepted,
        ctx.ingress_ports,
    ) && leader_write_fence(ctx)
    {
        listenerset_events::patch_listenerset_status(
            &ctx.client,
            ls,
            parent_health,
            accepted,
            ctx.ingress_ports,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_gateway_class(
    gc: Arc<GatewayClass>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_gateway_class_inner(&gc, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_gateway_class_inner(gc: &GatewayClass, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    if gc.spec.controller_name != ctx.controller_name {
        return Action::await_change();
    }
    if gateway_class_needs_status_patch(gc) {
        let Some(generation) = gc.metadata.generation else {
            tracing::warn!(
                name = gc.metadata.name.as_deref().unwrap_or(""),
                "Skipping GatewayClass status patch: metadata.generation is unset"
            );
            return Action::await_change();
        };
        let name = gc.metadata.name.as_deref().unwrap_or_default();
        if leader_write_fence(ctx) {
            gateway_class_events::patch_gateway_class_status(&ctx.client, name, generation).await;
        }
    }
    Action::await_change()
}

async fn reconcile_route(
    route: Arc<HttpRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_route_inner(&route, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_route_inner(route: &HttpRoute, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    // `mark_http_route_programmed` is idempotent (skips the patch when the
    // route already carries the conditions we would write), so it is safe to
    // call on both spec-change events and route-health re-drives without
    // churning `lastTransitionTime`.
    let owned = ctx.owned_gateways.load();
    let rh = ctx.route_status.load();
    if leader_write_fence(ctx) {
        route_events::mark_http_route_programmed(
            &ctx.client,
            route,
            &ctx.controller_name,
            &owned,
            &rh,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_grpc_route(
    route: Arc<GrpcRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_grpc_route_inner(&route, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_grpc_route_inner(route: &GrpcRoute, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let owned = ctx.owned_gateways.load();
    let rh = ctx.grpc_route_status.load();
    if leader_write_fence(ctx) {
        grpc_route_events::mark_grpc_route_programmed(
            &ctx.client,
            route,
            &ctx.controller_name,
            &owned,
            &rh,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_tls_route(
    route: Arc<TlsRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_tls_route_inner(&route, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_tls_route_inner(route: &TlsRoute, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let owned = ctx.owned_gateways.load();
    let rh = ctx.tls_route_status.load();
    if leader_write_fence(ctx) {
        tls_route_events::mark_tls_route_programmed(
            &ctx.client,
            route,
            &ctx.controller_name,
            &owned,
            &rh,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_tcp_route(
    route: Arc<TcpRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_tcp_route_inner(&route, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_tcp_route_inner(route: &TcpRoute, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let owned = ctx.owned_gateways.load();
    let rh = ctx.tcp_route_status.load();
    if leader_write_fence(ctx) {
        tcp_route_events::mark_tcp_route_programmed(
            &ctx.client,
            route,
            &ctx.controller_name,
            &owned,
            &rh,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_udp_route(
    route: Arc<UdpRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_udp_route_inner(&route, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_udp_route_inner(route: &UdpRoute, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let owned = ctx.owned_gateways.load();
    let rh = ctx.udp_route_status.load();
    if leader_write_fence(ctx) {
        udp_route_events::mark_udp_route_programmed(
            &ctx.client,
            route,
            &ctx.controller_name,
            &owned,
            &rh,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_ingress(
    ing: Arc<Ingress>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_ingress_inner(&ing, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_ingress_inner(ing: &Ingress, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let Some(addr) = ctx.status_address.as_ref() else {
        return Action::await_change();
    };
    let classes = ctx.ingress_classes.state();
    let (owned_classes, default_classes) = classify_ingress_classes(&classes, &ctx.controller_name);
    let owned = match coxswain_reflector::ingress::claimed_ingress_class(ing) {
        Some(c) => owned_classes.contains(c),
        None => !default_classes.is_empty(),
    };
    if owned && !ingress_lb_already_matches(ing, addr, ctx.ingress_ports) && leader_write_fence(ctx)
    {
        ingress_events::patch_ingress_status(&ctx.client, ing, addr, ctx.ingress_ports).await;
    }
    Action::await_change()
}

async fn reconcile_policy(
    policy: Arc<BackendTlsPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_policy_inner(&policy, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_policy_inner(policy: &BackendTlsPolicy, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let ph = ctx.policy_status.load();
    if leader_write_fence(ctx) {
        backend_tls_events::patch_backend_tls_policy_status(
            &ctx.client,
            policy,
            &ctx.controller_name,
            &ph,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_ctp(
    policy: Arc<ClientTrafficPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_ctp_inner(&policy, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_ctp_inner(policy: &ClientTrafficPolicy, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let ch = ctx.ctp_status.load();
    if leader_write_fence(ctx) {
        client_traffic_policy_events::patch_client_traffic_policy_status(
            &ctx.client,
            policy,
            &ctx.controller_name,
            &ch,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_cbp(
    policy: Arc<CoxswainBackendPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_cbp_inner(&policy, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_cbp_inner(policy: &CoxswainBackendPolicy, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let ch = ctx.cbp_status.load();
    if leader_write_fence(ctx) {
        coxswain_backend_policy_events::patch_coxswain_backend_policy_status(
            &ctx.client,
            policy,
            &ctx.controller_name,
            &ch,
        )
        .await;
    }
    Action::await_change()
}

async fn reconcile_external_auth(
    policy: Arc<CoxswainExternalAuth>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_external_auth_inner(&policy, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_external_auth_inner(
    policy: &CoxswainExternalAuth,
    ctx: &ReconcileContext,
) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let ch = ctx.external_auth_status.load();
    if leader_write_fence(ctx) {
        coxswain_external_auth_events::patch_coxswain_external_auth_status(
            &ctx.client,
            policy,
            &ctx.controller_name,
            &ch,
        )
        .await;
    }
    Action::await_change()
}

/// Classify GatewayClasses from a synced store snapshot into `(owned,
/// owned_dedicated)` ownership sets. Mirrors the per-event classification the
/// old watcher applied; pure, so it is unit-testable.
fn classify_gateway_classes(
    classes: &[Arc<GatewayClass>],
    controller_name: &str,
) -> (HashSet<String>, HashSet<String>) {
    let mut owned = HashSet::new();
    let mut dedicated = HashSet::new();
    for gc in classes {
        if gc.spec.controller_name != controller_name {
            continue;
        }
        let Some(name) = gc.metadata.name.clone() else {
            continue;
        };
        if class_has_coxswain_params_ref(gc) {
            dedicated.insert(name.clone());
        }
        owned.insert(name);
    }
    (owned, dedicated)
}

/// Classify IngressClasses from a synced store snapshot into `(owned,
/// owned_default)` ownership sets. Pure, so it is unit-testable.
fn classify_ingress_classes(
    classes: &[Arc<IngressClass>],
    controller_name: &str,
) -> (HashSet<String>, HashSet<String>) {
    let mut owned = HashSet::new();
    let mut default = HashSet::new();
    for ic in classes {
        let is_owned =
            ic.spec.as_ref().and_then(|s| s.controller.as_deref()) == Some(controller_name);
        if !is_owned {
            continue;
        }
        let Some(name) = ic.metadata.name.clone() else {
            continue;
        };
        if coxswain_reflector::ingress::is_default_ingress_class(ic) {
            default.insert(name.clone());
        }
        owned.insert(name);
    }
    (owned, default)
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

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_reflector::gw_types::v::gatewayclasses::{GatewayClass, GatewayClassSpec};
    use k8s_openapi::api::networking::v1::{IngressClass, IngressClassSpec};
    use kube::api::ObjectMeta;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(b: u8) -> StatusAddress {
        StatusAddress::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, b)))
    }

    fn addr_ip(a: &StatusAddress) -> Option<IpAddr> {
        match a {
            StatusAddress::Ip(i) => Some(*i),
            StatusAddress::Hostname(_) => None,
        }
    }

    // ── latched address preservation (#531) ──────────────────────────────────

    #[test]
    fn current_status_typed_addresses_parses_published_entries() {
        use crate::status_common::addresses::SupportedAddressType;
        use coxswain_reflector::gw_types::v::gateways::{
            Gateway, GatewayStatus, GatewayStatusAddresses,
        };
        let gw = Gateway {
            metadata: ObjectMeta::default(),
            spec: Default::default(),
            status: Some(GatewayStatus {
                addresses: Some(vec![
                    GatewayStatusAddresses {
                        r#type: Some("IPAddress".to_string()),
                        value: "10.96.9.11".to_string(),
                    },
                    GatewayStatusAddresses {
                        r#type: Some("Hostname".to_string()),
                        value: "lb.example.com".to_string(),
                    },
                    GatewayStatusAddresses {
                        r#type: Some("NamedAddress".to_string()),
                        value: "bogus".to_string(),
                    },
                ]),
                ..Default::default()
            }),
        };
        let typed = current_status_typed_addresses(&gw);
        assert_eq!(typed.len(), 2, "unsupported type tags are dropped");
        assert_eq!(typed[0].type_, SupportedAddressType::IpAddress);
        assert_eq!(typed[0].value, "10.96.9.11");
        assert_eq!(typed[1].type_, SupportedAddressType::Hostname);
        assert_eq!(typed[1].value, "lb.example.com");

        let empty = Gateway {
            metadata: ObjectMeta::default(),
            spec: Default::default(),
            status: None,
        };
        assert!(current_status_typed_addresses(&empty).is_empty());
    }

    // ── proxy-pool bind gate helpers (#531) ──────────────────────────────────

    #[test]
    fn service_internal_ports_extracts_numeric_target_ports() {
        use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
        use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
        let svc = Service {
            spec: Some(ServiceSpec {
                ports: Some(vec![
                    ServicePort {
                        port: 443,
                        target_port: Some(IntOrString::Int(30001)),
                        ..Default::default()
                    },
                    ServicePort {
                        port: 80,
                        target_port: Some(IntOrString::Int(30002)),
                        ..Default::default()
                    },
                    // Named targetPort cannot occur on VIP Services; skipped.
                    ServicePort {
                        port: 8443,
                        target_port: Some(IntOrString::String("named".to_owned())),
                        ..Default::default()
                    },
                    // Absent targetPort (defaults to `port` server-side); skipped —
                    // the VIP reconciler always renders explicit allocations.
                    ServicePort {
                        port: 9443,
                        target_port: None,
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            service_internal_ports(&svc),
            [30001u16, 30002].into_iter().collect()
        );
    }

    #[test]
    fn proxy_bind_pending_detail_names_empty_pool() {
        let reg = coxswain_core::node_registry::SharedNodeRegistry::new();
        let detail = proxy_bind_pending_detail(&reg.load(), &[30001u16].into_iter().collect());
        assert!(
            detail.contains("no shared proxy nodes connected"),
            "got: {detail}"
        );
    }

    #[test]
    fn proxy_bind_pending_detail_counts_unbound_nodes_and_ports() {
        use coxswain_core::node_registry::{NodeScope, SharedNodeRegistry};
        let reg = SharedNodeRegistry::new();
        let now = std::time::SystemTime::UNIX_EPOCH;
        reg.connect("node-a", NodeScope::SharedPool, now);
        reg.record_bound_ports("node-a", [30001u16, 30002].into_iter().collect());
        reg.connect("node-b", NodeScope::SharedPool, now);
        // node-b never reported. A dedicated node must not count either way:
        reg.connect(
            "node-d",
            NodeScope::Gateway {
                namespace: "ns".to_owned(),
                name: "gw".to_owned(),
            },
            now,
        );
        let detail =
            proxy_bind_pending_detail(&reg.load(), &[30001u16, 30002].into_iter().collect());
        assert_eq!(
            detail,
            "waiting for 1/2 connected shared proxy node(s) to bind internal port(s) [30001, 30002]"
        );
    }

    // ── LeadershipState renew-error tolerance (#531) ─────────────────────────

    /// Default lease settings: ttl 15 s / renew 5 s → tolerate errors until
    /// 10 s have elapsed since the last successful renew (one renew interval
    /// of fencing margin before the 15 s TTL can expire).
    fn default_lease_state() -> LeadershipState {
        LeadershipState::new(Duration::from_secs(15), Duration::from_secs(5))
    }

    fn at(base: tokio::time::Instant, secs: u64) -> tokio::time::Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn transient_renew_error_within_budget_keeps_leadership() {
        let t0 = tokio::time::Instant::now();
        let mut s = default_lease_state();
        assert!(s.observe(RenewOutcome::Leading, t0));
        assert!(
            s.observe(RenewOutcome::RenewError, at(t0, 5)),
            "one apiserver blip at 5 s must not demote a leader whose lease is still valid"
        );
        assert!(
            s.observe(RenewOutcome::Leading, at(t0, 10)),
            "a successful renew resets the wall-clock budget"
        );
        assert!(
            s.observe(RenewOutcome::RenewError, at(t0, 15)),
            "budget is measured from the LAST successful renew (5 s elapsed here)"
        );
    }

    #[test]
    fn renew_errors_demote_at_the_wall_clock_deadline() {
        let t0 = tokio::time::Instant::now();
        let mut s = default_lease_state();
        assert!(s.observe(RenewOutcome::Leading, t0));
        assert!(s.observe(RenewOutcome::RenewError, at(t0, 5)));
        assert!(
            !s.observe(RenewOutcome::RenewError, at(t0, 10)),
            "10 s since the last successful renew must demote — one renew interval \
             before the 15 s TTL can expire and another replica can acquire"
        );
    }

    #[test]
    fn slow_failing_renew_cannot_outlive_the_ttl() {
        // The failure mode tick-counting missed: each renew call itself takes
        // seconds (apiserver blackhole), so the FIRST error can already land
        // past the deadline and must demote immediately.
        let t0 = tokio::time::Instant::now();
        let mut s = default_lease_state();
        assert!(s.observe(RenewOutcome::Leading, t0));
        assert!(
            !s.observe(RenewOutcome::RenewError, at(t0, 12)),
            "a single error observed 12 s after the last success is past the 10 s \
             deadline and must demote — error counts are irrelevant"
        );
    }

    #[test]
    fn not_acquired_demotes_immediately() {
        let t0 = tokio::time::Instant::now();
        let mut s = default_lease_state();
        assert!(s.observe(RenewOutcome::Leading, t0));
        assert!(
            !s.observe(RenewOutcome::Standby, at(t0, 5)),
            "a positive observation that another replica holds the lease is never tolerated"
        );
    }

    #[test]
    fn renew_error_while_standby_never_promotes() {
        let t0 = tokio::time::Instant::now();
        let mut s = default_lease_state();
        assert!(!s.observe(RenewOutcome::Standby, t0));
        for i in 0..10u64 {
            assert!(
                !s.observe(RenewOutcome::RenewError, at(t0, i)),
                "errors carry no information about the lease; a standby must stay standby"
            );
        }
    }

    #[test]
    fn degenerate_lease_settings_demote_on_first_late_error() {
        // ttl == renew_interval leaves no fencing margin; the deadline floors
        // at one renew interval, so the first error at/after a full interval
        // demotes rather than the deadline underflowing to zero (which would
        // demote on an error arriving instantly after a successful renew).
        let t0 = tokio::time::Instant::now();
        let mut s = LeadershipState::new(Duration::from_secs(5), Duration::from_secs(5));
        assert!(s.observe(RenewOutcome::Leading, t0));
        assert!(
            !s.observe(RenewOutcome::RenewError, at(t0, 5)),
            "with ttl == renew the first error a full interval later must demote"
        );
    }

    #[test]
    fn shared_gateway_advertises_its_own_resolved_vip() {
        let global = ip(3);
        let got = select_shared_gateway_address(&VipAddress::Resolved(ip(7)), true, Some(&global));
        assert_eq!(got.as_ref().and_then(addr_ip), addr_ip(&ip(7)));
    }

    #[test]
    fn shared_gateway_reports_no_address_while_vip_pending() {
        let global = ip(3);
        let got = select_shared_gateway_address(&VipAddress::Pending, true, Some(&global));
        assert!(
            got.is_none(),
            "pending VIP must not borrow the global address"
        );
    }

    #[test]
    fn shared_gateway_never_falls_back_to_global_when_feature_on() {
        // The regression behind the conformance GatewayHTTPListenerIsolation /
        // HTTPRoute*Redirect failures: with per-Gateway addressing ON, the global
        // --status-address points at the shared proxy's Ingress-only 80/443, so a
        // Gateway whose VIP isn't provisioned yet must report NO address (and
        // requeue) rather than advertise an address that resets its own traffic.
        let global = ip(3);
        let got = select_shared_gateway_address(&VipAddress::NotProvisioned, true, Some(&global));
        assert!(
            got.is_none(),
            "feature-on Gateway must never advertise the global shared address"
        );
    }

    #[test]
    fn unprovisioned_gateway_uses_global_address_when_feature_off() {
        // Legacy single-shared-IP model: with the feature OFF there are no
        // per-Gateway VIPs, so the global address IS the Gateway's address.
        let global = ip(3);
        let got = select_shared_gateway_address(&VipAddress::NotProvisioned, false, Some(&global));
        assert_eq!(got.as_ref().and_then(addr_ip), addr_ip(&ip(3)));
    }

    fn gateway_class(name: &str, controller: &str, dedicated: bool) -> Arc<GatewayClass> {
        use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClassParametersRef;
        Arc::new(GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller.to_string(),
                parameters_ref: dedicated.then(|| GatewayClassParametersRef {
                    group: COXSWAIN_PARAMS_GROUP.to_string(),
                    kind: COXSWAIN_PARAMS_KIND.to_string(),
                    name: "params".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        })
    }

    fn ingress_class(name: &str, controller: Option<&str>, default: bool) -> Arc<IngressClass> {
        let annotations = default.then(|| {
            [(
                "ingressclass.kubernetes.io/is-default-class".to_string(),
                "true".to_string(),
            )]
            .into_iter()
            .collect()
        });
        Arc::new(IngressClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                annotations,
                ..Default::default()
            },
            spec: Some(IngressClassSpec {
                controller: controller.map(str::to_string),
                ..Default::default()
            }),
        })
    }

    #[test]
    fn classify_gateway_classes_partitions_owned_and_dedicated() {
        let classes = [
            gateway_class("ours-shared", "coxswain", false),
            gateway_class("ours-dedicated", "coxswain", true),
            gateway_class("theirs", "other", false),
        ];
        let (owned, dedicated) = classify_gateway_classes(&classes, "coxswain");
        assert!(owned.contains("ours-shared"));
        assert!(owned.contains("ours-dedicated"));
        assert!(!owned.contains("theirs"));
        assert!(dedicated.contains("ours-dedicated"));
        assert!(!dedicated.contains("ours-shared"));
    }

    #[test]
    fn classify_ingress_classes_partitions_owned_and_default() {
        let classes = [
            ingress_class("ours", Some("coxswain"), false),
            ingress_class("ours-default", Some("coxswain"), true),
            ingress_class("theirs", Some("other"), true),
        ];
        let (owned, default) = classify_ingress_classes(&classes, "coxswain");
        assert!(owned.contains("ours"));
        assert!(owned.contains("ours-default"));
        assert!(!owned.contains("theirs"));
        assert!(default.contains("ours-default"));
        assert!(!default.contains("ours"));
        // `theirs` is default-annotated but not ours, so it must not appear.
        assert!(!default.contains("theirs"));
    }

    #[test]
    fn is_dedicated_mode_detects_class_membership() {
        let gw = Arc::new(Gateway {
            metadata: ObjectMeta::default(),
            spec: coxswain_reflector::gw_types::v::gateways::GatewaySpec {
                gateway_class_name: "ours-dedicated".to_string(),
                ..Default::default()
            },
            status: None,
        });
        let dedicated: HashSet<String> = ["ours-dedicated".to_string()].into_iter().collect();
        assert!(is_dedicated_mode(&gw, &dedicated));
        let empty = HashSet::new();
        assert!(!is_dedicated_mode(&gw, &empty));
    }
}
