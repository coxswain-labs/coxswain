//! Wiring helper for the `controller` pod role.
//!
//! Bundles the configuration, the leader-elected [`crate::Controller`] background
//! service, and the reflector pipeline whose health channels the Controller
//! subscribes to. The bin's `run_controller` arm invokes [`spawn_status_writer`]
//! and registers the returned services with the Pingora server.
//!
//! The proxy pod role does NOT call into this module. The shared-proxy
//! ServiceAccount has zero write verbs and the proxy binary path never
//! constructs a [`crate::Controller`], so any future regression would have
//! both an RBAC failure at the API server AND a runtime panic from clap's
//! per-role arg validation — defense in depth for the read-only-proxy
//! invariant.

use crate::{Controller, ControllerConfig, StatusChannels};
use coxswain_core::DedicatedRoutingRegistry;
use coxswain_core::cluster::SharedClusterSummary;
use coxswain_core::health::HealthRegistry;
use coxswain_core::ownership::OwnedGateways;
use coxswain_core::tls::{SharedClientCertStore, SharedListenerHostnames};
use coxswain_reflector::{
    ControllerReconciler, IngressEvent, ReconcilerHealth, ReconcilerOptions, ReconcilerOutputs,
    SharedBackendTlsPolicyStatus, SharedClientTrafficPolicyStatus,
    SharedCoxswainBackendPolicyStatus, SharedCoxswainExternalAuthStatus,
    SharedGatewayListenerStatus, SharedRouteStatus,
};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use thiserror::Error;

/// Configuration bundle for the status-writer pod role.
///
/// Carries everything the controller pod needs to wire up its reflector
/// pipeline and the leader-elected [`Controller`]. Construction is the bin
/// layer's responsibility; the `controller` role of the CLI builds this from
/// `ControllerRoleArgs` plus `CommonArgs`. Not `#[non_exhaustive]` —
/// it's an internal wiring struct that only `coxswain-bin` instantiates, and
/// the construction-site convenience outweighs the (nonexistent) downstream
/// compatibility win.
// intentionally open: field-literal constructed in crates/coxswain-bin/src/main.rs from CLI args.
pub struct StatusWriterConfig {
    /// Identity, leader-election parameters, and status-write address.
    pub controller: ControllerConfig,
    /// Optional cluster scope: when `Some`, namespace-scoped reflectors watch
    /// only the named namespace. `None` means cluster-wide.
    pub watch_namespace: Option<String>,
    /// Controller-name string this instance claims on `GatewayClass`,
    /// `HTTPRoute`, and `BackendTLSPolicy` `controllerName` fields.
    pub controller_name: String,
    /// Controller-wide default backend for unmatched Ingress traffic.
    /// Mirrors the proxy's `--ingress-default-backend`; controller-side use is
    /// just so the routing-table-build runs cleanly when this pod is wired up
    /// in dev mode (the production controller never serves traffic, so it
    /// builds the routing table only as a side-effect of computing health).
    pub ingress_default_backend: Option<coxswain_reflector::IngressDefaultBackend>,
    /// Ingress listener ports (used for the `PortUnavailable` Gateway listener
    /// condition).
    pub ingress_ports: coxswain_reflector::IngressPorts,
    /// Enable the Gateway API surface (HTTPRoute, GatewayClass, etc.).
    /// When `false`, Gateway API reflectors and health checks are not
    /// registered, and the surface is silently ignored.
    pub enable_gateway_api: bool,
    /// Enable the Ingress surface. When `false`, Ingress reflectors and health
    /// checks are not registered.
    pub enable_ingress: bool,
}

/// Error returned from [`spawn_status_writer`] when the wiring fails before
/// the background services have a chance to start.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum StatusWriterError {
    /// Forwarded configuration error from the underlying `ControllerConfig`.
    #[error("controller config: {0}")]
    Config(#[from] crate::ControllerConfigError),
}

/// Output bundle from [`spawn_status_writer`].
///
/// Holds the `ControllerReconciler` and `Controller` background services that the caller
/// registers with the Pingora server, plus the shared handles the bin needs to
/// expose via the admin server (the leader flag and the routing-table snapshots,
/// which the controller pod does not serve traffic from but does aggregate
/// for the admin `/api/v1` endpoints and operator UI). Same rationale as
/// [`StatusWriterConfig`] for the lack of `#[non_exhaustive]`.
#[non_exhaustive]
pub struct SpawnedStatusWriter {
    /// Reflector + rebuild background service.
    pub reconciler: ControllerReconciler,
    /// Leader-elected status-writer background service.
    pub controller: Controller,
    /// Leader flag — `true` when this pod is the elected leader.
    pub leader: Arc<AtomicBool>,
    /// Routing-table outputs. Controller doesn't serve traffic from these, but
    /// the admin server uses them to render the `/api/v1` cluster views and UI.
    pub outputs: ReconcilerOutputs,
}

/// Build the wiring for the `controller` pod role and return the spawned
/// background services. The caller is responsible for registering them with
/// the Pingora server.
///
/// # Errors
///
/// Returns [`StatusWriterError::Config`] if the underlying [`ControllerConfig`]
/// failed validation (e.g. malformed status address).
#[must_use = "the spawned writer handle must be retained or the status-writer task is dropped"]
pub fn spawn_status_writer(
    config: StatusWriterConfig,
    health: HealthRegistry,
) -> Result<SpawnedStatusWriter, StatusWriterError> {
    let StatusWriterConfig {
        controller,
        watch_namespace,
        controller_name,
        ingress_default_backend,
        ingress_ports,
        enable_gateway_api,
        enable_ingress,
    } = config;

    let ingress_routes = coxswain_core::routing::SharedIngressRoutingTable::new();
    let gateway_routes = coxswain_core::routing::SharedGatewayRoutingTable::new();
    let tls_store = coxswain_core::tls::SharedPortTlsStore::new();
    let client_cert_store = SharedClientCertStore::new();
    let listener_hostnames = SharedListenerHostnames::new();
    let gateway_listener_status = SharedGatewayListenerStatus::new();
    let cluster_summary = SharedClusterSummary::new();
    let leader = Arc::new(AtomicBool::new(false));
    let owned_gateways = OwnedGateways::new();
    let dedicated_registry = DedicatedRoutingRegistry::new();

    // Always-on checks: shared by both surfaces and by the fleet watch +
    // rebuild pipeline. `auth_secret` lives here (not in INGRESS_CHECKS)
    // because its reflector is spawned unconditionally in
    // `coxswain_reflector::reconciler::proxy` — Gateway API's `BasicAuth`
    // ExtensionRef (#442) consumes the same label-scoped store, so the watch
    // was made always-on regardless of `enable_ingress`. Registering it only
    // when Ingress is enabled left it spawned-but-unregistered with Ingress
    // disabled, panicking the first time the reflector reached `InitDone`.
    // `jwt_auth`, `coxswain_external_auth`, `compression`, `retry_policy`,
    // `rate_limit`, and `ip_access_control` are the same fix on the opposite
    // axis: the Ingress `auth-jwt` (#441), `ext-auth` (#549), `compression`
    // (#550), `retry` (#551), `rate-limit` (#552), and `ip-access-control`
    // (#553) annotations each consume the same CR store as their
    // Gateway-API `ExtensionRef` counterpart, so those reflectors are
    // always-on regardless of `enable_gateway_api` — their check names must
    // live here too, or `SubsystemHandle::set` panics the first time the
    // reflector reaches `InitDone` with Gateway API disabled.
    const ALWAYS_ON_CHECKS: &[&str] = &[
        "endpoint_slice",
        "secret",
        "service",
        "pod",
        "routing_table_built",
        "auth_secret",
        "jwt_auth",
        "coxswain_external_auth",
        "compression",
        "retry_policy",
        "rate_limit",
        "ip_access_control",
    ];
    // Per-surface checks registered only when the surface is enabled;
    // disabled surfaces never mark a check ready so registering them would
    // block /readyz forever.
    const INGRESS_CHECKS: &[&str] = &[
        "ingress",
        "ingress_class",
        "ingress_class_parameters",
        "auth_tls_secret",
    ];
    const GATEWAY_API_CHECKS: &[&str] = &[
        "gateway_api_crds",
        "httproute",
        "grpcroute",
        "tls_route",
        "tcp_route",
        "udp_route",
        "gateway",
        "gateway_class",
        "listener_set",
        "namespace",
        "reference_grant",
        "backend_tls_policy",
        "client_traffic_policy",
        "coxswain_backend_policy",
        "config_map",
        "path_rewrite_regex",
        "basic_auth",
        "request_size_limit",
    ];

    let mut controller_checks: Vec<&str> = ALWAYS_ON_CHECKS.to_vec();
    if enable_ingress {
        controller_checks.extend_from_slice(INGRESS_CHECKS);
    }
    if enable_gateway_api {
        controller_checks.extend_from_slice(GATEWAY_API_CHECKS);
    }

    let controller_handle = health.register("controller", &controller_checks);
    let proxy_handle = health.register("proxy", &["routing_table_loaded"]);

    let passthrough_routes = coxswain_core::routing::SharedTlsPassthroughTable::new();
    let terminate_routes = coxswain_core::routing::SharedTlsPassthroughTable::new();
    let tcp_routes = coxswain_core::routing::SharedTcpRouteTable::new();
    let udp_routes = coxswain_core::routing::SharedUdpRouteTable::new();
    let outputs = ReconcilerOutputs {
        ingress_routes,
        gateway_routes,
        tls: tls_store,
        client_certs: client_cert_store,
        listener_hostnames,
        listener_status: gateway_listener_status.clone(),
        cluster_summary,
        dedicated_registry,
        passthrough_routes: passthrough_routes.clone(),
        terminate_routes: terminate_routes.clone(),
        tcp_routes: tcp_routes.clone(),
        udp_routes: udp_routes.clone(),
    };

    // Create the ingress-event channel before the reconciler, so the sender can
    // be moved into `ReconcilerOptions` and the receiver into `Controller`.
    // Bounded at 256: the reconciler uses `try_send`, so a slow consumer causes
    // events to be dropped rather than back-pressuring the rebuild loop.
    let (ingress_event_tx, ingress_event_rx) = tokio::sync::mpsc::channel::<IngressEvent>(256);

    let reconciler = ControllerReconciler::new(
        ReconcilerOutputs {
            ingress_routes: outputs.ingress_routes.clone(),
            gateway_routes: outputs.gateway_routes.clone(),
            tls: outputs.tls.clone(),
            client_certs: outputs.client_certs.clone(),
            listener_hostnames: outputs.listener_hostnames.clone(),
            listener_status: outputs.listener_status.clone(),
            cluster_summary: outputs.cluster_summary.clone(),
            dedicated_registry: outputs.dedicated_registry.clone(),
            passthrough_routes: passthrough_routes.clone(),
            terminate_routes: terminate_routes.clone(),
            tcp_routes: tcp_routes.clone(),
            udp_routes: udp_routes.clone(),
        },
        owned_gateways.clone(),
        Arc::clone(&leader),
        ReconcilerHealth::new(controller_handle, proxy_handle),
        controller_name.clone(),
        {
            let mut opts = ReconcilerOptions::default();
            opts.watch_namespace = watch_namespace;
            opts.ingress_default_backend = ingress_default_backend;
            opts.ingress_ports = ingress_ports;
            opts.metrics_prefix = coxswain_reflector::MetricsPrefix::Controller;
            opts.watch_fleet = true;
            // Back the status-relevant stores with shared informers so the
            // status-writer's work-queues reuse them instead of duplicating
            // watches (#347).
            opts.status_subscriptions = true;
            opts.ingress_event_tx = Some(ingress_event_tx);
            opts.enable_gateway_api = enable_gateway_api;
            opts.enable_ingress = enable_ingress;
            // Controller role only (#441) — the read-only proxy must never
            // egress to a JWKS identity provider; see `coxswain_reflector::jwks`.
            opts.fetch_remote_jwks = true;
            opts
        },
    );

    let route_status: SharedRouteStatus = reconciler.route_status();
    let grpc_route_status: SharedRouteStatus = reconciler.grpc_route_status();
    let tls_route_status: SharedRouteStatus = reconciler.tls_route_status();
    let tcp_route_status: SharedRouteStatus = reconciler.tcp_route_status();
    let udp_route_status: SharedRouteStatus = reconciler.udp_route_status();
    let policy_status: SharedBackendTlsPolicyStatus = reconciler.policy_status();
    let ctp_status: SharedClientTrafficPolicyStatus = reconciler.ctp_status();
    let cbp_status: SharedCoxswainBackendPolicyStatus = reconciler.cbp_status();
    let external_auth_status: SharedCoxswainExternalAuthStatus = reconciler.external_auth_status();

    // Take the shared-informer subscriptions the reconciler created (it must
    // hand them over since we set `status_subscriptions = true` above).
    let subscriptions = reconciler.status_subscriptions().unwrap_or_else(|| {
        panic!("invariant: reconciler built with status_subscriptions must yield subscriptions")
    });

    let controller_svc = Controller::new(
        health,
        leader.clone(),
        owned_gateways,
        StatusChannels {
            tls: gateway_listener_status,
            route: route_status,
            grpc_route: grpc_route_status,
            tls_route: tls_route_status,
            tcp_route: tcp_route_status,
            udp_route: udp_route_status,
            policy: policy_status,
            ctp: ctp_status,
            cbp: cbp_status,
            external_auth: external_auth_status,
        },
        subscriptions,
        controller,
        Some(ingress_event_rx),
    );

    Ok(SpawnedStatusWriter {
        reconciler,
        controller: controller_svc,
        leader,
        outputs,
    })
}
