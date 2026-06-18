//! Wiring helper for the `controller` pod role.
//!
//! Bundles the configuration, the leader-elected [`crate::Controller`] background
//! service, and (in production startup) the reflector pipeline whose health
//! channels the Controller subscribes to. The bin's `run_controller` arm
//! invokes [`spawn_status_writer`] and registers the returned services with the
//! Pingora server; the bin's `run_dev` arm reuses the same wiring for the
//! in-process all-in-one mode.
//!
//! The proxy pod role does NOT call into this module. The shared-proxy
//! ServiceAccount has zero write verbs and the proxy binary path never
//! constructs a [`crate::Controller`], so any future regression would have
//! both an RBAC failure at the API server AND a runtime panic from clap's
//! per-role arg validation — defense in depth for the read-only-proxy
//! invariant.

use crate::{Controller, ControllerConfig, StatusHealthChannels};
use coxswain_core::cluster::SharedClusterSummary;
use coxswain_core::health::HealthRegistry;
use coxswain_core::ownership::OwnedGateways;
use coxswain_reflector::{
    ControllerReconciler, ReconcilerHealth, ReconcilerOptions, ReconcilerOutputs,
    SharedBackendTlsPolicyHealth, SharedGatewayListenerHealth, SharedHttpRouteHealth,
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
/// for the future `/cluster` endpoint). Same rationale as
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
    /// the admin server uses them to render `/cluster`-style aggregates.
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
    } = config;

    let ingress_routes = coxswain_core::routing::SharedIngressRoutingTable::new();
    let gateway_routes = coxswain_core::routing::SharedGatewayRoutingTable::new();
    let tls_store = coxswain_core::tls::SharedTlsStore::new();
    let gateway_tls_health = SharedGatewayListenerHealth::new();
    let cluster_summary = SharedClusterSummary::new();
    let leader = Arc::new(AtomicBool::new(false));
    let owned_gateways = OwnedGateways::new();

    let controller_handle = health.register(
        "controller",
        &[
            "httproute",
            "ingress",
            "ingress_class",
            "ingress_class_parameters",
            "gateway",
            "gateway_class",
            "endpoint_slice",
            "reference_grant",
            "secret",
            "auth_secret",
            "service",
            "backend_tls_policy",
            "config_map",
            "rate_limit",
            "pod",
            "routing_table_built",
        ],
    );
    let proxy_handle = health.register("proxy", &["routing_table_loaded"]);

    let outputs = ReconcilerOutputs::new(
        ingress_routes,
        gateway_routes,
        tls_store,
        gateway_tls_health.clone(),
        cluster_summary,
    );

    let reconciler = ControllerReconciler::new(
        ReconcilerOutputs::new(
            outputs.ingress_routes.clone(),
            outputs.gateway_routes.clone(),
            outputs.tls.clone(),
            outputs.tls_health.clone(),
            outputs.cluster_summary.clone(),
        ),
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
            opts
        },
    );

    let route_health: SharedHttpRouteHealth = reconciler.route_health();
    let policy_health: SharedBackendTlsPolicyHealth = reconciler.policy_health();

    // Take the shared-informer subscriptions the reconciler created (it must
    // hand them over since we set `status_subscriptions = true` above).
    let subscriptions = reconciler.status_subscriptions().unwrap_or_else(|| {
        panic!("invariant: reconciler built with status_subscriptions must yield subscriptions")
    });

    let controller_svc = Controller::new(
        health,
        leader.clone(),
        owned_gateways,
        StatusHealthChannels {
            tls: gateway_tls_health,
            route: route_health,
            policy: policy_health,
        },
        subscriptions,
        controller,
    );

    Ok(SpawnedStatusWriter {
        reconciler,
        controller: controller_svc,
        leader,
        outputs,
    })
}
