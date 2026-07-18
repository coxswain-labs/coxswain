//! The `controller` pod role runner: leader-elected status writer.
//!
//! Watches the cluster, computes per-resource health, and patches `*/status`
//! subresources; runs no data-plane services. Shared wiring lives in
//! [`crate::wiring`], [`crate::services`], and [`crate::discovery`].

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use coxswain_admin::{AdminServer, EventSources, OperatorAggregator};
use coxswain_controller::{
    IngressPorts, OperatorConfig, RELAY_DISCOVERY_PORT, RELAY_SERVICE_ACCOUNT,
    SHARED_RELAY_SERVICE_ACCOUNT, StatusWriterConfig, spawn_status_writer,
};
use coxswain_core::health::HealthRegistry;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::shared::Shared;
use coxswain_discovery::{ProvisionedRelayAuthorizer, UpstreamResolverConfig};
use coxswain_reflector::{DebounceSettings, WatchScope};
use pingora_core::services::background::background_service;
use pingora_core::services::listening::Service;
use tokio::sync::watch;

use crate::args::ControllerRoleArgs;
use crate::discovery::{CONTROLLER_SPIFFE_SA, DiscoveryIdentityService, map_ca_mode};
use crate::wiring::{build_controller_config, build_minimal_server, init_logger};

/// Wire and run the `controller` pod role: leader-elected status writer, no
/// data-plane services. Watches the cluster, computes per-resource health, and
/// patches `*/status` subresources via [`coxswain_controller::Controller`].
pub(crate) fn run_controller(args: ControllerRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "controller",
        controller_name = %args.common.controller_name,
        "Starting"
    );

    let controller_config = build_controller_config(&args.common, &args.controller)?;
    let debounce = DebounceSettings::new(
        args.controller.reconcile_debounce_min,
        args.controller.reconcile_debounce_max,
    )
    .context("invalid --reconcile-debounce-min/--reconcile-debounce-max")?;

    let mut server = build_minimal_server();
    let health = HealthRegistry::new();
    // Relist wedge backstop (#573): the reconciler's monitor trips this gate on
    // a stuck watch relist; `/healthz` reports it so kubelet restarts the pod.
    let liveness_gate = coxswain_core::health::LivenessGate::new();

    let status_writer = spawn_status_writer(
        StatusWriterConfig {
            controller: controller_config,
            watch_scope: WatchScope::parse(args.common.watch_namespace.as_deref())?,
            controller_name: args.common.controller_name.clone(),
            ingress_default_backend: None,
            ingress_ports: IngressPorts::new(
                args.common.ingress_http_port,
                args.common.ingress_https_port,
            ),
            enable_gateway_api: !args.common.disable_gateway_api,
            enable_ingress: !args.common.disable_ingress,
            debounce,
            liveness_gate: Some(liveness_gate.clone()),
        },
        health.clone(),
    )?;

    // The operator publishes Gateway.status conditions for dedicated-mode
    // Gateways using the same per-listener TLS / route status channels the
    // shared-pool status writer subscribes to (#211). The bin layer is the
    // sole construction site for both — share the same instances so the
    // operator's reconcile-all retrigger fires off the exact channel the
    // reflector publishes into.
    let listener_status = status_writer.outputs.listener_status.clone();
    let route_status = status_writer.reconciler.route_status();

    // Capture the fleet handle before the reconciler is moved into its
    // background service — same pattern as `route_status` above.
    let fleet = status_writer.reconciler.fleet();

    // Event sources for the /api/v1/events SSE stream (#250). Capture the
    // rebuild generation receiver and clones of the fleet / cluster handles
    // before the originals are moved into the operator and aggregator below.
    let events = EventSources::new(
        route_status.subscribe(),
        fleet.clone(),
        status_writer.outputs.cluster_summary.clone(),
        args.common.pod_name.clone(),
    );

    // Discovery gRPC server: capture a rebuild-generation receiver off the
    // shared `route_status` handle. Every controller replica
    // LISTENS, but the Stream RPC is leader-gated (#531): standbys reject
    // streams so proxy readiness reports land on the status-writing leader.
    // Bootstrap (SVID issuance) stays un-gated on every replica.
    let discovery_rebuild_rx = route_status.subscribe();
    // Per-Gateway publish-sequence index (#531): stamped by the reconciler's
    // rebuild loop, captured by the discovery server before every snapshot
    // build, and consulted (with the node registry's acked sequences) by both
    // Programmed status writers as the ack half of the readiness gate.
    let publish_index = status_writer.reconciler.publish_index();
    let node_registry = coxswain_core::node_registry::NodeRegistryHandle::new();
    let node_registry_for_agg = node_registry.clone();
    let node_registry_for_controller = node_registry.clone();
    let node_registry_for_operator = node_registry.clone();
    // Leadership watch (#531): the lease loop is the single sender; the
    // discovery server gates streams on it and the operator re-drives on
    // promotion. Initialized false → discovery starts gated-closed and opens
    // on first promotion, so startup order is a non-issue.
    let (leader_watch_tx, leader_watch_rx) = tokio::sync::watch::channel(false);
    // Definitively-failed static-address VIP set (#533): written by the operator's
    // VIP reconciler, read by the status writer so a Gateway still provisioning
    // its VIP is held Pending rather than briefly reporting AddressNotUsable.
    let vip_failures = Shared::<HashSet<ObjectKey>>::new();
    let discovery_source = coxswain_discovery::SnapshotSource {
        ingress: status_writer.outputs.ingress_routes.clone(),
        gateway: status_writer.outputs.gateway_routes.clone(),
        tls: status_writer.outputs.tls.clone(),
        client_certs: status_writer.outputs.client_certs.clone(),
        listener_status: listener_status.clone(),
        dedicated: status_writer.outputs.dedicated_registry.clone(),
        passthrough_routes: status_writer.outputs.passthrough_routes.clone(),
        terminate_routes: status_writer.outputs.terminate_routes.clone(),
        tcp_routes: status_writer.outputs.tcp_routes.clone(),
        udp_routes: status_writer.outputs.udp_routes.clone(),
        publish: publish_index.clone(),
    };
    // The relay tier keeps two derived sets, both written solely by the operator's
    // relay control loop (#584/#602):
    // - `provisioned_relays` (authz): every namespace with a relay in any state
    //   (provisioning/active/draining). The discovery server's
    //   `ProvisionedRelayAuthorizer` reads it lock-free to authorize a relay's own
    //   `Scope::Namespace` upstream subscribe — a relay must be authorized *before*
    //   it can become Ready.
    // - `active_relays` (repoint): only namespaces whose relay is Ready and serving.
    //   The `UpstreamResolverConfig` reads it so a leaf repoints onto a relay only
    //   *after* it can serve — the make-before-break gate.
    // Both empty when relay tiering is off (authorizer denies every Namespace
    // subscribe, identical to the `DenyAllNamespaces` default; the resolver points
    // every leaf at the controller).
    let provisioned_relays = Shared::<HashSet<String>>::new();
    let active_relays = Shared::<HashSet<String>>::new();
    // Shared-pool repoint gate (#605): the shared-relay control loop flips this
    // `Active` once its relay is Ready, and the resolver points the pool at the
    // shared relay while it is set (else the controller). Written by the operator,
    // read here — the same make-before-break gate as `active_relays`, single-cell.
    let shared_relay_active = Shared::from_value(false);
    // The shared relay's fixed Service DNS — provisioned in the install namespace
    // under the same constant the operator renders it with, so the endpoint the pool
    // is repointed to stays in lockstep with the rendered Service by construction.
    let shared_relay_endpoint = format!(
        "https://{}.{}.svc:{}",
        SHARED_RELAY_SERVICE_ACCOUNT, args.common.pod_namespace, RELAY_DISCOVERY_PORT
    );
    // Live upstream-repoint (#601/#602/#605): the resolver computes each leaf's
    // current best upstream (its namespace's relay / the shared relay if Active, else
    // the controller); the relay-change watch wakes live streams when a repoint set
    // moves. The bootstrap service reuses the same resolver so a leaf's initial
    // upstream and its live repoints are computed identically.
    let controller_stream_endpoint = format!(
        "https://coxswain-controller-discovery.{}.svc:{}",
        args.common.pod_namespace, args.controller.discovery_port
    );
    let upstream_resolver = Arc::new(UpstreamResolverConfig {
        controller_endpoint: controller_stream_endpoint,
        controller_sa: CONTROLLER_SPIFFE_SA.to_string(),
        shared_relay_endpoint,
        shared_relay_sa: SHARED_RELAY_SERVICE_ACCOUNT.to_string(),
        shared_relay_active: shared_relay_active.clone(),
        relay_service_name: RELAY_SERVICE_ACCOUNT.to_string(),
        relay_port: RELAY_DISCOVERY_PORT,
        relay_sa: RELAY_SERVICE_ACCOUNT.to_string(),
        active_relays: active_relays.clone(),
    });
    let (relay_changed_tx, relay_changed_rx) = watch::channel(0u64);
    let discovery_service = coxswain_discovery::DiscoveryService::new(
        discovery_source,
        node_registry,
        discovery_rebuild_rx,
    )
    .with_leader_gate(leader_watch_rx.clone())
    .with_scope_authorizer(Arc::new(ProvisionedRelayAuthorizer::new(
        provisioned_relays.clone(),
        RELAY_SERVICE_ACCOUNT,
        args.controller.discovery_trust_domain.clone(),
    )))
    .with_upstream_directives(upstream_resolver.clone(), relay_changed_rx);
    let discovery_addr = SocketAddr::new(
        args.common.management_bind_address,
        args.controller.discovery_port,
    );
    let bootstrap_addr = SocketAddr::new(
        args.common.management_bind_address,
        args.controller.discovery_bootstrap_port,
    );
    server.add_service(background_service(
        "discovery-identity",
        DiscoveryIdentityService {
            discovery_service,
            stream_addr: discovery_addr,
            bootstrap_addr,
            ca_secret: args.controller.discovery_ca_secret.clone(),
            ca_mode: map_ca_mode(args.controller.discovery_ca_mode),
            namespace: args.common.pod_namespace.clone(),
            svid_ttl: args.controller.discovery_svid_ttl,
            trust_domain: args.controller.discovery_trust_domain.clone(),
            controller_name: args.common.controller_name.clone(),
            pod_name: args.common.pod_name.clone(),
            upstream_resolver,
        },
    ));

    // #574 fold: the dedicated-provisioning operator no longer runs as its own
    // `BackgroundService` with a separate Kubernetes client. Its reconcile
    // context is built by the controller off the reflector's `OperatorStores`,
    // its VIP reconciler is spawned by the controller, and the unified status
    // worker's Gateway branch drives dedicated provisioning. Capture the operator
    // stores from the reconciler (built with status stores in the controller
    // role) before it is moved into its background service below.
    let operator_stores = status_writer
        .reconciler
        .operator_stores()
        .unwrap_or_else(|| panic!("invariant: controller reconciler must yield operator stores"));
    let operator_config = OperatorConfig {
        controller_name: args.common.controller_name.clone(),
        controller_image: resolve_controller_image(),
        leader: Arc::clone(&status_writer.leader),
        listener_status,
        ingress_ports: IngressPorts::new(
            args.common.ingress_http_port,
            args.common.ingress_https_port,
        ),
        admin_port: args.common.admin_port,
        // Bootstrap lives on its own all-replicas Service (#531): the stream
        // Service is leader-selected, but SVID issuance must keep working through
        // leader churn. Since #601 this is the sole endpoint the operator renders
        // into the dedicated-proxy Deployment — the routing-stream upstream is
        // bootstrap-delivered and runtime-directed, not a rendered flag.
        discovery_bootstrap_endpoint: format!(
            "https://coxswain-controller-discovery-bootstrap.{}.svc:{}",
            args.common.pod_namespace, args.controller.discovery_bootstrap_port
        ),
        discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token".to_string(),
        discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt".to_string(),
        discovery_trust_domain: args.controller.discovery_trust_domain.clone(),
        controller_namespace: args.common.pod_namespace.clone(),
        shared_proxy_selector: args.controller.shared_proxy_selector.clone(),
        shared_vip_service_type: args.controller.shared_vip_service_type,
        shared_proxy: args.controller.shared_proxy_config(),
        health_port: args.common.health_port,
        enable_ingress: !args.common.disable_ingress,
        enable_gateway_api: !args.common.disable_gateway_api,
        vip_failures: vip_failures.clone(),
        node_registry: Some(node_registry_for_operator),
        publish_index: Some(publish_index.clone()),
        relay: args.controller.relay_config(),
        provisioned_relays,
        active_relays,
        // Shared-pool repoint gate (#605): the shared-relay control loop flips this,
        // the resolver reads it (same cell as above).
        shared_relay_active,
        // Repoint-set change signal (#601/#602/#605): the relay control loops bump
        // this whenever a namespace (or the shared pool) enters or leaves `Active`,
        // so the discovery server repoints the affected leaves live (make-before-break).
        relay_changed_tx: Some(relay_changed_tx),
    };

    server.add_service(background_service(
        "controller",
        status_writer
            .controller
            .with_vip_failures(vip_failures)
            .with_leadership_watch(leader_watch_tx)
            .with_node_registry(node_registry_for_controller)
            .with_publish_index(publish_index)
            .with_operator(operator_config, operator_stores),
    ));
    server.add_service(background_service("reconciler", status_writer.reconciler));

    // The aggregator's per-proxy routes/facets/problems views read these same
    // cells directly (#537) rather than fanning out to the proxy over HTTP —
    // it's the controller's own intent, the exact thing it pushes to proxies
    // over the discovery stream.
    // Fan-out HTTP client for the operator aggregator, built once here so a
    // rustls-init failure surfaces as a typed startup error rather than a panic
    // deep in the aggregator constructor.
    let aggregator_http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .context("building the operator-aggregator fan-out HTTP client")?;
    let aggregator = OperatorAggregator::new(
        aggregator_http,
        fleet,
        status_writer.outputs.cluster_summary,
        Some(node_registry_for_agg),
        status_writer.outputs.ingress_routes.clone(),
        status_writer.outputs.gateway_routes.clone(),
        status_writer.outputs.dedicated_registry.clone(),
    );

    let health_addr = SocketAddr::new(args.common.management_bind_address, args.common.health_port);
    server.add_service({
        let mut svc = Service::new(
            "health".to_string(),
            coxswain_health::HealthServer {
                registry: health.clone(),
                liveness: Some(liveness_gate.clone()),
            },
        );
        svc.add_tcp(&health_addr.to_string());
        svc
    });

    let admin_addr = SocketAddr::new(args.common.management_bind_address, args.common.admin_port);
    // The controller has no local routing tables of its own to wire — its
    // routing surface is the aggregate `/api/v1/{fleet,routing}/*` above, and
    // the proxy admin query surface (`/api/v1/routes`) was retired in #537.
    server.add_service(
        AdminServer::new(health, status_writer.leader)
            .with_aggregator(aggregator)
            .with_events(events)
            .with_ui()
            .with_api_surfaces(
                !args.common.disable_gateway_api,
                !args.common.disable_ingress,
            )
            .into_service(admin_addr),
    );

    tracing::info!(
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        discovery_addr = %discovery_addr,
        bootstrap_addr = %bootstrap_addr,
        "Listening"
    );
    server.run_forever();
}

/// Resolve the image string the provisioning operator embeds in rendered
/// dedicated-proxy Deployments when `CoxswainGatewayParameters.spec.image`
/// is unset.
pub(crate) fn resolve_controller_image() -> String {
    std::env::var("COXSWAIN_IMAGE").unwrap_or_else(|_| {
        format!(
            "ghcr.io/coxswain-labs/coxswain:{}",
            env!("CARGO_PKG_VERSION")
        )
    })
}
