//! Coxswain binary runtime: CLI parsing, shared-state wiring, and Pingora runtime bootstrap.

mod args;

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use coxswain_admin::{AdminServer, EventSources, OperatorAggregator};
use coxswain_controller::{
    BootstrapRejectHook, CaMode, ControllerConfig, IngressPorts, KubeTokenAuthenticator,
    LeaseSettings, OperatorConfig, RELAY_DISCOVERY_PORT, RELAY_SERVICE_ACCOUNT,
    SHARED_RELAY_SERVICE_ACCOUNT, SharedGatewayListenerStatus, StatusWriterConfig,
    load_or_generate, spawn_status_writer, spawn_trust_publisher,
};
use coxswain_core::health::{HealthRegistry, SubsystemHandle};
use coxswain_core::identity::{SpiffeId, SvidIssuer};
use coxswain_core::listener_status::ProxyProtocolListenerConfig;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::RouteTimeouts;
use coxswain_core::shared::Shared;
use coxswain_discovery::{
    BootstrapClient, BootstrapClientConfig, BootstrapRunner, BootstrapService,
    DiscoveryBootstrapServerTls, DiscoveryClient, DiscoveryClientConfig, DiscoveryServerTls,
    DiscoveryService, ProvisionedRelayAuthorizer, RelayUpstream, RotatingServerTls, Scope,
    SpiffeMatcher, Supervisor, UpstreamResolverConfig, namespace_relay, serve_discovery_with_tls,
    shared_relay,
};
use coxswain_proxy::{
    GatewayProxy, GrpcAuthChannelCache, IngressProxy, ListenerProtocol, ListenerSpec,
    PassthroughConfig, ProxyAcceptor, RateLimiterRegistry, RoutingEngine, RoutingSource,
    SharedProxyConfig, SniCertSelector, UpstreamCaCache,
};
use coxswain_reflector::{DebounceSettings, GatewayListenerStatus, ListenerReadiness, WatchScope};
use pingora_core::apps::HttpServerOptions;
use pingora_core::server::Server;
use pingora_core::server::ShutdownWatch;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::services::background::background_service;
use pingora_core::services::listening::Service;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::args::{
    AccessLogPathMode as BinAccessLogPathMode, CaModeArg, Cli, Commands, CommonArgs,
    ControllerArgs, ControllerRoleArgs, DiscoveryClientArgs, LogFormat, ProxyArgs, ProxyRoleArgs,
    ProxyScope, RelayRoleArgs, RelayScope, Role,
};
use coxswain_proxy::AccessLogPathMode;

/// Executes the Coxswain proxy/controller role specified by the CLI arguments.
///
/// This is the primary entry point for the binary, responsible for CLI parsing,
/// shared state wiring, and bootstrapping the Pingora runtime or Kubernetes
/// controllers.
///
/// # Errors
/// Returns an error if CLI parsing fails, an invalid configuration is provided,
/// or the server fails to bind or run.
#[must_use = "the run() result is the process exit status; dropping it hides startup failures"]
pub fn run() -> Result<()> {
    // reqwest is compiled with `rustls-no-provider`; install ring explicitly so
    // the ext_authz sub-request client can be constructed (rustls 0.23 requires
    // a crypto provider before any TLS object is created).
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cli = Cli::parse();
    let Commands::Serve(serve) = cli.command;

    let role = serve.role.ok_or_else(|| {
        anyhow::anyhow!(
            "missing role: pick one of `controller`, `proxy --shared`, `proxy --dedicated`, `relay --shared`, or `relay --namespace <NS>`"
        )
    })?;

    match role {
        Role::Controller(controller_args) => run_controller(controller_args),
        Role::Proxy(proxy_args) => match proxy_args.scope() {
            ProxyScope::Shared => run_proxy_shared(proxy_args),
            ProxyScope::Gateway { name, namespace } => {
                run_proxy_gateway(proxy_args, name, namespace)
            }
        },
        Role::Relay(relay_args) => run_relay(relay_args),
    }
}

/// Wire and run the `controller` pod role: leader-elected status writer, no
/// data-plane services. Watches the cluster, computes per-resource health, and
/// patches `*/status` subresources via [`coxswain_controller::Controller`].
fn run_controller(args: ControllerRoleArgs) -> Result<()> {
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
    let node_registry = coxswain_core::node_registry::SharedNodeRegistry::new();
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
        relay_enabled: args.controller.relay_enabled,
        relay_replicas: args.controller.relay_replicas,
        relay_min_proxy_replicas: args.controller.relay_min_proxy_replicas,
        relay_target_proxies_per_replica: args.controller.relay_target_proxies_per_replica,
        relay_max_replicas: args.controller.relay_max_replicas,
        relay_cooldown: args.controller.relay_cooldown,
        relay_scale_down_stabilization: args.controller.relay_scale_down_stabilization,
        relay_tolerance: args.controller.relay_tolerance,
        relay_cpu_request: args.controller.relay_cpu_request.clone(),
        relay_memory_request: args.controller.relay_memory_request.clone(),
        relay_memory_limit: args.controller.relay_memory_limit.clone(),
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
fn resolve_controller_image() -> String {
    std::env::var("COXSWAIN_IMAGE").unwrap_or_else(|_| {
        format!(
            "ghcr.io/coxswain-labs/coxswain:{}",
            env!("CARGO_PKG_VERSION")
        )
    })
}

/// Wire and run the `proxy --shared` pod role: read-only data plane for
/// Ingress + non-dedicated Gateway traffic. No status writes, no leader
/// election.
fn run_proxy_shared(args: ProxyRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "proxy",
        scope = "shared",
        controller_name = %args.common.controller_name,
        "Starting"
    );

    let mut server = build_server(&args.proxy);

    let health = HealthRegistry::new();
    let proxy_handle = health.register("proxy", &["routing_table_loaded"]);

    // Bound-port telemetry (#531): acceptor → discovery client → controller.
    let (bound_ports_tx, bound_ports_rx) = watch::channel(BTreeSet::new());
    let (client, supervisor, bootstrap_runner) = build_discovery_client(
        &args.discovery,
        &args.common,
        proxy_handle,
        Scope::SharedPool,
        Some(bound_ports_rx),
    )?;
    let listener_status = client.listener_status();

    wire_proxy_services(
        &mut server,
        &args.common,
        &args.proxy,
        &client,
        &listener_status,
        Some(bound_ports_tx),
    )?;

    register_discovery_background_services(&mut server, supervisor, bootstrap_runner);

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        ManagementServerConfig { health, leader },
    );

    tracing::info!(
        proxy_bind_address = %args.proxy.proxy_bind_address,
        ingress_http_port = ?args.common.ingress_http_port,
        ingress_https_port = ?args.common.ingress_https_port,
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        proxy_shutdown_grace_period = ?args.proxy.proxy_shutdown_grace_period,
        proxy_shutdown_timeout = ?args.proxy.proxy_shutdown_timeout,
        proxy_listener_drain_timeout = ?args.proxy.proxy_listener_drain_timeout,
        "Listening"
    );
    server.run_forever();
}

/// Wire and run the `proxy --dedicated` pod role: read-only data plane scoped
/// to one named Gateway.
///
/// `gateway_name`/`gateway_namespace` are the `ProxyScope::Gateway` payload the
/// caller already matched in [`run`] — passed in rather than re-derived via a
/// second `args.scope()` call, which would re-clone both strings and force a
/// dead `ProxyScope::Shared` arm that could only be reached by a caller bug.
fn run_proxy_gateway(
    args: ProxyRoleArgs,
    gateway_name: String,
    gateway_namespace: String,
) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "proxy",
        scope = "gateway",
        gateway = %format!("{gateway_namespace}/{gateway_name}"),
        controller_name = %args.common.controller_name,
        "Starting"
    );

    let mut server = build_server(&args.proxy);

    let health = HealthRegistry::new();
    let proxy_handle = health.register("proxy", &["routing_table_loaded"]);

    // This dedicated proxy subscribes with Scope::Gateway{name, namespace}; the
    // discovery server filters the snapshot to this Gateway's routing world via
    // the dedicated registry (#426), so it receives only its own routes.
    let scope = Scope::Gateway {
        name: gateway_name.clone(),
        namespace: gateway_namespace.clone(),
    };
    // Bound-port telemetry (#531): the dedicated Programmed gate consumes the
    // same NodeStatus reports as the shared one, scoped to this Gateway.
    let (bound_ports_tx, bound_ports_rx) = watch::channel(BTreeSet::new());
    let (client, supervisor, bootstrap_runner) = build_discovery_client(
        &args.discovery,
        &args.common,
        proxy_handle,
        scope,
        Some(bound_ports_rx),
    )?;
    let listener_status = client.listener_status();

    wire_gateway_only_proxy_services(
        &mut server,
        &args.common,
        &args.proxy,
        &client,
        &listener_status,
        Some(bound_ports_tx),
    )?;

    register_discovery_background_services(&mut server, supervisor, bootstrap_runner);

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        ManagementServerConfig { health, leader },
    );

    tracing::info!(
        proxy_bind_address = %args.proxy.proxy_bind_address,
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        proxy_shutdown_grace_period = ?args.proxy.proxy_shutdown_grace_period,
        proxy_shutdown_timeout = ?args.proxy.proxy_shutdown_timeout,
        proxy_listener_drain_timeout = ?args.proxy.proxy_listener_drain_timeout,
        "Listening"
    );
    server.run_forever();
}

/// Wire and run the `relay` pod role (#583): a zero-RBAC discovery cache that
/// subscribes upstream to the controller and re-serves the snapshot stream
/// downstream to proxies (leaves).
///
/// Kube-free by construction — the downstream server presents the relay's own
/// rotating bootstrapped SVID and the mounted trust bundle, so it needs no CA
/// Secret, trust-bundle ConfigMap, or TokenReview (all of which the controller's
/// discovery server needs and none of which the relay's RBAC-less SA can reach).
/// The default `DenyAllNamespaces` authorizer on the downstream `DiscoveryService`
/// rejects any leaf `Namespace` subscribe (relay-behind-relay is out of scope).
fn run_relay(args: RelayRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    let relay_scope = args.scope();
    let (scope, scope_label) = match &relay_scope {
        RelayScope::Shared => (Scope::SharedPool, "shared".to_owned()),
        RelayScope::Namespace { namespace } => (
            Scope::Namespace {
                namespace: namespace.clone(),
            },
            format!("namespace/{namespace}"),
        ),
    };

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        role = "relay",
        scope = %scope_label,
        controller_name = %args.common.controller_name,
        "Starting"
    );

    // The relay serves no client traffic; like the controller it needs only a
    // minimal Pingora server for its background services + management servers.
    let mut server = build_minimal_server();

    let health = HealthRegistry::new();
    let relay_handle = health.register("relay", &["routing_table_loaded", "downstream_serving"]);

    // The relay's downstream registry (populated by its downstream server as
    // leaves connect/ack/bind) is the SOURCE of the upstream `RosterReport`
    // (#585). It is retained here — unlike the controller, whose registry is the
    // gate's source of truth — precisely so the reporter below can watch it.
    let node_registry = coxswain_core::node_registry::SharedNodeRegistry::new();

    // Roster channel: the reporter publishes the downstream registry snapshot;
    // the upstream client forwards it to the controller as a `RosterReport`.
    let (roster_tx, roster_rx) =
        tokio::sync::watch::channel(coxswain_core::node_registry::NodeRegistry::default());

    // Upstream discovery client config (bootstrap + SVID + expected-server). The
    // relay reports no bound ports of its own (#531) — leaf state reaches the
    // controller via `RosterReport` (#585), wired here as the roster receiver.
    let (mut config, bootstrap_runner) =
        build_discovery_client_config(&args.discovery, &args.common, scope, None);
    config.roster_rx = Some(roster_rx);

    // The relay's downstream serving cert IS its rotating bootstrapped SVID, so a
    // bootstrap endpoint is mandatory — without it there is no serving identity.
    let svid = config.svid_cell.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "serve relay requires --discovery-bootstrap-endpoint to obtain a downstream serving SVID"
        )
    })?;

    // Assemble the upstream client + the downstream-serving `SnapshotSource` it
    // feeds. `relay_handle` marks `routing_table_loaded` on the first upstream
    // snapshot (the client's own readiness transition).
    let RelayUpstream {
        source,
        supervisor,
        rebuild_rx,
        directive_tx,
    } = match &relay_scope {
        RelayScope::Shared => shared_relay(config, relay_handle.clone(), "routing_table_loaded")?,
        RelayScope::Namespace { .. } => {
            namespace_relay(config, relay_handle.clone(), "routing_table_loaded")?
        }
    };

    // Downstream discovery service over the relay's own `SnapshotSource`. No
    // leader gate (the relay is not leader-elected) and the default
    // `DenyAllNamespaces` authorizer (a leaf never subscribes `Namespace`).
    // Directive forwarding (#601): the upstream client fans controller
    // `PreferredUpstream` directives into `directive_tx`; the downstream server
    // forwards each to the leaf it targets so a repoint reaches a relay-fronted
    // proxy through the relay.
    let discovery_service = DiscoveryService::new(source, node_registry.clone(), rebuild_rx)
        .with_directive_forwarding(directive_tx);

    // Debounced roster reporter: watch the downstream registry and republish it
    // to the upstream client whenever it changes (#585). A periodic backstop
    // tick catches ack-only changes — `record_ack` deliberately does NOT fire
    // the registry's change watch (per #531, to avoid re-driving gate consumers
    // on every push), yet acks carry the `acked_seq` the controller's gate needs.
    // The content dedup suppresses redundant sends so an idle relay stays quiet.
    {
        let registry = node_registry.clone();
        server.add_service(background_service(
            "relay-roster-reporter",
            FutureService::new(async move {
                let mut change = registry.subscribe();
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut last_sent: Option<coxswain_core::node_registry::NodeRegistry> = None;
                loop {
                    tokio::select! {
                        res = change.changed() => {
                            if res.is_err() {
                                break; // registry dropped (process shutdown)
                            }
                        }
                        _ = tick.tick() => {}
                    }
                    // Coalesce a burst of changes into one send.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    let snapshot = registry.load();
                    if last_sent.as_ref() == Some(&snapshot) {
                        continue;
                    }
                    if roster_tx.send(snapshot.clone()).is_err() {
                        break; // upstream client gone
                    }
                    last_sent = Some(snapshot);
                }
            }),
        ));
    }

    // Downstream mTLS acceptor: serving cert resolved from the rotating SVID
    // cell, client-CA = the mounted trust bundle, client identity = any SVID in
    // the trust domain (per-scope binding stays in the `DiscoveryService`).
    let client_ca_pem =
        std::fs::read(&args.discovery.discovery_ca_bundle_path).with_context(|| {
            format!(
                "reading relay client-CA trust bundle from {}",
                args.discovery.discovery_ca_bundle_path
            )
        })?;
    let downstream_tls = RotatingServerTls {
        svid,
        client_ca_pem,
        allowed_client: SpiffeMatcher::Prefix(format!(
            "spiffe://{}/",
            args.discovery.discovery_trust_domain
        )),
    };
    let acceptor = downstream_tls.acceptor()?;
    let downstream_addr = SocketAddr::new(args.common.management_bind_address, args.discovery_port);

    // Upstream bootstrap + reconnect supervisor as background services.
    server.add_service(background_service(
        "discovery-bootstrap",
        FutureService::new(bootstrap_runner.run()),
    ));
    server.add_service(background_service(
        "discovery-supervisor",
        FutureService::new(supervisor.run()),
    ));

    // Downstream server. The TLS material is already validated (acceptor built),
    // so mark `downstream_serving` ready as the server spawns; a late listener
    // bind failure logs and exits this one background service.
    relay_handle.ready("downstream_serving");
    {
        use coxswain_discovery::proto::v1::discovery_server::DiscoveryServer;
        let service = DiscoveryServer::new(discovery_service);
        server.add_service(background_service(
            "relay-downstream",
            FutureService::new(async move {
                if let Err(e) = serve_discovery_with_tls(
                    downstream_addr,
                    acceptor,
                    service,
                    std::future::pending::<()>(),
                )
                .await
                {
                    tracing::error!(error = %e, "relay downstream discovery server exited");
                }
            }),
        ));
    }

    let leader = Arc::new(AtomicBool::new(false));
    wire_management_servers(
        &mut server,
        &args.common,
        ManagementServerConfig { health, leader },
    );

    tracing::info!(
        downstream_discovery_port = args.discovery_port,
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        admin_port = args.common.admin_port,
        "Listening"
    );
    server.run_forever();
}

/// Create a Pingora proxy service with h2c (HTTP/2 cleartext prior-knowledge)
/// enabled on the standard accept path.
///
/// h2c detection is a non-destructive peek: HTTP/1.1 clients are unaffected.
/// The PROXY-protocol accept path ignores `server_options` (it runs an h1-only
/// keepalive loop), so setting `h2c = true` unconditionally is safe across all
/// deployment modes.
///
/// `HttpServerOptions` is `#[non_exhaustive]` from another crate, so struct
/// literal syntax is unavailable; the default-then-mutate pattern is the only
/// valid construction form.
fn make_http_proxy<SV>(conf: &Arc<ServerConf>, inner: SV) -> pingora_proxy::HttpProxy<SV>
where
    SV: pingora_proxy::ProxyHttp + Send + Sync + 'static,
    <SV as pingora_proxy::ProxyHttp>::CTX: Send + Sync,
{
    let mut proxy = pingora_proxy::http_proxy(conf, inner);
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    proxy.server_options = Some(opts);
    proxy
}

/// Wire only the `GatewayProxy` dynamic acceptor for `serve proxy --dedicated`.
///
/// The listener set is driven by `listener_status` via a [`ListenerSpecsAdapter`]
/// background service — no startup port-discovery query is needed.  The
/// acceptor starts with an empty listener set and binds ports as the first
/// reconciler cycle completes.
fn wire_gateway_only_proxy_services(
    server: &mut Server,
    common: &CommonArgs,
    proxy: &ProxyArgs,
    source: &dyn RoutingSource,
    listener_status: &SharedGatewayListenerStatus,
    bound_ports_tx: Option<watch::Sender<BTreeSet<u16>>>,
) -> Result<()> {
    let default_timeouts = RouteTimeouts {
        request: proxy.proxy_default_request_timeout,
        backend_request: proxy.proxy_default_backend_request_timeout,
        connect: None,
        read: None,
        send: None,
    };
    let ca_cache = Arc::new(UpstreamCaCache::new());
    let rate_limiter = RateLimiterRegistry::new();
    // Single connection-pooling reqwest::Client shared across all requests for
    // ext_authz sub-requests.  rustls backend — no native-tls dep.
    let auth_client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("building the ext_authz sub-request HTTP client")?;
    let cfg = SharedProxyConfig::new(
        default_timeouts,
        ca_cache,
        proxy.access_log,
        access_log_path_mode(proxy),
        rate_limiter.clone(),
        auth_client,
    );

    // Handle to the advertised-port map (#472), captured before `cfg` is moved
    // into the proxy; the listener-specs adapter republishes it on every tick.
    let advertised_ports = cfg.advertised_ports.clone();
    // Handle to the gRPC ext_authz channel pool (#544), captured before `cfg`
    // moves into the proxy; the GC service below sweeps it periodically.
    let grpc_auth_channels = cfg.grpc_auth_channels.clone();

    let gateway_proxy = Arc::new(make_http_proxy(
        &server.configuration,
        GatewayProxy::new(Arc::new(RoutingEngine::new(source.gateway_routes())), cfg),
    ));

    // Derive the initial listener set from the current health snapshot.
    // This may be empty if the reflector hasn't reconciled yet; the adapter
    // will push the first real set on its first tick.
    let initial_gw_specs = derive_gateway_specs(
        &listener_status.load(),
        proxy.proxy_bind_address,
        &HashSet::new(),
    );
    advertised_ports.store(Arc::new(derive_advertised_ports(&listener_status.load())));

    let (gw_tx, gw_rx) = watch::channel(initial_gw_specs.clone());

    // Gateway listeners carry their PROXY config via ClientTrafficPolicy →
    // ListenerInfo.proxy_protocol → ListenerSpec.proxy_protocol.
    // No global flag: --ingress-* flags only cover Ingress-origin listeners.
    let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
    let mut acceptor = ProxyAcceptor::new(
        gateway_proxy,
        initial_gw_specs,
        Some(gw_rx),
        selector,
        proxy.proxy_listener_drain_timeout,
        PassthroughConfig {
            table: source.passthrough_routes(),
            terminate_table: source.terminate_routes(),
            tcp_table: source.tcp_routes(),
            udp_table: source.udp_routes(),
            dial_timeout: proxy.proxy_tls_passthrough_dial_timeout,
            udp_session_timeout: proxy.proxy_udp_session_timeout,
        },
    )
    .context("build dedicated GatewayProxy acceptor")?;
    if let Some(tx) = bound_ports_tx {
        acceptor = acceptor.with_bound_ports_tx(tx);
    }
    server.add_service(acceptor);

    server.add_service(background_service(
        "gateway-listener-specs",
        ListenerSpecsAdapter {
            listener_status: listener_status.clone(),
            bind_addr: proxy.proxy_bind_address,
            excluded_ports: HashSet::new(),
            tx: gw_tx,
            advertised_ports,
        },
    ));

    server.add_service(background_service(
        "rate-limit-gc",
        RateLimiterGcService {
            registry: rate_limiter,
        },
    ));

    server.add_service(background_service(
        "grpc-auth-channel-gc",
        GrpcAuthChannelGcService {
            cache: grpc_auth_channels,
        },
    ));

    let _ = common;
    Ok(())
}

/// Convert the CLI `AccessLogPathMode` to the proxy-crate equivalent.
fn access_log_path_mode(proxy: &ProxyArgs) -> AccessLogPathMode {
    match proxy.access_log_path_mode {
        BinAccessLogPathMode::Full => AccessLogPathMode::Full,
        BinAccessLogPathMode::Pattern => AccessLogPathMode::Pattern,
        BinAccessLogPathMode::None => AccessLogPathMode::None,
    }
}

/// Register both the Ingress and Gateway dynamic proxy acceptors on the
/// supplied server.  Used by `run_proxy_shared`.
///
/// - The **Ingress acceptor** binds a static set of ports from
///   `--ingress-http-port` / `--ingress-https-port` that never changes.
/// - The **Gateway acceptor** drives a dynamic port set derived from
///   `listener_status` via a [`ListenerSpecsAdapter`] background service; ports
///   are added or removed in-process with no restart.
fn wire_proxy_services(
    server: &mut Server,
    common: &CommonArgs,
    proxy: &ProxyArgs,
    source: &dyn RoutingSource,
    listener_status: &SharedGatewayListenerStatus,
    bound_ports_tx: Option<watch::Sender<BTreeSet<u16>>>,
) -> Result<()> {
    let default_timeouts = RouteTimeouts {
        request: proxy.proxy_default_request_timeout,
        backend_request: proxy.proxy_default_backend_request_timeout,
        connect: None,
        read: None,
        send: None,
    };
    let ca_cache = Arc::new(UpstreamCaCache::new());
    let rate_limiter = RateLimiterRegistry::new();
    // Single connection-pooling reqwest::Client shared across all requests for
    // ext_authz sub-requests.  rustls backend — no native-tls dep.
    let auth_client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("building the ext_authz sub-request HTTP client")?;
    // Shared startup-time config for both proxy types.  Clone is cheap:
    // Arc pointer bumps + Copy/Clone values.
    let mut shared_cfg = SharedProxyConfig::new(
        default_timeouts,
        ca_cache,
        proxy.access_log,
        access_log_path_mode(proxy),
        rate_limiter.clone(),
        auth_client,
    );
    // Wire the live per-Ingress mTLS store from the reflector (#267).
    // The store is populated on the first reconcile cycle; reads before that
    // see an empty store (no mTLS enforced), which is correct — no Ingresses
    // have been observed yet.
    shared_cfg.client_certs = source.client_cert_store();
    // Wire the per-port HTTPS listener-hostname snapshot for misdirected-request
    // detection (GEP-3567, #96). Empty until the first reconcile cycle (check
    // inactive), which is correct — no Gateways observed yet.
    shared_cfg.listener_hostnames = source.listener_hostnames();

    let ingress_specs: HashSet<ListenerSpec> =
        build_ingress_listeners(common, proxy).into_iter().collect();
    let ingress_ports: HashSet<u16> = ingress_specs.iter().map(|s| s.addr.port()).collect();

    let initial_gw_specs = derive_gateway_specs(
        &listener_status.load(),
        proxy.proxy_bind_address,
        &ingress_ports,
    );
    let (gw_tx, gw_rx) = watch::channel(initial_gw_specs.clone());

    // Advertised-port map (#472): seed it now and let the listener-specs adapter
    // republish it on every tick. `shared_cfg` is cloned (not moved) into the
    // proxies, so its handle stays valid here.
    let advertised_ports = shared_cfg.advertised_ports.clone();
    advertised_ports.store(Arc::new(derive_advertised_ports(&listener_status.load())));
    // Handle to the gRPC ext_authz channel pool (#544), captured before
    // `shared_cfg` moves into the Gateway proxy below; the GC service sweeps it
    // periodically.
    let grpc_auth_channels = shared_cfg.grpc_auth_channels.clone();

    // Build the per-Ingress PROXY config from the --ingress-* flags.
    // Ingress-origin listeners carry this on their ListenerSpec.proxy_protocol.
    // Gateway-origin listeners get their PROXY config from ClientTrafficPolicy →
    // ListenerInfo.proxy_protocol → ListenerSpec.proxy_protocol in derive_gateway_specs.
    // The two mechanisms are disjoint: no flag bleed into Gateway listeners.
    let ingress_proxy_config: Option<ProxyProtocolListenerConfig> =
        if proxy.ingress_accept_proxy_protocol {
            if proxy.ingress_proxy_trusted_sources.is_empty() {
                tracing::warn!(
                    "--ingress-accept-proxy-protocol is set but --ingress-proxy-trusted-sources \
                     is empty; all Ingress connections will be rejected"
                );
            }
            Some(ProxyProtocolListenerConfig::new(
                true,
                proxy.ingress_proxy_trusted_sources.clone(),
            ))
        } else {
            None
        };

    let ingress_specs_with_pp: HashSet<ListenerSpec> = ingress_specs
        .into_iter()
        .map(|mut s| {
            s.proxy_protocol = ingress_proxy_config.clone();
            s
        })
        .collect();

    if !ingress_specs_with_pp.is_empty() {
        let p = Arc::new(make_http_proxy(
            &server.configuration,
            IngressProxy::new(
                Arc::new(RoutingEngine::new(source.ingress_routes())),
                shared_cfg.clone(),
            ),
        ));
        let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
        server.add_service(
            ProxyAcceptor::new(
                p,
                ingress_specs_with_pp,
                None, // static: ingress ports never change
                selector,
                proxy.proxy_listener_drain_timeout,
                PassthroughConfig {
                    table: source.passthrough_routes(),
                    terminate_table: source.terminate_routes(),
                    tcp_table: source.tcp_routes(),
                    udp_table: source.udp_routes(),
                    dial_timeout: proxy.proxy_tls_passthrough_dial_timeout,
                    udp_session_timeout: proxy.proxy_udp_session_timeout,
                },
            )
            .context("build IngressProxy acceptor")?,
        );
    }

    let p = Arc::new(make_http_proxy(
        &server.configuration,
        GatewayProxy::new(
            Arc::new(RoutingEngine::new(source.gateway_routes())),
            shared_cfg,
        ),
    ));
    let selector = SniCertSelector::new(source.tls_store(), source.client_cert_store());
    // Bound-port telemetry rides on the Gateway acceptor only (#531): the
    // Programmed gate is keyed on VIP internal ports, which only the Gateway
    // acceptor binds. Static Ingress ports are deliberately not reported.
    let mut gw_acceptor = ProxyAcceptor::new(
        p,
        initial_gw_specs,
        Some(gw_rx),
        selector,
        proxy.proxy_listener_drain_timeout,
        PassthroughConfig {
            table: source.passthrough_routes(),
            terminate_table: source.terminate_routes(),
            tcp_table: source.tcp_routes(),
            udp_table: source.udp_routes(),
            dial_timeout: proxy.proxy_tls_passthrough_dial_timeout,
            udp_session_timeout: proxy.proxy_udp_session_timeout,
        },
    )
    .context("build GatewayProxy acceptor")?;
    if let Some(tx) = bound_ports_tx {
        gw_acceptor = gw_acceptor.with_bound_ports_tx(tx);
    }
    server.add_service(gw_acceptor);

    server.add_service(background_service(
        "gateway-listener-specs",
        ListenerSpecsAdapter {
            listener_status: listener_status.clone(),
            bind_addr: proxy.proxy_bind_address,
            excluded_ports: ingress_ports,
            tx: gw_tx,
            advertised_ports,
        },
    ));

    server.add_service(background_service(
        "rate-limit-gc",
        RateLimiterGcService {
            registry: rate_limiter,
        },
    ));

    server.add_service(background_service(
        "grpc-auth-channel-gc",
        GrpcAuthChannelGcService {
            cache: grpc_auth_channels,
        },
    ));

    Ok(())
}

// ── Listener spec adapter ─────────────────────────────────────────────────────

/// Background service that watches [`SharedGatewayListenerStatus`] and
/// publishes the derived `HashSet<ListenerSpec>` to a watch channel consumed
/// by the [`ProxyAcceptor`].
///
/// The adapter fires immediately on startup (via `mark_changed`) so the
/// acceptor receives the first real spec set as soon as the reflector's
/// initial reconcile completes.
struct ListenerSpecsAdapter {
    listener_status: SharedGatewayListenerStatus,
    bind_addr: IpAddr,
    /// Ports already owned by a static acceptor (ingress ports in the shared-proxy
    /// case) that must be excluded from the gateway-derived set to avoid conflicts.
    excluded_ports: HashSet<u16>,
    tx: watch::Sender<HashSet<ListenerSpec>>,
    /// Published alongside the spec set on every tick: the `internal bind port →
    /// advertised port` map (#472) the proxy's redirect path reads. Derived from
    /// the same health snapshot, so it stays consistent with the bound listeners.
    advertised_ports: Shared<HashMap<u16, u16>>,
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for ListenerSpecsAdapter {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut gen_rx = self.listener_status.subscribe();
        // Fire immediately so the acceptor gets the initial spec set as soon
        // as the reflector reconciles; do NOT fire before the first reconcile
        // (the health map is empty at that point).
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                Ok(()) = gen_rx.changed() => {
                    let health = self.listener_status.load();
                    // Publish the advertised-port map BEFORE the spec set: the spec
                    // set (re)binds listeners, and a request can only arrive once a
                    // listener is bound, so the map must already be current (#472).
                    self.advertised_ports
                        .store(Arc::new(derive_advertised_ports(&health)));
                    let specs = derive_gateway_specs(&health, self.bind_addr, &self.excluded_ports);
                    if self.tx.send(specs).is_err() {
                        // Acceptor dropped — nothing more to do.
                        break;
                    }
                }
            }
        }
    }
}

// ── Discovery identity + gRPC background service (controller) ─────────────────

/// Conventional SPIFFE ServiceAccount segment the controller self-issues for its
/// own discovery/bootstrap server identity. Deliberately fixed (not the
/// release-templated k8s SA name): the controller's server identity is verified
/// by chain-of-trust + this stable name, and proxies match it exactly (see
/// `coxswain_discovery::bootstrap_client`). Keep in sync with that crate.
const CONTROLLER_SPIFFE_SA: &str = "coxswain-controller";

/// Audience the controller requires on proxy SA tokens (TokenReview). Must match
/// the `audience` of the proxy's projected SA-token volume in the chart/manifests.
const DISCOVERY_TOKEN_AUDIENCE: &str = "coxswain-discovery";

/// TTL for the controller's own server SVID. Long-lived and independent of
/// `--discovery-svid-ttl` (which governs short, rotated *proxy* SVIDs): the
/// server cert is refreshed when the controller pod restarts. Per-running-pod
/// server-cert rotation is deferred (#381).
const SERVER_SVID_TTL: std::time::Duration = std::time::Duration::from_secs(365 * 24 * 60 * 60);

/// Map the CLI CA-mode flag onto the controller crate's [`CaMode`].
fn map_ca_mode(mode: CaModeArg) -> CaMode {
    match mode {
        CaModeArg::Auto => CaMode::Auto,
        CaModeArg::External => CaMode::External,
    }
}

/// Background service that owns the controller's discovery identity and serves
/// both gRPC listeners for one controller replica:
///
/// - **Stream** (`stream_addr`, mTLS mandatory): pushes routing snapshots to
///   proxies that present a CA-signed SVID.
/// - **Bootstrap** (`bootstrap_addr`, server-auth-only): issues SVIDs to fresh
///   proxies that present a valid SA token + CSR.
///
/// On startup it loads (or, in `auto` mode, generates) the CA Secret, publishes
/// the public trust bundle ConfigMap, and self-issues its own server SVID. Both
/// listeners drain when the Pingora [`ShutdownWatch`] fires.
struct DiscoveryIdentityService {
    discovery_service: coxswain_discovery::DiscoveryService,
    stream_addr: SocketAddr,
    bootstrap_addr: SocketAddr,
    ca_secret: String,
    ca_mode: CaMode,
    namespace: String,
    svid_ttl: std::time::Duration,
    trust_domain: String,
    controller_name: String,
    pod_name: String,
    /// Best-upstream resolver (#601): the bootstrap handler returns each client's
    /// current best routing upstream `(endpoint, expected_server_sa)` from it.
    upstream_resolver: Arc<UpstreamResolverConfig>,
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for DiscoveryIdentityService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        use coxswain_discovery::proto::v1::discovery_server::DiscoveryServer;

        let client = match kube::Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "discovery identity: failed to initialise Kubernetes client; discovery will not serve");
                return;
            }
        };

        // 1. Load or generate the CA (race-free across replicas; no leader gate).
        let authority = match load_or_generate(
            &client,
            &self.ca_secret,
            &self.namespace,
            self.ca_mode,
            self.svid_ttl,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(error = %e, "discovery identity: CA load/generate failed; discovery will not serve");
                return;
            }
        };

        // 2. Publish the public trust bundle so proxies can verify the controller
        //    and mount it (zero proxy RBAC). Held for the process lifetime.
        let _publisher = spawn_trust_publisher(
            client.clone(),
            Arc::clone(&authority),
            self.ca_secret.clone(),
            self.namespace.clone(),
        );

        // 3. Self-issue the controller's own server SVID (long-lived).
        let controller_id =
            SpiffeId::from_parts(&self.trust_domain, &self.namespace, CONTROLLER_SPIFFE_SA);
        let server_svid = match authority.self_issue_server(&controller_id, SERVER_SVID_TTL) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "discovery identity: self-issuing server SVID failed; discovery will not serve");
                return;
            }
        };

        // Public CA roots double as the client-CA bundle the Stream listener
        // verifies connecting proxies against.
        let trust_bundle = authority.trust_bundle();

        // 4. Build the mTLS Stream acceptor. Any proxy with a CA-signed SVID is
        //    accepted (the CA only ever signs TokenReview-validated SAs).
        let stream_tls = DiscoveryServerTls {
            server_cert_pem: server_svid.cert_pem.clone(),
            server_key_pem: server_svid.key_pem.clone(),
            client_ca_pem: trust_bundle,
            allowed_client: SpiffeMatcher::Prefix(format!("spiffe://{}/", self.trust_domain)),
        };
        let stream_acceptor = match stream_tls.acceptor() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(error = %e, "discovery identity: building Stream TLS acceptor failed");
                return;
            }
        };

        // 5. Build the bootstrap (server-auth-only) acceptor.
        let bootstrap_tls = DiscoveryBootstrapServerTls {
            server_cert_pem: server_svid.cert_pem,
            server_key_pem: server_svid.key_pem,
        };
        let bootstrap_acceptor = match bootstrap_tls.acceptor() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(error = %e, "discovery identity: building bootstrap TLS acceptor failed");
                return;
            }
        };

        // 6. Assemble the bootstrap service: CA issuer + TokenReview authenticator
        //    + reject-event hook (the controller is the sole diagnostic emitter).
        let authenticator = Arc::new(KubeTokenAuthenticator::new(
            client.clone(),
            DISCOVERY_TOKEN_AUDIENCE,
            self.trust_domain.clone(),
        ));
        let reject_hook = Arc::new(BootstrapRejectHook::from_client(
            client,
            self.controller_name.clone(),
            self.pod_name.clone(),
            self.namespace.clone(),
        ));
        let bootstrap_service =
            BootstrapService::with_reject_hook(authority, authenticator, reject_hook)
                .with_upstream_resolver(self.upstream_resolver.clone());

        tracing::info!(
            stream_addr = %self.stream_addr,
            bootstrap_addr = %self.bootstrap_addr,
            "discovery identity: serving mTLS Stream + bootstrap listeners"
        );

        // 7. Serve both listeners concurrently; both drain on shutdown.
        let mut stream_shutdown = shutdown.clone();
        let stream_fut = serve_discovery_with_tls(
            self.stream_addr,
            stream_acceptor,
            DiscoveryServer::new(self.discovery_service.clone()),
            async move {
                let _ = stream_shutdown.changed().await;
            },
        );
        let bootstrap_fut = serve_discovery_with_tls(
            self.bootstrap_addr,
            bootstrap_acceptor,
            DiscoveryServer::new(bootstrap_service),
            async move {
                let _ = shutdown.changed().await;
            },
        );

        let (stream_res, bootstrap_res) = tokio::join!(stream_fut, bootstrap_fut);
        if let Err(e) = stream_res {
            tracing::error!(error = %e, "discovery identity: Stream listener exited with error");
        }
        if let Err(e) = bootstrap_res {
            tracing::error!(error = %e, "discovery identity: bootstrap listener exited with error");
        }
    }
}

// ── Proxy discovery client wiring ─────────────────────────────────────────────

/// Build the proxy-side discovery client and (when a bootstrap endpoint is
/// configured) the SVID bootstrap loop, wiring the shared SVID cell + rotation
/// signal into the discovery client config.
///
/// Returns the client (routing-cell read handles, consumed by the proxy
/// acceptors), the not-yet-running reconnect supervisor, and an optional
/// not-yet-running bootstrap loop. Both runnables are driven by Pingora
/// background services via [`register_discovery_background_services`] so they run
/// on a Pingora runtime (the caller is still on the synchronous startup path).
/// Extract the controller's namespace from an in-cluster discovery endpoint.
///
/// Kubernetes service DNS is `<service>.<namespace>.svc[.cluster.local]`, so the
/// controller's namespace is the second label of the host. Returns `None` for
/// anything that isn't a recognizable `…svc…` service DNS (IP literals, test
/// loopback addresses), letting the caller fall back to the proxy's own
/// namespace. This keeps the controller-identity check correct for proxies that
/// do not share the controller's namespace (dedicated proxies; any non-default
/// install namespace) instead of assuming co-location.
fn controller_namespace_from_endpoint(endpoint: &str) -> Option<String> {
    let after_scheme = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
    let mut labels = host.split('.');
    let _service = labels.next()?;
    let namespace = labels.next().filter(|ns| !ns.is_empty())?;
    // Only trust the parse when the third label is `svc` — i.e. it really is
    // cluster service DNS, not an arbitrary host like `localhost:50051`.
    (labels.next() == Some("svc")).then(|| namespace.to_owned())
}

/// Build a [`DiscoveryClientConfig`] (endpoints, scope, bootstrap/SVID wiring,
/// expected-server identity) shared by the `proxy` and `relay` roles.
///
/// The mTLS `Stream` `expected_server` is `spiffe://<td>/ns/<server-ns>/sa/<sa>`
/// where `<server-ns>` is derived from the **discovery** endpoint's service DNS
/// (the controller's namespace for a leaf on the controller; the relay's
/// namespace for a leaf behind a relay) and `<sa>` is
/// `--discovery-expected-server-sa` (default the controller SA). Bootstrap is
/// **not** tiered — its server namespace is always derived from the bootstrap
/// endpoint (the controller), independent of the discovery endpoint.
fn build_discovery_client_config(
    disco: &DiscoveryClientArgs,
    common: &CommonArgs,
    scope: Scope,
    bound_ports_rx: Option<watch::Receiver<BTreeSet<u16>>>,
) -> (DiscoveryClientConfig, BootstrapRunner) {
    // The routing-stream upstream is delivered by bootstrap, not a CLI flag (#601):
    // start with no static endpoints; the bootstrap loop populates `upstream_cell`.
    let mut config = DiscoveryClientConfig::new(Vec::new(), common.pod_name.clone());
    config.scope = scope.clone();
    config.trust_domain = disco.discovery_trust_domain.clone();
    config.fallback_namespace = common.pod_namespace.clone();
    // Bound-port reports (#531): the supervisor forwards the acceptor's
    // actually-bound set to the controller as NodeStatus messages, feeding the
    // Gateway Programmed readiness gate.
    config.bound_ports_rx = bound_ports_rx;

    // Bootstrap always targets the controller (never tiered), so its server
    // namespace comes from the BOOTSTRAP endpoint's service DNS. Fall back to the
    // node's own namespace for a non-cluster endpoint (test loopback).
    let bootstrap_namespace =
        controller_namespace_from_endpoint(&disco.discovery_bootstrap_endpoint)
            .unwrap_or_else(|| common.pod_namespace.clone());
    let boot_config = BootstrapClientConfig::new(
        disco.discovery_bootstrap_endpoint.clone(),
        disco.discovery_sa_token_path.clone(),
        disco.discovery_ca_bundle_path.clone(),
        disco.discovery_trust_domain.clone(),
        bootstrap_namespace,
        scope,
        common.pod_namespace.clone(),
    );
    let (handle, runner) = BootstrapClient::build(boot_config);
    config.svid_cell = Some(handle.svid);
    config.svid_rotated = Some(handle.rotation_rx);
    // Runtime-swappable routing upstream (#601): the bootstrap response seeds the
    // cell + fires `upstream_changed`; a live directive on the stream re-writes it;
    // repeated reconnect failures poke `re_bootstrap` to re-resolve the upstream.
    config.upstream_cell = Some(handle.upstream);
    config.upstream_changed = Some(handle.upstream_rx);
    config.re_bootstrap = Some(handle.re_bootstrap);

    (config, runner)
}

fn build_discovery_client(
    disco: &DiscoveryClientArgs,
    common: &CommonArgs,
    proxy_handle: SubsystemHandle,
    scope: Scope,
    bound_ports_rx: Option<watch::Receiver<BTreeSet<u16>>>,
) -> anyhow::Result<(DiscoveryClient, Supervisor, BootstrapRunner)> {
    let (config, bootstrap_runner) =
        build_discovery_client_config(disco, common, scope, bound_ports_rx);
    let (client, supervisor) = DiscoveryClient::new(config, proxy_handle, "routing_table_loaded")?;
    Ok((client, supervisor, bootstrap_runner))
}

/// Register the discovery supervisor (and optional bootstrap loop) as Pingora
/// background services so they run on a Pingora runtime.
fn register_discovery_background_services(
    server: &mut Server,
    supervisor: Supervisor,
    bootstrap_runner: BootstrapRunner,
) {
    server.add_service(background_service(
        "discovery-bootstrap",
        FutureService::new(bootstrap_runner.run()),
    ));
    server.add_service(background_service(
        "discovery-supervisor",
        FutureService::new(supervisor.run()),
    ));
}

// ── FutureService adapter ─────────────────────────────────────────────────────

/// Adapts an owned, long-running future into a Pingora [`BackgroundService`].
///
/// The future is built synchronously (no runtime needed to *construct* an
/// `async fn` future) and stored; Pingora awaits it inside one of its runtimes
/// when `start` fires. This is how the proxy's discovery supervisor and bootstrap
/// loop — which internally `tokio::spawn` and so need an active runtime — are
/// started from the otherwise-synchronous bin startup path.
struct FutureService {
    fut:
        parking_lot::Mutex<Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>>,
}

impl FutureService {
    fn new(fut: impl std::future::Future<Output = ()> + Send + 'static) -> Self {
        Self {
            fut: parking_lot::Mutex::new(Some(Box::pin(fut))),
        }
    }
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for FutureService {
    async fn start(&self, _shutdown: ShutdownWatch) {
        let fut = self.fut.lock().take();
        if let Some(fut) = fut {
            fut.await;
        }
    }
}

// ── Rate-limiter GC service ───────────────────────────────────────────────────

/// Background service that periodically evicts idle per-client rate-limit buckets.
///
/// Calls [`RateLimiterRegistry::sweep`] every 60 seconds. The sweep invokes
/// `retain_recent` on every live governor `DashMapStateStore`, removing keys
/// whose GCRA state has fully recovered (bucket full; client has been quiet for
/// at least one full rate period). Routes with zero remaining keys are removed
/// from the registry entirely, bounding memory growth under high-cardinality
/// client spaces (many distinct IPs or many distinct header values).
struct RateLimiterGcService {
    registry: RateLimiterRegistry,
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for RateLimiterGcService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = interval.tick() => self.registry.sweep(),
            }
        }
    }
}

// ── gRPC ext_authz channel-pool GC service (#544) ─────────────────────────────

/// Background service that periodically evicts idle pooled gRPC ext_authz
/// channels.
///
/// Calls [`GrpcAuthChannelCache::sweep`] every 60 seconds. The sweep applies
/// second-chance eviction: a channel used since the previous sweep survives,
/// an untouched one is dropped. An auth-service endpoint removed by reconcile
/// (pod scale-down/replacement) simply stops being selected by the round-robin
/// picker, goes idle, and is reclaimed on the next sweep — bounding the pool to
/// the live endpoint set without explicit invalidation.
struct GrpcAuthChannelGcService {
    cache: GrpcAuthChannelCache,
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for GrpcAuthChannelGcService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = interval.tick() => self.cache.sweep(),
            }
        }
    }
}

/// Derive a `HashSet<ListenerSpec>` from the current gateway listener status map.
///
/// Excludes ports already in `excluded_ports` (used to prevent the gateway
/// acceptor from binding ports already owned by the static ingress acceptor).
///
/// Per-port protocol upgrade rules:
/// - TLSRoute passthrough or terminate-only → `TlsL4`
/// - TLSRoute (any) + HTTPS terminate on the same port → `TlsHybrid`
/// - TCPRoute (`TcpProxy` readiness) → `Tcp`; never hybridizes with another
///   protocol on the same port (#505)
/// - UDPRoute (`UdpProxy` readiness) → `Udp`; never hybridizes with another
///   protocol on the same port (#506)
///
/// `ListenerInfo.proxy_protocol` (resolved from `ClientTrafficPolicy`) is
/// forwarded to the `ListenerSpec.proxy_protocol` field for the acceptor to
/// enforce per-listener PROXY protocol (#327). When multiple listeners share a
/// port (TlsHybrid), the first non-`None` PROXY config wins.
fn derive_gateway_specs(
    health: &std::collections::HashMap<ObjectKey, GatewayListenerStatus>,
    bind_addr: IpAddr,
    excluded_ports: &HashSet<u16>,
) -> HashSet<ListenerSpec> {
    // Accumulate the effective protocol and PROXY config per port.
    // Protocol rules (commutative):
    //   TlsL4 + TlsL4   → TlsL4    (passthrough+terminate on same port = Mixed #481)
    //   TlsL4 + Https   → TlsHybrid
    //   Https + Https   → Https
    let mut port_state: HashMap<u16, (ListenerProtocol, Option<ProxyProtocolListenerConfig>)> =
        HashMap::new();
    for gw_health in health.values() {
        for info in gw_health.listeners.values() {
            // Bind the allocated internal port for shared-mode Gateways (#472):
            // the VIP maps the advertised :443 → this internal port, and the
            // proxy keys routing/passthrough/TLS on the local port it accepts on.
            let port = info.bind_port();
            if excluded_ports.contains(&port) {
                continue;
            }
            let new_proto = match info.readiness {
                ListenerReadiness::NotApplicable => ListenerProtocol::Http,
                ListenerReadiness::TlsPassthrough | ListenerReadiness::TlsTerminate => {
                    ListenerProtocol::TlsL4
                }
                // TCPRoute (#505) / UDPRoute (#506): a TCP or UDP listener never
                // shares a port with another protocol (Gateway API port-compatibility
                // rules exclude the combination, enforced at listener-conflict
                // resolution), so no hybrid-upgrade arm is needed below, unlike TlsL4/Https.
                ListenerReadiness::TcpProxy => ListenerProtocol::Tcp,
                ListenerReadiness::UdpProxy => ListenerProtocol::Udp,
                _ => ListenerProtocol::Https,
            };
            let new_pp = info.proxy_protocol.clone();
            port_state
                .entry(port)
                .and_modify(|(existing_proto, existing_pp)| {
                    // Upgrade to TlsHybrid when TLS L4 and HTTPS terminate share a port.
                    if (*existing_proto == ListenerProtocol::TlsL4
                        && new_proto == ListenerProtocol::Https)
                        || (*existing_proto == ListenerProtocol::Https
                            && new_proto == ListenerProtocol::TlsL4)
                    {
                        *existing_proto = ListenerProtocol::TlsHybrid;
                    }
                    // TlsL4+TlsL4 (Mixed) or Https+Https stay as-is.
                    // Merge PROXY config: first non-None wins (same port, same CTP).
                    if existing_pp.is_none() {
                        *existing_pp = new_pp.clone();
                    }
                })
                .or_insert((new_proto, new_pp));
        }
    }
    port_state
        .into_iter()
        .map(|(port, (protocol, proxy_protocol))| ListenerSpec {
            addr: SocketAddr::new(bind_addr, port),
            protocol,
            proxy_protocol,
        })
        .collect()
}

/// Build the `internal bind port → advertised listener port` map (#472) from the
/// per-Gateway listener status snapshot — the inverse of the binding
/// [`derive_gateway_specs`] performs over the same map.
///
/// The proxy accepts a shared-mode Gateway listener on its allocated internal
/// port; a `RequestRedirect` that preserves the incoming port must echo the
/// *advertised* port (what the client connected to via the VIP), not the
/// internal accept port. Covers every listener regardless of protocol (HTTP
/// included), because [`GatewayListenerStatus::listeners`] holds them all. When
/// no internal port is allocated (dedicated mode / Ingress), `bind_port()` is the
/// spec port, so the entry maps the advertised port to itself — harmless.
fn derive_advertised_ports(
    health: &HashMap<ObjectKey, GatewayListenerStatus>,
) -> HashMap<u16, u16> {
    let mut map = HashMap::new();
    for gw_health in health.values() {
        for info in gw_health.listeners.values() {
            map.insert(info.bind_port(), info.port);
        }
    }
    map
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn build_controller_config(
    common: &CommonArgs,
    controller: &ControllerArgs,
) -> Result<ControllerConfig> {
    ControllerConfig::new(
        common.controller_name.clone(),
        common.pod_name.clone(),
        common.pod_namespace.clone(),
        LeaseSettings::new(
            controller.controller_lease_ttl,
            controller.controller_lease_renew_interval,
        ),
        WatchScope::parse(common.watch_namespace.as_deref())?,
        controller.status_address.clone(),
        IngressPorts::new(common.ingress_http_port, common.ingress_https_port),
    )
    .map(|c| c.with_shared_vip_addressing(!controller.shared_proxy_selector.is_empty()))
    .map_err(Into::into)
}

/// Construct the static Ingress listener specs from CLI args.
///
/// Returns an empty list when `--disable-ingress` is set — no listener ports
/// are bound even if `--ingress-http-port` / `--ingress-https-port` were
/// also passed.
fn build_ingress_listeners(common: &CommonArgs, proxy: &ProxyArgs) -> Vec<ListenerSpec> {
    if common.disable_ingress {
        return Vec::new();
    }
    let mut listeners: Vec<ListenerSpec> = Vec::new();
    if let Some(port) = common.ingress_http_port {
        listeners.push(ListenerSpec::http(SocketAddr::new(
            proxy.proxy_bind_address,
            port,
        )));
    }
    if let Some(port) = common.ingress_https_port {
        listeners.push(ListenerSpec::https(SocketAddr::new(
            proxy.proxy_bind_address,
            port,
        )));
    }
    listeners
}

/// Configuration bundle for [`wire_management_servers`].
struct ManagementServerConfig {
    health: HealthRegistry,
    leader: Arc<AtomicBool>,
}

fn wire_management_servers(
    server: &mut Server,
    common: &CommonArgs,
    config: ManagementServerConfig,
) {
    let health_addr = SocketAddr::new(common.management_bind_address, common.health_port);
    server.add_service({
        let mut svc = Service::new(
            "health".to_string(),
            coxswain_health::HealthServer {
                registry: config.health.clone(),
                // Proxy / dev roles have no relist monitor to trip a gate;
                // `/healthz` keeps its historical always-live semantics.
                liveness: None,
            },
        );
        svc.add_tcp(&health_addr.to_string());
        svc
    });

    let admin_addr = SocketAddr::new(common.management_bind_address, common.admin_port);
    // Proxy roles carry no admin query surface beyond /metrics and
    // /api/v1/health (#537) — the routing view lives on the controller,
    // served from its own local snapshot at `fleet/proxies/{name}/routes`.
    let admin = AdminServer::new(config.health, config.leader)
        .with_api_surfaces(!common.disable_gateway_api, !common.disable_ingress);
    server.add_service(admin.into_service(admin_addr));
}

/// Resolve the per-service proxy worker-thread count. A non-zero `configured`
/// value is honoured verbatim; `0` means **auto** — the effective CPU
/// parallelism from [`std::thread::available_parallelism`] (cgroup-quota-aware
/// on Linux, so it tracks the pod's `resources.limits.cpu`), floored at 2 and
/// falling back to 2 if the cgroup/affinity info cannot be read.
fn resolve_proxy_threads(configured: usize) -> usize {
    if configured != 0 {
        return configured;
    }
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(2)
        .max(2)
}

fn build_server(args: &ProxyArgs) -> Server {
    let threads = resolve_proxy_threads(args.proxy_threads);
    tracing::info!(
        proxy_threads = threads,
        configured = args.proxy_threads,
        "Resolved per-service proxy worker threads (0 configured = auto from CPU quota)"
    );
    let conf = ServerConf {
        threads,
        grace_period_seconds: Some(args.proxy_shutdown_grace_period.as_secs()),
        graceful_shutdown_timeout_seconds: Some(args.proxy_shutdown_timeout.as_secs()),
        upstream_keepalive_pool_size: args.proxy_upstream_keepalive_pool_size,
        ..Default::default()
    };

    let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), conf);
    server.bootstrap();
    server
}

fn build_minimal_server() -> Server {
    let conf = ServerConf {
        // The controller role serves no client traffic — there is nothing to
        // drain on shutdown. Pingora's `GracefulTerminate` (SIGTERM) path
        // sleeps the FULL grace period unconditionally (`thread::sleep`, not
        // a drain wait), and an unset grace defaults to pingora's
        // EXIT_TIMEOUT of 300s — longer than Kubernetes' 30s
        // `terminationGracePeriodSeconds`, so every controller pod rode out
        // the whole 30s and died by SIGKILL: rollouts, chart upgrades, and
        // node drains all paid ~30s per replica (#570 follow-up; measured
        // via `kubectl delete pod`). Zero grace exits immediately after the
        // shutdown signal propagates; background services (lease step-down,
        // reflector teardown) get the runtime-shutdown timeout to finish.
        grace_period_seconds: Some(0),
        graceful_shutdown_timeout_seconds: Some(5),
        ..ServerConf::default()
    };
    let mut server = Server::new_with_opt_and_conf(Some(Opt::default()), conf);
    server.bootstrap();
    server
}

fn init_logger(format: LogFormat, log_filter: &str) -> Result<()> {
    let env_filter = EnvFilter::new(log_filter);

    match format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().flatten_event(true))
                .try_init()
                .context("failed to initialize JSON logger")?;
        }
        LogFormat::Console => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_ansi(true))
                .try_init()
                .context("failed to initialize console logger")?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_proxy_threads_honours_explicit_and_floors_auto() {
        // Explicit non-zero values pass through verbatim.
        assert_eq!(resolve_proxy_threads(1), 1);
        assert_eq!(resolve_proxy_threads(8), 8);
        // Auto (0) resolves to the effective parallelism, never below the
        // floor of 2 (so a sub-2-core CPU quota still gets 2 threads).
        assert!(resolve_proxy_threads(0) >= 2);
    }

    #[test]
    fn controller_namespace_parsed_from_service_dns() {
        assert_eq!(
            controller_namespace_from_endpoint(
                "https://coxswain-controller-discovery.coxswain-system.svc:50052"
            ),
            Some("coxswain-system".to_owned())
        );
        assert_eq!(
            controller_namespace_from_endpoint(
                "https://coxswain-controller-discovery.tenant-a.svc.cluster.local:50051"
            ),
            Some("tenant-a".to_owned())
        );
    }

    #[test]
    fn advertised_ports_map_covers_http_and_https_listeners() {
        use coxswain_reflector::GatewayListenerStatus;
        use std::collections::BTreeMap;

        // An HTTP listener (NotApplicable TLS outcome) and an HTTPS listener, each
        // with a distinct allocated internal port (#472). The map must recover the
        // advertised port from the internal accept port for BOTH — the HTTP one is
        // exactly the redirect path that regressed.
        let mut listeners = BTreeMap::new();
        let mut http = coxswain_reflector::status::ListenerInfo::default();
        http.port = 80;
        http.internal_port = 30000;
        listeners.insert(
            coxswain_reflector::status::ListenerStatusKey::gateway("http"),
            http,
        );
        let mut https = coxswain_reflector::status::ListenerInfo::default();
        https.port = 443;
        https.internal_port = 30001;
        listeners.insert(
            coxswain_reflector::status::ListenerStatusKey::gateway("https"),
            https,
        );
        let mut glh = GatewayListenerStatus::default();
        glh.listeners = listeners;

        let mut health = HashMap::new();
        health.insert(ObjectKey::new("ns", "gw"), glh);

        let map = derive_advertised_ports(&health);
        assert_eq!(map.get(&30000), Some(&80), "internal 30000 → advertised 80");
        assert_eq!(
            map.get(&30001),
            Some(&443),
            "internal 30001 → advertised 443"
        );
    }

    #[test]
    fn advertised_ports_map_is_identity_without_internal_port() {
        use coxswain_reflector::GatewayListenerStatus;
        use std::collections::BTreeMap;

        // Dedicated mode / Ingress: no internal port allocated, so bind_port() is
        // the spec port and the entry maps it to itself — a redirect then preserves
        // the real advertised port unchanged.
        let mut listeners = BTreeMap::new();
        let mut li = coxswain_reflector::status::ListenerInfo::default();
        li.port = 8080;
        li.internal_port = 0;
        listeners.insert(
            coxswain_reflector::status::ListenerStatusKey::gateway("http"),
            li,
        );
        let mut glh = GatewayListenerStatus::default();
        glh.listeners = listeners;

        let mut health = HashMap::new();
        health.insert(ObjectKey::new("ns", "gw"), glh);

        let map = derive_advertised_ports(&health);
        assert_eq!(
            map.get(&8080),
            Some(&8080),
            "unallocated listener maps to itself"
        );
    }

    #[test]
    fn controller_namespace_none_for_non_service_dns() {
        // Loopback / IP / bare host: not cluster service DNS → caller falls back
        // to the proxy's own namespace.
        assert_eq!(
            controller_namespace_from_endpoint("http://127.0.0.1:50051"),
            None
        );
        assert_eq!(
            controller_namespace_from_endpoint("https://localhost:50052"),
            None
        );
        assert_eq!(
            controller_namespace_from_endpoint("https://example.com:443"),
            None
        );
    }
}
