//! The `relay` pod role runner: Kube-free discovery fan-out node.
//!
//! Relays delta snapshots from the controller to proxy replicas without watching
//! the cluster. Shared wiring lives in [`crate::wiring`], [`crate::services`], and
//! [`crate::discovery`].
//!
//! # `--shared-proxy-name` (#726)
//!
//! A **shared** relay (`--shared`) needs the shared-proxy pool's
//! ServiceAccount name to authorize its own downstream `SharedPool`
//! subscribers — its leaves are ordinary shared-proxy pool pods, and without
//! this the relay's `ScopeAuthorizer` would reject every one of them. Unused
//! by a **dedicated** relay (`--namespace`), whose leaves subscribe `Gateway`
//! scope instead (a separate SVID-binding check, not gated by
//! `ScopeAuthorizer` at all). The controller always renders this flag from
//! its own `--shared-proxy-name` when it provisions a relay Deployment
//! (`coxswain-controller`'s `render_relay.rs`), so the two configured names
//! cannot drift apart; the CLI default here matters only for manual or test
//! invocations that bypass controller rendering.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use coxswain_controller::{RELAY_SERVICE_ACCOUNT, SHARED_RELAY_SERVICE_ACCOUNT};
use coxswain_core::Shared;
use coxswain_core::health::HealthRegistry;
use coxswain_discovery::{
    DiscoveryService, ProvisionedRelayAuthorizer, RelayAuthzConfig, RelayUpstream,
    RotatingServerTls, Scope, SpiffeMatcher, namespace_relay, serve_discovery_with_tls,
    shared_relay,
};
use pingora_core::services::background::background_service;

use crate::args::{RelayRoleArgs, RelayScope};
use crate::discovery::{build_discovery_client_config, register_discovery_background_services};
use crate::services::FutureService;
use crate::wiring::{
    ManagementServerConfig, build_minimal_server, init_logger, wire_management_servers,
};

/// Wire and run the `relay` pod role (#583): a zero-RBAC discovery cache that
/// subscribes upstream to the controller and re-serves the snapshot stream
/// downstream to proxies (leaves).
///
/// Kube-free by construction — the downstream server presents the relay's own
/// rotating bootstrapped SVID and the mounted trust bundle, so it needs no CA
/// Secret, trust-bundle ConfigMap, or TokenReview (all of which the controller's
/// discovery server needs and none of which the relay's RBAC-less SA can reach).
/// The downstream `DiscoveryService`'s `ProvisionedRelayAuthorizer` (an empty
/// provenance set) rejects any leaf `Namespace` subscribe (relay-behind-relay is
/// out of scope) while still authorizing the shared-proxy pool's `SharedPool`
/// subscribes on a shared relay (#726).
pub(crate) fn run_relay(args: RelayRoleArgs) -> Result<()> {
    init_logger(args.common.log_format, &args.common.log_filter)?;

    let relay_scope = args.scope();
    let (scope, scope_label) = match &relay_scope {
        RelayScope::Shared => (Scope::SharedPool, "shared".to_owned()),
        RelayScope::Dedicated { namespace } => (
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
    let node_registry = coxswain_core::node_registry::NodeRegistryHandle::new();

    // Roster channel: the reporter publishes the downstream registry snapshot;
    // the upstream client forwards it to the controller as a `RosterReport`.
    let (roster_tx, roster_rx) =
        tokio::sync::watch::channel(coxswain_core::node_registry::NodeRegistry::default());

    // Upstream discovery client config (bootstrap + SVID + expected-server). The
    // relay reports no bound ports of its own (#531) — leaf state reaches the
    // controller via `RosterReport` (#585), wired here as the roster receiver.
    // The relay's downstream serving cert IS its rotating bootstrapped SVID; the
    // builder hands it back (the bootstrap endpoint is `required = true` at clap).
    //
    // It DOES report its own health (#677), and this is the only channel that
    // can carry it: a relay never appears in its own `RosterReport` (that
    // iterates its downstream registry, which holds leaves only), so without
    // this wiring the controller would know a relay's convergence state but
    // nothing about its subsystems.
    let (mut config, bootstrap_runner, svid) =
        build_discovery_client_config(&args.discovery, &args.common, scope, None, health.clone());
    config.roster_rx = Some(roster_rx);

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
        RelayScope::Dedicated { .. } => {
            namespace_relay(config, relay_handle.clone(), "routing_table_loaded")?
        }
    };

    // Downstream discovery service over the relay's own `SnapshotSource`. No
    // leader gate (the relay is not leader-elected). A leaf never subscribes
    // `Namespace` (relay-behind-relay is out of scope), but a *shared*
    // relay's leaves ARE ordinary shared-proxy pool pods subscribing
    // `SharedPool` — reusing the default `DenyAll` here would reject every
    // one of them post-#726, so `ProvisionedRelayAuthorizer` is wired with an
    // empty provenance set (no `Namespace` subscribe is ever legitimate here)
    // and the shared-proxy/shared-relay identity constants, exactly as the
    // controller wires its own. Inert but harmless on a dedicated relay,
    // whose leaves subscribe `Gateway` scope (a separate SVID-binding check,
    // not gated by `ScopeAuthorizer` at all).
    // Directive forwarding (#601): the upstream client fans controller
    // `PreferredUpstream` directives into `directive_tx`; the downstream server
    // forwards each to the leaf it targets so a repoint reaches a relay-fronted
    // proxy through the relay.
    let downstream_authorizer = Arc::new(ProvisionedRelayAuthorizer::new(RelayAuthzConfig {
        provisioned: Shared::from_value(HashSet::new()),
        relay_sa: RELAY_SERVICE_ACCOUNT.to_string(),
        trust_domain: args.discovery.discovery_trust_domain.clone(),
        shared_relay_sa: SHARED_RELAY_SERVICE_ACCOUNT.to_string(),
        install_namespace: args.common.pod_namespace.clone(),
        shared_proxy_sa: args.shared_proxy_name.clone(),
    }));
    let discovery_service = DiscoveryService::new(source, node_registry.clone(), rebuild_rx)
        .with_scope_authorizer(downstream_authorizer)
        .with_directive_forwarding(directive_tx);

    // Debounced roster reporter: watch the downstream registry and republish it
    // to the upstream client whenever it changes (#585, #621). The roster-change
    // watch fires on EVERY mutation — including the ack/target stamps the #531
    // `notify` channel deliberately skips — so it is the authoritative change
    // oracle; no periodic backstop tick or content dedup is needed. On an idle
    // relay the counter is stable, `changed()` parks, and the reporter performs
    // no `load()` and no clone.
    {
        // Debounce a burst of roster changes into one upstream `RosterReport`.
        const ROSTER_COALESCE: std::time::Duration = std::time::Duration::from_millis(200);
        let registry = node_registry.clone();
        server.add_service(background_service(
            "relay-roster-reporter",
            FutureService::new(async move {
                let mut change = registry.subscribe_roster();
                loop {
                    if change.changed().await.is_err() {
                        break; // registry dropped (process shutdown)
                    }
                    // Coalesce a burst of changes into one send.
                    tokio::time::sleep(ROSTER_COALESCE).await;
                    if roster_tx.send(registry.load()).is_err() {
                        break; // upstream client gone
                    }
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

    // Upstream bootstrap + reconnect supervisor as background services (the same
    // pair both proxy roles register).
    register_discovery_background_services(&mut server, supervisor, bootstrap_runner);

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

    wire_management_servers(&mut server, &args.common, ManagementServerConfig { health });

    tracing::info!(
        downstream_discovery_port = args.discovery_port,
        management_bind_address = %args.common.management_bind_address,
        health_port = args.common.health_port,
        telemetry_port = args.common.telemetry_port,
        "Listening"
    );
    server.run_forever();
}
