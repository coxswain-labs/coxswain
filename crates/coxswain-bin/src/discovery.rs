//! Discovery client construction and controller-side identity wiring.
//!
//! The controller side self-issues its SVID and serves bootstrap; the proxy side
//! builds the discovery client + bootstrap runner and registers them as background
//! services.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use coxswain_controller::{
    BootstrapRejectHook, CONTROLLER_DISCOVERY_SERVICE, CaMode, KubeTokenAuthenticator,
    RELAY_SERVICE_ACCOUNT, SHARED_RELAY_SERVICE_ACCOUNT, load_or_generate, spawn_trust_publisher,
};
use coxswain_core::health::{HealthRegistry, SubsystemHandle};
use coxswain_core::identity::{SpiffeId, SvidIssuer};
use coxswain_discovery::{
    BootstrapClient, BootstrapClientConfig, BootstrapIdentityAllowlist, BootstrapRunner,
    BootstrapService, DiscoveryBootstrapServerTls, DiscoveryClient, DiscoveryClientConfig,
    DiscoveryServerTls, Scope, SharedSvid, SpiffeMatcher, Supervisor, UpstreamNames,
    UpstreamPolicy, UpstreamResolverConfig, serve_discovery_with_tls,
};
use pingora_core::server::{Server, ShutdownWatch};
use pingora_core::services::background::background_service;
use tokio::sync::watch;

use crate::args::{CaModeArg, CommonArgs, DiscoveryClientArgs};
use crate::services::FutureService;

/// Conventional SPIFFE ServiceAccount segment the controller self-issues for its
/// own discovery/bootstrap server identity. Deliberately fixed (not the
/// release-templated k8s SA name): the controller's server identity is verified
/// by chain-of-trust + this stable name, and proxies match it exactly (see
/// `coxswain_discovery::bootstrap_client`). Keep in sync with that crate.
pub(crate) const CONTROLLER_SPIFFE_SA: &str = "coxswain-controller";

/// Audience the controller requires on proxy SA tokens (TokenReview). Must match
/// the `audience` of the proxy's projected SA-token volume in the chart/manifests.
pub(crate) const DISCOVERY_TOKEN_AUDIENCE: &str = "coxswain-discovery";

/// TTL for the controller's own server SVID. Long-lived and independent of
/// `--discovery-svid-ttl` (which governs short, rotated *proxy* SVIDs): the
/// server cert is refreshed when the controller pod restarts. Per-running-pod
/// server-cert rotation is deferred (#381).
pub(crate) const SERVER_SVID_TTL: std::time::Duration =
    std::time::Duration::from_secs(365 * 24 * 60 * 60);

/// Map the CLI CA-mode flag onto the controller crate's [`CaMode`].
pub(crate) fn map_ca_mode(mode: CaModeArg) -> CaMode {
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
pub(crate) struct DiscoveryIdentityService {
    pub(crate) discovery_service: coxswain_discovery::DiscoveryService,
    pub(crate) stream_addr: SocketAddr,
    pub(crate) bootstrap_addr: SocketAddr,
    pub(crate) ca_secret: String,
    pub(crate) ca_mode: CaMode,
    pub(crate) namespace: String,
    pub(crate) svid_ttl: std::time::Duration,
    pub(crate) trust_domain: String,
    pub(crate) controller_name: String,
    pub(crate) pod_name: String,
    /// Best-upstream resolver (#601): the bootstrap handler returns each client's
    /// current best routing upstream `(endpoint, expected_server_sa)` from it.
    /// Also supplies `shared_relay_sa`/`relay_sa`/`install_namespace` for the
    /// identity allowlist below — one source for both, so the two seams can't
    /// drift apart on the relay tier's own identity constants.
    pub(crate) upstream_resolver: Arc<UpstreamResolverConfig>,
    /// The shared-proxy pool's ServiceAccount name (#726 identity allowlist).
    pub(crate) shared_proxy_sa: String,
    /// Namespaces with a controller-provisioned relay (#726 identity
    /// allowlist) — the same live set `ScopeAuthorizer::allows_namespace`
    /// reads for the relay's own live subscribe.
    pub(crate) provisioned_relays: coxswain_core::Shared<std::collections::HashSet<String>>,
    /// Every dedicated-mode Gateway's expected proxy identity (#726 identity
    /// allowlist), published by the operator at *provisioning intent* —
    /// before cut-over — so a fresh dedicated proxy's very first bootstrap
    /// attempt is already authorized.
    pub(crate) dedicated_identities: coxswain_core::Shared<
        std::collections::HashMap<coxswain_core::ownership::ObjectKey, String>,
    >,
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
        let identity_allowlist = Arc::new(BootstrapIdentityAllowlist {
            install_namespace: self.upstream_resolver.install_namespace.clone(),
            shared_proxy_sa: self.shared_proxy_sa.clone(),
            shared_relay_sa: self.upstream_resolver.shared_relay_sa.clone(),
            relay_sa: self.upstream_resolver.relay_sa.clone(),
            provisioned_relays: self.provisioned_relays.clone(),
            dedicated_identities: self.dedicated_identities.clone(),
        });
        let bootstrap_service =
            BootstrapService::with_reject_hook(authority, authenticator, reject_hook)
                .with_upstream_resolver(self.upstream_resolver.clone())
                .with_identity_allowlist(identity_allowlist);

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

/// Build the closed set of routing upstreams this node will accept (#665).
///
/// `install_namespace` is the namespace label of the node's own
/// `--discovery-bootstrap-endpoint`: the controller and the shared relay both
/// live there, so it plus the node's own namespace is enough to name all three
/// legal upstreams — no additional flag, and nothing derived from the wire.
///
/// The three names come from the controller's own constants rather than literals
/// so the endpoint a leaf is *pointed at* and the host it will *accept* cannot
/// drift apart.
fn build_upstream_policy(
    disco: &DiscoveryClientArgs,
    common: &CommonArgs,
    install_namespace: &str,
) -> UpstreamPolicy {
    UpstreamPolicy::new(
        disco.discovery_trust_domain.clone(),
        install_namespace,
        &common.pod_namespace,
        &UpstreamNames {
            controller_service: CONTROLLER_DISCOVERY_SERVICE.to_owned(),
            controller_sa: CONTROLLER_SPIFFE_SA.to_owned(),
            relay: RELAY_SERVICE_ACCOUNT.to_owned(),
            shared_relay: SHARED_RELAY_SERVICE_ACCOUNT.to_owned(),
        },
    )
}

/// Build a [`DiscoveryClientConfig`] (endpoints, scope, bootstrap/SVID wiring)
/// shared by the `proxy` and `relay` roles.
///
/// The routing `Stream` upstream — its endpoint and the `expected_server` SPIFFE
/// identity the server's SVID must present — is not a CLI flag since #601: the
/// bootstrap response seeds it and live `PreferredUpstream` directives re-point it
/// (a leaf on the controller verifies the controller SA; a leaf behind a relay the
/// relay SA). Bootstrap itself is **not** tiered — its server namespace is always
/// derived from the bootstrap endpoint (the controller), independent of the
/// routing upstream.
///
/// Both of those writers resolve through the [`UpstreamPolicy`] built here, so
/// neither can hand this node an identity to trust.
pub(crate) fn build_discovery_client_config(
    disco: &DiscoveryClientArgs,
    common: &CommonArgs,
    scope: Scope,
    bound_ports_rx: Option<watch::Receiver<BTreeSet<u16>>>,
    health: HealthRegistry,
) -> (DiscoveryClientConfig, BootstrapRunner, SharedSvid) {
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
    // Self-reported health (#677): the node pushes its own subsystem state up
    // the stream it has already authenticated, so the controller serves the
    // operator API's fleet and problems views from its registry instead of
    // dialling this pod's `/statusz` over unauthenticated HTTP. Wired for BOTH
    // roles — a relay reports no bound ports and never appears in its own
    // roster, so this is the only channel its own health has.
    config.health = Some(health);

    // Bootstrap always targets the controller (never tiered), so its server
    // namespace comes from the BOOTSTRAP endpoint's service DNS. Fall back to the
    // node's own namespace for a non-cluster endpoint (test loopback).
    //
    // The canonical parser, not a local copy: it is what the upstream policy
    // below validates hosts with, so a hardening there (a form the dialer
    // resolves differently than a naive parse) must reach this derivation too.
    let bootstrap_namespace =
        coxswain_discovery::namespace_from_service_dns(&disco.discovery_bootstrap_endpoint)
            .unwrap_or_else(|| common.pod_namespace.clone());
    // Both writers to the upstream cell get the policy (#665), so neither the
    // bootstrap response nor a live directive can hand this node an identity.
    let upstream_policy = build_upstream_policy(disco, common, &bootstrap_namespace);
    config.upstream_policy = Some(upstream_policy.clone());
    let mut boot_config = BootstrapClientConfig::new(
        disco.discovery_bootstrap_endpoint.clone(),
        disco.discovery_sa_token_path.clone(),
        disco.discovery_ca_bundle_path.clone(),
        disco.discovery_trust_domain.clone(),
        bootstrap_namespace,
        scope,
        common.pod_namespace.clone(),
    );
    boot_config.upstream_policy = Some(upstream_policy);
    let (handle, runner) = BootstrapClient::build(boot_config);
    // `--discovery-bootstrap-endpoint` is `required = true` at the clap layer, so a
    // bootstrap client — and thus a serving SVID cell — always exists here. Hand it
    // back so the relay wires its downstream serving cert from it directly, rather
    // than re-extracting the always-`Some` `config.svid_cell`.
    let svid = handle.svid;
    config.svid_cell = Some(svid.clone());
    config.svid_rotated = Some(handle.rotation_rx);
    // Runtime-swappable routing upstream (#601): the bootstrap response seeds the
    // cell + fires `upstream_changed`; a live directive on the stream re-writes it;
    // repeated reconnect failures poke `re_bootstrap` to re-resolve the upstream.
    config.upstream_cell = Some(handle.upstream);
    config.upstream_changed = Some(handle.upstream_rx);
    config.re_bootstrap = Some(handle.re_bootstrap);

    (config, runner, svid)
}

/// Build the proxy-side discovery client and the SVID bootstrap loop, wiring the
/// shared SVID cell + rotation signal into the discovery client config.
///
/// Returns the client (routing-cell read handles, consumed by the proxy
/// acceptors), the not-yet-running reconnect supervisor, and the not-yet-running
/// bootstrap loop. Both runnables are driven by Pingora background services via
/// [`register_discovery_background_services`] so they run on a Pingora runtime
/// (the caller is still on the synchronous startup path).
///
/// # Errors
///
/// Propagates [`DiscoveryClient::new`](coxswain_discovery::DiscoveryClient::new)
/// when a configured endpoint is not a valid URI.
pub(crate) fn build_discovery_client(
    disco: &DiscoveryClientArgs,
    common: &CommonArgs,
    proxy_handle: SubsystemHandle,
    scope: Scope,
    bound_ports_rx: Option<watch::Receiver<BTreeSet<u16>>>,
    health: HealthRegistry,
) -> anyhow::Result<(DiscoveryClient, Supervisor, BootstrapRunner)> {
    // A proxy client authenticates with its SVID but does not serve downstream, so
    // the returned serving-cell handle is unused here (the relay path uses it).
    let (config, bootstrap_runner, _svid) =
        build_discovery_client_config(disco, common, scope, bound_ports_rx, health);
    let (client, supervisor) = DiscoveryClient::new(config, proxy_handle, "routing_table_loaded")?;
    Ok((client, supervisor, bootstrap_runner))
}

/// Register the discovery supervisor (and optional bootstrap loop) as Pingora
/// background services so they run on a Pingora runtime.
pub(crate) fn register_discovery_background_services(
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── upstream policy wiring (#665) ─────────────────────────────────────────

    /// Parse a real `serve proxy --shared` invocation and return the two arg
    /// groups `build_discovery_client_config` consumes, so the policy under test
    /// is parameterised exactly as production parameterises it.
    fn proxy_args(bootstrap_endpoint: &str) -> (crate::args::CommonArgs, DiscoveryClientArgs) {
        use crate::args::{Cli, Commands, Role};
        use clap::Parser;

        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            &format!("--discovery-bootstrap-endpoint={bootstrap_endpoint}"),
            "--pod-namespace=team-a",
        ])
        .expect("serve proxy --shared must parse");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected Role::Proxy");
        };
        (args.common, args.discovery)
    }

    /// A proxy's policy accepts exactly the three upstreams the controller can
    /// legitimately point it at, each with a locally-derived identity.
    #[test]
    fn policy_accepts_the_three_legal_upstreams() {
        let (common, disco) =
            proxy_args("https://coxswain-controller-discovery-bootstrap.coxswain-system.svc:50052");
        let policy = build_upstream_policy(&disco, &common, "coxswain-system");

        for (endpoint, sa) in [
            (
                "https://coxswain-controller-discovery.coxswain-system.svc:50051",
                "coxswain-controller",
            ),
            ("https://coxswain-relay.team-a.svc:50051", "coxswain-relay"),
            (
                "https://coxswain-relay-shared.coxswain-system.svc:50051",
                "coxswain-relay-shared",
            ),
        ] {
            assert!(
                policy.resolve(endpoint, sa).is_ok(),
                "{endpoint} is a legitimate upstream the controller renders; the policy must accept it"
            );
        }
    }

    /// The policy is built from the controller's own naming constants, so a
    /// relay outside this proxy's namespace — and any host the controller never
    /// renders — is refused.
    #[test]
    fn policy_refuses_upstreams_outside_this_nodes_own_set() {
        let (common, disco) =
            proxy_args("https://coxswain-controller-discovery-bootstrap.coxswain-system.svc:50052");
        let policy = build_upstream_policy(&disco, &common, "coxswain-system");

        for endpoint in [
            "https://coxswain-relay.team-b.svc:50051",
            "https://attacker.team-a.svc:50051",
        ] {
            assert!(
                policy.resolve(endpoint, "coxswain-relay").is_err(),
                "{endpoint} is not an upstream this node may be pointed at"
            );
        }
    }

    /// Production never runs without the policy: `build_discovery_client_config`
    /// must populate it on every client it builds. `None` is the test-only
    /// fail-open default, so this is the assertion that keeps it out of a
    /// shipped binary.
    #[test]
    fn built_client_config_always_carries_an_upstream_policy() {
        let (common, disco) =
            proxy_args("https://coxswain-controller-discovery-bootstrap.coxswain-system.svc:50052");
        let (config, _runner, _svid) = build_discovery_client_config(
            &disco,
            &common,
            Scope::SharedPool,
            None,
            HealthRegistry::new(),
        );
        let policy = config
            .upstream_policy
            .as_ref()
            .expect("a built discovery client config must always carry an upstream policy");
        assert!(
            policy
                .resolve("https://coxswain-relay.team-a.svc:50051", "coxswain-relay")
                .is_ok(),
            "the wired policy must be parameterised with this node's own namespace"
        );
        assert!(
            policy
                .resolve("https://coxswain-relay.team-b.svc:50051", "coxswain-relay")
                .is_err(),
            "the wired policy must refuse a peer tenant's relay"
        );
    }

    /// A loopback bootstrap endpoint yields no install namespace, so the policy
    /// falls back to the node's own — the plaintext/test path. Asserted here
    /// rather than on the parser (covered in `coxswain-discovery`) because what
    /// matters at this seam is that the fallback keeps the node's OWN relay
    /// legal and everything else refused.
    #[test]
    fn loopback_bootstrap_endpoint_falls_back_to_the_nodes_own_namespace() {
        let (common, disco) = proxy_args("https://127.0.0.1:50052");
        let install_ns =
            coxswain_discovery::namespace_from_service_dns(&disco.discovery_bootstrap_endpoint)
                .unwrap_or_else(|| common.pod_namespace.clone());
        assert_eq!(
            install_ns, "team-a",
            "a non-service-DNS bootstrap endpoint must fall back to the pod's own namespace"
        );

        let policy = build_upstream_policy(&disco, &common, &install_ns);
        assert!(
            policy
                .resolve("https://coxswain-relay.team-a.svc:50051", "coxswain-relay")
                .is_ok(),
            "the node's own namespace relay stays legal under the fallback"
        );
        assert!(
            policy
                .resolve("https://coxswain-relay.team-b.svc:50051", "coxswain-relay")
                .is_err(),
            "the fallback must not widen the legal set to other namespaces"
        );
    }
}
