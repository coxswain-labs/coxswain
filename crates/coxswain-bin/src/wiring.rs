//! Pingora server + proxy-service wiring, config builders, and logger init.
//!
//! The shared assembly the role runners compose: Pingora `Server` construction,
//! ingress/gateway proxy service registration, the controller/management config
//! builders, and tracing-subscriber setup.

use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result};
use coxswain_admin::AdminServer;
use coxswain_controller::{
    ControllerConfig, GatewayListenerStatusHandle, IngressPorts, LeaseSettings,
};
use coxswain_core::health::HealthRegistry;
use coxswain_core::listener_status::ProxyProtocolListenerConfig;
use coxswain_core::routing::RouteTimeouts;
use coxswain_proxy::{
    AccessLogPathMode, GatewayProxy, IngressProxy, ListenerSpec, PassthroughConfig, ProxyAcceptor,
    ProxyServices, RateLimiterRegistry, RoutingEngine, RoutingSource, SniCertSelector,
    UpstreamCaCache,
};
use coxswain_reflector::WatchScope;
use pingora_core::apps::HttpServerOptions;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::services::background::background_service;
use pingora_core::services::listening::Service;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::args::{
    AccessLogPathMode as BinAccessLogPathMode, CommonArgs, ControllerArgs, LogFormat, ProxyArgs,
};
use crate::services::{
    GrpcAuthChannelGcService, ListenerSpecsAdapter, RateLimiterGcService, derive_advertised_ports,
    derive_gateway_specs,
};

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
pub(crate) fn make_http_proxy<SV>(conf: &Arc<ServerConf>, inner: SV) -> pingora_proxy::HttpProxy<SV>
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
pub(crate) fn wire_gateway_only_proxy_services(
    server: &mut Server,
    common: &CommonArgs,
    proxy: &ProxyArgs,
    source: &dyn RoutingSource,
    listener_status: &GatewayListenerStatusHandle,
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
    let cfg = ProxyServices::new(
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
pub(crate) fn access_log_path_mode(proxy: &ProxyArgs) -> AccessLogPathMode {
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
pub(crate) fn wire_proxy_services(
    server: &mut Server,
    common: &CommonArgs,
    proxy: &ProxyArgs,
    source: &dyn RoutingSource,
    listener_status: &GatewayListenerStatusHandle,
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
    let mut shared_cfg = ProxyServices::new(
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

// ── Shared helpers ────────────────────────────────────────────────────────────

pub(crate) fn build_controller_config(
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
pub(crate) fn build_ingress_listeners(common: &CommonArgs, proxy: &ProxyArgs) -> Vec<ListenerSpec> {
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
pub(crate) struct ManagementServerConfig {
    pub(crate) health: HealthRegistry,
    pub(crate) leader: Arc<AtomicBool>,
}

pub(crate) fn wire_management_servers(
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
pub(crate) fn resolve_proxy_threads(configured: usize) -> usize {
    if configured != 0 {
        return configured;
    }
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(2)
        .max(2)
}

pub(crate) fn build_server(args: &ProxyArgs) -> Server {
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

pub(crate) fn build_minimal_server() -> Server {
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

pub(crate) fn init_logger(format: LogFormat, log_filter: &str) -> Result<()> {
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
}
