//! Pingora `BackgroundService` adapters and listener-spec derivation.
//!
//! The startup path is otherwise synchronous; these adapters bridge the
//! reflector's watch channels, the discovery supervisor, and the GC loops into
//! Pingora's `BackgroundService` lifecycle.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use coxswain_controller::GatewayListenerStatusHandle;
use coxswain_core::listener_status::ProxyProtocolListenerConfig;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::shared::Shared;
use coxswain_proxy::{GrpcAuthChannelCache, ListenerProtocol, ListenerSpec, RateLimiterRegistry};
use coxswain_reflector::{GatewayListenerStatus, ListenerReadiness};
use pingora_core::server::ShutdownWatch;
use tokio::sync::watch;

/// Background service that watches [`GatewayListenerStatusHandle`] and
/// publishes the derived `HashSet<ListenerSpec>` to a watch channel consumed
/// by the [`ProxyAcceptor`].
///
/// The adapter fires immediately on startup (via `mark_changed`) so the
/// acceptor receives the first real spec set as soon as the reflector's
/// initial reconcile completes.
pub(crate) struct ListenerSpecsAdapter {
    pub(crate) listener_status: GatewayListenerStatusHandle,
    pub(crate) bind_addr: IpAddr,
    /// Ports already owned by a static acceptor (ingress ports in the shared-proxy
    /// case) that must be excluded from the gateway-derived set to avoid conflicts.
    pub(crate) excluded_ports: HashSet<u16>,
    pub(crate) tx: watch::Sender<HashSet<ListenerSpec>>,
    /// Published alongside the spec set on every tick: the `internal bind port →
    /// advertised port` map (#472) the proxy's redirect path reads. Derived from
    /// the same health snapshot, so it stays consistent with the bound listeners.
    pub(crate) advertised_ports: Shared<HashMap<u16, u16>>,
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

/// Adapts an owned, long-running future into a Pingora [`BackgroundService`].
///
/// The future is built synchronously (no runtime needed to *construct* an
/// `async fn` future) and stored; Pingora awaits it inside one of its runtimes
/// when `start` fires. This is how the proxy's discovery supervisor and bootstrap
/// loop — which internally `tokio::spawn` and so need an active runtime — are
/// started from the otherwise-synchronous bin startup path.
pub(crate) struct FutureService {
    fut:
        parking_lot::Mutex<Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>>,
}

impl FutureService {
    pub(crate) fn new(fut: impl std::future::Future<Output = ()> + Send + 'static) -> Self {
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
pub(crate) struct RateLimiterGcService {
    pub(crate) registry: RateLimiterRegistry,
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
pub(crate) struct GrpcAuthChannelGcService {
    pub(crate) cache: GrpcAuthChannelCache,
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
pub(crate) fn derive_gateway_specs(
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
pub(crate) fn derive_advertised_ports(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_ports_map_covers_http_and_https_listeners() {
        use coxswain_reflector::GatewayListenerStatus;
        use std::collections::BTreeMap;

        // An HTTP listener (NotApplicable TLS outcome) and an HTTPS listener, each
        // with a distinct allocated internal port (#472). The map must recover the
        // advertised port from the internal accept port for BOTH — the HTTP one is
        // exactly the redirect path that regressed.
        let mut listeners = BTreeMap::new();
        let http = coxswain_reflector::status::ListenerInfo {
            port: 80,
            internal_port: 30000,
            ..Default::default()
        };
        listeners.insert(
            coxswain_reflector::status::ListenerStatusKey::gateway("http"),
            http,
        );
        let https = coxswain_reflector::status::ListenerInfo {
            port: 443,
            internal_port: 30001,
            ..Default::default()
        };
        listeners.insert(
            coxswain_reflector::status::ListenerStatusKey::gateway("https"),
            https,
        );
        let glh = GatewayListenerStatus {
            listeners,
            ..Default::default()
        };

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
        let li = coxswain_reflector::status::ListenerInfo {
            port: 8080,
            internal_port: 0,
            ..Default::default()
        };
        listeners.insert(
            coxswain_reflector::status::ListenerStatusKey::gateway("http"),
            li,
        );
        let glh = GatewayListenerStatus {
            listeners,
            ..Default::default()
        };

        let mut health = HashMap::new();
        health.insert(ObjectKey::new("ns", "gw"), glh);

        let map = derive_advertised_ports(&health);
        assert_eq!(
            map.get(&8080),
            Some(&8080),
            "unallocated listener maps to itself"
        );
    }
}
