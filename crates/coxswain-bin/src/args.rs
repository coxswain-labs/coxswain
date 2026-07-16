//! Command-line argument parsing for the coxswain binary.
//!
//! The binary is invoked as `coxswain serve <role>`, where each role identifies
//! a pod's purpose in the controller/proxy split topology. Roles flatten only
//! the argument groups they semantically need so clap rejects flag/role
//! mismatches at parse time, before any runtime code runs.
//!
//! Roles:
//!
//! - `controller`: reconciler and status writer pod. Reads K8s, writes status.
//! - `proxy --shared`: read-only data plane for Ingress + non-dedicated
//!   Gateways. Connects to the controller discovery gRPC server.
//! - `proxy --dedicated --gateway-name=NAME --gateway-namespace=NS`: read-only
//!   data plane scoped to a single Gateway. Connects to the controller
//!   discovery gRPC server.
//! - `relay --shared` / `relay --namespace=NS`: zero-RBAC discovery cache that
//!   subscribes upstream to the controller and re-serves the snapshot stream
//!   downstream to proxies (#583).
//!
//! Bare `coxswain serve` (no role) parses with `role = None`; the dispatch in
//! `lib.rs` rejects it, since production must pick a role explicitly.

use coxswain_core::crd::ServiceType;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use coxswain_controller::{IngressDefaultBackend, SharedProxyConfig};
use ipnet::IpNet;

/// Log output format selector.
#[derive(ValueEnum, Clone, Debug, Copy, PartialEq, Eq)]
pub(crate) enum LogFormat {
    /// Human-readable output for local development.
    Console,
    /// Structured JSON output for production environments.
    Json,
}

/// Controls what the access log records in the `path` field.
#[derive(ValueEnum, Clone, Debug, Copy, PartialEq, Eq)]
pub(crate) enum AccessLogPathMode {
    /// Emit the concrete request path as received (default).
    Full,
    /// Emit the matched rule's path pattern instead of the concrete path.
    ///
    /// E.g. `/users/` instead of `/users/42/orders/7`. When no route
    /// matched, emits `/` as a stable placeholder.
    Pattern,
    /// Omit the `path` field from the access log entirely.
    None,
}

impl AccessLogPathMode {
    /// The `--access-log-path-mode` value string, for re-rendering onto a
    /// provisioned pod's flags (#604).
    pub(crate) fn as_flag_value(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Pattern => "pattern",
            Self::None => "none",
        }
    }
}

/// Coxswain: a Kubernetes Ingress & Gateway API Controller built on Pingora.
#[derive(Parser, Debug)]
#[command(
    name = "coxswain",
    version,
    about = "A Kubernetes Ingress & Gateway API Controller built on Pingora",
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Start a long-running coxswain pod.
    Serve(ServeArgs),
}

/// Arguments for the `serve` subcommand.
#[derive(Parser, Debug)]
pub(crate) struct ServeArgs {
    /// Pod role.
    #[command(subcommand)]
    pub role: Option<Role>,
}

/// Pod role — selects which subsystems run and which flags are accepted.
///
/// `#[non_exhaustive]` reserves room for future roles (e.g. an xDS sink) without
/// breaking exhaustive matches in downstream code; same-crate matches still
/// remain exhaustive without a wildcard arm.
#[derive(Subcommand, Debug)]
#[non_exhaustive]
pub(crate) enum Role {
    /// Reconciler + status writer pod.
    Controller(ControllerRoleArgs),
    /// Read-only data plane pod. Use `--shared` for the shared pool or
    /// `--dedicated` for a per-Gateway pod.
    Proxy(ProxyRoleArgs),
    /// Zero-RBAC discovery cache pod: subscribes upstream to the controller and
    /// re-serves the snapshot stream downstream to proxies. Use `--shared` to
    /// front the shared pool or `--namespace <NS>` to front one namespace's
    /// dedicated Gateways.
    Relay(RelayRoleArgs),
}

/// Flags shared by every role.
///
/// Includes logging, pod identity, the controller-name filter, and the
/// management-surface (health + admin) bind/port settings. These are the
/// minimum every pod needs regardless of what subsystems it runs.
#[derive(Args, Debug)]
pub(crate) struct CommonArgs {
    /// GatewayClass `spec.controllerName` this instance claims.
    ///
    /// Must match exactly; resources belonging to other controllers are silently ignored.
    #[arg(
        long,
        env = "COXSWAIN_CONTROLLER_NAME",
        default_value = "coxswain-labs.dev/gateway-controller"
    )]
    pub controller_name: String,

    /// Name of this pod, used as the leader-election holder identity.
    ///
    /// Injected automatically by Kubernetes via the Downward API in production.
    #[arg(long, env = "POD_NAME", default_value = "coxswain-local")]
    pub pod_name: String,

    /// Namespace of this pod, used to scope the leader-election Lease resource.
    ///
    /// Injected automatically by Kubernetes via the Downward API in production.
    #[arg(long, env = "POD_NAMESPACE", default_value = "coxswain-system")]
    pub pod_namespace: String,

    /// Log output format: `json` (default) or `console`.
    ///
    /// Use `json` in production environments; `console` for local development.
    #[arg(long, env = "COXSWAIN_LOG_FORMAT", default_value = "json")]
    pub log_format: LogFormat,

    /// Log verbosity level: `trace`, `debug`, `info`, `warn`, or `error`.
    ///
    /// Supports the `RUST_LOG` directive syntax for per-crate overrides (e.g. `info,coxswain=debug`).
    #[arg(long = "log", env = "COXSWAIN_LOG", default_value = "info")]
    pub log_filter: String,

    /// IP address shared by the health and admin HTTP servers.
    ///
    /// Both `/healthz`/`/readyz` (health) and `/metrics`/`/api/v1/routes`/`/api/v1/health`
    /// (admin) bind to this address. Set it to a management-network IP to
    /// restrict access; leave at `0.0.0.0` so kubelet probes and Prometheus
    /// scraping work out of the box. Independent from the data-plane
    /// `--proxy-bind-address`.
    ///
    /// SECURITY: on the controller role the admin API relays cluster data —
    /// pod logs (`/api/v1/pods/{name}/logs`) and verbatim Kubernetes manifests
    /// (`/api/v1/manifests/...`) — and is currently unauthenticated. When bound to
    /// `0.0.0.0` it MUST be fenced by a NetworkPolicy that admits only trusted
    /// scrapers/probes; admin-port authentication is tracked in #251.
    #[arg(
        long,
        env = "COXSWAIN_MANAGEMENT_BIND_ADDRESS",
        default_value = "0.0.0.0"
    )]
    pub management_bind_address: IpAddr,

    /// Port to listen on for the admin, metrics, and diagnostics endpoints.
    ///
    /// The bind address is controlled by `--management-bind-address`.
    #[arg(long, env = "COXSWAIN_ADMIN_PORT", default_value_t = 8082)]
    pub admin_port: u16,

    /// Port to listen on for liveness and readiness health endpoints.
    ///
    /// The bind address is controlled by `--management-bind-address`.
    #[arg(long, env = "COXSWAIN_HEALTH_PORT", default_value_t = 8081)]
    pub health_port: u16,

    /// Kubernetes namespace(s) to watch. Omit for cluster-wide scope.
    ///
    /// Accepts a comma-separated list (`ns1,ns2,ns3`, #59): each entry spawns
    /// one namespaced watch per resource type, letting the controller run with a
    /// namespaced `Role` per namespace instead of cluster-wide read. A single
    /// entry is the exact equivalent of the pre-list single-namespace scope; an
    /// empty entry (e.g. a trailing comma) is rejected at startup.
    #[arg(long, env = "COXSWAIN_WATCH_NAMESPACE")]
    pub watch_namespace: Option<String>,

    /// Port on which Ingress traffic is served cluster-wide.
    ///
    /// The proxy pod binds this port; the controller pod compares Gateway
    /// listener ports against it for the `PortUnavailable` listener
    /// condition. When omitted, no static Ingress HTTP listener is bound and
    /// Coxswain serves only the ports declared by `Gateway.spec.listeners`.
    #[arg(long, env = "COXSWAIN_INGRESS_HTTP_PORT")]
    pub ingress_http_port: Option<u16>,

    /// Port on which TLS-terminated Ingress traffic is served cluster-wide.
    ///
    /// The proxy pod binds this port; the controller pod compares Gateway
    /// listener ports against it for the `PortUnavailable` listener
    /// condition. SNI selects the certificate from each `Ingress.spec.tls`
    /// block. When omitted, no static Ingress HTTPS listener is bound.
    #[arg(long, env = "COXSWAIN_INGRESS_HTTPS_PORT")]
    pub ingress_https_port: Option<u16>,

    /// Disable the Gateway API surface entirely.
    ///
    /// When set, no Gateway API reflectors (`Gateway`, `GatewayClass`,
    /// `HTTPRoute`, `GRPCRoute`, `TLSRoute`, `ListenerSet`, `ReferenceGrant`,
    /// `BackendTLSPolicy`) are started, no CRD-presence probe runs, and the
    /// `gateway_api_crds` readiness check is not registered. Useful for
    /// Ingress-only installs. Default (unset): the surface is enabled and, if
    /// the CRDs are absent at startup, readiness fails until they appear
    /// (self-healing re-probe — no restart required).
    #[arg(long, env = "COXSWAIN_DISABLE_GATEWAY_API")]
    pub disable_gateway_api: bool,

    /// Disable the Ingress surface entirely.
    ///
    /// When set, no Ingress reflectors (`Ingress`, `IngressClass`,
    /// `CoxswainIngressClassParameters`) are started and the proxy binds no
    /// static Ingress listeners. Useful for Gateway-API-only installs, or
    /// clusters where Ingress is handled by a separate controller. Default
    /// (unset): the surface is enabled.
    #[arg(long, env = "COXSWAIN_DISABLE_INGRESS")]
    pub disable_ingress: bool,
}

/// Flags specific to roles that bind Pingora proxy listeners (`proxy`, `dev`).
#[derive(Args, Debug)]
pub(crate) struct ProxyArgs {
    /// Worker threads per proxy service.
    ///
    /// Threads are not shared across services. `0` (the default) means **auto**:
    /// resolve to the effective CPU parallelism at startup via
    /// [`std::thread::available_parallelism`], which is cgroup-quota-aware on
    /// Linux (it reads `cpu.max` / `cfs_quota`), so the count tracks the pod's
    /// `resources.limits.cpu` with no manual tuning — floored at 2. Set an
    /// explicit non-zero value to override. Tune to the pod's CPU *limit*, not
    /// the host core count: over-provisioning threads under a CFS quota only
    /// adds context-switching.
    #[arg(long, env = "COXSWAIN_PROXY_THREADS", default_value_t = 0)]
    pub proxy_threads: usize,

    /// Drain window before the final shutdown step.
    ///
    /// After a shutdown signal, existing connections are given this long to complete
    /// before the final runtime-shutdown step begins.
    /// Accepts human-readable durations: `30s`, `1m`, `1m30s`. Set to `0s` to disable.
    /// Maps to Pingora's `grace_period_seconds`.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_SHUTDOWN_GRACE_PERIOD",
        default_value = "30s",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_shutdown_grace_period: Duration,

    /// Hard deadline for the final runtime-shutdown step after the grace period expires.
    ///
    /// Accepts human-readable durations: `5s`, `10s`. Set to `0s` to disable.
    /// Maps to Pingora's `graceful_shutdown_timeout_seconds`.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_SHUTDOWN_TIMEOUT",
        default_value = "5s",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_shutdown_timeout: Duration,

    /// Time budget for draining in-flight connections when a listener is
    /// added or removed at runtime.
    ///
    /// When a Gateway listener is removed, the acceptor stops accepting new
    /// connections on that port and waits up to this long for all in-flight
    /// requests to complete.  If any connections remain after the timeout,
    /// they are force-closed (TCP abort), the
    /// `coxswain_proxy_requests_force_closed_total` counter is incremented,
    /// and a `WARN` log is emitted.
    ///
    /// Distinct from `--proxy-shutdown-grace-period`, which controls the
    /// whole-process shutdown window on SIGTERM/SIGQUIT.
    ///
    /// Accepts human-readable durations: `30s`, `1m`. Set to `0s` to
    /// force-close immediately on listener removal (not recommended for
    /// production).
    #[arg(
        long,
        env = "COXSWAIN_PROXY_LISTENER_DRAIN_TIMEOUT",
        default_value = "30s",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_listener_drain_timeout: Duration,

    /// Maximum number of idle upstream connections held in Pingora's keepalive pool.
    ///
    /// Connections beyond this limit are evicted on an LRU basis. Raise when upstream
    /// services have many distinct hosts or ports and you observe high connection
    /// establishment rates in `coxswain_proxy_upstream_connections_total{state="new"}`.
    /// Lowering saves file descriptors at the cost of more reconnects.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_UPSTREAM_KEEPALIVE_POOL_SIZE",
        default_value_t = 128
    )]
    pub proxy_upstream_keepalive_pool_size: usize,

    /// IP address to bind all proxy listeners to.
    ///
    /// Shared by both HTTP and HTTPS listeners; combine with
    /// `--ingress-http-port` and/or `--ingress-https-port` (on `CommonArgs`)
    /// to form the full bind address for each listener. The health and admin
    /// servers bind separately via `--management-bind-address`.
    #[arg(long, env = "COXSWAIN_PROXY_BIND_ADDRESS", default_value = "0.0.0.0")]
    pub proxy_bind_address: IpAddr,

    /// Timeout for dialling a TLS passthrough backend.
    ///
    /// When a TLS-passthrough connection matches a TLSRoute, the proxy opens a
    /// TCP connection to the selected backend within this window.  If the
    /// backend does not accept within the timeout the client connection is closed.
    ///
    /// Accepts human-readable durations: `5s`, `30s`.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_TLS_PASSTHROUGH_DIAL_TIMEOUT",
        default_value = "10s",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_tls_passthrough_dial_timeout: Duration,

    /// Idle timeout for a UDPRoute session (#506).
    ///
    /// Not a connect timeout — UDP `connect()` is a local operation with no
    /// handshake. A UDPRoute session is a client 5-tuple pinned to a backend;
    /// this bounds how long that pin and its reply-forwarding task stay alive
    /// between datagrams before the proxy evicts it (the next datagram from
    /// that client re-selects a backend as a fresh session).
    ///
    /// Kept short by default: a session's server-side lifetime is decoupled
    /// from how fast its exchange actually completes (UDP has no protocol-level
    /// "done" signal), so it always lingers for the full timeout even after a
    /// one-shot request/response (DNS-shaped) has already finished. A long
    /// default compounds badly under bursty short-lived traffic — thousands of
    /// completed-but-still-lingering sessions can exhaust the per-listener
    /// session table in seconds.
    ///
    /// Accepts human-readable durations: `5s`, `30s`.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_UDP_SESSION_TIMEOUT",
        default_value = "10s",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_udp_session_timeout: Duration,

    /// Enable HAProxy PROXY protocol v1/v2 on **Ingress** listeners.
    ///
    /// When set, every connection accepted on the Ingress HTTP/HTTPS ports
    /// (from `--ingress-http-port` / `--ingress-https-port`) MUST carry a valid
    /// PROXY v1 or v2 header. Connections from sources not listed in
    /// `--ingress-proxy-trusted-sources` are dropped immediately. Connections
    /// that omit or malform the header are also dropped (strict mode).
    ///
    /// This flag applies **only** to Ingress-origin listeners. For Gateway API
    /// listeners, use a `ClientTrafficPolicy` CRD targeting the desired
    /// listener (or Gateway) instead.
    ///
    /// The real client address extracted from the PROXY header is propagated
    /// upstream via the RFC 7239 `Forwarded` header.
    #[arg(
        long,
        env = "COXSWAIN_INGRESS_ACCEPT_PROXY_PROTOCOL",
        default_value_t = false
    )]
    pub ingress_accept_proxy_protocol: bool,

    /// Comma-separated CIDR ranges permitted to send PROXY headers on Ingress listeners.
    ///
    /// Only meaningful when `--ingress-accept-proxy-protocol` is set. Connections
    /// from addresses outside this list are rejected at the TCP level.
    ///
    /// Example: `10.0.0.0/8,172.16.0.0/12,127.0.0.1/32`
    #[arg(
        long,
        env = "COXSWAIN_INGRESS_PROXY_TRUSTED_SOURCES",
        value_delimiter = ','
    )]
    pub ingress_proxy_trusted_sources: Vec<IpNet>,

    /// Global default for the total request timeout (client → proxy → upstream → client).
    ///
    /// Applied to routes that do not set `HTTPRouteRule.timeouts.request`. A route-level
    /// setting always overrides this value.
    /// Accepts human-readable durations: `30s`, `1m`, `1m30s`. Omit to disable.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_DEFAULT_REQUEST_TIMEOUT",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_default_request_timeout: Option<Duration>,

    /// Global default for the upstream-only (backend) request timeout.
    ///
    /// Applied to routes that do not set `HTTPRouteRule.timeouts.backendRequest`. A
    /// route-level setting always overrides this value.
    /// Accepts human-readable durations: `10s`, `500ms`. Omit to disable.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_DEFAULT_BACKEND_REQUEST_TIMEOUT",
        value_parser = humantime::parse_duration,
    )]
    pub proxy_default_backend_request_timeout: Option<Duration>,

    /// Controller-wide default backend for Ingress traffic that does not match any rule.
    ///
    /// Format: `<namespace>/<service>:<port>` — e.g. `default/my-404-page:80`.
    ///
    /// When set, requests to hosts with no matching path (and requests to entirely
    /// unknown hosts) are forwarded to this service. A per-Ingress `spec.defaultBackend`
    /// always overrides this setting within that Ingress's rule hosts.
    ///
    /// The backing service is re-resolved on every routing-table rebuild; the default
    /// disappears automatically if its endpoints become unavailable and reappears when
    /// they recover.
    #[arg(long, env = "COXSWAIN_INGRESS_DEFAULT_BACKEND")]
    pub ingress_default_backend: Option<IngressDefaultBackend>,

    /// Enable per-request access logging.
    ///
    /// When `true` (default), one structured log event is emitted per request at
    /// `INFO` level on the `coxswain_proxy::access` target. Set to `false` to
    /// silence access logs entirely (useful for high-traffic benchmarking).
    ///
    /// Individual fields can be suppressed or transformed with `--access-log-path-mode`.
    #[arg(
        long,
        env = "COXSWAIN_ACCESS_LOG",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub access_log: bool,

    /// Controls what the access log records in the `path` field.
    ///
    /// `full` (default): the concrete request path. `pattern`: the matched
    /// rule's registered path pattern — e.g. `/users/` instead of
    /// `/users/42/orders/7`. `none`: the field is omitted entirely.
    ///
    /// Prefer pipeline-side redaction when your log collector supports it.
    /// Use `pattern` or `none` only when the pipeline cannot filter.
    #[arg(long, env = "COXSWAIN_ACCESS_LOG_PATH_MODE", default_value = "full")]
    pub access_log_path_mode: AccessLogPathMode,
}

/// Parse a comma-separated `key=value` label selector into a map (#472).
///
/// An empty string yields an empty map (shared-mode per-Gateway addressing
/// disabled). Whitespace around keys/values is trimmed.
///
/// # Errors
///
/// Returns a human-readable message when a pair lacks `=` or has an empty key.
fn parse_label_selector(s: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for pair in s.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("invalid label selector entry {pair:?}: expected key=value"))?;
        let k = k.trim();
        if k.is_empty() {
            return Err(format!("invalid label selector entry {pair:?}: empty key"));
        }
        map.insert(k.to_string(), v.trim().to_string());
    }
    Ok(map)
}

/// Parse a `--shared-proxy-pod-template` JSON object into a [`serde_json::Value`]
/// (#604). The chart builds this from the `proxy.shared.*` scheduling / pod-metadata
/// values; the controller strategic-merges it onto the rendered pool pod.
///
/// # Errors
///
/// Returns the `serde_json` parse error message for malformed JSON.
fn parse_json(s: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(s).map_err(|e| format!("invalid pod-template JSON: {e}"))
}

/// Parse the `--shared-vip-service-type` value into a [`ServiceType`] (#472).
///
/// `NodePort` is intentionally rejected: a shared-VIP NodePort maps the
/// advertised listener port (`:443`) to a random high node port, so it cannot
/// preserve per-Gateway addressing on the spec port, and the shared status
/// writer has no Node store to resolve a node IP from — the Gateway would
/// report no address forever. `LoadBalancer` (external) and `ClusterIP`
/// (in-cluster / on-prem / test) both yield a stable per-Gateway address.
///
/// # Errors
///
/// Returns a human-readable message for any value other than `LoadBalancer`
/// or `ClusterIP` (case-insensitive).
fn parse_service_type(s: &str) -> Result<ServiceType, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "loadbalancer" => Ok(ServiceType::LoadBalancer),
        "clusterip" => Ok(ServiceType::ClusterIp),
        other => Err(format!(
            "invalid shared VIP service type {other:?}: expected LoadBalancer or ClusterIP"
        )),
    }
}

/// Flags specific to roles that run the status writer (`controller`, `dev`).
#[derive(Args, Debug)]
pub(crate) struct ControllerArgs {
    /// How long a leader lease stays valid without renewal.
    ///
    /// Determines how quickly a standby replica can take over after the leader dies.
    /// Must be at least 3× `--controller-lease-renew-interval`.
    #[arg(
        long,
        env = "COXSWAIN_CONTROLLER_LEASE_TTL",
        default_value = "15s",
        value_parser = humantime::parse_duration,
    )]
    pub controller_lease_ttl: Duration,

    /// How often the active leader renews its lease.
    ///
    /// Must be at most 1/3 of `--controller-lease-ttl`.
    #[arg(
        long,
        env = "COXSWAIN_CONTROLLER_LEASE_RENEW_INTERVAL",
        default_value = "5s",
        value_parser = humantime::parse_duration,
    )]
    pub controller_lease_renew_interval: Duration,

    /// External address written to every owned `Ingress.status.loadBalancer.ingress[0]`
    /// and `Gateway.status.addresses[0]`.
    ///
    /// Accepts either a bare IP (`203.0.113.1`) or a DNS hostname
    /// (`coxswain.example.com`). IP values are written to `.ip`;
    /// hostname values are written to `.hostname`.
    ///
    /// Required for cert-manager HTTP-01 challenge resolution and
    /// external-dns DNS record creation. When omitted, status is
    /// not patched (backward-compatible default).
    #[arg(long, env = "COXSWAIN_STATUS_ADDRESS")]
    pub status_address: Option<String>,

    /// Label selector targeting the shared proxy pod, used as the `selector` of
    /// every per-Gateway shared-mode VIP Service (#472).
    ///
    /// Comma-separated `key=value` pairs. The Helm chart supplies the install's
    /// selector — typically
    /// `app.kubernetes.io/name=coxswain,app.kubernetes.io/instance=<release>,app.kubernetes.io/component=shared-proxy`
    /// — because the controller cannot derive the release name
    /// (`app.kubernetes.io/instance`) itself. Empty (the default) disables
    /// shared-mode per-Gateway addressing, leaving Gateways on the fixed shared
    /// listeners (Ingress-style); set it to enable cross-Gateway isolation.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_SELECTOR",
        default_value = "",
        value_parser = parse_label_selector,
    )]
    pub shared_proxy_selector: BTreeMap<String, String>,

    /// Service type for the per-Gateway shared-mode VIP Services (#472).
    ///
    /// `LoadBalancer` (default) gives each Gateway its own external address;
    /// `ClusterIP` gives a stable in-cluster address for on-prem or test
    /// clusters. `NodePort` is rejected — see [`parse_service_type`].
    #[arg(
        long,
        env = "COXSWAIN_SHARED_VIP_SERVICE_TYPE",
        default_value = "LoadBalancer",
        value_parser = parse_service_type,
    )]
    pub shared_vip_service_type: ServiceType,

    // ── Controller-owned shared proxy pool (#604) ──────────────────────────
    // The shared proxy pool is provisioned by the controller (not Helm). These
    // flags are the full-parity remap of the former `proxy.shared.*` chart
    // values; the controller renders them onto the pool's pod. Ports, ingress /
    // gateway-api enablement, and the discovery bootstrap material come from the
    // controller's own `CommonArgs` (shared install-wide), not from here.
    /// Provision the controller-owned shared proxy pool (#604).
    ///
    /// `true` (default) provisions the base data plane at install. `false` leaves
    /// it unprovisioned (as does an empty `--shared-proxy-selector`, an
    /// Ingress-only / test install).
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_ENABLED",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    pub shared_proxy_enabled: bool,

    /// Name of the shared proxy Deployment / ServiceAccount / HPA / PDB (and the
    /// stem of the internal Service, `<name>-internal`). Chart-supplied, release
    /// prefixed.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_NAME",
        default_value = "coxswain-shared-proxy"
    )]
    pub shared_proxy_name: String,

    /// Static replica count for the shared proxy pool. Ignored under autoscaling.
    #[arg(long, env = "COXSWAIN_SHARED_PROXY_REPLICAS", default_value_t = 1)]
    pub shared_proxy_replicas: u32,

    /// Container CPU request for the shared proxy pool. Empty omits it.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_CPU_REQUEST",
        default_value = "100m"
    )]
    pub shared_proxy_cpu_request: String,

    /// Container memory request for the shared proxy pool. Empty omits it.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_MEMORY_REQUEST",
        default_value = "128Mi"
    )]
    pub shared_proxy_memory_request: String,

    /// Container CPU limit for the shared proxy pool. Empty omits it.
    #[arg(long, env = "COXSWAIN_SHARED_PROXY_CPU_LIMIT", default_value = "500m")]
    pub shared_proxy_cpu_limit: String,

    /// Container memory limit for the shared proxy pool. Empty omits it.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_MEMORY_LIMIT",
        default_value = "256Mi"
    )]
    pub shared_proxy_memory_limit: String,

    /// Provision a traffic-scaling `HorizontalPodAutoscaler` over the pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_AUTOSCALING_ENABLED",
        default_value_t = false,
        action = clap::ArgAction::Set,
    )]
    pub shared_proxy_autoscaling_enabled: bool,

    /// HPA `minReplicas` for the shared proxy pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_AUTOSCALING_MIN_REPLICAS",
        default_value_t = 2
    )]
    pub shared_proxy_autoscaling_min_replicas: u32,

    /// HPA `maxReplicas` for the shared proxy pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_AUTOSCALING_MAX_REPLICAS",
        default_value_t = 10
    )]
    pub shared_proxy_autoscaling_max_replicas: u32,

    /// HPA target average CPU utilization percentage for the shared proxy pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_AUTOSCALING_TARGET_CPU",
        default_value_t = 80
    )]
    pub shared_proxy_autoscaling_target_cpu: u32,

    /// Worker threads per proxy service for the pool (`0` = auto).
    #[arg(long, env = "COXSWAIN_SHARED_PROXY_THREADS", default_value_t = 0)]
    pub shared_proxy_threads: usize,

    /// Upstream keepalive pool size for the shared proxy pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_UPSTREAM_KEEPALIVE_POOL_SIZE",
        default_value_t = 128
    )]
    pub shared_proxy_upstream_keepalive_pool_size: usize,

    /// Shutdown grace period for the shared proxy pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_SHUTDOWN_GRACE_PERIOD",
        default_value = "30s",
        value_parser = humantime::parse_duration,
    )]
    pub shared_proxy_shutdown_grace_period: Duration,

    /// Shutdown timeout for the shared proxy pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_SHUTDOWN_TIMEOUT",
        default_value = "5s",
        value_parser = humantime::parse_duration,
    )]
    pub shared_proxy_shutdown_timeout: Duration,

    /// Listener drain timeout for the shared proxy pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_LISTENER_DRAIN_TIMEOUT",
        default_value = "30s",
        value_parser = humantime::parse_duration,
    )]
    pub shared_proxy_listener_drain_timeout: Duration,

    /// Global default total request timeout for the pool. Omit to disable.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_DEFAULT_REQUEST_TIMEOUT",
        value_parser = humantime::parse_duration,
    )]
    pub shared_proxy_default_request_timeout: Option<Duration>,

    /// Global default backend (upstream-only) request timeout. Omit to disable.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_DEFAULT_BACKEND_REQUEST_TIMEOUT",
        value_parser = humantime::parse_duration,
    )]
    pub shared_proxy_default_backend_request_timeout: Option<Duration>,

    /// Enable HAProxy PROXY protocol on the pool's Ingress listeners.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_ACCEPT_PROXY_PROTOCOL",
        default_value_t = false,
        action = clap::ArgAction::Set,
    )]
    pub shared_proxy_accept_proxy_protocol: bool,

    /// CIDR ranges permitted to send PROXY headers to the pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_TRUSTED_SOURCES",
        value_delimiter = ','
    )]
    pub shared_proxy_trusted_sources: Vec<IpNet>,

    /// Controller-wide default backend for the pool (`<namespace>/<service>:<port>`).
    #[arg(long, env = "COXSWAIN_SHARED_PROXY_INGRESS_DEFAULT_BACKEND")]
    pub shared_proxy_ingress_default_backend: Option<IngressDefaultBackend>,

    /// Enable per-request access logging on the pool.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_ACCESS_LOG",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    pub shared_proxy_access_log: bool,

    /// What the pool's access log records in the `path` field
    /// (`full`|`pattern`|`none`).
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_ACCESS_LOG_PATH_MODE",
        default_value = "full"
    )]
    pub shared_proxy_access_log_path_mode: AccessLogPathMode,

    /// Partial `PodTemplateSpec` (JSON) strategic-merged onto the shared pool pod:
    /// scheduling (nodeSelector/tolerations/affinity/topologySpreadConstraints/
    /// priorityClassName), pod labels/annotations, and image pull secrets. The
    /// chart builds it from `proxy.shared.*`. Controller-managed fields (SA,
    /// security context, discovery volumes, coxswain container) survive the merge.
    #[arg(
        long,
        env = "COXSWAIN_SHARED_PROXY_POD_TEMPLATE",
        value_parser = parse_json,
    )]
    pub shared_proxy_pod_template: Option<serde_json::Value>,

    /// Port the discovery gRPC server binds to.
    ///
    /// The proxy's `--source=discovery` mode connects here to receive pushed
    /// routing snapshots. Every controller replica serves discovery independently;
    /// no leader election gate applies to this listener.
    ///
    /// The bind address is controlled by `--management-bind-address`.
    #[arg(long, env = "COXSWAIN_DISCOVERY_PORT", default_value_t = 50051)]
    pub discovery_port: u16,

    /// Port the bootstrap gRPC server binds to.
    ///
    /// Fresh proxies with no SVID connect here to exchange a Kubernetes
    /// ServiceAccount token + CSR for a short-lived SVID.  Uses server-auth-only
    /// TLS (no client cert required on this port).
    ///
    /// The bind address is controlled by `--management-bind-address`.
    #[arg(
        long,
        env = "COXSWAIN_DISCOVERY_BOOTSTRAP_PORT",
        default_value_t = 50052
    )]
    pub discovery_bootstrap_port: u16,

    /// Name of the Kubernetes Secret holding the CA certificate and key.
    ///
    /// Must be in the same namespace as the controller pod (`POD_NAMESPACE`).
    /// With `--discovery-ca-mode=auto` (default), the controller creates this
    /// Secret if absent.  With `--discovery-ca-mode=external`, the operator
    /// must pre-create it (e.g. via cert-manager) before the controller starts.
    #[arg(
        long,
        env = "COXSWAIN_DISCOVERY_CA_SECRET",
        default_value = "coxswain-discovery-ca"
    )]
    pub discovery_ca_secret: String,

    /// CA provisioning mode.
    ///
    /// `auto` (default): the controller self-generates a CA if the Secret is
    /// absent.  `external`: fail closed if the Secret is absent — the operator
    /// must supply it (e.g. via cert-manager) before deploying.
    #[arg(long, env = "COXSWAIN_DISCOVERY_CA_MODE", default_value = "auto")]
    pub discovery_ca_mode: CaModeArg,

    /// TTL for SVIDs issued to proxy nodes.
    ///
    /// Proxies refresh their SVID at ~50 % of this value.  Short TTLs improve
    /// revocation responsiveness; long TTLs reduce bootstrap RPC traffic.
    /// Accepts human-readable durations: `24h`, `1h`, `30m`.
    #[arg(
        long,
        env = "COXSWAIN_DISCOVERY_SVID_TTL",
        default_value = "24h",
        value_parser = humantime::parse_duration,
    )]
    pub discovery_svid_ttl: Duration,

    /// SPIFFE trust domain written into every issued SVID.
    ///
    /// Must match across the controller and all proxy nodes.  The default
    /// (`cluster.local`) matches the Kubernetes default.
    #[arg(
        long,
        env = "COXSWAIN_DISCOVERY_TRUST_DOMAIN",
        default_value = "cluster.local"
    )]
    pub discovery_trust_domain: String,

    /// Enable the discovery relay tier (#584).
    ///
    /// When set, every namespace that holds ≥1 dedicated Gateway is provisioned a
    /// controller-managed namespace relay (SA + Deployment + Service), and that
    /// namespace's dedicated proxies subscribe for routing snapshots through the
    /// relay instead of directly to the controller — so the leader fans out one
    /// stream per relay rather than one per proxy replica. Off by default: no
    /// relays are provisioned and the install is byte-identical to a non-relay
    /// one. The controller authorizes a relay's `Namespace` subscribe only for the
    /// SA it provisioned in that namespace (provenance, deny-by-default).
    #[arg(long, env = "COXSWAIN_RELAY_ENABLED", default_value_t = false)]
    pub relay_enabled: bool,

    /// Routing (Stream) endpoint of the **shared** relay, when one fronts the
    /// shared proxy pool (#601).
    ///
    /// A static Helm toggle in v0.6 (the shared relay is not controller-managed
    /// like namespace relays). When set, the controller hands shared-pool proxies
    /// this endpoint as their best upstream at bootstrap instead of the controller's
    /// own Stream endpoint. Unset (default) → shared proxies stream from the
    /// controller. Example:
    /// `https://coxswain-relay-shared.coxswain-system.svc:50051`.
    #[arg(long, env = "COXSWAIN_SHARED_RELAY_ENDPOINT")]
    pub shared_relay_endpoint: Option<String>,

    /// Replica count for each provisioned namespace relay (#584).
    ///
    /// Only meaningful with `--relay-enabled`. Default 2 (HA): at replica 1 a
    /// relay restart drops the streams of every leaf behind it until it returns,
    /// so production keeps ≥2; a small cluster that enables tiering but wants a
    /// single pod sets `--relay-replicas=1`. Values below 1 are clamped to 1 —
    /// per-namespace scale-to-0 is governed by `--relay-min-proxy-replicas`,
    /// not this flag.
    #[arg(long, env = "COXSWAIN_RELAY_REPLICAS", default_value_t = 2)]
    pub relay_replicas: u32,

    /// Minimum downstream demand before a namespace gets its own relay (#584).
    ///
    /// A relay is provisioned for a namespace only once its *desired* dedicated-
    /// proxy replica count (summed across that namespace's dedicated Gateways)
    /// reaches this value; below it, the namespace's proxies subscribe directly to
    /// the controller (a relay is scaled to zero). This is a break-even control:
    /// each relay replica opens its own upstream stream to the leader, so a relay
    /// only *reduces* leader load when it fronts more downstream streams than it
    /// costs (`--relay-replicas`). The default (8) keeps relays off small and
    /// medium namespaces — the tier earns its extra hop and pods only at fan-out
    /// scale. Only meaningful with `--relay-enabled`.
    #[arg(long, env = "COXSWAIN_RELAY_MIN_PROXY_REPLICAS", default_value_t = 8)]
    pub relay_min_proxy_replicas: u32,

    /// Capacity ratio: downstream dedicated proxies per relay replica the sizing
    /// loop targets (#602).
    ///
    /// **Decoupled from** the break-even `--relay-min-proxy-replicas`: that gate
    /// answers "is a relay worth existing?", this answers "how many subscribers can
    /// one replica front?". A relay is a fan-out cache (one upstream stream in,
    /// broadcast to N subscribers), so real per-replica capacity is O(100s), bounded
    /// by egress/serialization and failover blast radius — not the break-even
    /// number. An autoscaled relay (`CoxswainRelayPolicy` with a capped
    /// `RelayAutoscaling`) runs `clamp(ceil(live_subscribers / this), min, max)`.
    /// Default 50 (provisional; #603 measures it). Per-namespace override:
    /// `RelayAutoscaling.targetProxiesPerReplica`.
    #[arg(
        long,
        env = "COXSWAIN_RELAY_TARGET_PROXIES_PER_REPLICA",
        default_value_t = 50
    )]
    pub relay_target_proxies_per_replica: u32,

    /// Deactivation cooldown for a namespace relay (#602).
    ///
    /// Once the namespace's live dedicated-proxy subscriber count falls below the
    /// break-even threshold (`--relay-min-proxy-replicas`), the relay is torn down
    /// only after the signal has stayed below it continuously for this long — the
    /// KEDA-style hysteresis that replaces the old keep-until-fully-drained rule. A
    /// namespace that genuinely drains (no dedicated Gateways left) tears down at
    /// once; a transient 0 while Gateways remain (relay restart / control-stream
    /// reconnect) waits the cooldown, so a blip never deletes a live relay.
    /// Per-namespace override: `RelayAutoscaling.cooldownSeconds`. Only meaningful
    /// with `--relay-enabled`.
    #[arg(
        long,
        env = "COXSWAIN_RELAY_COOLDOWN",
        default_value = "300s",
        value_parser = humantime::parse_duration,
    )]
    pub relay_cooldown: Duration,

    /// Scale-down stabilization window for an autoscaled namespace relay (#602).
    ///
    /// When scaling **down**, the loop sizes on the **maximum** subscriber count
    /// observed over this trailing window, so a brief dip does not immediately shed a
    /// replica (scale-**up** is not damped — a relay grows promptly under load).
    /// Per-namespace override: `RelayAutoscaling.scaleDownStabilizationSeconds`.
    #[arg(
        long,
        env = "COXSWAIN_RELAY_SCALE_DOWN_STABILIZATION",
        default_value = "300s",
        value_parser = humantime::parse_duration,
    )]
    pub relay_scale_down_stabilization: Duration,

    /// Relative sizing deadband for an autoscaled namespace relay (#602).
    ///
    /// The loop changes the replica count only when the usage ratio
    /// (`live_subscribers / (current_replicas × target)`) deviates from 1.0 by more
    /// than this fraction — a `0.10` tolerance ignores load within ±10% of target, so
    /// small jitter does not churn the Deployment. Per-namespace override:
    /// `RelayAutoscaling.tolerance`.
    #[arg(long, env = "COXSWAIN_RELAY_TOLERANCE", default_value_t = 0.10)]
    pub relay_tolerance: f64,

    /// CPU **request** for each provisioned namespace relay container (#584).
    ///
    /// A relay is otherwise BestEffort (no requests) — unschedulable-priority and
    /// first to be evicted. A request only, no CPU limit, is deliberate: a CPU
    /// limit would throttle the delta-fan-out path. Empty omits the request.
    /// Per-namespace overrides land with `CoxswainRelayPolicy` (v0.6).
    #[arg(long, env = "COXSWAIN_RELAY_CPU_REQUEST", default_value = "50m")]
    pub relay_cpu_request: String,

    /// Memory **request** for each provisioned namespace relay container (#584).
    /// Empty omits it. See [`Self::relay_cpu_request`].
    #[arg(long, env = "COXSWAIN_RELAY_MEMORY_REQUEST", default_value = "64Mi")]
    pub relay_memory_request: String,

    /// Memory **limit** for each provisioned namespace relay container (#584).
    ///
    /// Memory is the OOM risk (the relay caches the namespace's routing world +
    /// per-leaf delta baselines), so it carries a limit to protect the node.
    /// Empty omits it. See [`Self::relay_cpu_request`].
    #[arg(long, env = "COXSWAIN_RELAY_MEMORY_LIMIT", default_value = "256Mi")]
    pub relay_memory_limit: String,

    /// Minimum trailing-edge quiet window for the reconciler's rebuild
    /// debounce (#512).
    ///
    /// A watch event resets this timer; when it elapses with no further
    /// events, the routing table rebuilds. Governs how fast an isolated
    /// resource change converges. Must be at most `--reconcile-debounce-max`.
    #[arg(
        long,
        env = "COXSWAIN_RECONCILE_DEBOUNCE_MIN",
        default_value = "20ms",
        value_parser = humantime::parse_duration,
    )]
    pub reconcile_debounce_min: Duration,

    /// Maximum debounce wait for the reconciler's rebuild loop (#512).
    ///
    /// A hard ceiling measured from the first event of a debounce cycle: even
    /// under continuous churn (e.g. a rolling deploy) that keeps resetting
    /// `--reconcile-debounce-min`, the routing table rebuilds within this
    /// bound. Must be at least `--reconcile-debounce-min`.
    #[arg(
        long,
        env = "COXSWAIN_RECONCILE_DEBOUNCE_MAX",
        default_value = "500ms",
        value_parser = humantime::parse_duration,
    )]
    pub reconcile_debounce_max: Duration,
}

impl ControllerArgs {
    /// Build the render-ready [`SharedProxyConfig`] the operator carries (#604)
    /// from the `--shared-proxy-*` flags. Durations/CIDRs/enums are pre-formatted
    /// to strings here so `coxswain-controller` stays free of `humantime`/`ipnet`
    /// and its renderer is pure string interpolation. The selector is not on this
    /// struct — `--shared-proxy-selector` reaches the renderer via
    /// `OperatorConfig::shared_proxy_selector`, the single source the VIP Services
    /// also select on.
    pub(crate) fn shared_proxy_config(&self) -> SharedProxyConfig {
        SharedProxyConfig {
            enabled: self.shared_proxy_enabled,
            name: self.shared_proxy_name.clone(),
            replicas: self.shared_proxy_replicas,
            cpu_request: self.shared_proxy_cpu_request.clone(),
            memory_request: self.shared_proxy_memory_request.clone(),
            cpu_limit: self.shared_proxy_cpu_limit.clone(),
            memory_limit: self.shared_proxy_memory_limit.clone(),
            autoscaling_enabled: self.shared_proxy_autoscaling_enabled,
            autoscaling_min_replicas: self.shared_proxy_autoscaling_min_replicas,
            autoscaling_max_replicas: self.shared_proxy_autoscaling_max_replicas,
            autoscaling_target_cpu: self.shared_proxy_autoscaling_target_cpu,
            threads: self.shared_proxy_threads,
            upstream_keepalive_pool_size: self.shared_proxy_upstream_keepalive_pool_size,
            shutdown_grace_period: humantime::format_duration(
                self.shared_proxy_shutdown_grace_period,
            )
            .to_string(),
            shutdown_timeout: humantime::format_duration(self.shared_proxy_shutdown_timeout)
                .to_string(),
            listener_drain_timeout: humantime::format_duration(
                self.shared_proxy_listener_drain_timeout,
            )
            .to_string(),
            default_request_timeout: self
                .shared_proxy_default_request_timeout
                .map(|d| humantime::format_duration(d).to_string()),
            default_backend_request_timeout: self
                .shared_proxy_default_backend_request_timeout
                .map(|d| humantime::format_duration(d).to_string()),
            accept_proxy_protocol: self.shared_proxy_accept_proxy_protocol,
            trusted_sources: self
                .shared_proxy_trusted_sources
                .iter()
                .map(ToString::to_string)
                .collect(),
            ingress_default_backend: self
                .shared_proxy_ingress_default_backend
                .as_ref()
                .map(|b| format!("{}/{}:{}", b.namespace, b.name, b.port)),
            access_log: self.shared_proxy_access_log,
            access_log_path_mode: self
                .shared_proxy_access_log_path_mode
                .as_flag_value()
                .to_string(),
            pod_template: self.shared_proxy_pod_template.clone(),
        }
    }
}

/// CA provisioning mode selector.
#[derive(ValueEnum, Clone, Debug, Copy, PartialEq, Eq)]
pub(crate) enum CaModeArg {
    /// Self-generate a CA if the Secret is absent (default).
    Auto,
    /// Require a pre-existing Secret; fail closed if absent.
    External,
}

/// Arguments accepted by the `controller` role.
///
/// Controller pods run the reconciler and status writer; they do not bind
/// proxy listeners, so `ProxyArgs` is not flattened in.
#[derive(Args, Debug)]
pub(crate) struct ControllerRoleArgs {
    /// Flags shared by every role.
    #[command(flatten)]
    pub common: CommonArgs,
    /// Reconciler + status writer flags.
    #[command(flatten)]
    pub controller: ControllerArgs,
}

/// Arguments accepted by the `proxy` role.
///
/// Exactly one of `--shared` (serve the shared pool) or `--dedicated` (serve a
/// single dedicated Gateway) must be set; clap's `scope` argument group
/// enforces this at parse time. When `--dedicated` is set, `--gateway-name`
/// and `--gateway-namespace` are required; when `--shared` is set, they are
/// rejected.
#[derive(Args, Debug)]
#[command(group(ArgGroup::new("scope").required(true).multiple(false)))]
pub(crate) struct ProxyRoleArgs {
    /// Flags shared by every role.
    #[command(flatten)]
    pub common: CommonArgs,
    /// Proxy data-plane flags.
    #[command(flatten)]
    pub proxy: ProxyArgs,

    /// Serve Ingress and non-dedicated Gateways from a shared pool.
    #[arg(long, group = "scope")]
    pub shared: bool,

    /// Serve a single dedicated Gateway. Requires `--gateway-name` and
    /// `--gateway-namespace`.
    #[arg(long, group = "scope")]
    pub dedicated: bool,

    /// Name of the Gateway this proxy is scoped to.
    ///
    /// Required with `--dedicated`; rejected with `--shared`.
    #[arg(
        long,
        env = "COXSWAIN_GATEWAY_NAME",
        required_if_eq("dedicated", "true"),
        conflicts_with = "shared"
    )]
    pub gateway_name: Option<String>,

    /// Namespace of the Gateway this proxy is scoped to.
    ///
    /// Required with `--dedicated`; rejected with `--shared`.
    #[arg(
        long,
        env = "COXSWAIN_GATEWAY_NAMESPACE",
        required_if_eq("dedicated", "true"),
        conflicts_with = "shared"
    )]
    pub gateway_namespace: Option<String>,

    /// Discovery-client flags (upstream endpoint, bootstrap, SVID material).
    #[command(flatten)]
    pub discovery: DiscoveryClientArgs,
}

/// The discovery-**client** flag set, shared by the `proxy` and `relay` roles.
///
/// Both roles connect to an upstream discovery server (the controller, or — for
/// a leaf behind a relay — the relay), bootstrap an SVID, and open the mTLS
/// `Stream`. Flattened into each role's args so the `--discovery-*` flags,
/// env vars, and defaults stay identical across roles.
#[derive(Args, Debug)]
pub(crate) struct DiscoveryClientArgs {
    /// Bootstrap endpoint — the sole endpoint anchor and fallback (#601).
    ///
    /// Must be an `https://` URI pointing to the controller's bootstrap listener
    /// (port 50052 by default). Bootstrap is **not** tiered — even a leaf behind a
    /// relay bootstraps its SVID directly from the controller. The bootstrap
    /// response also carries this client's current best **routing** upstream
    /// (`(endpoint, expected_server_sa)`): the relay fronting its scope if one is
    /// provisioned, else the controller. The client then dials that upstream for
    /// its mTLS `Stream` — there is no separate stream-endpoint flag. A live
    /// `PreferredUpstream` directive on the stream repoints it at runtime without
    /// a pod restart; if the upstream becomes unreachable the client re-bootstraps
    /// here to re-resolve it (this endpoint is the always-up anchor).
    ///
    /// Example: `https://coxswain-controller-discovery.coxswain-system.svc:50052`
    #[arg(long, env = "COXSWAIN_DISCOVERY_BOOTSTRAP_ENDPOINT", required = true)]
    pub discovery_bootstrap_endpoint: String,

    /// Path to the projected ServiceAccount token file.
    ///
    /// The token is sent to the bootstrap listener so the controller can validate
    /// the node's identity via the Kubernetes TokenReview API.
    ///
    /// Default: `/var/run/secrets/coxswain/discovery-token/token`
    #[arg(
        long,
        env = "COXSWAIN_DISCOVERY_SA_TOKEN_PATH",
        default_value = "/var/run/secrets/coxswain/discovery-token/token"
    )]
    pub discovery_sa_token_path: String,

    /// Path to the CA bundle from the trust-bundle ConfigMap mount.
    ///
    /// Used to verify the upstream server's TLS certificate during bootstrap and
    /// to build the mTLS channel for `Stream`. A relay reuses the same bundle as
    /// the client-CA for the downstream proxies it serves.
    ///
    /// Default: `/var/run/secrets/coxswain/trust-bundle/ca.crt`
    #[arg(
        long,
        env = "COXSWAIN_DISCOVERY_CA_BUNDLE_PATH",
        default_value = "/var/run/secrets/coxswain/trust-bundle/ca.crt"
    )]
    pub discovery_ca_bundle_path: String,

    /// SPIFFE trust domain; must match the controller's `--discovery-trust-domain`.
    ///
    /// Used to verify the controller's SPIFFE URI SAN during bootstrap and to
    /// construct the mTLS `Stream` channel's expected server identity from the
    /// bootstrap-delivered upstream `(endpoint, expected_server_sa)` pointer.
    #[arg(
        long,
        env = "COXSWAIN_DISCOVERY_TRUST_DOMAIN",
        default_value = "cluster.local"
    )]
    pub discovery_trust_domain: String,
}

/// Resolved scope for a `proxy` role invocation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProxyScope {
    /// Serve the shared pool.
    Shared,
    /// Serve a single dedicated Gateway.
    Gateway {
        /// Gateway name.
        name: String,
        /// Gateway namespace.
        namespace: String,
    },
}

impl ProxyRoleArgs {
    /// Returns the resolved [`ProxyScope`] without leaking the underlying
    /// flag pair.
    ///
    /// # Panics
    ///
    /// Panics if `--dedicated` is set but `--gateway-name` or
    /// `--gateway-namespace` is absent. The clap `required_if_eq` constraint
    /// makes this statically unreachable through the CLI; a violation indicates
    /// a bug in the argument definition.
    pub(crate) fn scope(&self) -> ProxyScope {
        if self.shared {
            ProxyScope::Shared
        } else {
            // Invariant: clap's `scope` ArgGroup guarantees exactly one of
            // `shared`/`dedicated` is set, and `required_if_eq` guarantees the
            // identifiers are present whenever `dedicated` is.
            match (&self.gateway_name, &self.gateway_namespace) {
                (Some(name), Some(namespace)) => ProxyScope::Gateway {
                    name: name.clone(),
                    namespace: namespace.clone(),
                },
                _ => panic!(
                    "invariant: --gateway-name and --gateway-namespace required by clap scope group when --dedicated is set"
                ),
            }
        }
    }
}

/// Arguments accepted by the `relay` role (#583).
///
/// A relay is a zero-RBAC discovery cache: an upstream discovery **client** and
/// a downstream discovery **server** in one pod. Exactly one of `--shared`
/// (front the shared pool) or `--namespace <NS>` (front one namespace's
/// dedicated Gateways) selects the upstream subscription scope; clap's `scope`
/// group enforces the choice at parse time.
#[derive(Args, Debug)]
#[command(group(ArgGroup::new("scope").required(true).multiple(false)))]
pub(crate) struct RelayRoleArgs {
    /// Flags shared by every role.
    #[command(flatten)]
    pub common: CommonArgs,
    /// Discovery-client flags for the **upstream** subscription (to the
    /// controller). `--discovery-bootstrap-endpoint` is the sole anchor (#601):
    /// the relay bootstraps its SVID there and learns its own routing upstream
    /// (always the controller — relays never tier) from the bootstrap response.
    #[command(flatten)]
    pub discovery: DiscoveryClientArgs,

    /// Front the shared pool: subscribe `SharedPool` upstream and re-serve it.
    #[arg(long, group = "scope")]
    pub shared: bool,

    /// Front one namespace's dedicated Gateways: subscribe `Namespace{NS}`
    /// upstream and re-serve each Gateway's world downstream. (Requires the
    /// controller's provenance authorizer — provisioned relays land in #584.)
    #[arg(long, value_name = "NS", group = "scope")]
    pub namespace: Option<String>,

    /// Port the relay's **downstream** discovery server binds, for leaf proxies
    /// to subscribe. Mirrors the controller's `--discovery-port`.
    #[arg(long, env = "COXSWAIN_DISCOVERY_PORT", default_value_t = 50051)]
    pub discovery_port: u16,
}

/// Resolved upstream subscription scope for a `relay` role invocation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelayScope {
    /// Front the shared pool (`SharedPool` upstream).
    Shared,
    /// Front one namespace's dedicated Gateways (`Namespace{ns}` upstream).
    Namespace {
        /// The namespace whose dedicated Gateways this relay aggregates.
        namespace: String,
    },
}

impl RelayRoleArgs {
    /// Returns the resolved [`RelayScope`] without leaking the underlying
    /// flag pair.
    ///
    /// # Panics
    ///
    /// Panics if neither `--shared` nor `--namespace` is set — statically
    /// unreachable through the CLI (clap's `scope` ArgGroup is `required`), so a
    /// violation indicates a bug in the argument definition.
    pub(crate) fn scope(&self) -> RelayScope {
        if self.shared {
            RelayScope::Shared
        } else {
            match &self.namespace {
                Some(namespace) => RelayScope::Namespace {
                    namespace: namespace.clone(),
                },
                None => panic!(
                    "invariant: clap scope group requires exactly one of --shared/--namespace"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Sanity-check clap's derive output for inconsistencies.
    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// Bare `coxswain serve` parses with `role = None`; the implicit-dev
    /// fallback is handled in `main.rs`.
    #[test]
    fn bare_serve_omits_role() {
        let cli = Cli::try_parse_from(["coxswain", "serve"]).expect("parses");
        let Commands::Serve(serve) = cli.command;
        assert!(serve.role.is_none());
    }

    /// `coxswain serve controller` parses to `Role::Controller`.
    #[test]
    fn serve_controller_parses() {
        let cli = Cli::try_parse_from(["coxswain", "serve", "controller"]).expect("parses");
        let Commands::Serve(serve) = cli.command;
        assert!(matches!(serve.role, Some(Role::Controller(_))));
    }

    /// `coxswain serve proxy --shared` resolves to `ProxyScope::Shared`.
    #[test]
    fn serve_proxy_shared_parses() {
        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--discovery-bootstrap-endpoint=https://ctrl:50052",
        ])
        .expect("parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected Role::Proxy");
        };
        assert_eq!(args.scope(), ProxyScope::Shared);
        assert_eq!(
            args.discovery.discovery_bootstrap_endpoint,
            "https://ctrl:50052"
        );
    }

    /// `coxswain serve proxy --dedicated --gateway-name=NAME
    /// --gateway-namespace=NS` resolves to `ProxyScope::Gateway`.
    #[test]
    fn serve_proxy_gateway_parses() {
        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--dedicated",
            "--gateway-name=my-gw",
            "--gateway-namespace=tenant-a",
            "--discovery-bootstrap-endpoint=https://ctrl:50052",
        ])
        .expect("parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected Role::Proxy");
        };
        assert_eq!(
            args.scope(),
            ProxyScope::Gateway {
                name: "my-gw".to_string(),
                namespace: "tenant-a".to_string(),
            }
        );
    }

    /// `--discovery-bootstrap-endpoint` is the sole required endpoint anchor for
    /// the proxy role (#601): with `--discovery-endpoint` removed, a proxy that
    /// omits the bootstrap endpoint cannot resolve any upstream.
    #[test]
    fn serve_proxy_requires_bootstrap_endpoint() {
        let err = Cli::try_parse_from(["coxswain", "serve", "proxy", "--shared"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// `serve proxy` with no scope flag fails the ArgGroup `required` rule.
    #[test]
    fn serve_proxy_requires_a_scope() {
        let err = Cli::try_parse_from(["coxswain", "serve", "proxy"]).unwrap_err();
        // clap's MissingRequiredArgument kind when an ArgGroup is unsatisfied.
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// `serve proxy --shared --dedicated` fails the ArgGroup `multiple = false`
    /// rule.
    #[test]
    fn serve_proxy_rejects_both_scopes() {
        let err = Cli::try_parse_from(["coxswain", "serve", "proxy", "--shared", "--dedicated"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// `serve proxy --dedicated` without identifiers fails the `required_if_eq`
    /// rule.
    #[test]
    fn serve_proxy_gateway_requires_identifiers() {
        let err = Cli::try_parse_from(["coxswain", "serve", "proxy", "--dedicated"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        let err = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--dedicated",
            "--gateway-name=my-gw",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// `serve proxy --shared --gateway-name=…` fails the `conflicts_with`
    /// rule (gateway identifiers don't belong on the shared pool).
    #[test]
    fn serve_proxy_shared_rejects_gateway_identifiers() {
        let err = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--gateway-name=my-gw",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// `--proxy-bind-address` does not exist on the `controller` role.
    #[test]
    fn controller_rejects_proxy_bind_address() {
        let err = Cli::try_parse_from([
            "coxswain",
            "serve",
            "controller",
            "--proxy-bind-address=10.0.0.1",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `--status-address` does not exist on the `proxy` role.
    #[test]
    fn proxy_rejects_status_address() {
        let err = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--status-address=example.com",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `serve --help` lists controller and proxy roles.
    #[test]
    fn serve_help_lists_roles() {
        let mut cmd = Cli::command();
        let serve = cmd.find_subcommand_mut("serve").expect("serve exists");
        let help = serve.render_help().to_string();
        assert!(help.contains("controller"), "help should list controller");
        assert!(help.contains("proxy"), "help should list proxy");
        assert!(help.contains("relay"), "help should list relay");
    }

    /// `serve proxy --help` lists both scope flags.
    #[test]
    fn serve_proxy_help_lists_scope_flags() {
        let mut cmd = Cli::command();
        let proxy = cmd
            .find_subcommand_mut("serve")
            .and_then(|s| s.find_subcommand_mut("proxy"))
            .expect("proxy subcommand exists");
        let help = proxy.render_help().to_string();
        assert!(help.contains("--shared"), "proxy help lists --shared");
        assert!(help.contains("--dedicated"), "proxy help lists --dedicated");
        assert!(
            help.contains("--gateway-name"),
            "proxy help lists --gateway-name"
        );
    }

    /// `--management-bind-address` defaults to `0.0.0.0` when neither the CLI
    /// flag nor the env var are set.
    #[test]
    fn management_bind_address_defaults_to_unspecified_v4() {
        // Set env vars to empty to avoid bleed-through from the test runner.
        let cli =
            Cli::try_parse_from(["coxswain", "serve", "controller"]).expect("controller parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Controller(controller)) = serve.role else {
            panic!("expected controller role");
        };
        assert_eq!(
            controller.common.management_bind_address,
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
    }

    /// `--access-log` defaults to `true` and `--access-log-path-mode` to `full`.
    #[test]
    fn access_log_defaults() {
        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--discovery-bootstrap-endpoint=https://ctrl:50052",
        ])
        .expect("proxy parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected proxy role");
        };
        assert!(args.proxy.access_log, "access_log defaults to true");
        assert_eq!(
            args.proxy.access_log_path_mode,
            AccessLogPathMode::Full,
            "access_log_path_mode defaults to Full"
        );
    }

    /// `--access-log false` and all three path mode values parse correctly.
    #[test]
    fn access_log_flags_parse() {
        let parse = |extra: &[&str]| {
            let mut args = vec![
                "coxswain",
                "serve",
                "proxy",
                "--shared",
                "--discovery-bootstrap-endpoint=https://ctrl:50052",
            ];
            args.extend_from_slice(extra);
            Cli::try_parse_from(args).expect("parses")
        };

        // Disabled access log
        let cli = parse(&["--access-log=false"]);
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected proxy role");
        };
        assert!(!args.proxy.access_log);

        // Pattern mode
        let cli = parse(&["--access-log-path-mode=pattern"]);
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected proxy role");
        };
        assert_eq!(args.proxy.access_log_path_mode, AccessLogPathMode::Pattern);

        // None mode
        let cli = parse(&["--access-log-path-mode=none"]);
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected proxy role");
        };
        assert_eq!(args.proxy.access_log_path_mode, AccessLogPathMode::None);
    }

    /// `--access-log` and `--access-log-path-mode` appear in `proxy --help`.
    #[test]
    fn access_log_flags_in_proxy_help() {
        let mut cmd = Cli::command();
        let proxy = cmd
            .find_subcommand_mut("serve")
            .and_then(|s| s.find_subcommand_mut("proxy"))
            .expect("proxy subcommand exists");
        let help = proxy.render_help().to_string();
        assert!(
            help.contains("--access-log"),
            "proxy help lists --access-log"
        );
        assert!(
            help.contains("--access-log-path-mode"),
            "proxy help lists --access-log-path-mode"
        );
    }

    /// `--proxy-upstream-keepalive-pool-size` defaults to 128 and parses a
    /// custom value correctly on `serve proxy --shared`.
    #[test]
    fn proxy_upstream_keepalive_pool_size_parses() {
        // Default
        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--discovery-bootstrap-endpoint=https://ctrl:50052",
        ])
        .expect("parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected Role::Proxy");
        };
        assert_eq!(args.proxy.proxy_upstream_keepalive_pool_size, 128);

        // Explicit value
        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--discovery-bootstrap-endpoint=https://ctrl:50052",
            "--proxy-upstream-keepalive-pool-size=256",
        ])
        .expect("parses with explicit value");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected Role::Proxy");
        };
        assert_eq!(args.proxy.proxy_upstream_keepalive_pool_size, 256);
    }

    /// `--discovery-port` defaults to 50051 on the `controller` role.
    #[test]
    fn discovery_port_defaults_to_50051() {
        let cli =
            Cli::try_parse_from(["coxswain", "serve", "controller"]).expect("controller parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Controller(args)) = serve.role else {
            panic!("expected controller role");
        };
        assert_eq!(args.controller.discovery_port, 50051);
    }

    /// `--discovery-port` accepts a custom port on the `controller` role.
    #[test]
    fn discovery_port_accepts_custom_port() {
        let cli = Cli::try_parse_from(["coxswain", "serve", "controller", "--discovery-port=9090"])
            .expect("controller parses with custom discovery port");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Controller(args)) = serve.role else {
            panic!("expected controller role");
        };
        assert_eq!(args.controller.discovery_port, 9090);
    }

    /// `--discovery-port` does not exist on the `proxy` role.
    #[test]
    fn proxy_rejects_discovery_port() {
        let err = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--discovery-port=50051",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `--reconcile-debounce-min`/`-max` default to 20ms/500ms on the
    /// `controller` role.
    #[test]
    fn reconcile_debounce_defaults() {
        let cli =
            Cli::try_parse_from(["coxswain", "serve", "controller"]).expect("controller parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Controller(args)) = serve.role else {
            panic!("expected controller role");
        };
        assert_eq!(
            args.controller.reconcile_debounce_min,
            Duration::from_millis(20)
        );
        assert_eq!(
            args.controller.reconcile_debounce_max,
            Duration::from_millis(500)
        );
    }

    /// `--reconcile-debounce-min`/`-max` accept custom human-readable durations.
    #[test]
    fn reconcile_debounce_accepts_custom_values() {
        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "controller",
            "--reconcile-debounce-min=10ms",
            "--reconcile-debounce-max=1s",
        ])
        .expect("controller parses with custom debounce bounds");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Controller(args)) = serve.role else {
            panic!("expected controller role");
        };
        assert_eq!(
            args.controller.reconcile_debounce_min,
            Duration::from_millis(10)
        );
        assert_eq!(
            args.controller.reconcile_debounce_max,
            Duration::from_secs(1)
        );
    }

    /// `--reconcile-debounce-min`/`-max` do not exist on the `proxy` role.
    #[test]
    fn proxy_rejects_reconcile_debounce_flags() {
        let err = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--reconcile-debounce-min=10ms",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// Both disable flags default to `false` (surfaces enabled) when absent.
    #[test]
    fn disable_surface_flags_default_false() {
        let cli =
            Cli::try_parse_from(["coxswain", "serve", "controller"]).expect("controller parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Controller(args)) = serve.role else {
            panic!("expected controller role");
        };
        assert!(
            !args.common.disable_gateway_api,
            "--disable-gateway-api defaults to false (gateway-api enabled)"
        );
        assert!(
            !args.common.disable_ingress,
            "--disable-ingress defaults to false (ingress enabled)"
        );
    }

    /// `--disable-gateway-api` and `--disable-ingress` set their bools to `true`.
    #[test]
    fn disable_surface_flags_parse() {
        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "controller",
            "--disable-gateway-api",
            "--disable-ingress",
        ])
        .expect("parses with disable flags");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Controller(args)) = serve.role else {
            panic!("expected controller role");
        };
        assert!(
            args.common.disable_gateway_api,
            "--disable-gateway-api must be true when flag is set"
        );
        assert!(
            args.common.disable_ingress,
            "--disable-ingress must be true when flag is set"
        );
    }
}
