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
//!
//! Bare `coxswain serve` (no role) parses with `role = None`; the dispatch in
//! `lib.rs` rejects it, since production must pick a role explicitly.

use coxswain_core::crd::ServiceType;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use coxswain_controller::IngressDefaultBackend;
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

    /// Kubernetes namespace to watch. Omit for cluster-wide scope.
    ///
    /// Both the controller and proxy pods watch the same namespace scope so
    /// they agree on which resources count. Mirror this value across both
    /// pods when installing manually; Helm renders it identically by default.
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
}

/// Flags specific to roles that bind Pingora proxy listeners (`proxy`, `dev`).
#[derive(Args, Debug)]
pub(crate) struct ProxyArgs {
    /// Worker threads per proxy service.
    ///
    /// Threads are not shared across services. Set to the available CPU core count for maximum throughput.
    #[arg(long, env = "COXSWAIN_PROXY_THREADS", default_value_t = 2)]
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

    /// Enable HAProxy PROXY protocol v1/v2 on the proxy listeners.
    ///
    /// When set, every accepted connection MUST carry a valid PROXY header.
    /// Connections from sources not listed in `--proxy-trusted-sources` are
    /// dropped immediately. Connections that omit or malform the header are
    /// also dropped (strict mode).
    ///
    /// The real client address is propagated upstream via the RFC 7239
    /// `Forwarded` header.
    #[arg(
        long,
        env = "COXSWAIN_PROXY_ACCEPT_PROXY_PROTOCOL",
        default_value_t = false
    )]
    pub proxy_accept_proxy_protocol: bool,

    /// Comma-separated list of CIDR ranges that are permitted to send PROXY headers.
    ///
    /// Only meaningful when `--proxy-accept-proxy-protocol` is set. Connections
    /// from addresses outside this list are rejected at the TCP level.
    ///
    /// Example: `10.0.0.0/8,172.16.0.0/12,127.0.0.1/32`
    #[arg(long, env = "COXSWAIN_PROXY_TRUSTED_SOURCES", value_delimiter = ',')]
    pub proxy_trusted_sources: Vec<IpNet>,

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

    /// Maximum total size of the in-memory RFC 7234 response cache.
    ///
    /// Accepts a bare byte count or a binary unit suffix `k`/`m`/`g` (e.g.
    /// `100m` = 100 MiB, the default). When the cache exceeds this size,
    /// least-recently-used entries are evicted. `0` disables response caching
    /// entirely. Caching is opt-in per route via the
    /// `ingress.coxswain-labs.dev/cache-enabled` annotation; this flag only
    /// bounds the shared store those routes share.
    #[arg(
        long,
        env = "COXSWAIN_CACHE_MAX_SIZE",
        default_value = "100m",
        value_parser = parse_cache_size,
    )]
    pub cache_max_size: usize,
}

/// Parse a `--cache-max-size` value: a bare byte count or a binary-unit suffix
/// (`k`/`m`/`g`, case-insensitive). Mirrors the `max-body-size` annotation's
/// units but errors (rather than warning) on bad input, as befits a CLI flag.
///
/// # Errors
///
/// Returns a human-readable message when the value is not a non-negative integer
/// optionally followed by a single `k`/`m`/`g` suffix, or when it overflows `usize`.
fn parse_cache_size(s: &str) -> Result<usize, String> {
    let t = s.trim();
    let (digits, mult): (&str, usize) = match t.as_bytes().last() {
        Some(b'k' | b'K') => (&t[..t.len() - 1], 1024),
        Some(b'm' | b'M') => (&t[..t.len() - 1], 1024 * 1024),
        Some(b'g' | b'G') => (&t[..t.len() - 1], 1024 * 1024 * 1024),
        _ => (t, 1),
    };
    let n: usize = digits.trim().parse().map_err(|_| {
        format!("invalid cache size {s:?}: expected an integer with optional k/m/g suffix")
    })?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("cache size {s:?} overflows usize"))
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

    /// Comma-separated list of controller discovery endpoints.
    ///
    /// Each entry is an `http://host:port` (plaintext) or `https://host:port`
    /// (mTLS) URI for a controller replica's discovery gRPC server. Providing
    /// more than one endpoint enables high-availability: the client load-balances
    /// RPCs across all listed replicas. Must not be empty.
    ///
    /// In production the controller operator renders this from the conventional
    /// `coxswain-controller-discovery.<namespace>.svc:<discovery-port>` DNS
    /// name; the value is inert until the discovery Service exists (T10).
    ///
    /// Example: `http://coxswain-controller-discovery.coxswain-system.svc:50051`
    #[arg(
        long,
        env = "COXSWAIN_DISCOVERY_ENDPOINT",
        value_delimiter = ',',
        required = true
    )]
    pub discovery_endpoint: Vec<String>,

    /// Bootstrap endpoint for obtaining an SVID from the controller.
    ///
    /// Must be an `https://` URI pointing to the controller's bootstrap listener
    /// (port 50052 by default).  The proxy verifies the controller's SPIFFE cert
    /// against the CA bundle from `--discovery-ca-bundle-path` before sending
    /// its SA token.
    ///
    /// Example: `https://coxswain-controller-discovery.coxswain-system.svc:50052`
    #[arg(long, env = "COXSWAIN_DISCOVERY_BOOTSTRAP_ENDPOINT")]
    pub discovery_bootstrap_endpoint: Option<String>,

    /// Path to the projected ServiceAccount token file.
    ///
    /// The token is sent to the bootstrap listener so the controller can validate
    /// the proxy's identity via the Kubernetes TokenReview API.
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
    /// The proxy uses this to verify the controller's TLS certificate during
    /// bootstrap and to build the mTLS channel for `Stream`.
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
    /// Used to verify the controller's SPIFFE URI SAN during bootstrap and
    /// to construct the mTLS channel's expected server identity.
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
            "--discovery-endpoint=http://ctrl:50051",
        ])
        .expect("parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected Role::Proxy");
        };
        assert_eq!(args.scope(), ProxyScope::Shared);
        assert_eq!(args.discovery_endpoint, vec!["http://ctrl:50051"]);
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
            "--discovery-endpoint=http://ctrl:50051",
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

    /// `--discovery-endpoint` is required for the proxy role.
    #[test]
    fn serve_proxy_requires_discovery_endpoint() {
        let err = Cli::try_parse_from(["coxswain", "serve", "proxy", "--shared"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// `--discovery-endpoint` accepts a comma-separated list of multiple endpoints.
    #[test]
    fn discovery_endpoint_parses_multi_value() {
        let cli = Cli::try_parse_from([
            "coxswain",
            "serve",
            "proxy",
            "--shared",
            "--discovery-endpoint=http://ctrl-1:50051,http://ctrl-2:50051",
        ])
        .expect("parses");
        let Commands::Serve(serve) = cli.command;
        let Some(Role::Proxy(args)) = serve.role else {
            panic!("expected Role::Proxy");
        };
        assert_eq!(
            args.discovery_endpoint,
            vec!["http://ctrl-1:50051", "http://ctrl-2:50051"]
        );
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
            "--discovery-endpoint=http://ctrl:50051",
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
                "--discovery-endpoint=http://ctrl:50051",
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
            "--discovery-endpoint=http://ctrl:50051",
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
            "--discovery-endpoint=http://ctrl:50051",
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
}
