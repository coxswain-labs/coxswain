//! Command-line argument parsing for the coxswain binary.
//!
//! The binary is invoked as `coxswain serve <role>`, where each role identifies
//! a pod's purpose in the controller/proxy split topology. Roles flatten only
//! the argument groups they semantically need so clap rejects flag/role
//! mismatches at parse time, before any runtime code runs.
//!
//! Roles (issue #202 — Step 3 of the architecture plan):
//!
//! - `controller`: reconciler and status writer pod. Reads K8s, writes status.
//!   Not yet implemented — exits with "not yet implemented".
//! - `proxy --shared`: read-only data plane for Ingress + non-dedicated Gateways.
//!   Not yet implemented.
//! - `proxy --dedicated --gateway-name=NAME --gateway-namespace=NS`: read-only
//!   data plane scoped to a single Gateway. Not yet implemented.
//! - `dev` (hidden from `--help`): monolithic single-process pod for local
//!   development. Equivalent to today's behaviour.
//!
//! Bare `coxswain serve` (no role) currently falls back to `dev` with a
//! deprecation warning so the existing Helm chart and Dockerfile keep working
//! through v0.2.0; Step 5 removes the fallback once the chart sets the role
//! explicitly.

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
///
/// The role is optional: bare `coxswain serve` falls back to [`Role::Dev`]
/// with a deprecation warning so today's Helm chart keeps working. Once the
/// chart sets the role explicitly (Step 5), the implicit fallback is removed.
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
    /// Hidden: monolithic single-process pod for local development. Production
    /// deployments must pick `controller` or `proxy` explicitly.
    #[command(hide = true)]
    Dev(DevRoleArgs),
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
    /// Both `/healthz`/`/readyz` (health) and `/metrics`/`/routes`/`/status`
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

    /// IP address to bind all proxy listeners to.
    ///
    /// Shared by both HTTP and HTTPS listeners; combine with
    /// `--ingress-http-port` and/or `--ingress-https-port` (on `CommonArgs`)
    /// to form the full bind address for each listener. The health and admin
    /// servers bind separately via `--management-bind-address`.
    #[arg(long, env = "COXSWAIN_PROXY_BIND_ADDRESS", default_value = "0.0.0.0")]
    pub proxy_bind_address: IpAddr,

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
}

/// Arguments accepted by the hidden `dev` role.
///
/// Carries every flag the monolithic single-process pod needs: management
/// surface, proxy data plane, and reconciler.
#[derive(Args, Debug)]
pub(crate) struct DevRoleArgs {
    /// Flags shared by every role.
    #[command(flatten)]
    pub common: CommonArgs,
    /// Proxy data-plane flags.
    #[command(flatten)]
    pub proxy: ProxyArgs,
    /// Reconciler + status writer flags.
    #[command(flatten)]
    pub controller: ControllerArgs,
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

    /// Permit cluster-wide HTTPRoute reads — required when the target Gateway
    /// has any listener with `allowedRoutes.namespaces.from: All`.
    ///
    /// Defaults to `false` (precise least-privilege opt-in). When the target
    /// Gateway has such a listener and this flag is `false`, the reconciler
    /// logs a warning today (Step 7); Step 10 will add an `Accepted=false`
    /// listener condition.
    ///
    /// Only meaningful with `--dedicated`; rejected with `--shared`.
    #[arg(
        long,
        env = "COXSWAIN_ALLOW_CLUSTER_WIDE_ROUTE_READ",
        default_value_t = false,
        conflicts_with = "shared"
    )]
    pub allow_cluster_wide_route_read: bool,

    /// Permit cluster-wide Namespace reads — required when the target Gateway
    /// has any listener with `allowedRoutes.namespaces.from: Selector`.
    ///
    /// Defaults to `false`. Same semantics as `--allow-cluster-wide-route-read`
    /// but for the Namespace resource (selector-based attachment uses
    /// `Namespace` labels).
    ///
    /// Only meaningful with `--dedicated`; rejected with `--shared`.
    #[arg(
        long,
        env = "COXSWAIN_ALLOW_CLUSTER_WIDE_NAMESPACE_READ",
        default_value_t = false,
        conflicts_with = "shared"
    )]
    pub allow_cluster_wide_namespace_read: bool,

    /// Comma-separated list of namespaces the dedicated proxy is permitted to
    /// watch backend resources in (Services, EndpointSlices, Secrets,
    /// ConfigMaps, HTTPRoutes, ReferenceGrants, BackendTLSPolicies, Gateways).
    ///
    /// The controller renders this list from the desired-namespace set
    /// computed for the Gateway: the Gateway's own namespace plus every
    /// namespace its HTTPRoutes route backends into (gated by `ReferenceGrant`
    /// for cross-namespace refs). The list mirrors the `RoleBinding`s the
    /// controller has provisioned for this proxy's `ServiceAccount` — every
    /// listed namespace must have a matching binding, or the proxy's watches
    /// hard-fail with a permission denied.
    ///
    /// When the list changes, the controller updates the rendered Deployment
    /// spec and K8s rolls the proxy pod; the proxy itself never re-discovers
    /// the namespace set at runtime.
    ///
    /// Required with `--dedicated`; rejected with `--shared`. Empty list is
    /// rejected (every dedicated proxy must at least watch its Gateway's own
    /// namespace).
    #[arg(
        long,
        env = "COXSWAIN_PROXY_WATCH_NAMESPACES",
        value_delimiter = ',',
        required_if_eq("dedicated", "true"),
        conflicts_with = "shared"
    )]
    pub proxy_watch_namespaces: Vec<String>,
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
        /// Whether the operator opted into cluster-wide HTTPRoute reads.
        allow_cluster_wide_route_read: bool,
        /// Whether the operator opted into cluster-wide Namespace reads.
        allow_cluster_wide_namespace_read: bool,
        /// Namespaces the proxy is permitted to watch backend resources in.
        /// Set by the controller from the Gateway's resolved
        /// desired-namespace set.
        watch_namespaces: Vec<String>,
    },
}

impl ProxyRoleArgs {
    /// Returns the resolved [`ProxyScope`] without leaking the underlying
    /// flag pair.
    pub(crate) fn scope(&self) -> ProxyScope {
        if self.shared {
            ProxyScope::Shared
        } else {
            // Invariant: clap's `scope` ArgGroup guarantees exactly one of
            // `shared`/`dedicated` is set, and `required_if_eq` guarantees the
            // identifiers are present whenever `dedicated` is.
            let name = self.gateway_name.clone().unwrap_or_else(|| {
                panic!(
                    "invariant: --gateway-name required by clap scope group when --dedicated is set"
                )
            });
            let namespace = self.gateway_namespace.clone().unwrap_or_else(|| {
                panic!("invariant: --gateway-namespace required by clap scope group when --dedicated is set")
            });
            ProxyScope::Gateway {
                name,
                namespace,
                allow_cluster_wide_route_read: self.allow_cluster_wide_route_read,
                allow_cluster_wide_namespace_read: self.allow_cluster_wide_namespace_read,
                watch_namespaces: self.proxy_watch_namespaces.clone(),
            }
        }
    }
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
