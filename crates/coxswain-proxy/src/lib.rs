//! Pingora-based reverse proxy for Coxswain.
//!
//! The data plane is split into two `ProxyHttp` implementations sharing the
//! per-rule machinery: [`IngressProxy`] serves traffic for Kubernetes
//! `Ingress` resources, and [`GatewayProxy`] serves traffic for Gateway-API
//! resources. The [`RoutingSource`] trait (defined in `coxswain-core`)
//! abstracts over where routing snapshots come from — today's
//! `KubernetesSource` (dev role) or `DiscoveryClient` (proxy role).
//!
//! The crate is layered: `edge` accepts and terminates connections, `routing`
//! resolves a request to a backend, `filters` apply declarative
//! Gateway-API/Ingress `FilterAction`s, `policy` enforces stateful per-route
//! subsystems (auth, rate-limit, circuit-breaking, …), and the root `hooks`
//! module wires them into the Pingora request lifecycle shared by both proxies.
//! `ctx`, `config`, and `metrics` are cross-cutting and live at the root.

pub mod config;
mod ctx;
pub(crate) mod edge;
pub(crate) mod filters;
mod gateway;
mod hooks;
mod ingress;
pub(crate) mod metrics;
pub(crate) mod policy;
mod retry;
pub(crate) mod routing;

pub use config::{AccessLogPathMode, SharedProxyConfig};
pub use ctx::{ProxyCtx, ResolvedRoute};
pub use edge::accept::{
    AcceptorBuildError, ListenerProtocol, ListenerSpec, PassthroughConfig, ProxyAcceptor,
};
pub use edge::tls::SniCertSelector;
pub use edge::upstream_ca::UpstreamCaCache;
pub use gateway::{GatewayEngine, GatewayProxy};
pub use ingress::{IngressEngine, IngressProxy};
pub use policy::auth::JwksKeyCache;
pub use policy::grpc_channel::GrpcAuthChannelCache;
pub use policy::rate_limit::RateLimiterRegistry;
pub use routing::engine::RoutingEngine;
pub use routing::source::{KubernetesSource, RoutingSource};
