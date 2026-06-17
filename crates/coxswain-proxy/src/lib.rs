//! Pingora-based reverse proxy for Coxswain.
//!
//! The data plane is split into two `ProxyHttp` implementations sharing the
//! per-rule machinery: [`IngressProxy`] serves traffic for Kubernetes
//! `Ingress` resources, and [`GatewayProxy`] serves traffic for Gateway-API
//! resources. The [`RoutingSource`] trait defines the boundary between the
//! proxies and whatever delivers their routing snapshots (today: the
//! in-process Kubernetes reflectors via [`KubernetesSource`]; tomorrow: an
//! xDS client).

pub(crate) mod accept;
pub(crate) mod auth;
pub(crate) mod common;
pub mod config;
mod gateway;
mod ingress;
pub(crate) mod metrics;
pub mod rate_limit;
pub mod reflector;
mod source;
mod tls;
pub mod upstream_ca;

pub use accept::{
    AcceptorBuildError, ListenerProtocol, ListenerSpec, ProxyAcceptor, TrustedSources,
};
pub use common::ctx::{ProxyCtx, ResolvedRoute};
pub use common::engine::RoutingEngine;
pub use config::{AccessLogPathMode, SharedProxyConfig};
pub use gateway::{GatewayEngine, GatewayProxy};
pub use ingress::{IngressEngine, IngressProxy};
pub use rate_limit::RateLimiterRegistry;
pub use reflector::{
    DedicatedProxyReflector, DedicatedProxyReflectorConfig, ProxyReflector, ProxyReflectorConfig,
    spawn_dedicated_routing_table_builder, spawn_routing_table_builder,
};
pub use source::{KubernetesSource, RoutingSource};
pub use tls::SniCertSelector;
pub use upstream_ca::UpstreamCaCache;
