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
pub(crate) mod common;
mod gateway;
mod ingress;
mod source;
mod tls;
pub mod upstream_ca;

#[cfg(test)]
mod tests;

pub use accept::{
    AcceptorBuildError, ListenerProtocol, ListenerSpec, ProxyAcceptor, TrustedSources,
};
pub use common::ctx::{ProxyCtx, ResolvedRoute};
pub use common::engine::RoutingEngine;
pub use gateway::{GatewayEngine, GatewayProxy};
pub use ingress::{IngressEngine, IngressProxy};
pub use source::{KubernetesSource, RoutingSource};
pub use tls::SniCertSelector;
pub use upstream_ca::UpstreamCaCache;
