//! Pingora-based reverse proxy for Coxswain.
//!
//! Exports the [`Proxy`] Pingora service, the lock-free [`RoutingEngine`], the
//! SNI certificate selector [`SniCertSelector`], and the PROXY-protocol acceptor
//! [`ProxyAcceptor`].

pub(crate) mod accept;
pub(crate) mod filter;
mod proxy;
mod tls;

#[cfg(test)]
mod tests;

pub use accept::{
    AcceptorBuildError, ListenerProtocol, ListenerSpec, ProxyAcceptor, TrustedSources,
};
pub use proxy::{Proxy, RoutingEngine};
pub use tls::SniCertSelector;
