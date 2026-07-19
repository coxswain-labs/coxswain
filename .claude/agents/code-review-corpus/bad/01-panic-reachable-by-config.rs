//! Listener binding.
use std::net::SocketAddr;

/// Resolve the listener address from operator-supplied config.
pub(crate) fn listener_addr(cfg: &ProxyConfig) -> SocketAddr {
    // The operator sets `bind_addr` from a CLI flag / Helm value.
    cfg.bind_addr
        .parse()
        .unwrap_or_else(|e| panic!("invariant: bind address must be valid: {e}"))
}
