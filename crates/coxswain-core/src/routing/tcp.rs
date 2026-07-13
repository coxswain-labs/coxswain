//! Port-keyed TCP routing table for `TCPRoute` / GEP-1901.
//!
//! TCPRoute has no hostname dimension: the Standard channel allows exactly one
//! rule with no matches, so a bound backend is selected purely by listener
//! port. This table is deliberately simpler than [`TlsPassthroughTable`] —
//! there is no SNI router, no wildcard/exact/catchall layer, just
//! `port → BackendGroup`.
//!
//! [`TlsPassthroughTable`]: crate::routing::TlsPassthroughTable

use crate::routing::BackendGroup;
use crate::shared::Shared;
use std::collections::HashMap;
use std::sync::Arc;

/// Atomically-swappable handle to the active [`TcpRouteTable`].
pub type SharedTcpRouteTable = Shared<TcpRouteTable>;

/// Immutable routing table mapping `port → BackendGroup` for `TCPRoute`.
///
/// Built once per reconcile cycle and published via [`SharedTcpRouteTable`].
/// The proxy loads it with a single atomic pointer read on each accepted TCP
/// connection — no SNI peek is required before the lookup.
#[non_exhaustive]
#[derive(Default, Debug)]
pub struct TcpRouteTable {
    by_port: HashMap<u16, Arc<BackendGroup>>,
}

impl TcpRouteTable {
    /// Return the backend bound to `port`, if any.
    #[must_use]
    pub fn port(&self, port: u16) -> Option<&Arc<BackendGroup>> {
        self.by_port.get(&port)
    }

    /// Number of ports with a registered route.
    #[must_use]
    pub fn port_count(&self) -> usize {
        self.by_port.len()
    }

    /// Iterate over `(port, backend)` pairs in arbitrary order.
    pub fn ports_iter(&self) -> impl Iterator<Item = (u16, &Arc<BackendGroup>)> {
        self.by_port.iter().map(|(p, b)| (*p, b))
    }
}

/// Builder that compiles a [`TcpRouteTable`].
///
/// Typical usage: create one builder per reconcile cycle, call
/// [`Self::add_route`] for every bound `TCPRoute`, then call [`Self::build`].
#[non_exhaustive]
#[derive(Default, Debug)]
pub struct TcpRouteTableBuilder {
    by_port: HashMap<u16, Arc<BackendGroup>>,
}

impl TcpRouteTableBuilder {
    /// Construct an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `backend` as the target for `port`.
    ///
    /// The last `add_route` call for a duplicate port wins (last-writer-wins;
    /// reconcile sorts routes by precedence before calling this, so the
    /// winner is deterministic).
    #[must_use]
    pub fn add_route(mut self, port: u16, backend: Arc<BackendGroup>) -> Self {
        self.by_port.insert(port, backend);
        self
    }

    /// Compile into an immutable [`TcpRouteTable`].
    #[must_use]
    pub fn build(self) -> TcpRouteTable {
        TcpRouteTable {
            by_port: self.by_port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> Arc<BackendGroup> {
        Arc::new(BackendGroup::new("test".into(), vec![]))
    }

    #[test]
    fn registered_port_resolves_to_backend() {
        let bg = backend();
        let t = TcpRouteTableBuilder::new()
            .add_route(9000, Arc::clone(&bg))
            .build();
        assert!(Arc::ptr_eq(t.port(9000).unwrap(), &bg));
    }

    #[test]
    fn unknown_port_returns_none() {
        let t = TcpRouteTableBuilder::new()
            .add_route(9000, backend())
            .build();
        assert!(t.port(9001).is_none());
    }

    #[test]
    fn duplicate_port_last_writer_wins() {
        let bg_first = backend();
        let bg_second = backend();
        let t = TcpRouteTableBuilder::new()
            .add_route(9000, Arc::clone(&bg_first))
            .add_route(9000, Arc::clone(&bg_second))
            .build();
        assert!(Arc::ptr_eq(t.port(9000).unwrap(), &bg_second));
    }

    #[test]
    fn port_count_reflects_distinct_ports() {
        let t = TcpRouteTableBuilder::new()
            .add_route(9000, backend())
            .add_route(9001, backend())
            .build();
        assert_eq!(t.port_count(), 2);
    }

    #[test]
    fn ports_iter_yields_all_entries() {
        let t = TcpRouteTableBuilder::new()
            .add_route(9000, backend())
            .add_route(9001, backend())
            .build();
        let mut ports: Vec<u16> = t.ports_iter().map(|(p, _)| p).collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![9000, 9001]);
    }
}
