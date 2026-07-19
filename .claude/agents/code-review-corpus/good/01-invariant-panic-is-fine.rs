//! Route table construction.
impl RoutingTableBuilder {
    /// Finish the table.
    ///
    /// The port map is populated by `for_port` before any caller can reach
    /// `build`, so an absent entry here means this module enqueued a port it
    /// never created — a logic bug in this file, not reachable from config,
    /// peer bytes, or contention.
    pub fn build(mut self) -> RoutingTable {
        debug_assert!(!self.ports.is_empty(), "for_port must run before build");
        RoutingTable { ports: self.ports }
    }
}
