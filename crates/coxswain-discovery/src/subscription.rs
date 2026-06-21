//! Subscription scope for a discovery stream.

/// The slice of the routing world a discovery client subscribes to.
///
/// Matches the `Scope` message in `discovery.proto`; the two must stay
/// in sync. Epic design decision #5 in #238 defines the recursive
/// "discovery node" model this enum supports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// The shared proxy pool's full routing world (all namespaces).
    SharedPool,
    /// A single Gateway's routing world (one namespace + name pair).
    Gateway {
        /// Gateway resource name.
        name: String,
        /// Namespace the Gateway belongs to.
        namespace: String,
    },
}
