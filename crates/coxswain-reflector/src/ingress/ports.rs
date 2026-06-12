//! Ingress data-plane port configuration carried alongside the routing table.

/// Ports on which Ingress routes are served.
///
/// Both fields are optional; when both are `None` no listener is configured
/// and the Ingress is skipped with a warning.
// No dedicated tests/ports.rs: trivial struct fully covered by tests/reconcile.rs.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct IngressPorts {
    /// Port for plain HTTP Ingress routes, if configured.
    pub http: Option<u16>,
    /// Port for HTTPS Ingress routes, if configured.
    pub https: Option<u16>,
}

impl IngressPorts {
    /// Construct from optional HTTP and HTTPS port numbers.
    pub fn new(http: Option<u16>, https: Option<u16>) -> Self {
        Self { http, https }
    }
}
