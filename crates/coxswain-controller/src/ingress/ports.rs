/// Ports on which Ingress routes are served.
///
/// Both fields are optional; when both are `None` no listener is configured
/// and the Ingress is skipped with a warning.
// No dedicated tests/ports.rs: trivial struct fully covered by tests/reconcile.rs.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct IngressPorts {
    pub http: Option<u16>,
    pub https: Option<u16>,
}

impl IngressPorts {
    pub fn new(http: Option<u16>, https: Option<u16>) -> Self {
        Self { http, https }
    }
}
