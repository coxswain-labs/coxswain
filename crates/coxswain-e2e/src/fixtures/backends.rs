//! YAML fixture paths for echo backend deployments used across all e2e tests.

/// Echo server deployment (HTTP+JSON, echo-a/b/c variants).
pub const ECHO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/backends/echo.yaml");

/// WebSocket echo server deployment.
pub const WEBSOCKET_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/websocket_echo.yaml"
);

/// Slow-response echo server deployment (used for timeout tests).
pub const SLOW_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/slow_echo.yaml"
);

/// HTTP/2 cleartext echo server deployment (used for h2c backend protocol tests).
pub const H2C_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/h2c_echo.yaml"
);

/// TLS echo server deployment (HTTPS on port 8443, used for BackendTLSPolicy tests).
/// Requires `TLS_SERVER_CERT_B64`, `TLS_SERVER_KEY_B64` substitutions.
pub const ECHO_TLS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/echo_tls.yaml"
);
