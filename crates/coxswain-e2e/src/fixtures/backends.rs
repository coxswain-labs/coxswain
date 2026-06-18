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

/// TLS echo server exposing TWO named Service ports (`https-1`/443 and `https-2`/8443)
/// — both targeting the same container — used for BackendTLSPolicy section-name routing tests.
/// Requires `TLS_SERVER_CERT_B64`, `TLS_SERVER_KEY_B64` substitutions.
pub const ECHO_TLS_DUAL_PORT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/echo_tls_dual_port.yaml"
);

/// Auth-stub deployment pair used by ext_authz e2e tests (#24).
///
/// Creates two Services in the test namespace:
///   - `auth-allow` (port 4000) — always returns 200 + `X-Auth-User: testuser`.
///   - `auth-deny` (port 4001) — always returns 403 + `Set-Cookie: session=test123`.
///
/// Both use a busybox nc loop (one connection per invocation).
pub const AUTH_STUB: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/auth_stub.yaml"
);
