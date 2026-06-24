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

/// Mixed-latency backend pair for load-balance algorithm tests (#275).
///
/// Creates:
///   - `lb-fast` Deployment (echo-basic, port 3000) — immediate JSON response with `POD_NAME`.
///   - `lb-slow` Deployment (go-httpbin, port 3000) — serves `/delay/<N>` for configurable latency.
///   - `lb-pool` Service (port 3000) selecting both Deployments via `app: lb-pool`.
///
/// Tests assert that `least_conn` routes more requests to `lb-fast` by observing
/// which pod name appears in responses (`lb-fast-*` prefix vs. absent for go-httpbin).
pub const LB_MIXED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/lb_mixed.yaml"
);

/// Two-replica echo backend for `ip_hash` and fallback load-balance tests (#275).
///
/// Same image as [`ECHO`] but with `replicas: 2` so the Ingress has two endpoints
/// to distribute across (necessary to observe consistent-hash pinning and round-robin spread).
pub const ECHO_TWO_REPLICAS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/echo_two_replicas.yaml"
);

/// Two-replica echo backend for endpoint-drain tests (#281).
///
/// Each pod carries a `preStop: sleep 20` hook and
/// `terminationGracePeriodSeconds: 30` so a deleted pod stays
/// `terminating+serving` for ~20 seconds — a deterministic window to verify
/// that new requests are NOT routed to the terminating endpoint.
pub const DRAIN_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/drain_echo.yaml"
);

/// gRPC echo backend for GRPCRoute e2e tests (#33).
///
/// Runs `echo-basic` in `GRPC_ECHO_SERVER=1` mode, serving the
/// `gateway_api_conformance.echo_basic.grpcecho.GrpcEcho` service on port 50051
/// over h2c. Service declares `appProtocol: kubernetes.io/h2c`.
pub const GRPC_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/grpc_echo.yaml"
);

/// Standalone go-httpbin backend for circuit-breaker tests (#282).
///
/// Exposes `/status/:code` so tests can drive configurable upstream HTTP
/// status codes — `/status/500` to record errors and trip the circuit
/// breaker, `/status/200` to let the half-open probe succeed and close it.
/// A single `go-httpbin` Deployment + `go-httpbin` Service, port 3000.
pub const GO_HTTPBIN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/go_httpbin.yaml"
);
