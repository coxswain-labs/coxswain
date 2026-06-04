use anyhow::Context as _;
use std::path::Path;
use tokio::io::AsyncWriteExt as _;

pub const BACKENDS_ECHO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/backends/echo.yaml");

pub const BACKENDS_WEBSOCKET_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/websocket_echo.yaml"
);

pub const BACKENDS_SLOW_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/slow_echo.yaml"
);

pub const GATEWAY_API_PATH_MATCHING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/path_matching.yaml"
);

pub const GATEWAY_API_HOST_POOL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/host_pool.yaml"
);

pub const GATEWAY_API_WILDCARD_HOST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/wildcard_host.yaml"
);

pub const GATEWAY_API_CROSS_NAMESPACE_ROUTE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/cross_namespace_route.yaml"
);

pub const GATEWAY_API_CROSS_NAMESPACE_TENANT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/cross_namespace_tenant.yaml"
);

pub const GATEWAY_API_HEADER_MATCHING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/header_matching.yaml"
);

pub const GATEWAY_API_METHOD_MATCHING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/method_matching.yaml"
);

pub const GATEWAY_API_QUERY_PARAM_MATCHING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/query_param_matching.yaml"
);

pub const GATEWAY_API_COMBINED_MATCHING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/combined_matching.yaml"
);

pub const GATEWAY_API_TLS_TERMINATION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/tls_termination.yaml"
);

pub const GATEWAY_API_TLS_GATEWAY_NO_CERTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/tls_gateway_no_certs.yaml"
);

pub const GATEWAY_API_TLS_CROSS_NAMESPACE_GW: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/tls_cross_namespace_gw.yaml"
);

pub const GATEWAY_API_TLS_CROSS_NAMESPACE_CERTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/tls_cross_namespace_certs.yaml"
);

pub const INGRESS_PATH_MATCHING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/ingress/path_matching.yaml"
);

pub const INGRESS_DEFAULT_BACKEND: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/ingress/default_backend.yaml"
);

pub const INGRESS_TLS_TERMINATION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/ingress/tls_termination.yaml"
);

pub const INGRESS_CERT_MANAGER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/ingress/cert_manager.yaml"
);

pub const INGRESS_WILDCARD_HOST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/ingress/wildcard_host.yaml"
);

pub const INGRESS_NAMED_PORT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/ingress/named_port.yaml"
);

pub const GATEWAY_API_CERT_MANAGER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/cert_manager.yaml"
);

pub const GATEWAY_API_WEBSOCKET: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/websocket.yaml"
);

pub const GATEWAY_API_FILTERS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/filters.yaml"
);

pub const GATEWAY_API_TIMEOUTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/timeouts.yaml"
);

pub const GATEWAY_API_TLS_REDIRECT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/tls_redirect.yaml"
);

pub const GATEWAY_API_WEIGHTED_SPLIT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/weighted_split.yaml"
);

pub const GATEWAY_API_SERVING_DRAIN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/gateway_api/serving_drain.yaml"
);

/// Apply a fixture YAML to `namespace`.
///
/// Supports template substitutions: `TESTNS` is always replaced with `namespace`.
/// Pass additional `vars` as `[("KEY", "value")]` pairs for cross-namespace fixtures.
pub async fn apply_fixture(
    path: impl AsRef<Path>,
    namespace: &str,
    vars: &[(&str, &str)],
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let mut content =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;

    // Apply named var overrides first so callers can override TESTNS itself.
    for (key, val) in vars {
        content = content.replace(key, val);
    }
    // Substitute any remaining TESTNS with the target namespace.
    content = content.replace("TESTNS", namespace);

    let mut child = tokio::process::Command::new("kubectl")
        .args(["apply", "-n", namespace, "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("kubectl apply")?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(content.as_bytes())
            .await
            .context("write to kubectl stdin")?;
    }
    // Close stdin so kubectl knows the input is complete.
    drop(child.stdin.take());

    let status = child.wait().await.context("kubectl wait")?;
    anyhow::ensure!(
        status.success(),
        "kubectl apply failed for {}",
        path.display()
    );
    Ok(())
}
