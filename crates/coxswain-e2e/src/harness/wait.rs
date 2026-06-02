use anyhow::Context as _;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::Api;
use std::{net::SocketAddr, time::Duration};
use tokio::time;
use tokio_tungstenite::tungstenite;

/// Poll HTTPS handshakes until the served leaf certificate DER differs from `old_der`.
///
/// Covers the full propagation path: reflector → debounce (500 ms) → rebuild → `ArcSwap` store
/// → SNI callback on next handshake. The 10 s deadline surfaces regressions in any stage.
pub async fn wait_for_tls_cert_rotation(
    tls_addr: SocketAddr,
    host: &str,
    old_der: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    let deadline = time::Instant::now() + timeout;
    loop {
        match crate::harness::http::https_peer_leaf_der(host, "/", tls_addr).await {
            Ok(new_der) if new_der != old_der => return Ok(new_der),
            Ok(_) => tracing::debug!(host, "TLS leaf unchanged, waiting for rotation"),
            Err(e) => tracing::debug!(host, error = %e, "could not read TLS peer cert"),
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for TLS cert rotation on {host}");
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn wait_for_https_route(
    tls_addr: SocketAddr,
    host: &str,
    path: &str,
    timeout: Duration,
) -> anyhow::Result<crate::harness::http::EchoResponse> {
    let deadline = time::Instant::now() + timeout;
    loop {
        match crate::harness::http::https_get(host, path, tls_addr).await {
            Ok((_, Some(body))) => return Ok(body),
            Ok((status, None)) => {
                tracing::debug!(host, path, status, "https route returned non-2xx")
            }
            Err(e) => tracing::debug!(host, path, error = %e, "https route not yet live"),
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for HTTPS route {host}{path} to become live");
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn wait_for_ready(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    let url = format!("http://{addr}/readyz");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build reqwest client")?;
    let deadline = time::Instant::now() + timeout;
    loop {
        match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => return Ok(()),
            _ => {}
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for readyz at {addr}");
        }
        time::sleep(Duration::from_millis(200)).await;
    }
}

pub async fn wait_for_httproute_programmed(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<HTTPRoute> = Api::namespaced(client.clone(), namespace);
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Ok(route) = api.get(name).await
            && route_has_condition(&route, "Programmed")
        {
            return Ok(());
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for HTTPRoute {namespace}/{name} to be Programmed");
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn wait_for_gateway_programmed(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Ok(gw) = api.get(name).await
            && gateway_has_condition(&gw, "Accepted")
            && gateway_has_condition(&gw, "Programmed")
        {
            return Ok(());
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for Gateway {namespace}/{name} to be Accepted and Programmed"
            );
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// Poll until a `kubernetes.io/tls` Secret with non-empty `tls.crt` data exists.
/// Used by cert-manager tests to wait for certificate issuance before testing TLS.
pub async fn wait_for_tls_secret(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Ok(secret) = api.get(name).await {
            let is_tls = secret.type_.as_deref() == Some("kubernetes.io/tls");
            let has_cert = secret
                .data
                .as_ref()
                .and_then(|d| d.get("tls.crt"))
                .is_some_and(|b| !b.0.is_empty());
            if is_tls && has_cert {
                return Ok(());
            }
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for kubernetes.io/tls Secret {namespace}/{name} to be populated"
            );
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// Wait for the named Deployments in `namespace` to become Available.
/// Covers the image-pull + pod-start time on a fresh cluster.
pub async fn wait_for_backends(namespace: &str) -> anyhow::Result<()> {
    wait_for_deployments(namespace, &["echo-a", "echo-b", "echo-c"]).await
}

pub async fn wait_for_deployments(namespace: &str, names: &[&str]) -> anyhow::Result<()> {
    let deployments: Vec<String> = names.iter().map(|n| format!("deployment/{n}")).collect();
    let mut args = vec!["wait", "--for=condition=available", "--timeout=300s"];
    for d in &deployments {
        args.push(d.as_str());
    }
    args.extend(["-n", namespace]);
    let status = tokio::process::Command::new("kubectl")
        .args(&args)
        .status()
        .await
        .context("kubectl wait deployments")?;
    anyhow::ensure!(status.success(), "deployments not ready in {namespace}");
    Ok(())
}

/// Retry WebSocket handshakes against the proxy until one succeeds or `timeout` expires.
///
/// Uses a custom request so the TCP connection goes to `proxy_addr` while the `Host`
/// header is set to `host` — the same split used by `HttpClient` for virtual hosting.
pub async fn wait_for_ws_route(
    proxy_addr: SocketAddr,
    host: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let uri = format!("ws://{proxy_addr}/");
    let deadline = time::Instant::now() + timeout;
    loop {
        let req = tungstenite::http::Request::builder()
            .uri(&uri)
            .header("Host", host)
            .body(())
            .context("build WebSocket request")?;
        match tokio_tungstenite::connect_async(req).await {
            Ok((mut stream, _)) => {
                let _ = stream.close(None).await;
                return Ok(());
            }
            Err(e) => tracing::debug!(host, error = %e, "ws route not yet live"),
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for WebSocket route on {host}");
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn wait_for_route(
    http: &crate::harness::HttpClient,
    host: &str,
    path: &str,
    timeout: Duration,
) -> anyhow::Result<crate::harness::http::EchoResponse> {
    let deadline = time::Instant::now() + timeout;
    loop {
        match http.get(host, path).await {
            Ok(resp) => return Ok(resp),
            Err(e) => tracing::debug!(host, path, error = %e, "route not yet live"),
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for route {host}{path} to become live");
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn wait_for_ingress_lb_ip(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    expected_ip: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Ok(ing) = api.get(name).await {
            let current = ing
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_deref())
                .and_then(|entries| entries.first())
                .and_then(|e| e.ip.as_deref());
            if current == Some(expected_ip) {
                return Ok(());
            }
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for Ingress {namespace}/{name} to have loadBalancer ip={expected_ip}"
            );
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// Poll until the named Gateway has a top-level condition with the given type
/// and status value (e.g. `"True"` or `"False"`).
pub async fn wait_for_gateway_condition(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    type_: &str,
    status: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Ok(gw) = api.get(name).await {
            let found = gw
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_deref())
                .map(|conds| condition_matches(conds, type_, status))
                .unwrap_or(false);
            if found {
                return Ok(());
            }
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for Gateway {namespace}/{name} to have condition {type_}={status}"
            );
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// Poll until the named Gateway's per-listener status has a condition with the
/// given type and status value for the specified listener.
pub async fn wait_for_gateway_listener_condition(
    client: &kube::Client,
    gw_name: &str,
    namespace: &str,
    listener_name: &str,
    type_: &str,
    status: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Ok(gw) = api.get(gw_name).await {
            let found = gw
                .status
                .as_ref()
                .and_then(|s| s.listeners.as_deref())
                .and_then(|listeners| listeners.iter().find(|l| l.name == listener_name))
                .map(|l| condition_matches(l.conditions.as_slice(), type_, status))
                .unwrap_or(false);
            if found {
                return Ok(());
            }
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for Gateway {namespace}/{gw_name} listener \
                 '{listener_name}' to have condition {type_}={status}"
            );
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

fn gateway_has_condition(gw: &Gateway, type_: &str) -> bool {
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .map(|conds| has_condition(conds, type_))
        .unwrap_or(false)
}

fn route_has_condition(route: &HTTPRoute, type_: &str) -> bool {
    route
        .status
        .as_ref()
        .map(|s| {
            s.parents
                .iter()
                .any(|p| has_condition(p.conditions.as_slice(), type_))
        })
        .unwrap_or(false)
}

fn has_condition(conditions: &[Condition], type_: &str) -> bool {
    condition_matches(conditions, type_, "True")
}

fn condition_matches(conditions: &[Condition], type_: &str, status: &str) -> bool {
    conditions
        .iter()
        .any(|c| c.type_ == type_ && c.status == status)
}
