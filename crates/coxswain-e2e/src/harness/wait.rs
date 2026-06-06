use anyhow::Context as _;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::Api;
use std::{net::SocketAddr, time::Duration};
use tokio::time;

const POLL: Duration = Duration::from_millis(500);
const POLL_FAST: Duration = Duration::from_millis(200);

/// Poll `check` every `interval` until it returns `Some(T)` or `timeout` elapses.
async fn poll_until<T, F, Fut>(
    timeout: Duration,
    interval: Duration,
    timeout_msg: impl Fn() -> String,
    mut check: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Some(val) = check().await {
            return Ok(val);
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("{}", timeout_msg());
        }
        time::sleep(interval).await;
    }
}

/// Poll HTTPS handshakes until the served leaf certificate DER differs from `old_der`.
pub async fn wait_for_tls_cert_rotation(
    tls_addr: SocketAddr,
    host: &str,
    old_der: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    poll_until(
        timeout,
        POLL,
        || format!("TLS cert rotation on {host}"),
        || async {
            match crate::harness::http::https_peer_leaf_der(host, "/", tls_addr).await {
                Ok(new_der) if new_der != old_der => Some(new_der),
                Ok(_) => {
                    tracing::debug!(host, "TLS leaf unchanged, waiting for rotation");
                    None
                }
                Err(e) => {
                    tracing::debug!(host, error = %e, "could not read TLS peer cert");
                    None
                }
            }
        },
    )
    .await
}

pub async fn wait_for_https_route(
    tls_addr: SocketAddr,
    host: &str,
    path: &str,
    timeout: Duration,
) -> anyhow::Result<crate::harness::http::EchoResponse> {
    poll_until(
        timeout,
        POLL,
        || format!("HTTPS route {host}{path} to become live"),
        || async {
            match crate::harness::http::https_get(host, path, tls_addr).await {
                Ok((_, Some(body))) => Some(body),
                Ok((status, None)) => {
                    tracing::debug!(host, path, status, "https route returned non-2xx");
                    None
                }
                Err(e) => {
                    tracing::debug!(host, path, error = %e, "https route not yet live");
                    None
                }
            }
        },
    )
    .await
}

pub async fn wait_for_ready(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    let url = format!("http://{addr}/readyz");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build reqwest client")?;
    poll_until(
        timeout,
        POLL_FAST,
        || format!("readyz at {addr}"),
        || async {
            client
                .get(&url)
                .send()
                .await
                .ok()
                .filter(|r| r.status().is_success())
                .map(|_| ())
        },
    )
    .await
}

pub async fn wait_for_gatewayclass_supported_features(
    client: &kube::Client,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<Vec<String>> {
    let api: Api<GatewayClass> = Api::all(client.clone());
    poll_until(
        timeout,
        POLL,
        || format!("GatewayClass {name} to have status.supportedFeatures"),
        || async {
            api.get(name).await.ok().and_then(|gc| {
                let feats: Vec<String> = gc
                    .status
                    .as_ref()
                    .and_then(|s| s.supported_features.as_deref())
                    .map(|fs| fs.iter().map(|f| f.name.clone()).collect())
                    .unwrap_or_default();
                if feats.is_empty() { None } else { Some(feats) }
            })
        },
    )
    .await
}

pub async fn wait_for_httproute_programmed(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<HTTPRoute> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || format!("HTTPRoute {namespace}/{name} to be Programmed"),
        || async {
            api.get(name)
                .await
                .ok()
                .filter(|r| route_has_condition(r, "Programmed"))
                .map(|_| ())
        },
    )
    .await
}

pub async fn wait_for_gateway_programmed(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || format!("Gateway {namespace}/{name} to be Accepted and Programmed"),
        || async {
            api.get(name)
                .await
                .ok()
                .filter(|gw| {
                    gateway_has_condition(gw, "Accepted") && gateway_has_condition(gw, "Programmed")
                })
                .map(|_| ())
        },
    )
    .await
}

/// Poll until a `kubernetes.io/tls` Secret with non-empty `tls.crt` data exists.
pub async fn wait_for_tls_secret(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || format!("kubernetes.io/tls Secret {namespace}/{name} to be populated"),
        || async {
            api.get(name)
                .await
                .ok()
                .filter(|s| {
                    s.type_.as_deref() == Some("kubernetes.io/tls")
                        && s.data
                            .as_ref()
                            .and_then(|d| d.get("tls.crt"))
                            .is_some_and(|b| !b.0.is_empty())
                })
                .map(|_| ())
        },
    )
    .await
}

/// Wait for the named Deployments in `namespace` to become Available.
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
pub async fn wait_for_ws_route(
    proxy_addr: SocketAddr,
    host: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    use tokio_tungstenite::tungstenite;
    let uri = format!("ws://{proxy_addr}/");
    poll_until(
        timeout,
        POLL,
        || format!("WebSocket route on {host}"),
        || async {
            let req = tungstenite::http::Request::builder()
                .uri(&uri)
                .header("Host", host)
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header(
                    "Sec-WebSocket-Key",
                    tungstenite::handshake::client::generate_key(),
                )
                .body(())
                .ok()?;
            match tokio_tungstenite::connect_async(req).await {
                Ok((mut stream, _)) => {
                    let _ = stream.close(None).await;
                    Some(())
                }
                Err(e) => {
                    tracing::debug!(host, error = %e, "ws route not yet live");
                    None
                }
            }
        },
    )
    .await
}

pub async fn wait_for_route(
    http: &crate::harness::HttpClient,
    host: &str,
    path: &str,
    timeout: Duration,
) -> anyhow::Result<crate::harness::http::EchoResponse> {
    poll_until(
        timeout,
        POLL,
        || format!("route {host}{path} to become live"),
        || async {
            match http.get(host, path).await {
                Ok(resp) => Some(resp),
                Err(e) => {
                    tracing::debug!(host, path, error = %e, "route not yet live");
                    None
                }
            }
        },
    )
    .await
}

/// Poll `host`+`path` until the response comes from `expected_backend`.
pub async fn wait_for_backend(
    http: &crate::harness::HttpClient,
    host: &str,
    path: &str,
    expected_backend: &str,
    timeout: Duration,
) -> anyhow::Result<crate::harness::http::EchoResponse> {
    poll_until(
        timeout,
        POLL,
        || format!("backend '{expected_backend}' at {host}{path}"),
        || async {
            match http.get(host, path).await {
                Ok(resp) => {
                    let pod = resp.pod.as_deref().unwrap_or("");
                    if pod.starts_with(&format!("{expected_backend}-")) {
                        Some(resp)
                    } else {
                        tracing::debug!(
                            host,
                            path,
                            pod,
                            expected_backend,
                            "wrong backend — retrying"
                        );
                        None
                    }
                }
                Err(e) => {
                    tracing::debug!(host, path, error = %e, "route not yet live");
                    None
                }
            }
        },
    )
    .await
}

/// Poll until `host`+`path` returns `expected_status`.
pub async fn wait_for_route_status(
    http: &crate::harness::HttpClient,
    host: &str,
    path: &str,
    expected_status: u16,
    timeout: Duration,
) -> anyhow::Result<()> {
    poll_until(
        timeout,
        POLL,
        || format!("{host}{path} to return {expected_status}"),
        || async {
            match http.get_status(host, path).await {
                Ok(status) if status == expected_status => Some(()),
                Ok(status) => {
                    tracing::debug!(host, path, status, expected_status, "wrong status");
                    None
                }
                Err(e) => {
                    tracing::debug!(host, path, error = %e, "request failed");
                    None
                }
            }
        },
    )
    .await
}

pub async fn wait_for_ingress_lb_ip(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    expected_ip: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || format!("Ingress {namespace}/{name} to have loadBalancer ip={expected_ip}"),
        || async {
            api.get(name)
                .await
                .ok()
                .filter(|ing| {
                    ing.status
                        .as_ref()
                        .and_then(|s| s.load_balancer.as_ref())
                        .and_then(|lb| lb.ingress.as_deref())
                        .and_then(|entries| entries.first())
                        .and_then(|e| e.ip.as_deref())
                        == Some(expected_ip)
                })
                .map(|_| ())
        },
    )
    .await
}

/// Poll until the named Gateway has a top-level condition with the given type and status value.
pub async fn wait_for_gateway_condition(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    type_: &str,
    status: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || format!("Gateway {namespace}/{name} to have condition {type_}={status}"),
        || async {
            api.get(name)
                .await
                .ok()
                .filter(|gw| {
                    gw.status
                        .as_ref()
                        .and_then(|s| s.conditions.as_deref())
                        .is_some_and(|conds| condition_matches(conds, type_, status))
                })
                .map(|_| ())
        },
    )
    .await
}

/// Poll until the named Gateway's per-listener status has a condition with the given type and status.
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
    poll_until(
        timeout,
        POLL,
        || {
            format!(
                "Gateway {namespace}/{gw_name} listener '{listener_name}' to have condition {type_}={status}"
            )
        },
        || async {
            api.get(gw_name).await.ok().filter(|gw| {
                gw.status
                    .as_ref()
                    .and_then(|s| s.listeners.as_deref())
                    .and_then(|ls| ls.iter().find(|l| l.name == listener_name))
                    .is_some_and(|l| condition_matches(l.conditions.as_slice(), type_, status))
            }).map(|_| ())
        },
    )
    .await
}

fn gateway_has_condition(gw: &Gateway, type_: &str) -> bool {
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .is_some_and(|conds| has_condition(conds, type_))
}

fn route_has_condition(route: &HTTPRoute, type_: &str) -> bool {
    route.status.as_ref().is_some_and(|s| {
        s.parents
            .iter()
            .any(|p| has_condition(p.conditions.as_slice(), type_))
    })
}

fn has_condition(conditions: &[Condition], type_: &str) -> bool {
    condition_matches(conditions, type_, "True")
}

fn condition_matches(conditions: &[Condition], type_: &str, status: &str) -> bool {
    conditions
        .iter()
        .any(|c| c.type_ == type_ && c.status == status)
}
