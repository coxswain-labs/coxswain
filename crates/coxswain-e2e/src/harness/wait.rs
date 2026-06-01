use anyhow::Context as _;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::Api;
use std::{net::SocketAddr, time::Duration};
use tokio::time;

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
    conditions
        .iter()
        .any(|c| c.type_ == type_ && c.status == "True")
}
