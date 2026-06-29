//! Polling helpers that retry until Kubernetes resources reach the desired state.

use anyhow::Context as _;
use gateway_api::apis::standard::backendtlspolicies::BackendTlsPolicy;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::grpcroutes::GrpcRoute;
use gateway_api::apis::standard::httproutes::HttpRoute;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::Api;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::time;

/// Default poll interval — tight enough to keep total wall-clock low, loose
/// enough not to hammer the API server.
pub const POLL: Duration = Duration::from_millis(500);
/// Faster poll interval for cheap local probes (e.g. `/readyz`).
pub const POLL_FAST: Duration = Duration::from_millis(200);

/// Poll `check` every `interval` until it returns `Some(T)`, or fail when
/// `timeout` elapses.
///
/// This is the single canonical poller for the e2e suite. Tests and harness
/// waiters route every blind wait through it rather than sleeping, so the
/// "poll the real post-condition, never sleep" rubric is enforced by reuse.
///
/// On timeout the `on_timeout` closure is awaited and its string is embedded in
/// the error. That closure is expected to *fetch and render the last-observed
/// world state* (conditions, pod identity, HTTP status), so a timeout is
/// diagnosable from the log alone — without re-running under `RUST_LOG`.
///
/// # Errors
///
/// Returns an error if `check` does not yield `Some` before `timeout` elapses;
/// the message carries the `on_timeout` state dump.
pub async fn poll_until<T, F, Fut, D, DFut>(
    timeout: Duration,
    interval: Duration,
    on_timeout: D,
    mut check: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
    D: Fn() -> DFut,
    DFut: std::future::Future<Output = String>,
{
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Some(val) = check().await {
            return Ok(val);
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out after {timeout:?} waiting for {}",
                on_timeout().await
            );
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
        || async {
            match crate::harness::http::https_peer_leaf_der(host, "/", tls_addr).await {
                Ok(der) => format!(
                    "TLS leaf on {host} to rotate (was {} bytes); current leaf is {} bytes",
                    old_der.len(),
                    der.len()
                ),
                Err(e) => format!("TLS leaf on {host} to rotate; current handshake fails: {e}"),
            }
        },
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

/// Poll HTTPS GET requests until the route returns a 2xx JSON body.
pub async fn wait_for_https_route(
    tls_addr: SocketAddr,
    host: &str,
    path: &str,
    timeout: Duration,
) -> anyhow::Result<crate::harness::http::EchoResponse> {
    poll_until(
        timeout,
        POLL,
        || async {
            match crate::harness::http::https_get(host, path, tls_addr).await {
                Ok((status, _)) => {
                    format!("HTTPS route {host}{path} to return 2xx; last status {status}")
                }
                Err(e) => format!("HTTPS route {host}{path} to become live; handshake error: {e}"),
            }
        },
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

/// Poll `/readyz` at `addr` until it returns 200 or `timeout` expires.
pub async fn wait_for_ready(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    let url = format!("http://{addr}/readyz");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build reqwest client")?;
    poll_until(
        timeout,
        POLL_FAST,
        || async {
            match client.get(&url).send().await {
                Ok(r) => format!(
                    "/readyz at {addr} to return 200; last status {}",
                    r.status()
                ),
                Err(e) => format!("/readyz at {addr} to return 200; request error: {e}"),
            }
        },
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

/// Poll until the GatewayClass has a non-empty `status.supportedFeatures` list.
pub async fn wait_for_gatewayclass_supported_features(
    client: &kube::Client,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<Vec<String>> {
    let api: Api<GatewayClass> = Api::all(client.clone());
    poll_until(
        timeout,
        POLL,
        || async {
            format!(
                "GatewayClass {name} to publish status.supportedFeatures; {}",
                gatewayclass_state(&api, name).await
            )
        },
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

/// Poll until the HTTPRoute has a `Programmed=True` condition from at least one parent.
pub async fn wait_for_httproute_programmed(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<HttpRoute> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || async {
            format!(
                "HTTPRoute {namespace}/{name} to be Programmed; observed {}",
                route_state(&api, name).await
            )
        },
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

/// Poll until the GRPCRoute has a `Programmed=True` condition from at least one parent.
///
/// # Errors
///
/// Returns an error if the condition is not observed before `timeout` elapses.
pub async fn wait_for_grpcroute_programmed(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<GrpcRoute> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || async {
            format!(
                "GRPCRoute {namespace}/{name} to be Programmed; observed {}",
                grpcroute_state(&api, name).await
            )
        },
        || async {
            api.get(name)
                .await
                .ok()
                .filter(|r| grpcroute_has_condition(r, "Programmed"))
                .map(|_| ())
        },
    )
    .await
}

/// Poll until the Gateway has both `Accepted=True` and `Programmed=True` conditions.
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
        || async {
            format!(
                "Gateway {namespace}/{name} to be Accepted and Programmed; observed {}",
                gateway_state(&api, name).await
            )
        },
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

/// Poll until the Gateway's own `status.addresses[0]` is populated, returning a
/// [`SocketAddr`] on `port` at that address.
///
/// Shared-mode Gateways each advertise their OWN per-Gateway VIP (#472), not the
/// shared proxy Service — so a Gateway data-plane test resolves the address from
/// the Gateway's status here instead of using the shared `gateway_*_addr`
/// fields. `port` is the advertised listener (spec) port; the VIP maps it to the
/// proxy's internal target port transparently.
pub async fn wait_for_gateway_address(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    port: u16,
    timeout: Duration,
) -> anyhow::Result<SocketAddr> {
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || async {
            format!("Gateway {namespace}/{name} status.addresses[0] to be populated with its VIP")
        },
        || async {
            let gw = api.get(name).await.ok()?;
            let value = gw.status?.addresses?.into_iter().next()?.value;
            let ip: IpAddr = value.parse().ok()?;
            Some(SocketAddr::new(ip, port))
        },
    )
    .await
}

/// Poll until the single Gateway in `namespace` has its `status.addresses[0]`
/// populated, returning a [`SocketAddr`] on `port` at that VIP (#472).
///
/// Convenience over [`wait_for_gateway_address`] for the common case of a test
/// that owns exactly one Gateway in its fresh namespace: the caller need not
/// name the Gateway. Errors if the namespace ever holds more than one Gateway
/// (use the by-name form for multi-Gateway tests) or if none appears in time.
pub async fn wait_for_single_gateway_address(
    client: &kube::Client,
    namespace: &str,
    port: u16,
    timeout: Duration,
) -> anyhow::Result<SocketAddr> {
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || async {
            format!("the single Gateway in {namespace} to have status.addresses[0] populated with its VIP")
        },
        || async {
            let list = api.list(&Default::default()).await.ok()?;
            // Fail loud rather than silently address one of several Gateways.
            let [gw] = list.items.as_slice() else {
                return None;
            };
            let value = gw.status.as_ref()?.addresses.as_ref()?.first()?.value.clone();
            let ip: IpAddr = value.parse().ok()?;
            Some(SocketAddr::new(ip, port))
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
        || async {
            format!(
                "kubernetes.io/tls Secret {namespace}/{name} to be populated; observed {}",
                secret_state(&api, name).await
            )
        },
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

/// Poll the proxy until at least `expected` distinct backend pods answer 200 on
/// `host``path`, returning the set of pod names observed.
///
/// Load-balancing and session-affinity tests must not start asserting until the
/// *full* replica set's EndpointSlices have propagated into the proxy routing
/// snapshot. [`wait_for_route`] only proves **one** endpoint is live; the rest of
/// the set can still be landing, and a still-growing set breaks two ways:
/// round-robin distribution sees fewer pods than expected, and consistent-hash
/// rings rebalance (a "pinned" key jumps to a different pod) the instant a new
/// endpoint is added. Waiting for the set to reach its full size makes it stable,
/// so the subsequent pinning / distribution assertions are deterministic.
///
/// Each poll iteration fans out `expected * 5` requests so round-robin visits
/// every endpoint within one pass; failures and non-200s are simply not counted.
///
/// # Errors
///
/// Returns an error if fewer than `expected` distinct pods are seen before
/// `timeout` elapses.
pub async fn wait_for_distinct_backends(
    client: &crate::harness::http::HttpClient,
    host: &str,
    path: &str,
    expected: usize,
    timeout: Duration,
) -> anyhow::Result<std::collections::HashSet<String>> {
    poll_until(
        timeout,
        POLL,
        || async { format!("at least {expected} distinct backend pods to answer on {host}{path}") },
        || async {
            let mut pods = std::collections::HashSet::new();
            for _ in 0..(expected * 5) {
                if let Ok((200, _, Some(body))) = client.get_full(host, path).await
                    && let Some(p) = body.pod
                {
                    pods.insert(p);
                }
            }
            (pods.len() >= expected).then_some(pods)
        },
    )
    .await
}

/// Poll the proxy admin `/api/v1/routes` until the route serving `host` exposes
/// at least `expected` compiled endpoints, returning the count observed.
///
/// Mode-independent companion to [`wait_for_distinct_backends`] for load-balancing
/// tests whose client cannot distribute requests across the backend set — e.g.
/// `ip_hash`, where a single source IP always pins to one pod, so request sampling
/// can never observe more than one endpoint. Reading the proxy's own compiled
/// endpoint set confirms the full EndpointSlice has propagated before the test
/// pins a baseline, closing the same propagation race without needing
/// distribution.
///
/// # Errors
///
/// Returns an error if the route exposes fewer than `expected` endpoints before
/// `timeout` elapses.
pub async fn wait_for_route_endpoints(
    routes_url: &str,
    host: &str,
    expected: usize,
    timeout: Duration,
) -> anyhow::Result<usize> {
    let client = reqwest::Client::new();
    // Largest endpoint count across any compiled route (ingress or gateway
    // surface) whose host group matches `host`.
    let count_for = |json: &serde_json::Value, host: &str| -> usize {
        ["ingress", "gateway"]
            .iter()
            .filter_map(|surface| json[surface]["hosts"].as_array())
            .flatten()
            .filter(|hg| hg["host"].as_str() == Some(host))
            .flat_map(|hg| hg["routes"].as_array().into_iter().flatten())
            .map(|r| r["endpoints"].as_array().map_or(0, Vec::len))
            .max()
            .unwrap_or(0)
    };
    poll_until(
        timeout,
        POLL,
        || async {
            let state = match client.get(routes_url).send().await {
                Ok(r) => match r.json::<serde_json::Value>().await {
                    Ok(j) => format!("observed {} endpoints", count_for(&j, host)),
                    Err(e) => format!("routes body parse error: {e}"),
                },
                Err(e) => format!("routes request error: {e}"),
            };
            format!("route '{host}' to expose >= {expected} endpoints; {state}")
        },
        || async {
            let json = client
                .get(routes_url)
                .send()
                .await
                .ok()?
                .json::<serde_json::Value>()
                .await
                .ok()?;
            let n = count_for(&json, host);
            (n >= expected).then_some(n)
        },
    )
    .await
}

/// Poll until the named Deployments in `namespace` have `condition=Available`.
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

/// Poll until the named namespaced resource exists, returning it.
///
/// The single most common shape in the provisioning/status suites — "wait for
/// the controller to create object `name`, then assert on it". Routes through
/// the canonical [`poll_until`] (no ad-hoc loop) and dumps the resource kind +
/// name on timeout.
///
/// # Errors
///
/// Returns an error if the resource does not exist before `timeout` elapses.
pub async fn wait_for_resource<K>(api: &Api<K>, name: &str, timeout: Duration) -> anyhow::Result<K>
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
    K::DynamicType: Default,
{
    let kind = K::kind(&K::DynamicType::default()).to_string();
    poll_until(
        timeout,
        POLL,
        || async { format!("{kind} '{name}' to be created") },
        || async { api.get(name).await.ok() },
    )
    .await
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
        || async {
            format!("WebSocket route on {host} via {proxy_addr} to complete its upgrade handshake")
        },
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

/// Poll until `host`+`path` returns a successful echo response.
pub async fn wait_for_route(
    http: &crate::harness::HttpClient,
    host: &str,
    path: &str,
    timeout: Duration,
) -> anyhow::Result<crate::harness::http::EchoResponse> {
    poll_until(
        timeout,
        POLL,
        || async {
            format!(
                "route {host}{path} to become live; {}",
                http_probe_state(http, host, path).await
            )
        },
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
        || async {
            match http.get(host, path).await {
                Ok(resp) => format!(
                    "backend '{expected_backend}' at {host}{path}; last response from pod {:?}",
                    resp.pod
                ),
                Err(e) => {
                    format!("backend '{expected_backend}' at {host}{path}; request error: {e}")
                }
            }
        },
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
        || async {
            match http.get_status(host, path).await {
                Ok(status) => {
                    format!("{host}{path} to return {expected_status}; last status {status}")
                }
                Err(e) => format!("{host}{path} to return {expected_status}; request error: {e}"),
            }
        },
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

/// Poll until the route returns an upstream-rejection status — `400` or any `5xx`.
///
/// For negative wire-protocol assertions where the proxy cannot speak the
/// upstream's wire protocol (e.g. HTTP/1.1 to an h2c-only port, or cleartext to a
/// TLS-only port), the rejection
/// surfaces as a `502` (the proxy got no valid upstream response) or a `400` (the
/// upstream replied with a protocol error) depending on how the handshake fails —
/// both prove the request did not succeed. A `404` (route not yet programmed) or any
/// `2xx`/`3xx` keeps polling, so this never passes on a transient not-ready state or
/// a success. Returns the observed rejection status.
///
/// # Errors
///
/// Returns an error if no rejection status is observed before `timeout` elapses.
pub async fn wait_for_route_rejected(
    http: &crate::harness::HttpClient,
    host: &str,
    path: &str,
    timeout: Duration,
) -> anyhow::Result<u16> {
    let is_rejection = |s: u16| s == 400 || (500..=599).contains(&s);
    poll_until(
        timeout,
        POLL,
        || async {
            match http.get_status(host, path).await {
                Ok(status) => {
                    format!("{host}{path} to be rejected (400 or 5xx); last status {status}")
                }
                Err(e) => format!("{host}{path} to be rejected (400 or 5xx); request error: {e}"),
            }
        },
        move || async move {
            match http.get_status(host, path).await {
                Ok(status) if is_rejection(status) => Some(status),
                Ok(status) => {
                    tracing::debug!(host, path, status, "not a rejection yet");
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

/// Poll `host`+`path` until the route returns the expected redirect status without
/// following the redirect. Returns the `Location` header value on success.
///
/// Useful for waiting until an `ssl-redirect` or `redirect-*` annotated Ingress is
/// programmed: `404` (not yet installed) keeps the poller waiting, a non-redirect
/// status also keeps it waiting, and only the exact `expected_status` with a
/// `Location` header satisfies the condition. Uses a separate no-redirect
/// `reqwest::Client` so the 3xx is observed rather than automatically followed.
///
/// # Errors
///
/// Returns an error if the redirect is not observed before `timeout` elapses.
pub async fn wait_for_route_redirect(
    proxy_addr: std::net::SocketAddr,
    host: &str,
    path: &str,
    expected_status: u16,
    timeout: Duration,
) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build no-redirect reqwest client")?;
    let url = format!("http://{proxy_addr}{path}");
    poll_until(
        timeout,
        POLL,
        || async {
            match client.get(&url).header("Host", host).send().await {
                Ok(resp) => format!(
                    "{host}{path} to return {expected_status} redirect; last status {}",
                    resp.status().as_u16()
                ),
                Err(e) => {
                    format!("{host}{path} to return {expected_status} redirect; error: {e}")
                }
            }
        },
        || async {
            match client.get(&url).header("Host", host).send().await {
                Ok(resp) if resp.status().as_u16() == expected_status => Some(
                    resp.headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string(),
                ),
                Ok(resp) => {
                    tracing::debug!(
                        host,
                        path,
                        status = resp.status().as_u16(),
                        "not the expected redirect yet"
                    );
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

/// Return a `SocketAddr` for the dedicated-proxy Service using its NodePort.
///
/// The dedicated-proxy Service is rendered with `type: NodePort` (avoids klipper-lb
/// host-port conflicts on single-node clusters where the shared-proxy already owns
/// ports 80/443/8000/8443). Traffic is reachable at `<node-ip>:<node-port>`.
///
/// The dedicated-proxy Service name is `<gateway-name>-coxswain` as rendered by
/// the controller's provisioning operator.
///
/// # Errors
///
/// Returns an error if the Service has no NodePort within `timeout`, or if the
/// node address cannot be determined.
pub async fn wait_for_dedicated_proxy_endpoint(
    namespace: &str,
    gateway_name: &str,
    timeout: Duration,
) -> anyhow::Result<std::net::SocketAddr> {
    let svc_name = format!("{gateway_name}-coxswain");
    let node_ip = get_node_ip().await?;
    let node_port = poll_until(
        timeout,
        POLL,
        || async {
            format!(
                "dedicated-proxy Service {namespace}/{svc_name} to have a NodePort; {}",
                svc_nodeport_state(namespace, &svc_name).await
            )
        },
        || async {
            let out = tokio::process::Command::new("kubectl")
                .args([
                    "get",
                    "svc",
                    &svc_name,
                    "-n",
                    namespace,
                    "-o",
                    "jsonpath={.spec.ports[0].nodePort}",
                ])
                .output()
                .await
                .ok()?;
            let port_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if port_str.is_empty() {
                return None;
            }
            port_str.parse::<u16>().ok()
        },
    )
    .await?;
    Ok(std::net::SocketAddr::new(node_ip, node_port))
}

/// Poll until the controller has deleted the dedicated-proxy `Service` and
/// `Deployment` for a Gateway that migrated out of dedicated mode.
///
/// This is the spec-driven, controller-owned observable for a dedicated→shared
/// migration teardown. Owner-ref GC cannot reclaim these resources — the owning
/// Gateway survives a migration, so the cluster garbage collector never fires —
/// so the controller deletes them explicitly once the shared pool is serving the
/// migrated routes. Asserting their *API deletion* is deterministic and
/// cluster-independent; probing the NodePort instead would assert kube-proxy/CNI
/// teardown timing, which differs across clusters and is not the controller's
/// contract.
///
/// The dedicated resources are named `<gateway-name>-coxswain` (GEP-1762
/// `<NAME>-<GATEWAY CLASS>`, with `coxswain` the class used across the suite).
///
/// # Errors
///
/// Returns an error if either resource still exists when `timeout` elapses.
pub async fn wait_for_dedicated_proxy_deleted(
    client: &kube::Client,
    namespace: &str,
    gateway_name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let name = format!("{gateway_name}-coxswain");
    let services: Api<Service> = Api::namespaced(client.clone(), namespace);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || async {
            format!(
                "dedicated-proxy Service+Deployment {namespace}/{name} to be deleted by the \
                 controller; {}",
                svc_nodeport_state(namespace, &name).await
            )
        },
        || async {
            let svc_gone = matches!(services.get_opt(&name).await, Ok(None));
            let deploy_gone = matches!(deployments.get_opt(&name).await, Ok(None));
            (svc_gone && deploy_gone).then_some(())
        },
    )
    .await
}

/// Return the address of the first Kubernetes node.
///
/// On single-node clusters (OrbStack, kind) there is exactly one node and its
/// `InternalIP` is routable from the test runner host.
///
/// # Errors
///
/// Returns an error if `kubectl get nodes` fails or the output cannot be parsed
/// as an IP address.
async fn get_node_ip() -> anyhow::Result<std::net::IpAddr> {
    let out = tokio::process::Command::new("kubectl")
        .args([
            "get",
            "nodes",
            "-o",
            "jsonpath={.items[0].status.addresses[?(@.type==\"InternalIP\")].address}",
        ])
        .output()
        .await
        .context("kubectl get nodes")?;
    let raw = String::from_utf8_lossy(&out.stdout);
    // Nodes may report multiple InternalIP addresses (IPv4 + IPv6); the
    // jsonpath returns them space-separated. Prefer the first IPv4 address
    // so test clients bind to a well-known family.
    raw.split_whitespace()
        .find_map(|s| s.parse::<std::net::IpAddr>().ok().filter(|ip| ip.is_ipv4()))
        .or_else(|| raw.split_whitespace().find_map(|s| s.parse().ok()))
        .with_context(|| format!("no parseable IP in node address output: {raw}"))
}

/// Poll the controller admin `/metrics` endpoint until the replica reports it
/// holds the leader lease *and* has completed at least one successful reconcile
/// on the current process.
///
/// This is the real post-condition that replaces blind "wait for the operator to
/// settle" sleeps after a controller restart: `coxswain_controller_leader` flips
/// to `1` on leader-election, and `coxswain_controller_reconcile_total{...,
/// result="ok"}` starts unregistered (effectively `0`) in a fresh process, so a
/// value `>= 1` proves the new leader has run a full reconcile pass. Because SSA is
/// deterministic (identical rendered spec never bumps `.metadata.generation`),
/// one confirmed post-restart reconcile is sufficient to then assert generation
/// stability.
///
/// # Errors
///
/// Returns an error if the endpoint does not report `leader=1` with a successful
/// reconcile before `timeout`.
pub async fn wait_for_controller_reconciled(
    metrics_url: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build reqwest client")?;
    poll_until(
        timeout,
        POLL,
        || async {
            match fetch_metrics(&client, metrics_url).await {
                Ok(body) => format!(
                    "controller {metrics_url} to report leader=1 with a successful reconcile; \
                     last leader={:?}, reconcile_ok={:?}",
                    metric_value(&body, "coxswain_controller_leader"),
                    reconcile_ok_total(&body),
                ),
                Err(e) => {
                    format!(
                        "controller {metrics_url} to report leader + reconcile; fetch error: {e}"
                    )
                }
            }
        },
        || async {
            let body = fetch_metrics(&client, metrics_url).await.ok()?;
            let is_leader = metric_value(&body, "coxswain_controller_leader") == Some(1.0);
            let reconciled = reconcile_ok_total(&body).is_some_and(|v| v >= 1.0);
            (is_leader && reconciled).then_some(())
        },
    )
    .await
}

async fn fetch_metrics(client: &reqwest::Client, url: &str) -> anyhow::Result<String> {
    Ok(client.get(url).send().await?.text().await?)
}

/// Parse the value of a no-label Prometheus gauge/counter line
/// (`<name> <value>`). Returns `None` if the series is absent.
fn metric_value(body: &str, name: &str) -> Option<f64> {
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        let rest = l.strip_prefix(name)?;
        // Match the bare series only — `name <value>`, not `name_other` or
        // `name{labels}`.
        rest.strip_prefix(' ')?.trim().parse::<f64>().ok()
    })
}

/// Sum `coxswain_controller_reconcile_total{...,result="ok"}` across all
/// `controller` labels. Returns `None` if no `result="ok"` series is present
/// (the metric `observe_reconcile` labels a successful reconcile `result="ok"`).
fn reconcile_ok_total(body: &str) -> Option<f64> {
    let mut total = 0.0;
    let mut seen = false;
    for line in body.lines().filter(|l| !l.starts_with('#')) {
        let Some(rest) = line.strip_prefix("coxswain_controller_reconcile_total{") else {
            continue;
        };
        let Some((labels, value)) = rest.split_once('}') else {
            continue;
        };
        if !labels.contains("result=\"ok\"") {
            continue;
        }
        if let Ok(v) = value.trim().parse::<f64>() {
            total += v;
            seen = true;
        }
    }
    seen.then_some(total)
}

/// Poll until `Ingress.status.loadBalancer.ingress[0].ip` equals `expected_ip`.
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
        || async {
            format!(
                "Ingress {namespace}/{name} to have loadBalancer ip={expected_ip}; observed {}",
                ingress_lb_state(&api, name).await
            )
        },
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
        || async {
            format!(
                "Gateway {namespace}/{name} to have condition {type_}={status}; observed {}",
                gateway_state(&api, name).await
            )
        },
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
        || async {
            format!(
                "Gateway {namespace}/{gw_name} listener '{listener_name}' to have condition {type_}={status}; observed {}",
                gateway_listener_state(&api, gw_name, listener_name).await
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

fn route_has_condition(route: &HttpRoute, type_: &str) -> bool {
    route.status.as_ref().is_some_and(|s| {
        s.parents
            .iter()
            .any(|p| has_condition(p.conditions.as_slice(), type_))
    })
}

fn grpcroute_has_condition(route: &GrpcRoute, type_: &str) -> bool {
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

/// Render a condition list as `[type=status(reason), ...]` for timeout dumps.
fn summarize_conditions(conditions: &[Condition]) -> String {
    if conditions.is_empty() {
        return "[]".to_string();
    }
    let rendered: Vec<String> = conditions
        .iter()
        .map(|c| format!("{}={}({})", c.type_, c.status, c.reason))
        .collect();
    format!("[{}]", rendered.join(", "))
}

/// Fetch and summarize a Gateway's top-level conditions for a timeout dump.
async fn gateway_state(api: &Api<Gateway>, name: &str) -> String {
    match api.get(name).await {
        Ok(gw) => {
            let conds = gw
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_deref())
                .unwrap_or(&[]);
            format!("conditions={}", summarize_conditions(conds))
        }
        Err(e) => format!("<could not fetch Gateway {name}: {e}>"),
    }
}

/// Fetch and summarize a single Gateway listener's conditions for a timeout dump.
async fn gateway_listener_state(api: &Api<Gateway>, gw_name: &str, listener_name: &str) -> String {
    match api.get(gw_name).await {
        Ok(gw) => {
            let conds = gw
                .status
                .as_ref()
                .and_then(|s| s.listeners.as_deref())
                .and_then(|ls| ls.iter().find(|l| l.name == listener_name))
                .map_or_else(
                    || "<listener absent>".to_string(),
                    |l| summarize_conditions(l.conditions.as_slice()),
                );
            format!("listener conditions={conds}")
        }
        Err(e) => format!("<could not fetch Gateway {gw_name}: {e}>"),
    }
}

/// Fetch and summarize a GRPCRoute's per-parent conditions for a timeout dump.
async fn grpcroute_state(api: &Api<GrpcRoute>, name: &str) -> String {
    match api.get(name).await {
        Ok(route) => match route.status.as_ref() {
            Some(s) => {
                let parents: Vec<String> = s
                    .parents
                    .iter()
                    .map(|p| {
                        format!(
                            "{}:{}",
                            p.controller_name,
                            summarize_conditions(p.conditions.as_slice())
                        )
                    })
                    .collect();
                format!("parents=[{}]", parents.join(", "))
            }
            None => "<no status yet>".to_string(),
        },
        Err(e) => format!("<could not fetch GRPCRoute {name}: {e}>"),
    }
}

/// Fetch and summarize an HTTPRoute's per-parent conditions for a timeout dump.
async fn route_state(api: &Api<HttpRoute>, name: &str) -> String {
    match api.get(name).await {
        Ok(route) => match route.status.as_ref() {
            Some(s) => {
                let parents: Vec<String> = s
                    .parents
                    .iter()
                    .map(|p| {
                        format!(
                            "{}:{}",
                            p.controller_name,
                            summarize_conditions(p.conditions.as_slice())
                        )
                    })
                    .collect();
                format!("parents=[{}]", parents.join(", "))
            }
            None => "<no status yet>".to_string(),
        },
        Err(e) => format!("<could not fetch HTTPRoute {name}: {e}>"),
    }
}

/// Fetch and summarize a Secret's type and `tls.crt` presence for a timeout dump.
async fn secret_state(api: &Api<Secret>, name: &str) -> String {
    match api.get(name).await {
        Ok(s) => {
            let has_crt = s
                .data
                .as_ref()
                .and_then(|d| d.get("tls.crt"))
                .is_some_and(|b| !b.0.is_empty());
            format!("type={:?}, tls.crt present={has_crt}", s.type_)
        }
        Err(e) => format!("<could not fetch Secret {name}: {e}>"),
    }
}

/// Fetch and summarize a GatewayClass's `supportedFeatures` count for a timeout dump.
async fn gatewayclass_state(api: &Api<GatewayClass>, name: &str) -> String {
    match api.get(name).await {
        Ok(gc) => {
            let count = gc
                .status
                .as_ref()
                .and_then(|s| s.supported_features.as_ref())
                .map_or(0, Vec::len);
            format!("supportedFeatures count={count}")
        }
        Err(e) => format!("<could not fetch GatewayClass {name}: {e}>"),
    }
}

/// Fetch and summarize an Ingress's load-balancer IPs for a timeout dump.
async fn ingress_lb_state(api: &Api<Ingress>, name: &str) -> String {
    match api.get(name).await {
        Ok(ing) => {
            let ips: Vec<String> = ing
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_deref())
                .map(|entries| entries.iter().filter_map(|e| e.ip.clone()).collect())
                .unwrap_or_default();
            format!("loadBalancer ips={ips:?}")
        }
        Err(e) => format!("<could not fetch Ingress {name}: {e}>"),
    }
}

/// Re-probe an HTTP route and report the current status/error for a timeout dump.
async fn http_probe_state(http: &crate::harness::HttpClient, host: &str, path: &str) -> String {
    match http.get_status(host, path).await {
        Ok(status) => format!("last status {status}"),
        Err(e) => format!("request error: {e}"),
    }
}

/// Report the current `type`/`nodePort` of a Service for a timeout dump.
async fn svc_nodeport_state(namespace: &str, svc_name: &str) -> String {
    match tokio::process::Command::new("kubectl")
        .args([
            "get",
            "svc",
            svc_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.spec.type}/{.spec.ports[0].nodePort}",
        ])
        .output()
        .await
    {
        Ok(out) => format!(
            "kubectl reports type/nodePort='{}'",
            String::from_utf8_lossy(&out.stdout).trim()
        ),
        Err(e) => format!("<could not run kubectl get svc {svc_name}: {e}>"),
    }
}

/// Poll until a `BackendTLSPolicy`'s `status.ancestors[]` contains a condition
/// with the given type and status from our controller.
pub async fn wait_for_backend_tls_policy_condition(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    controller_name: &str,
    type_: &str,
    status: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<BackendTlsPolicy> = Api::namespaced(client.clone(), namespace);
    poll_until(
        timeout,
        POLL,
        || async {
            format!(
                "BackendTLSPolicy {namespace}/{name} to have ancestor condition {type_}={status}; observed {}",
                backend_tls_policy_state(&api, name).await
            )
        },
        || async {
            api.get(name)
                .await
                .ok()
                .filter(|p| {
                    p.status
                        .as_ref()
                        .map(|s| s.ancestors.as_slice())
                        .unwrap_or(&[])
                        .iter()
                        .filter(|a| a.controller_name == controller_name)
                        .any(|a| condition_matches(&a.conditions, type_, status))
                })
                .map(|_| ())
        },
    )
    .await
}

/// Condition expectation for [`wait_for_backend_tls_policy_condition_with_reason`].
///
/// Bundles the `(type, status, reason)` triple so the wait helper stays under
/// the workspace `clippy::too_many_arguments` threshold.
pub struct ExpectedCondition<'a> {
    /// The condition `type_` we expect (e.g. `"Accepted"`).
    pub type_: &'a str,
    /// The condition `status` we expect (e.g. `"False"`).
    pub status: &'a str,
    /// The condition `reason` we expect (e.g. `"NoValidCACertificate"`).
    pub reason: &'a str,
}

/// Poll until a `BackendTLSPolicy`'s `status.ancestors[]` contains a condition
/// matching `expected` from our controller.
///
/// Stricter than [`wait_for_backend_tls_policy_condition`] — required when the
/// test cares about the specific failure reason (e.g. `NoValidCACertificate`,
/// `Conflicted`).
pub async fn wait_for_backend_tls_policy_condition_with_reason(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    controller_name: &str,
    expected: ExpectedCondition<'_>,
    timeout: Duration,
) -> anyhow::Result<()> {
    let api: Api<BackendTlsPolicy> = Api::namespaced(client.clone(), namespace);
    let ExpectedCondition {
        type_,
        status,
        reason,
    } = expected;
    poll_until(
        timeout,
        POLL,
        || async {
            format!(
                "BackendTLSPolicy {namespace}/{name} to have ancestor condition {type_}={status} reason={reason}; observed {}",
                backend_tls_policy_state(&api, name).await
            )
        },
        || async {
            api.get(name)
                .await
                .ok()
                .filter(|p| {
                    p.status
                        .as_ref()
                        .map(|s| s.ancestors.as_slice())
                        .unwrap_or(&[])
                        .iter()
                        .filter(|a| a.controller_name == controller_name)
                        .any(|a| {
                            a.conditions.iter().any(|c| {
                                c.type_ == type_ && c.status == status && c.reason == reason
                            })
                        })
                })
                .map(|_| ())
        },
    )
    .await
}

/// Poll `events.k8s.io/v1` Events until a `Warning` Event matching `reason` and
/// `ingress_name` appears in `namespace`, or `timeout` elapses.
///
/// The kube `Recorder` deduplicates Events in-process, so the first reconcile
/// after an issue appears will emit the Event; subsequent resyncs update the
/// count rather than creating a new object. This helper therefore only needs to
/// find **one** matching Event.
///
/// Returns the matching Event.
///
/// # Errors
///
/// Returns an error if no matching Event is found before `timeout` elapses.
pub async fn wait_for_ingress_warning_event(
    client: &kube::Client,
    namespace: &str,
    ingress_name: &str,
    reason: &str,
    timeout: Duration,
) -> anyhow::Result<k8s_openapi::api::events::v1::Event> {
    use k8s_openapi::api::events::v1::Event;
    let api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let ingress_name = ingress_name.to_owned();
    let reason = reason.to_owned();
    poll_until(
        timeout,
        POLL,
        || {
            let ingress_name = ingress_name.clone();
            let reason = reason.clone();
            async move {
                format!(
                    "Warning Event reason={reason} on Ingress {ingress_name}/{namespace} to appear"
                )
            }
        },
        || {
            let api = api.clone();
            let ingress_name = ingress_name.clone();
            let reason = reason.clone();
            async move {
                let list = api.list(&kube::api::ListParams::default()).await.ok()?;
                list.items.into_iter().find(|e| {
                    e.type_.as_deref() == Some("Warning")
                        && e.reason.as_deref() == Some(&reason)
                        && e.regarding.as_ref().and_then(|r| r.name.as_deref())
                            == Some(&ingress_name)
                        && e.regarding.as_ref().and_then(|r| r.kind.as_deref()) == Some("Ingress")
                })
            }
        },
    )
    .await
}

/// Poll until a `ClientTrafficPolicy`'s `status.ancestors[]` contains a condition
/// with the given type and status from the named controller.
///
/// Uses [`kube::api::DynamicObject`] because `ClientTrafficPolicy` is a coxswain-owned
/// CRD with no generated typed Rust struct.
///
/// # Errors
///
/// Returns an error if no matching condition is found before `timeout` elapses.
pub async fn wait_for_client_traffic_policy_condition(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    controller_name: &str,
    type_: &str,
    status: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    use kube::api::{ApiResource, DynamicObject};

    let ar = ApiResource {
        group: "gateway.coxswain-labs.dev".into(),
        version: "v1alpha1".into(),
        api_version: "gateway.coxswain-labs.dev/v1alpha1".into(),
        kind: "ClientTrafficPolicy".into(),
        plural: "clienttrafficpolicies".into(),
    };
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let name = name.to_owned();
    let controller_name = controller_name.to_owned();
    let type_ = type_.to_owned();
    let status = status.to_owned();
    poll_until(
        timeout,
        POLL,
        || {
            let api = api.clone();
            let name = name.clone();
            let controller_name = controller_name.clone();
            let type_ = type_.clone();
            let status = status.clone();
            async move {
                match api.get(&name).await {
                    Ok(obj) => {
                        let ancestors = obj.data["status"]["ancestors"]
                            .as_array()
                            .map(|v| {
                                v.iter()
                                    .map(|a| {
                                        format!(
                                            "{}:{}",
                                            a["controllerName"].as_str().unwrap_or(""),
                                            a["conditions"]
                                                .as_array()
                                                .map(|conds| {
                                                    conds
                                                        .iter()
                                                        .map(|c| {
                                                            format!(
                                                                "{}={}({})",
                                                                c["type"].as_str().unwrap_or(""),
                                                                c["status"].as_str().unwrap_or(""),
                                                                c["reason"].as_str().unwrap_or("")
                                                            )
                                                        })
                                                        .collect::<Vec<_>>()
                                                        .join(",")
                                                })
                                                .unwrap_or_default()
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join("; ")
                            })
                            .unwrap_or_else(|| "<no ancestors>".into());
                        format!(
                            "ClientTrafficPolicy {namespace}/{name} to have ancestor condition \
                             {type_}={status} from {controller_name}; observed ancestors=[{ancestors}]"
                        )
                    }
                    Err(e) => format!(
                        "ClientTrafficPolicy {namespace}/{name} to exist; fetch error: {e}"
                    ),
                }
            }
        },
        || {
            let api = api.clone();
            let name = name.clone();
            let controller_name = controller_name.clone();
            let type_ = type_.clone();
            let status = status.clone();
            async move {
                let obj = api.get(&name).await.ok()?;
                let ancestors = obj.data["status"]["ancestors"].as_array()?;
                let matched = ancestors.iter().any(|a| {
                    a["controllerName"].as_str() == Some(&controller_name)
                        && a["conditions"].as_array().is_some_and(|conds| {
                            conds.iter().any(|c| {
                                c["type"].as_str() == Some(&type_)
                                    && c["status"].as_str() == Some(&status)
                            })
                        })
                });
                if matched { Some(()) } else { None }
            }
        },
    )
    .await
}

/// Fetch and summarize a `BackendTLSPolicy`'s ancestor conditions for a timeout dump.
async fn backend_tls_policy_state(api: &Api<BackendTlsPolicy>, name: &str) -> String {
    match api.get(name).await {
        Ok(p) => {
            let ancestors: Vec<String> = p
                .status
                .as_ref()
                .map(|s| s.ancestors.as_slice())
                .unwrap_or(&[])
                .iter()
                .map(|a| {
                    format!(
                        "{}:{}",
                        a.controller_name,
                        summarize_conditions(&a.conditions)
                    )
                })
                .collect();
            format!("ancestors=[{}]", ancestors.join(", "))
        }
        Err(e) => format!("<could not fetch BackendTLSPolicy {name}: {e}>"),
    }
}
