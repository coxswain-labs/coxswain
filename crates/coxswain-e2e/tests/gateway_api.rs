use coxswain_e2e::{
    fixtures::{
        self, BACKENDS_ECHO, GATEWAY_API_CROSS_NAMESPACE_ROUTE, GATEWAY_API_CROSS_NAMESPACE_TENANT,
        GATEWAY_API_HOST_POOL, GATEWAY_API_PATH_MATCHING, GATEWAY_API_WILDCARD_HOST,
    },
    harness::{Harness, NamespaceGuard, wait},
};
use std::time::Duration;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("coxswain_e2e=debug,warn")
        .try_init();
}

#[tokio::test]
async fn path_matching() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-path").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_PATH_MATCHING, &ns.name, &[]).await?;

    let host = format!("echo.{}.local", ns.name);

    // Wait for the route to become live before asserting individual paths.
    let resp = wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let resp = h.http.get(&host, "/b").await?;
    resp.assert_backend("echo-b");

    // Catch-all rule routes to echo-a.
    let resp = h.http.get(&host, "/").await?;
    resp.assert_backend("echo-a");

    Ok(())
}

#[tokio::test]
async fn host_pool() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-pool").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_HOST_POOL, &ns.name, &[]).await?;

    let host = format!("pool.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Round-robin across echo-a and echo-b — collect enough responses to see both.
    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..20 {
        let resp = h.http.get(&host, "/").await?;
        let pod = resp.pod.as_deref().unwrap_or("");
        if pod.starts_with("echo-a-") {
            saw_a = true;
        }
        if pod.starts_with("echo-b-") {
            saw_b = true;
        }
        if saw_a && saw_b {
            break;
        }
    }
    assert!(saw_a, "never saw echo-a in round-robin pool");
    assert!(saw_b, "never saw echo-b in round-robin pool");

    Ok(())
}

#[tokio::test]
async fn wildcard_host() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-wildcard").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_WILDCARD_HOST, &ns.name, &[]).await?;

    // Any subdomain of *.wildcard.TESTNS.local should reach echo-c.
    let host = format!("foo.wildcard.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-c");

    let host2 = format!("bar.wildcard.{}.local", ns.name);
    let resp2 = h.http.get(&host2, "/").await?;
    resp2.assert_backend("echo-c");

    Ok(())
}

#[tokio::test]
async fn cross_namespace_with_grant() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-xns-tenant").await?;

    // Deploy the backend + ReferenceGrant into the tenant namespace.
    fixtures::apply_fixture(
        GATEWAY_API_CROSS_NAMESPACE_TENANT,
        &tenant.name,
        &[("TESTNS", &ns.name)],
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    // Deploy the Gateway + HTTPRoute into the primary namespace.
    fixtures::apply_fixture(
        GATEWAY_API_CROSS_NAMESPACE_ROUTE,
        &ns.name,
        &[("TENANTNS", &tenant.name)],
    )
    .await?;

    let host = format!("cross-ns.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-d");

    Ok(())
}

#[tokio::test]
async fn cross_namespace_without_grant() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-xns-deny").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-xns-deny-tenant").await?;

    // Deploy tenant backend WITHOUT a ReferenceGrant.
    // Apply only the Deployment + Service from the tenant fixture
    // by stripping the ReferenceGrant via a second apply after deletion.
    fixtures::apply_fixture(
        GATEWAY_API_CROSS_NAMESPACE_TENANT,
        &tenant.name,
        &[("TESTNS", &ns.name)],
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    // Delete the ReferenceGrant that was just applied.
    tokio::process::Command::new("kubectl")
        .args([
            "delete",
            "referencegrant",
            &format!("allow-httproute-from-{}", ns.name),
            "-n",
            &tenant.name,
            "--ignore-not-found",
        ])
        .status()
        .await?;

    fixtures::apply_fixture(
        GATEWAY_API_CROSS_NAMESPACE_ROUTE,
        &ns.name,
        &[("TENANTNS", &tenant.name)],
    )
    .await?;

    let host = format!("cross-ns.{}.local", ns.name);

    // Give the controller time to reconcile; without the grant the host is
    // never added to the routing table, so requests should return 503.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let status = h.http.get_status(&host, "/").await?;
    assert_eq!(
        status, 503,
        "expected 503 without ReferenceGrant, got {status}"
    );

    Ok(())
}
