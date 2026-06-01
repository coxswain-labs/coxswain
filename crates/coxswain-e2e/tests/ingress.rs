use coxswain_e2e::{
    fixtures::{self, BACKENDS_ECHO, INGRESS_PATH_MATCHING},
    harness::{wait, Harness, NamespaceGuard},
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
    let ns = NamespaceGuard::create(&h.client, "ing-path").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    fixtures::apply_fixture(INGRESS_PATH_MATCHING, &ns.name, &[]).await?;

    let host = format!("ingress.{}.local", ns.name);

    let resp = wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let resp = h.http.get(&host, "/b").await?;
    resp.assert_backend("echo-b");

    Ok(())
}
