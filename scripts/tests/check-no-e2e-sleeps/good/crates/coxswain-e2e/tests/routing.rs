//! Routing plane.
#[tokio::test]
async fn route_serves_after_apply() {
    wait::poll_until(Duration::from_secs(30), POLL, || async { "route to serve".into() },
        || async { client.get("/").await.ok() }).await.unwrap();
}
