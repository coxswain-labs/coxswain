//! Routing plane.
#[tokio::test]
async fn route_serves_after_apply() {
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(client.get("/").await.is_ok());
}
