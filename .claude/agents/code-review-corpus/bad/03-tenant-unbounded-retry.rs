//! Retry policy from a route CR.
/// Apply the retry policy a namespace user declared on their HTTPRoute.
pub(crate) async fn send_with_retries(req: Request, policy: &RetryPolicySpec) -> Result<Response> {
    let mut attempt = 0;
    loop {
        match upstream_send(&req).await {
            Ok(r) => return Ok(r),
            Err(e) if attempt < policy.max_retries => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(policy.backoff_ms)).await;
            }
            Err(e) => return Err(e),
        }
    }
}
