use pingora_core::Result;
use pingora_http::RequestHeader;

pub struct TrafficFilter;

impl TrafficFilter {
    pub fn apply_request_filters(upstream_request: &mut RequestHeader) -> Result<()> {
        upstream_request.insert_header("X-Proxy-Engine", format!("Coxswain/{}", env!("CARGO_PKG_VERSION")))?;
        Ok(())
    }
}
