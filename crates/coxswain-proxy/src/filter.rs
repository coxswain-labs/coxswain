use crate::proxy::ProxyCtx;
use pingora_core::Result;
use pingora_http::RequestHeader;

pub struct TrafficFilter;

impl TrafficFilter {
    pub fn apply_request_filters(
        upstream_request: &mut RequestHeader,
        ctx: &ProxyCtx,
    ) -> Result<()> {
        upstream_request.insert_header(
            "X-Proxy-Engine",
            concat!("Coxswain/", env!("CARGO_PKG_VERSION")),
        )?;

        if let Some(addr) = ctx.real_client_addr {
            let proto = ctx.real_client_proto.unwrap_or("http");
            let for_value = format_forwarded_for(&addr);
            upstream_request
                .insert_header("Forwarded", format!("for=\"{for_value}\";proto={proto}"))?;
        }

        Ok(())
    }
}

/// Format the `for=` component of a Forwarded header per RFC 7239.
///
/// IPv6 addresses are bracketed: `[2001:db8::1]:12345`.
/// IPv4 addresses are not: `198.51.100.42:12345`.
fn format_forwarded_for(addr: &std::net::SocketAddr) -> String {
    match addr {
        std::net::SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        std::net::SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}
