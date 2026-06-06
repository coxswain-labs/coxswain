macro_rules! fixture {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/gateway_api/", $path)
    };
}

pub const PATH_MATCHING: &str = fixture!("path_matching.yaml");
pub const HOST_POOL: &str = fixture!("host_pool.yaml");
pub const WILDCARD_HOST: &str = fixture!("wildcard_host.yaml");
pub const CROSS_NAMESPACE_ROUTE: &str = fixture!("cross_namespace_route.yaml");
pub const CROSS_NAMESPACE_TENANT: &str = fixture!("cross_namespace_tenant.yaml");
pub const HEADER_MATCHING: &str = fixture!("header_matching.yaml");
pub const METHOD_MATCHING: &str = fixture!("method_matching.yaml");
pub const QUERY_PARAM_MATCHING: &str = fixture!("query_param_matching.yaml");
pub const COMBINED_MATCHING: &str = fixture!("combined_matching.yaml");
pub const TLS_TERMINATION: &str = fixture!("tls_termination.yaml");
pub const TLS_GATEWAY_NO_CERTS: &str = fixture!("tls_gateway_no_certs.yaml");
pub const TLS_CROSS_NAMESPACE_GW: &str = fixture!("tls_cross_namespace_gw.yaml");
pub const TLS_CROSS_NAMESPACE_CERTS: &str = fixture!("tls_cross_namespace_certs.yaml");
pub const CERT_MANAGER: &str = fixture!("cert_manager.yaml");
pub const WEBSOCKET: &str = fixture!("websocket.yaml");
pub const FILTERS: &str = fixture!("filters.yaml");
pub const TIMEOUTS: &str = fixture!("timeouts.yaml");
pub const TLS_REDIRECT: &str = fixture!("tls_redirect.yaml");
pub const WEIGHTED_SPLIT: &str = fixture!("weighted_split.yaml");
pub const SERVING_DRAIN: &str = fixture!("serving_drain.yaml");
pub const PARENT_REF_PORT: &str = fixture!("parent_ref_port.yaml");
pub const BACKEND_PROTOCOL_H2C: &str = fixture!("backend_protocol_h2c.yaml");
