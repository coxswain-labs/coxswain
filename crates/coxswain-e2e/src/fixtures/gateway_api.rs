//! YAML fixture paths for Gateway API HTTPRoute and Gateway tests.

macro_rules! fixture {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/gateway_api/", $path)
    };
}

/// HTTPRoute path-based routing rules.
pub const PATH_MATCHING: &str = fixture!("path_matching.yaml");
/// HTTPRoute with multiple backends pooled into a single upstream.
pub const HOST_POOL: &str = fixture!("host_pool.yaml");
/// HTTPRoute with a wildcard hostname listener.
pub const WILDCARD_HOST: &str = fixture!("wildcard_host.yaml");
/// HTTPRoute in namespace A referencing a backend in namespace B (route side).
pub const CROSS_NAMESPACE_ROUTE: &str = fixture!("cross_namespace_route.yaml");
/// `ReferenceGrant` and backend for the cross-namespace route test (tenant side).
pub const CROSS_NAMESPACE_TENANT: &str = fixture!("cross_namespace_tenant.yaml");
/// HTTPRoute header-match rules.
pub const HEADER_MATCHING: &str = fixture!("header_matching.yaml");
/// HTTPRoute method-match rules.
pub const METHOD_MATCHING: &str = fixture!("method_matching.yaml");
/// HTTPRoute query-parameter-match rules.
pub const QUERY_PARAM_MATCHING: &str = fixture!("query_param_matching.yaml");
/// HTTPRoute combining header, method, and query-parameter matches.
pub const COMBINED_MATCHING: &str = fixture!("combined_matching.yaml");
/// Gateway HTTPS listener with TLS termination via a Secret.
pub const TLS_TERMINATION: &str = fixture!("tls_termination.yaml");
/// Gateway HTTPS listener with no `certificateRefs` (tests error status).
pub const TLS_GATEWAY_NO_CERTS: &str = fixture!("tls_gateway_no_certs.yaml");
/// Gateway in namespace A with a TLS listener referencing a Secret in namespace B (gateway side).
pub const TLS_CROSS_NAMESPACE_GW: &str = fixture!("tls_cross_namespace_gw.yaml");
/// `ReferenceGrant` and Secret for the cross-namespace TLS test (cert side).
pub const TLS_CROSS_NAMESPACE_CERTS: &str = fixture!("tls_cross_namespace_certs.yaml");
/// Gateway with cert-manager `Certificate` and `ClusterIssuer` integration.
pub const CERT_MANAGER: &str = fixture!("cert_manager.yaml");
/// WebSocket echo route for protocol-upgrade tests.
pub const WEBSOCKET: &str = fixture!("websocket.yaml");
/// HTTPRoute with `URLRewrite`, `RequestRedirect`, and header-modifier filters.
pub const FILTERS: &str = fixture!("filters.yaml");
/// HTTPRoute with `timeouts.request` and `timeouts.backendRequest` set.
pub const TIMEOUTS: &str = fixture!("timeouts.yaml");
/// HTTPRoute triggering an HTTP-to-HTTPS redirect via `RequestRedirect`.
pub const TLS_REDIRECT: &str = fixture!("tls_redirect.yaml");
/// HTTPRoute with weighted `backendRefs` (traffic splitting).
pub const WEIGHTED_SPLIT: &str = fixture!("weighted_split.yaml");
/// EndpointSlice drain test: marks an endpoint as `serving=false` mid-request.
pub const SERVING_DRAIN: &str = fixture!("serving_drain.yaml");
/// HTTPRoute with a `parentRef.port` selector.
pub const PARENT_REF_PORT: &str = fixture!("parent_ref_port.yaml");
/// HTTPRoute backend using `kubernetes.io/h2c` app protocol.
pub const BACKEND_PROTOCOL_H2C: &str = fixture!("backend_protocol_h2c.yaml");
/// BackendTLSPolicy test: Gateway + HTTPRoute + ConfigMap CA + policy targeting the TLS echo Service.
/// Requires `CA_PEM`, `TLS_HOSTNAME` substitutions.
pub const BACKEND_TLS_POLICY: &str = fixture!("backend_tls_policy.yaml");

/// BackendTLSPolicy with an invalid CA cert ref (ConfigMap that does NOT exist).
/// Used to verify `Accepted=False/NoValidCACertificate` + 5xx routing.
pub const BACKEND_TLS_POLICY_INVALID_CA: &str = fixture!("backend_tls_policy_invalid_ca.yaml");

/// BackendTLSPolicy section-name routing: two policies (with + without `sectionName`)
/// against a dual-port Service. Requires `SNI_PRIMARY`, `SNI_SECONDARY`, `CA_PEM`.
pub const BACKEND_TLS_POLICY_SECTION_NAME: &str = fixture!("backend_tls_policy_section_name.yaml");

/// BackendTLSPolicy conflict resolution: two policies on the same Service with NO
/// `sectionName`. Requires `TLS_HOSTNAME`, `CA_PEM`.
pub const BACKEND_TLS_POLICY_CONFLICT: &str = fixture!("backend_tls_policy_conflict.yaml");

/// Minimal single-listener Gateway used by the listener-drain traffic tests (#231).
/// Declares one HTTP listener on `GATEWAY_HTTP_PORT`.
pub const LISTENER_DRAIN: &str = fixture!("listener_drain.yaml");
