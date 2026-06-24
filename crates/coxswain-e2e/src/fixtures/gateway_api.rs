//! YAML fixture paths for Gateway API HTTPRoute and Gateway tests.

macro_rules! fixture {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/gateway_api/", $path)
    };
}

/// HTTPRoute path-based routing rules.
pub const PATH_MATCHING: &str = fixture!("path_matching.yaml");
/// One Gateway with two HTTPRoutes — a resolvable backend and a missing one —
/// for asserting per-parent `ResolvedRefs` (`True` vs `False/BackendNotFound`)
/// while both stay `Accepted=True`.
pub const ROUTE_STATUS_BACKENDS: &str = fixture!("route_status_backends.yaml");
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

/// Gateway + `RateLimit` CRD + HTTPRoute with `ExtensionRef` capping the
/// `/rl/` path to 1 req/s (#25). Used to verify the proxy enforces the limit
/// (within-quota → 200; over-quota → 429 + `Retry-After`).
pub const RATE_LIMIT_EXTENSIONREF: &str = fixture!("rate_limit_extensionref.yaml");
/// Gateway + HTTPRoute with a dangling `ExtensionRef` pointing at a
/// `RateLimit` CR that does not exist (#25). Used to verify fail-open:
/// the missing CR is ignored (warn) and all traffic is served.
pub const RATE_LIMIT_MISSING_CR: &str = fixture!("rate_limit_missing_cr.yaml");
/// Dedicated-mode Gateway whose `CoxswainGatewayParameters` references an
/// image that cannot be pulled (#210). The dedicated proxy Pod never becomes
/// Ready, so the operator never publishes `DedicatedProxyReady=True` and the
/// shared pool must keep serving. Declares one HTTP listener on
/// `GATEWAY_HTTP_PORT`.
pub const CUTOVER_CRASH_LOOP: &str = fixture!("cutover_crash_loop.yaml");

/// HTTPRoute host rewrite.
pub const HOST_REWRITE: &str = fixture!("host_rewrite.yaml");

/// HTTPRoute redirect status codes.
pub const REDIRECT_STATUS_CODES: &str = fixture!("redirect_status_codes.yaml");

/// Gateway empty address.
pub const EMPTY_ADDRESS: &str = fixture!("empty_address.yaml");

/// BackendTLSPolicy cross-namespace.
pub const BACKEND_TLS_POLICY_CROSS_NAMESPACE_ROUTE: &str =
    fixture!("backend_tls_policy_cross_namespace_route.yaml");
/// BackendTLSPolicy cross-namespace (tenant side).
pub const BACKEND_TLS_POLICY_CROSS_NAMESPACE_TENANT: &str =
    fixture!("backend_tls_policy_cross_namespace_tenant.yaml");

// ── path-normalize (#280) ─────────────────────────────────────────────────────

/// Default `base` normalization applies to Gateway API HTTPRoutes with no
/// per-route annotation. Used to verify that `%2E%2E` encoded dot-dot segments
/// are decoded and removed so the route `/v1` is reachable via `/api/%2E%2E/v1`.
pub const PATH_NORMALIZE_DEFAULT: &str = fixture!("path_normalize_default.yaml");

// ── CRD openAPIV3Schema rejection (#335) ─────────────────────────────────────

/// Gateway with `port: 99999` — rejected by the gateway-api CRD schema
/// (`port` has `maximum: 65535` in the structural schema).
pub const REJECT_GATEWAY_OUT_OF_RANGE_PORT: &str =
    fixture!("reject_gateway_out_of_range_port.yaml");

/// HTTPRoute with `path.type: Glob` — rejected by the gateway-api CRD schema
/// (`Glob` is not in the enum `{Exact, PathPrefix, RegularExpression}`).
pub const REJECT_HTTPROUTE_INVALID_PATH_TYPE: &str =
    fixture!("reject_httproute_invalid_path_type.yaml");

// ── GRPCRoute (#33) ──────────────────────────────────────────────────────────

/// Gateway + GRPCRoute with an exact `service`+`method` match on
/// `gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo`.
/// Hostnamed `grpc-echo.${TESTNS}.local`. Backend: `grpc-echo:50051` (h2c).
pub const GRPC_ROUTE_EXACT_METHOD: &str = fixture!("grpc_route_exact_method.yaml");

/// Gateway + two GRPCRoutes: `good-grpc-route` (resolvable backend) and
/// `ghost-grpc-route` (missing backend). Used for status-condition assertions.
pub const GRPC_ROUTE_STATUS: &str = fixture!("grpc_route_status.yaml");

/// `RateLimit` CR with `requestsPerSecond` omitted — rejected by the
/// coxswain-owned CRD schema (`requestsPerSecond` is a required field).
pub const REJECT_RATELIMIT_MISSING_RPS: &str = fixture!("reject_ratelimit_missing_rps.yaml");
