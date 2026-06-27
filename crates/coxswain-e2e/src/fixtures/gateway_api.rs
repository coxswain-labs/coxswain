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
/// Two shared-mode Gateways terminating the SAME hostname with different certs,
/// each on its own per-Gateway VIP — cross-Gateway TLS isolation (#472).
pub const TLS_ISOLATION_CROSS_GATEWAY: &str = fixture!("tls_isolation_cross_gateway.yaml");
/// Gateway HTTPS listener with two `certificateRefs` (ECDSA + RSA) — GEP-851 dual-cert.
/// Requires `HOSTNAME`, `ECDSA_SECRET`, `RSA_SECRET`, `ECDSA_CRT_B64`, `ECDSA_KEY_B64`,
/// `RSA_CRT_B64`, `RSA_KEY_B64` substitutions.
pub const TLS_DUAL_CERT: &str = fixture!("tls_dual_cert.yaml");
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
pub const GATEWAY_APP_PROTOCOL_H2C: &str = fixture!("gateway_app_protocol_h2c.yaml");
/// BackendTLSPolicy test: Gateway + HTTPRoute + ConfigMap CA + policy targeting the TLS echo Service.
/// Requires `CA_PEM`, `TLS_HOSTNAME` substitutions.
pub const BACKEND_TLS_POLICY: &str = fixture!("backend_tls_policy.yaml");
/// Gateway + HTTPRoute to the TLS-only echo backend (port 8443) with NO
/// BackendTLSPolicy. The Service declares `appProtocol: https`, which no longer
/// originates upstream TLS (#466) — the proxy connects cleartext and the request
/// fails. Proves a BackendTLSPolicy is required for upstream TLS.
pub const BACKEND_TLS_NO_POLICY: &str = fixture!("backend_tls_no_policy.yaml");
/// h2-over-TLS via BackendTLSPolicy: an `appProtocol: kubernetes.io/h2c` Service over
/// the echo-tls pods + a BackendTLSPolicy. The proxy originates TLS and negotiates
/// HTTP/2 over it (#466). Requires `CA_PEM`, `TLS_HOSTNAME` substitutions.
pub const BACKEND_TLS_H2: &str = fixture!("backend_tls_h2.yaml");

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

/// HTTPRoute with a CORS filter (GEP-1767): `https://allowed.example` is
/// the sole allowed origin; GET and POST are the allowed methods.
/// Hostnamed `cors.${TESTNS}.local`.
pub const CORS: &str = fixture!("cors.yaml");

// ── RequestMirror (#261) ──────────────────────────────────────────────────────

/// Gateway + HTTPRoute with a single `RequestMirror` filter (GEP-3171).
/// Primary backend: echo-a.  Mirror backend: echo-b (100%) and a second rule
/// with `percent: 0` (never mirrors).  Hostnamed `mirror.${TESTNS}.local`.
pub const MIRROR: &str = fixture!("mirror.yaml");

/// Gateway + HTTPRoute with two `RequestMirror` filters on one rule (GEP-3171).
/// Primary: echo-a.  Mirrors: echo-b AND echo-c.
/// Hostnamed `mirror-multi.${TESTNS}.local`.
pub const MIRROR_MULTIPLE: &str = fixture!("mirror_multiple.yaml");

/// Gateway + HTTPRoute with a cross-namespace `RequestMirror` filter (GEP-3171).
/// Primary: echo-a in TESTNS.  Mirror: echo-d in TENANTNS.
/// Pair with [`CROSS_NAMESPACE_TENANT`] (echo-d + ReferenceGrant) applied to TENANTNS.
/// Hostnamed `mirror-xns.${TESTNS}.local`.  Requires `TENANTNS` substitution.
pub const MIRROR_XNS: &str = fixture!("mirror_xns.yaml");

// ── Gateway frontend client-cert mTLS — GEP-91 (#86) ─────────────────────────

/// Gateway + HTTPS listener with `spec.tls.frontend.default.validation`
/// (AllowValidOnly, the GEP-91 default).  CA delivered via a ConfigMap with
/// key `ca.crt`.  Handshakes without a valid client cert are aborted.
/// Hostnamed `${HOSTNAME}`.
/// Placeholders: `HOSTNAME`, `SECRET_NAME`, `TLS_CRT_B64`, `TLS_KEY_B64`, `CA_CRT_PEM`.
pub const FRONTEND_MTLS_CONFIGMAP: &str = fixture!("frontend_mtls_configmap.yaml");

/// Gateway + HTTPS listener with `spec.tls.frontend.default.validation.mode:
/// AllowInsecureFallback` (GEP-91).  Client cert is requested but the handshake
/// is never aborted on a missing or invalid cert.
/// Hostnamed `${HOSTNAME}`.
/// Placeholders: `HOSTNAME`, `SECRET_NAME`, `TLS_CRT_B64`, `TLS_KEY_B64`, `CA_CRT_PEM`.
pub const FRONTEND_MTLS_INSECURE_FALLBACK: &str = fixture!("frontend_mtls_insecure_fallback.yaml");

/// Gateway + HTTPS listener whose `spec.tls.frontend.default.validation`
/// references a ConfigMap (`does-not-exist`) that is absent from the cluster.
/// The controller resolves to `Unavailable` and the proxy fail-closes every
/// TLS handshake on this hostname.
/// Hostnamed `${HOSTNAME}`.
/// Placeholders: `HOSTNAME`, `SECRET_NAME`, `TLS_CRT_B64`, `TLS_KEY_B64`.
pub const FRONTEND_MTLS_MISSING_CA: &str = fixture!("frontend_mtls_missing_ca.yaml");

/// Gateway HTTP listener + HTTPRoute → echo-tls backend + BackendTLSPolicy +
/// `spec.tls.backend.clientCertificateRef` pointing to a `kubernetes.io/tls` Secret.
/// Happy path for GEP-3155 (#87).
/// Placeholders: `TLS_HOSTNAME`, `CA_PEM`, `CLIENT_CERT_B64`, `CLIENT_KEY_B64`.
pub const BACKEND_CLIENT_CERT: &str = fixture!("backend_client_cert.yaml");

/// Gateway with `spec.tls.backend.clientCertificateRef` pointing to a Secret that
/// does not exist — controller must write `ResolvedRefs=False/InvalidClientCertificateRef`.
/// Sad path for GEP-3155 (#87).  No backend deployment needed.
pub const BACKEND_CLIENT_CERT_MISSING_SECRET: &str =
    fixture!("backend_client_cert_missing_secret.yaml");

/// Gateway with an unresolvable `clientCertificateRef` (missing Secret), routing to
/// echo-tls under a BackendTLSPolicy.  The proxy must fail closed (502) rather than
/// connect to the TLS upstream without the configured client identity (GEP-3155, #87).
/// Placeholders: `TLS_HOSTNAME`, `CA_PEM`.
pub const BACKEND_CLIENT_CERT_FAILS_CLOSED: &str =
    fixture!("backend_client_cert_fails_closed.yaml");

// ── TLS passthrough (TLSRoute / GEP-2643, #70) ───────────────────────────────

/// Gateway with `protocol: TLS, tls.mode: Passthrough` + TLSRoute (GEP-2643, #70).
/// The proxy peeks the ClientHello SNI and forwards the raw encrypted stream to
/// the backend — no TLS termination at the proxy.
/// Placeholders: `GATEWAY_TLS_PASSTHROUGH_PORT`, `PASSTHROUGH_HOSTNAME`.
pub const TLS_PASSTHROUGH: &str = fixture!("tls_passthrough.yaml");

/// Gateway with `protocol: TLS, tls.mode: Passthrough` listener only (no TLSRoute).
/// Used to verify the Gateway becomes `Programmed=True` even with zero routes,
/// and that incoming connections are dropped (no backend to forward to).
/// Placeholders: `GATEWAY_TLS_PASSTHROUGH_PORT`, `PASSTHROUGH_HOSTNAME`.
pub const TLS_PASSTHROUGH_GW_ONLY: &str = fixture!("tls_passthrough_gw_only.yaml");
