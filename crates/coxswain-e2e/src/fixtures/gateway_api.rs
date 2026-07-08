//! YAML fixture paths for Gateway API HTTPRoute and Gateway tests.

macro_rules! fixture {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/gateway_api/", $path)
    };
}

/// HTTPRoute path-based routing rules.
pub const PATH_MATCHING: &str = fixture!("path_matching.yaml");
/// HTTPRoute (#504) with a first rule named `named-rule` (matches `/a`) and a
/// second unnamed rule (matches `/b`). Hostnamed
/// `http-named-rule.${TESTNS}.local`. Backends: `echo-a`/`echo-b` (via
/// `backends::ECHO`).
pub const HTTP_ROUTE_NAMED_RULE: &str = fixture!("http_route_named_rule.yaml");
/// HTTPRoute whose rules omit / empty their `backendRefs` (#517). One rule has
/// real backends (routes 200); one omits `backendRefs`; one sets it to `[]`.
/// Both no-backend rules must return a distinct 500, not a 404.
/// Placeholders: `TESTNS`.
pub const HTTPROUTE_NO_BACKEND_REFS: &str = fixture!("httproute_no_backend_refs.yaml");

/// Two shared-pool Gateways for `parametersRef` validation (#517): `coxswain-clean`
/// (no `parametersRef` → Accepted=True) and `coxswain-bad-params` (a foreign
/// `parametersRef` kind → Accepted=False/InvalidParameters). Status-only.
pub const GATEWAY_INVALID_PARAMS_REF: &str = fixture!("gateway_invalid_params_ref.yaml");

/// Two Gateways for listener-protocol validation (#517): `coxswain-all-bad`
/// (one unsupported-protocol listener → Gateway Accepted=False/ListenersNotValid)
/// and `coxswain-mixed` (one HTTP + one unsupported → Gateway
/// Accepted=True/ListenersNotValid). Status-only.
pub const GATEWAY_UNSUPPORTED_PROTOCOL: &str = fixture!("gateway_unsupported_protocol.yaml");
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
/// GEP-1713: Gateway opting into same-ns ListenerSets + a ListenerSet adding a
/// listener on a NEW port (8001) + an HTTPRoute attaching via `parentRef.kind:
/// ListenerSet`. Happy path for ListenerSet routing + new-port provisioning.
pub const LISTENERSET_BASIC: &str = fixture!("listenerset_basic.yaml");
/// GEP-1713 sad path: the Gateway sets no `allowedListeners` (defaults to None),
/// so the ListenerSet is rejected (`Accepted=False/NotAllowed`).
pub const LISTENERSET_OPT_OUT: &str = fixture!("listenerset_opt_out.yaml");
/// GEP-1713: a Gateway listener and a ListenerSet listener share the name "web"
/// on different ports; both must program (provenance-keyed health).
pub const LISTENERSET_DUPLICATE_NAME: &str = fixture!("listenerset_duplicate_name.yaml");
/// GEP-1713 conflict-with-survivor: a ListenerSet with one listener that loses a
/// hostname conflict to the parent Gateway and one that programs cleanly. The
/// set must stay `Accepted=True`/`Programmed=True` despite the losing listener.
pub const LISTENERSET_CONFLICT: &str = fixture!("listenerset_conflict.yaml");
/// GEP-1713 `ListenerSetAllowedRoutesCrossNamespace` (#515), primary namespace
/// side: a Gateway + ListenerSet `team-ls` with two listeners, `ls-same`
/// (`allowedRoutes.namespaces: Same`, the ListenerSet's OWN namespace) and
/// `ls-all` (`allowedRoutes.namespaces: All`). Pair with
/// [`LISTENERSET_XNS_TENANT`] applied to a separate namespace.
pub const LISTENERSET_XNS_ROUTE: &str = fixture!("listenerset_xns_route.yaml");
/// GEP-1713 `ListenerSetAllowedRoutesCrossNamespace` (#515), tenant namespace
/// side: two HTTPRoutes targeting `team-ls`'s listeners by `sectionName`.
/// `xns-route-same` (targets `ls-same`) must be rejected
/// (`Accepted=False/NotAllowedByListeners`); `xns-route-all` (targets
/// `ls-all`) must be accepted. Requires `TESTNS` substitution.
pub const LISTENERSET_XNS_TENANT: &str = fixture!("listenerset_xns_tenant.yaml");
/// GEP-1713 `ListenerSetAllowedRoutesSupportedKinds` (#515): a ListenerSet with
/// two TLS-passthrough listeners — `ls-bad-kind` restricts `allowedRoutes.kinds`
/// to `HTTPRoute` (incompatible with its `TLS` protocol, which only ever
/// carries `TLSRoute`) and must report `ResolvedRefs=False/InvalidRouteKinds`;
/// `ls-good-kind` restricts to the matching `TLSRoute` kind and must report
/// `ResolvedRefs=True`. Asserted purely from listener config — no route needs
/// to attach.
pub const LISTENERSET_KIND_RESTRICTION: &str = fixture!("listenerset_kind_restriction.yaml");
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

/// BackendTLSPolicy with `subjectAltNames` (GEP-1897 Extended, #133).
/// Requires `TLS_HOSTNAME`, `CA_PEM`, `SPIFFE_URI`.
/// Shared by the happy (matching URI) and sad (wrong URI) paths.
pub const BACKEND_TLS_POLICY_SAN: &str = fixture!("backend_tls_policy_san.yaml");

/// CoxswainBackendPolicy with `spec.timeouts.connect: 500ms` attached to a
/// black-holed Service (192.0.2.1) behind a Gateway-API HTTPRoute (#354). Proves
/// the per-backend connect timeout reaches a Gateway-API upstream → prompt 502.
pub const BACKEND_POLICY_CONNECT_TIMEOUT: &str = fixture!("backend_policy_connect_timeout.yaml");

/// CoxswainBackendPolicy with an unparseable `spec.timeouts.connect` attached to
/// the reachable echo-a Service (#354). Proves the bad value WARNs and falls back
/// to default behaviour → route still returns 200. Depends on `backends::ECHO`.
pub const BACKEND_POLICY_INVALID_TIMEOUT: &str = fixture!("backend_policy_invalid_timeout.yaml");

/// CoxswainBackendPolicy with `spec.loadBalancer.algorithm: least_conn` attached
/// to the shared `lb-pool` Service behind a Gateway-API HTTPRoute (#389). Proves
/// the LB algorithm reaches a Gateway-API upstream → traffic skews to the idle
/// endpoint. Depends on `backends::LB_MIXED`.
pub const BACKEND_POLICY_LEAST_CONN: &str = fixture!("backend_policy_least_conn.yaml");

/// CoxswainBackendPolicy with an unrecognised `spec.loadBalancer.algorithm`
/// attached to the reachable echo-a Service (#389). Proves the bad value WARNs and
/// falls back to round-robin → route still returns 200. Depends on `backends::ECHO`.
pub const BACKEND_POLICY_INVALID_LOAD_BALANCE: &str =
    fixture!("backend_policy_invalid_load_balance.yaml");

/// CoxswainBackendPolicy with `spec.circuitBreaker` (threshold 50%, window 500ms,
/// open 2s, min-requests 4) attached to the go-httpbin Service behind a
/// Gateway-API HTTPRoute (#478). Drives the breaker open/recover tests. Depends on
/// `backends::GO_HTTPBIN`.
pub const BACKEND_POLICY_CIRCUIT_BREAKER: &str = fixture!("backend_policy_circuit_breaker.yaml");

/// CoxswainBackendPolicy with an out-of-range `spec.circuitBreaker.threshold: 0`
/// attached to the go-httpbin Service (#478). Proves the disabled gate WARNs and
/// installs no breaker → upstream 500s pass through (never a fail-fast 503).
/// Depends on `backends::GO_HTTPBIN`.
pub const BACKEND_POLICY_INVALID_CIRCUIT_BREAKER: &str =
    fixture!("backend_policy_invalid_circuit_breaker.yaml");

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
/// Gateway + `IpAccessControl` CR (allow-list only) + HTTPRoute with an
/// `ExtensionRef`, plus a `ClientTrafficPolicy` enabling PROXY protocol so the
/// synthetic client IP can be injected (#479). Clients in `203.0.113.0/24` pass;
/// all others get 403.
pub const IP_ACCESS_ALLOW: &str = fixture!("ip_access_allow.yaml");
/// Gateway + `IpAccessControl` CR (deny-list only) + HTTPRoute + PROXY-protocol
/// `ClientTrafficPolicy` (#479). Clients in `203.0.113.0/24` get 403; with no
/// allow-list, every other source IP is admitted.
pub const IP_ACCESS_DENY: &str = fixture!("ip_access_deny.yaml");
/// Gateway + `IpAccessControl` CR listing `203.0.113.0/24` in BOTH allow and
/// deny + HTTPRoute + PROXY-protocol `ClientTrafficPolicy` (#479). Verifies deny
/// is evaluated before allow: a client in that range is rejected 403.
pub const IP_ACCESS_DENY_PRECEDENCE: &str = fixture!("ip_access_deny_precedence.yaml");
/// Gateway + GRPCRoute (`GrpcEcho/Echo`) + `IpAccessControl` allow-list covering
/// all sources (`0.0.0.0/0`, `::/0`) via `ExtensionRef` (#479 gRPC happy path).
/// The real client IP is admitted, so the gRPC call reaches `grpc-echo`.
pub const GRPC_IP_ACCESS_ALLOW: &str = fixture!("grpc_ip_access_allow.yaml");
/// Gateway + GRPCRoute + `IpAccessControl` allow-list of only `203.0.113.0/24`
/// (TEST-NET-3) via `ExtensionRef` (#479 gRPC sad path). The real client IP is
/// outside the range, so the gRPC call is rejected before the backend.
pub const GRPC_IP_ACCESS_RESTRICTED: &str = fixture!("grpc_ip_access_restricted.yaml");
/// Gateway + GRPCRoute + `RateLimit` (rps=1) via `ExtensionRef` (#25 gRPC
/// parity). The first call is served; rapid follow-ups are rejected.
pub const GRPC_RATE_LIMIT: &str = fixture!("grpc_rate_limit.yaml");
/// Gateway + `RetryPolicy` CR (attempts=2, codes=[503], backoff=200ms) + HTTPRoute
/// `ExtensionRef` (#445 HTTP happy path). Routes to go-httpbin `/status/503`; the
/// proxy fires two retries (observable via the retry metric) with backoff before the
/// final 503. Apply `backends::GO_HTTPBIN` first.
pub const RETRY_HTTP: &str = fixture!("retry_http.yaml");
/// Gateway + `RetryPolicy` CR (codes=[500]) + HTTPRoute `ExtensionRef` (#445 HTTP sad
/// path). Backend returns 503, which is not in the code set, so no retry fires. Apply
/// `backends::GO_HTTPBIN` first.
pub const RETRY_HTTP_NON_RETRIABLE: &str = fixture!("retry_http_non_retriable.yaml");
/// Gateway + `RetryPolicy` CR (attempts=2, grpcCodes=[12]) + GRPCRoute `ExtensionRef`
/// (#445 gRPC happy path). A call to a non-existent method yields trailers-only
/// UNIMPLEMENTED, which the proxy retries (grpc-aware). Apply `backends::GRPC_ECHO` first.
pub const RETRY_GRPC: &str = fixture!("retry_grpc.yaml");
/// Gateway + `RetryPolicy` CR (grpcCodes=[14]) + GRPCRoute `ExtensionRef` (#445 gRPC
/// sad path). UNIMPLEMENTED (12) is not in the set, so no retry fires. Apply
/// `backends::GRPC_ECHO` first.
pub const RETRY_GRPC_NON_RETRIABLE: &str = fixture!("retry_grpc_non_retriable.yaml");
/// Gateway + `BasicAuth` CR (labeled htpasswd Secret, alice:secret bcrypt) +
/// HTTPRoute with `ExtensionRef` (#442). Valid `Authorization: Basic`
/// credentials are admitted; missing/invalid credentials get 401.
pub const BASIC_AUTH_EXTENSIONREF: &str = fixture!("basic_auth_extensionref.yaml");
/// Gateway + `CoxswainExternalAuth` (HTTP, auth-allow:4000) + HTTPRoute with an
/// `ExtensionRef` filter (#23 happy path). The ext_authz check allows → echo-a.
pub const EXTERNAL_AUTH_ROUTE_ALLOW: &str = fixture!("external_auth_route_allow.yaml");
/// Gateway + `CoxswainExternalAuth` (HTTP, auth-deny:4001) + HTTPRoute with an
/// `ExtensionRef` filter (#23 sad path). The ext_authz check denies → 403.
pub const EXTERNAL_AUTH_ROUTE_DENY: &str = fixture!("external_auth_route_deny.yaml");
/// Gateway with a `CoxswainExternalAuth` `targetRefs` mandate (auth-deny) plus a
/// route whose own `ExtensionRef` filter would allow (#23). Proves the mandate
/// applies to every route and is additive — a route cannot weaken it (both hosts
/// return 403).
pub const EXTERNAL_AUTH_GATEWAY_ADDITIVE: &str = fixture!("external_auth_gateway_additive.yaml");
/// Gateway + `CoxswainExternalAuth` (protocol: GRPC, `ext-authz-grpc:9000`) +
/// HTTPRoute `ExtensionRef` (#23 gRPC transport). Allowed with `x-ext-authz:
/// allow`, denied (403) otherwise. Apply `backends::EXT_AUTHZ_GRPC` first.
pub const EXTERNAL_AUTH_GRPC: &str = fixture!("external_auth_grpc.yaml");
/// Gateway + `BasicAuth` CR referencing an UNLABELED htpasswd Secret +
/// HTTPRoute with `ExtensionRef` (#442 sad path). The reflector never loads
/// the Secret, so the proxy fails closed with 503 even for valid credentials.
pub const BASIC_AUTH_EXTENSIONREF_UNLABELED: &str =
    fixture!("basic_auth_extensionref_unlabeled.yaml");
/// Tenant-side of the cross-namespace `BasicAuth` secretRef pair (#520): the
/// htpasswd Secret + a `BasicAuth → Secret` ReferenceGrant permitting a
/// `BasicAuth` CR in `TESTNS`. Apply to the tenant namespace with
/// `.with("TESTNS", <route-ns>)`. Pair with [`BASIC_AUTH_XNS_ROUTE`].
pub const BASIC_AUTH_XNS_TENANT: &str = fixture!("basic_auth_xns_tenant.yaml");
/// Route-side of the cross-namespace `BasicAuth` secretRef pair (#520): Gateway +
/// `BasicAuth` CR whose `secretRef.namespace` is `TENANTNS` + HTTPRoute. Apply to
/// the route namespace with `.with("TENANTNS", <tenant-ns>)`. Without the
/// ReferenceGrant from [`BASIC_AUTH_XNS_TENANT`] the proxy fails closed (503).
pub const BASIC_AUTH_XNS_ROUTE: &str = fixture!("basic_auth_xns_route.yaml");
/// Gateway + `RequestSizeLimit` CR (maxSize: 1k) + HTTPRoute with
/// `ExtensionRef` (#443). Under-limit bodies pass; over-limit bodies get 413.
pub const REQUEST_SIZE_LIMIT_EXTENSIONREF: &str = fixture!("request_size_limit_extensionref.yaml");
/// Gateway + GRPCRoute + `RequestSizeLimit` (maxSize: 1k) via `ExtensionRef`
/// (#443 GRPCRoute parity). Proves the byte cap applies to gRPC (HTTP/2)
/// message bodies too.
pub const REQUEST_SIZE_LIMIT_GRPCROUTE: &str = fixture!("request_size_limit_grpcroute.yaml");
/// Gateway + `Compression` CR (gzip+brotli) + HTTPRoute with `ExtensionRef`
/// (#446). Verifies `Content-Encoding`/`Vary` negotiation and the
/// `application/grpc` passthrough guard.
pub const COMPRESSION_EXTENSIONREF: &str = fixture!("compression_extensionref.yaml");
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

/// GatewayStaticAddresses (#260): a shared Gateway requesting a single static
/// address. Templated `ADDR_TYPE`/`ADDR_VALUE` cover the unsupported-type,
/// out-of-CIDR-IP, and probed-free-clusterIP cases.
pub const STATIC_ADDRESS: &str = fixture!("gateway_static_address.yaml");
/// GatewayStaticAddresses (#260): a shared Gateway requesting two distinct
/// static IPs (`ADDR_ONE`/`ADDR_TWO`) — never all satisfiable by one Service.
pub const STATIC_ADDRESSES_PAIR: &str = fixture!("gateway_static_addresses_pair.yaml");

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

/// Gateway + GRPCRoute (#504) with a first rule named `named-rule` (matches
/// `GrpcEcho/Echo`) and a second unnamed rule (matches `GrpcEcho/EchoTwo`).
/// Both resolve to the `grpc-echo` backend. Hostnamed
/// `grpc-named-rule.${TESTNS}.local`.
pub const GRPC_ROUTE_NAMED_RULE: &str = fixture!("grpc_route_named_rule.yaml");

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

/// Gateway with TWO HTTPS listeners on different ports, each validating client
/// certs against a different CA: listener A via `spec.tls.frontend.default`, and
/// listener B (on `${PORT_B}`) via `spec.tls.frontend.perPort`. Guards the
/// per-port enforcement regression from #517 — a cert signed by the default CA
/// must be rejected on listener B.
/// Placeholders: `HOSTNAME_A`, `HOSTNAME_B`, `PORT_B`, `SECRET_A`, `SECRET_B`,
/// `TLS_CRT_A_B64`, `TLS_KEY_A_B64`, `TLS_CRT_B_B64`, `TLS_KEY_B_B64`,
/// `CA_A_PEM`, `CA_B_PEM`.
pub const FRONTEND_MTLS_PER_PORT: &str = fixture!("frontend_mtls_per_port.yaml");

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

// ── TLS terminate (TLSRouteModeTerminate, #481) ───────────────────────────────

/// Gateway with `protocol: TLS, tls.mode: Terminate` + TLSRoute to a plaintext backend.
/// The proxy terminates TLS using the listener cert and L4-splices to the backend.
/// Placeholders: `GATEWAY_TLS_PASSTHROUGH_PORT`, `TERMINATE_HOSTNAME`,
///               `GW_TLS_CRT_B64`, `GW_TLS_KEY_B64`.
pub const TLS_TERMINATE: &str = fixture!("tls_terminate.yaml");

/// One Gateway with both a Terminate and a Passthrough TLS listener on the same port.
/// Disambiguated by SNI; each routes to its own isolated backend (TLSRouteModeMixed, #481).
/// Placeholders: `GATEWAY_TLS_PASSTHROUGH_PORT`, `TERMINATE_HOSTNAME`, `PASSTHROUGH_HOSTNAME`,
///               `GW_TLS_CRT_B64`, `GW_TLS_KEY_B64`.
pub const TLS_MIXED: &str = fixture!("tls_mixed.yaml");

/// Gateway-scoped `ClientTrafficPolicy` enabling PROXY protocol.
/// Substitutions: `CTP_NAME`, `GATEWAY_NAME`, `TRUSTED_SOURCES` (CIDR).
pub const CLIENT_TRAFFIC_POLICY: &str = fixture!("client_traffic_policy.yaml");

/// Two section-scoped `ClientTrafficPolicy` resources on the same listener (conflict test).
/// Substitutions: `GATEWAY_NAME`, `SECTION_NAME`.
pub const CLIENT_TRAFFIC_POLICY_CONFLICT: &str = fixture!("client_traffic_policy_conflict.yaml");
