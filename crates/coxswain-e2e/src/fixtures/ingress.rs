//! YAML fixture paths for classic Kubernetes Ingress tests.

macro_rules! fixture {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/ingress/", $path)
    };
}

/// Ingress with path-based routing rules.
pub const PATH_MATCHING: &str = fixture!("path_matching.yaml");
/// Two Ingresses: one claiming our `coxswain` class (owned) and one claiming a
/// foreign class (unowned). Exercises the status-writer ownership negative —
/// the foreign Ingress must never receive a `loadBalancer` status patch.
pub const FOREIGN_CLASS: &str = fixture!("foreign_class.yaml");
/// Ingress with a `spec.defaultBackend` alongside normal rules.
pub const DEFAULT_BACKEND: &str = fixture!("default_backend.yaml");
/// Ingress with only `spec.defaultBackend` and no rules.
pub const DEFAULT_BACKEND_ONLY: &str = fixture!("default_backend_only.yaml");
/// Ingress with `spec.tls[]` for HTTPS termination.
pub const TLS_TERMINATION: &str = fixture!("tls_termination.yaml");
/// Ingress with a `spec.tls[]` entry that has no `hosts` list.
pub const TLS_NO_HOSTS: &str = fixture!("tls_no_hosts.yaml");
/// Ingress with cert-manager `Certificate` integration.
pub const CERT_MANAGER: &str = fixture!("cert_manager.yaml");
/// Ingress with a wildcard hostname rule.
pub const WILDCARD_HOST: &str = fixture!("wildcard_host.yaml");
/// Ingress with a named service port (tests port-name resolution).
pub const NAMED_PORT: &str = fixture!("named_port.yaml");
/// IngressClass annotated `is-default-class: "true"` for default-class tests.
pub const DEFAULT_CLASS: &str = fixture!("default_class.yaml");
/// Ingress whose backend Service has zero ready endpoints (dead route / 503),
/// for the `/api/v1/problems` dead-backend route-identity test.
pub const PROBLEMS_DEAD_BACKEND: &str = fixture!("problems_dead_backend.yaml");
/// Ingress whose `/shadow/` rule is shadowed by its `/shadow` rule (routing
/// conflict), for the `/api/v1/problems` conflict route-identity test.
pub const PROBLEMS_CONFLICT: &str = fixture!("problems_conflict.yaml");
/// Ingress with `ingress.coxswain-labs.dev/rewrite-target` annotation.
/// Used to verify that the upstream request path is replaced by the annotation value.
pub const ANNOTATION_REWRITE_TARGET: &str = fixture!("annotation_rewrite_target.yaml");
/// `ingress.coxswain-labs.dev/use-regex` (#265): four Ingresses on distinct hosts —
/// regex matching with a sibling prefix path, capture-group `rewrite-target`, an
/// invalid pattern that skips only its own path, and an Ingress without the opt-in
/// whose `ImplementationSpecific` path stays a literal Prefix.
pub const USE_REGEX: &str = fixture!("regex_path.yaml");
/// Ingress with `max-retries: 2` and `retry-on: connect-failure` annotations,
/// backed by a Service whose endpoints refuse connections (wrong port on real pods).
/// Used to verify that connect-failure retries fire and the route returns 502.
pub const ANNOTATION_CONNECT_RETRY: &str = fixture!("annotation_connect_retry.yaml");
/// Ingress with `connect-timeout: 500ms`, backed by a Service whose single
/// EndpointSlice address (`192.0.2.1`, RFC 5737) black-holes the TCP connect.
/// Used to verify the annotation shortens the connect deadline (prompt 502).
pub const ANNOTATION_CONNECT_TIMEOUT: &str = fixture!("annotation_connect_timeout.yaml");
/// Ingress with `read-timeout: 500ms` pointed at the slow-echo backend (accepts
/// TCP, never responds). Used to verify the annotation shortens the upstream-read
/// deadline (prompt 502).
pub const ANNOTATION_READ_TIMEOUT: &str = fixture!("annotation_read_timeout.yaml");
/// Two Ingresses sharing an appProtocol-less Service on the h2c-only port 3001:
/// one with `backend-protocol: GRPC` (proxy speaks h2c → serves), one with no
/// annotation (proxy speaks HTTP/1.1 → rejected). Reuses the h2c-echo Deployment.
pub const ANNOTATION_BACKEND_PROTOCOL: &str = fixture!("annotation_backend_protocol.yaml");
/// Ingress with `ingress.coxswain-labs.dev/request-header-{set,add,remove}` annotations.
/// Used to verify that request headers are set, added, and removed before forwarding.
pub const ANNOTATION_REQUEST_HEADERS: &str = fixture!("annotation_request_headers.yaml");
/// Ingress with `ingress.coxswain-labs.dev/response-header-{set,add,remove}` annotations.
/// Used to verify that response headers are set, added, and removed before delivering to client.
pub const ANNOTATION_RESPONSE_HEADERS: &str = fixture!("annotation_response_headers.yaml");
/// Ingress with `ingress.coxswain-labs.dev/redirect-{scheme,hostname,port,path,status-code}`.
/// Used to verify that the proxy issues a redirect with all fields populated.
pub const ANNOTATION_REDIRECT: &str = fixture!("annotation_redirect.yaml");
/// Ingress with `ingress.coxswain-labs.dev/ssl-redirect` and `ssl-redirect-code`.
/// HTTP-only (no TLS termination). Used to verify HTTP-to-HTTPS redirect status codes.
/// Requires `SSL_REDIRECT_CODE` fixture var.
pub const ANNOTATION_SSL_REDIRECT: &str = fixture!("annotation_ssl_redirect.yaml");
/// Ingress with `ingress.coxswain-labs.dev/ssl-redirect` **and** `spec.tls[]`.
/// Used to verify that the ssl-redirect filter fires only on the HTTP listener, not the TLS one.
/// Requires `SECRET_NAME`, `TLS_CRT_B64`, `TLS_KEY_B64` fixture vars.
pub const ANNOTATION_SSL_REDIRECT_TLS: &str = fixture!("annotation_ssl_redirect_tls.yaml");
/// Ingress with an invalid `request-header-set` annotation value (space in header name)
/// alongside a valid `response-header-set`. Used to verify the bad modifier is dropped but
/// the route still serves and the valid sibling modifier is applied.
pub const ANNOTATION_INVALID_HEADER: &str = fixture!("annotation_invalid_header.yaml");
/// Ingress with `ingress.coxswain-labs.dev/max-body-size: "1k"` (#263). Used to verify
/// the proxy rejects over-limit POSTs with 413 (both Content-Length and chunked) and
/// serves under-limit POSTs.
pub const ANNOTATION_MAX_BODY_SIZE: &str = fixture!("annotation_max_body_size.yaml");
/// Ingress with an unparseable `max-body-size: "garbage"` value (#263). Used to verify
/// fail-open: the invalid limit is ignored and an oversized POST still succeeds.
pub const ANNOTATION_MAX_BODY_SIZE_INVALID: &str =
    fixture!("annotation_max_body_size_invalid.yaml");
/// Ingress with `ingress.coxswain-labs.dev/allow-source-range: "203.0.113.0/24"` (#264).
/// Used to verify the proxy admits an in-range client (200, echo identity) and rejects an
/// out-of-range client with 403; the real client IP is supplied via the PROXY protocol.
pub const ANNOTATION_ALLOW_SOURCE_RANGE: &str = fixture!("annotation_allow_source_range.yaml");
/// Ingress with `ingress.coxswain-labs.dev/cache-enabled: "true"` plus a
/// `response-header-set` that injects `Cache-Control: ${CACHE_CONTROL}` (#40).
/// Used to verify the proxy serves a second identical GET from cache (an `Age`
/// header appears), respects `no-store`, bypasses the cache for `Authorization`
/// requests, and honors the admin purge endpoint. Supply `CACHE_CONTROL` via
/// `FixtureVars::with`.
pub const ANNOTATION_CACHE_ENABLED: &str = fixture!("annotation_cache_enabled.yaml");
/// Cookie-mode session affinity (#15): a 3-pod `echo-aff` Service plus an Ingress
/// carrying `session-affinity: cookie` and a custom `session-cookie-name`
/// (`SESSIONID`). The proxy injects the cookie on the first response and pins
/// subsequent requests bearing it to the same pod; a stale cookie re-establishes.
pub const ANNOTATION_SESSION_AFFINITY_COOKIE: &str =
    fixture!("annotation_session_affinity_cookie.yaml");
/// Header-mode session affinity (#15): a 3-pod `echo-aff` Service plus an Ingress
/// carrying `session-affinity: header` and `session-header: X-Session-Id`. The
/// header value is rendezvous-hashed to one pod; an absent header round-robins.
pub const ANNOTATION_SESSION_AFFINITY_HEADER: &str =
    fixture!("annotation_session_affinity_header.yaml");
/// Baseline for #15: the same 3-pod `echo-aff` Service with NO session-affinity
/// annotation — proves the default path stays plain round-robin.
pub const SESSION_AFFINITY_NONE: &str = fixture!("session_affinity_none.yaml");
/// Ingress with `ingress.coxswain-labs.dev/rate-limit-rps: "1"` (#25).
/// Used to verify the proxy admits a single request within quota (200) and rejects
/// subsequent rapid-fire requests with 429 + `Retry-After`.
pub const ANNOTATION_RATE_LIMIT_RPS: &str = fixture!("annotation_rate_limit_rps.yaml");
/// Ingress with `ingress.coxswain-labs.dev/rate-limit-rps: "1"` and `rate-limit-burst: "5"` (#25).
/// Used to verify the proxy absorbs an initial spike up to the burst cap then starts
/// returning 429 + `Retry-After`.
pub const ANNOTATION_RATE_LIMIT_BURST: &str = fixture!("annotation_rate_limit_burst.yaml");
/// Ingress with `ingress.coxswain-labs.dev/rate-limit-by: "header:X-Rate-Key"` (#25).
/// Used to verify fail-open when the keying header is absent — all requests pass even
/// at high rates.
pub const ANNOTATION_RATE_LIMIT_BY_HEADER: &str = fixture!("annotation_rate_limit_by_header.yaml");
/// Ingress with `ingress.coxswain-labs.dev/rate-limit-rps: "notanumber"` (#25).
/// Used to verify that an invalid annotation value is ignored (warn + fail-open) and
/// traffic flows unthrottled.
pub const ANNOTATION_RATE_LIMIT_INVALID: &str = fixture!("annotation_rate_limit_invalid.yaml");
/// Per-class annotation defaults via `IngressClass.spec.parameters` (#190): a
/// `CoxswainIngressClassParameters` CR sets a default `rewrite-target`, one
/// Ingress inherits it and a second overrides it per-key. The IngressClass is
/// cluster-scoped and uniquely named — wrap it in an `IngressClassGuard`.
pub const CLASS_DEFAULT_REWRITE: &str = fixture!("class_default_rewrite.yaml");
/// Class-default `connect-timeout` (#190) via a `CoxswainIngressClassParameters`
/// CR, pointed at a black-holed backend. Proves the class-defaults merge applies
/// to traffic-policy annotations, not just `rewrite-target`. Cluster-scoped
/// IngressClass — wrap it in an `IngressClassGuard`.
pub const CLASS_DEFAULT_TIMEOUT: &str = fixture!("class_default_timeout.yaml");
/// Unhappy-path (#190): an IngressClass whose `spec.parameters` points at a
/// non-existent `CoxswainIngressClassParameters`. The route must still serve with
/// built-in defaults (graceful degrade). Cluster-scoped IngressClass — wrap it in
/// an `IngressClassGuard`.
pub const CLASS_DEFAULT_DANGLING: &str = fixture!("class_default_dangling.yaml");
