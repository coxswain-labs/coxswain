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
/// Ingress with `ingress.coxswain-labs.dev/deny-source-range: "203.0.113.0/24"` (#268).
/// Used to verify the proxy rejects an in-range client with 403 and admits an out-of-range
/// client (200, echo identity); the real client IP is supplied via the PROXY protocol.
pub const ANNOTATION_DENY_SOURCE_RANGE: &str = fixture!("annotation_deny_source_range.yaml");
/// Ingress with both `allow-source-range: "203.0.113.0/24"` and
/// `deny-source-range: "203.0.113.5/32"` (#268). Used to verify that deny is evaluated
/// before allow: a client that matches both is rejected (403); a client in the allow range
/// but not the deny range is admitted (200).
pub const ANNOTATION_DENY_AND_ALLOW_SOURCE_RANGE: &str =
    fixture!("annotation_deny_and_allow_source_range.yaml");
/// Ingress with `trust-forwarded-for: "true"` and `allow-source-range: "203.0.113.0/24"` (#271).
/// Used to verify the proxy uses the first non-private IP from `X-Forwarded-For` as the effective
/// client IP when header trust is enabled (no CIDR gate — unconditional trust).
pub const ANNOTATION_TRUST_FORWARDED_FOR: &str = fixture!("annotation_trust_forwarded_for.yaml");
/// Ingress with `trust-forwarded-for: "true"`, `forwarded-for-header: "X-Real-IP"`,
/// `forwarded-for-trusted-cidrs: "10.0.0.1/32"`, and `allow-source-range: "10.0.0.1/32,203.0.113.0/24"` (#271).
/// Used to verify the anti-spoofing gate: the proxy only trusts the custom header when the L4
/// peer is within the configured CIDR; requests from other peers ignore the header and use the L4 IP.
pub const ANNOTATION_TRUST_FORWARDED_FOR_CIDRS: &str =
    fixture!("annotation_trust_forwarded_for_cidrs.yaml");
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
/// Ingress with `ingress.coxswain-labs.dev/auth-url` pointing at the `auth-allow` stub (200)
/// (#24 happy path). Used to verify the proxy allows the request and forwards it to echo-a.
/// Depends on `backends::AUTH_STUB` being applied first.
pub const ANNOTATION_AUTH_EXT_ALLOW: &str = fixture!("annotation_auth_ext_allow.yaml");
/// Ingress with `ingress.coxswain-labs.dev/auth-url` pointing at the `auth-deny` stub (403)
/// (#24 sad path). Used to verify the proxy returns 403 and never reaches echo-a.
/// Depends on `backends::AUTH_STUB` being applied first.
pub const ANNOTATION_AUTH_EXT_DENY: &str = fixture!("annotation_auth_ext_deny.yaml");
/// Ingress with `ingress.coxswain-labs.dev/auth-url` pointing at `slow-echo` (never responds)
/// and `auth-timeout: 500ms` (#24 sad path — timeout). Used to verify the proxy returns 503
/// when the auth sub-request exceeds its timeout. Depends on `backends::SLOW_ECHO`.
pub const ANNOTATION_AUTH_TIMEOUT: &str = fixture!("annotation_auth_timeout.yaml");
/// Ingress with `auth-url` (auth-allow) and `auth-response-headers: X-Auth-User` (#24).
/// Used to verify the proxy copies the named header from the auth response onto the upstream
/// request; echo-a reflects it back in its JSON body. Depends on `backends::AUTH_STUB`.
pub const ANNOTATION_AUTH_RESPONSE_HEADERS: &str =
    fixture!("annotation_auth_response_headers.yaml");
/// Ingress with `auth-url` (auth-deny) and `auth-always-set-cookie: "true"` (#24).
/// Used to verify the proxy forwards `Set-Cookie` from the auth deny response to the client.
/// Depends on `backends::AUTH_STUB`.
pub const ANNOTATION_AUTH_ALWAYS_SET_COOKIE: &str =
    fixture!("annotation_auth_always_set_cookie.yaml");
/// Labeled htpasswd Secret for basic-auth e2e tests (#24).
/// Carries `ingress.coxswain-labs.dev/auth-basic: "true"` so the reflector picks it up.
/// Contains: `alice` (bcrypt, password `secret`) + `bob` (SHA1, password `secret`).
pub const AUTH_BASIC_SECRET: &str = fixture!("auth_basic_secret.yaml");
/// Unlabeled htpasswd Secret — the reflector ignores it, causing the proxy to return 503
/// (fail-closed) when an Ingress references it via `auth-basic-secret` (#24 sad path).
pub const AUTH_BASIC_SECRET_UNLABELED: &str = fixture!("auth_basic_secret_unlabeled.yaml");
/// Ingress with `ingress.coxswain-labs.dev/auth-basic-secret` pointing at the labeled
/// htpasswd Secret (#24). Used by bcrypt, SHA1, and invalid-credentials tests.
pub const ANNOTATION_AUTH_BASIC: &str = fixture!("annotation_auth_basic.yaml");
/// Ingress with `auth-basic-secret` pointing at the UNLABELED Secret (#24 fail-closed).
/// Used to verify the proxy returns 503 when the Secret is not opt-in labeled.
pub const ANNOTATION_AUTH_BASIC_UNLABELED: &str = fixture!("annotation_auth_basic_unlabeled.yaml");
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
/// Ingress with `ingress.coxswain-labs.dev/mirror-target: "echo-b.TESTNS.svc:3000"`
/// and `max-body-size: 1k` (#283). Primary traffic routes to echo-a; every request
/// is mirrored fire-and-forget to echo-b. Used to verify the access-log
/// `mirror = true` row appears and the primary response is unaffected.
pub const ANNOTATION_MIRROR_TARGET: &str = fixture!("annotation_mirror_target.yaml");
/// Ingress with `ingress.coxswain-labs.dev/mirror-target: "echo-b.TESTNS.svc:9999"` (#283
/// sad path). Port 9999 has no ready EndpointSlices so the reflector disables the
/// mirror. Used to verify the primary route still returns 200 and no mirror row
/// appears in the access log.
pub const ANNOTATION_MIRROR_TARGET_UNREACHABLE: &str =
    fixture!("annotation_mirror_target_unreachable.yaml");
/// Ingress with `ingress.coxswain-labs.dev/compression-gzip: "true"`,
/// `compression-level: "6"`, `compression-types: "application/json,..."` and
/// `compression-min-size: "1"` (#270). Used to verify the proxy compresses
/// `application/json` echo responses with gzip when the client advertises
/// `Accept-Encoding: gzip`.
pub const ANNOTATION_COMPRESSION_GZIP: &str = fixture!("annotation_compression_gzip.yaml");
/// Ingress with both `compression-gzip: "true"` and `compression-brotli: "true"` and
/// `compression-min-size: "1"` (#270). Used to verify brotli is preferred when the
/// client advertises both `br` and `gzip` in `Accept-Encoding`.
pub const ANNOTATION_COMPRESSION_BROTLI: &str = fixture!("annotation_compression_brotli.yaml");
/// Ingress with `compression-gzip: "true"` and `compression-min-size: "1048576"` (#270
/// sad path). Used to verify the proxy passes the echo response through uncompressed
/// when `Content-Length` is below `min-size`.
pub const ANNOTATION_COMPRESSION_MIN_SIZE: &str = fixture!("annotation_compression_min_size.yaml");
/// Ingress with `compression-gzip: "true"` and `compression-types: "text/plain"` (#270
/// sad path). Used to verify the proxy passes the `application/json` echo response through
/// uncompressed when its `Content-Type` is not in the allow-list.
pub const ANNOTATION_COMPRESSION_TYPES: &str = fixture!("annotation_compression_types.yaml");
/// Ingress with `ingress.coxswain-labs.dev/upstream-keepalive-timeout: 60s` (#266).
/// Used to verify that sequential requests to the same upstream reuse pooled
/// connections — `coxswain_proxy_upstream_connections_total{state="reused"}` must
/// increment above zero.
pub const ANNOTATION_KEEPALIVE_TIMEOUT: &str = fixture!("annotation_keepalive_timeout.yaml");
/// Ingress with an unparseable `ingress.coxswain-labs.dev/upstream-keepalive-timeout`
/// value (#266 sad path). The proxy must serve requests normally (fail-open) and not
/// reject traffic due to the invalid annotation.
pub const ANNOTATION_KEEPALIVE_TIMEOUT_INVALID: &str =
    fixture!("annotation_keepalive_timeout_invalid.yaml");
/// Labeled CA Secret for per-Ingress client-certificate mTLS tests (#267).
/// Carries `ingress.coxswain-labs.dev/auth-tls: "true"` so the reflector's
/// label-scoped watcher picks it up; without the label the proxy fails closed for
/// every Ingress that references it. Requires `CA_CRT_B64` fixture var (base64-encoded
/// PEM of the CA certificate stored under key `ca.crt`).
pub const AUTH_TLS_CA_SECRET: &str = fixture!("auth_tls_ca_secret.yaml");
/// TLS-terminated Ingress carrying `auth-tls-secret`, `auth-tls-verify-depth`, and
/// `auth-tls-pass-certificate-to-upstream` annotations (#267), plus the
/// `kubernetes.io/tls` server-cert Secret. The proxy aborts the TLS handshake when no
/// valid client cert is presented; a verified cert is forwarded as `X-SSL-Client-Cert`.
/// Requires `SECRET_NAME`, `TLS_CRT_B64`, `TLS_KEY_B64` fixture vars; host is
/// `mtls.TESTNS.local`. Apply `AUTH_TLS_CA_SECRET` first.
pub const ANNOTATION_AUTH_TLS: &str = fixture!("annotation_auth_tls.yaml");

// ── load-balance (#275) ───────────────────────────────────────────────────────

/// Ingress with `ingress.coxswain-labs.dev/load-balance: "least_conn"` (#275),
/// routing to the shared `lb-pool` Service (two endpoints: `lb-fast` echo-basic +
/// `lb-slow` go-httpbin). Under `least_conn`, concurrent requests accumulate higher
/// in-flight counts on `lb-slow`, so subsequent selections favour `lb-fast`.
/// Apply `backends::LB_MIXED` first.
pub const ANNOTATION_LOAD_BALANCE_LEAST_CONN: &str =
    fixture!("annotation_load_balance_least_conn.yaml");

/// Ingress with `ingress.coxswain-labs.dev/load-balance: "ip_hash"` (#275),
/// routing to the `echo-two-replicas` Service (2 pods). A fixed client IP hashes
/// to the same endpoint, so every sequential request from the test runner lands on
/// the same pod.
/// Apply `backends::ECHO_TWO_REPLICAS` first.
pub const ANNOTATION_LOAD_BALANCE_IP_HASH: &str = fixture!("annotation_load_balance_ip_hash.yaml");

/// Ingress with an unknown `load-balance` value (`"bogus"`) (#275 sad path),
/// routing to the `echo-two-replicas` Service. An unknown value warns and falls
/// back to `round_robin`; all requests must succeed (200) and both pods must be
/// reachable, proving the invalid annotation never blocks routing.
/// Apply `backends::ECHO_TWO_REPLICAS` first.
pub const ANNOTATION_LOAD_BALANCE_UNKNOWN: &str = fixture!("annotation_load_balance_unknown.yaml");

// ── satisfy any/all (#273) ────────────────────────────────────────────────────
