# Ingress annotations

Coxswain supports the `ingress.coxswain-labs.dev/*` annotation namespace for per-Ingress configuration. All annotations are optional and are set once per Ingress; most apply uniformly to every rule and path (`use-regex` additionally keys off each rule's `pathType`).

**Admission-time validation.** On Kubernetes ≥ 1.30, Coxswain installs a `ValidatingAdmissionPolicy` that rejects Ingresses with invalid annotation values at `kubectl apply` time, surfacing the error immediately. On older clusters, or when `vap.enabled=false` is set in the Helm values, invalid values are handled fail-open: the controller emits a warning and treats the annotation as absent, so traffic is never blocked. Disable the VAP only if your cluster does not support `admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy`.

**Runtime diagnostics.** When the VAP is absent or an annotation slips through, the controller emits a Kubernetes `Warning` Event (`reason: InvalidAnnotation`) directly on the Ingress. Run `kubectl describe ingress <name>` to see it inline. See the [Observability reference — Kubernetes Events](../reference/observability.md#kubernetes-events) for details on deduplication and querying.

## Quick reference

| Annotation | Type | Default | Example |
|------------|------|---------|---------|
| `ingress.coxswain-labs.dev/connect-timeout` | duration | _none_ | `"5s"` |
| `ingress.coxswain-labs.dev/read-timeout` | duration | _none_ | `"60s"` |
| `ingress.coxswain-labs.dev/send-timeout` | duration | _none_ | `"60s"` |
| `ingress.coxswain-labs.dev/max-retries` | integer | `0` | `"3"` |
| `ingress.coxswain-labs.dev/retry-on` | csv | _none_ | `"connect-failure,5xx"` |
| `ingress.coxswain-labs.dev/rewrite-target` | string | _none_ | `"/v2"` |
| `ingress.coxswain-labs.dev/use-regex` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/request-header-set` | newline-list | _none_ | `"X-Via: coxswain"` |
| `ingress.coxswain-labs.dev/request-header-add` | newline-list | _none_ | `"X-Tag: v2"` |
| `ingress.coxswain-labs.dev/request-header-remove` | csv | _none_ | `"X-Forwarded-For"` |
| `ingress.coxswain-labs.dev/response-header-set` | newline-list | _none_ | `"Cache-Control: no-store"` |
| `ingress.coxswain-labs.dev/response-header-add` | newline-list | _none_ | `"X-Frame-Options: DENY"` |
| `ingress.coxswain-labs.dev/response-header-remove` | csv | _none_ | `"Server"` |
| `ingress.coxswain-labs.dev/redirect-scheme` | string | _none_ | `"https"` |
| `ingress.coxswain-labs.dev/redirect-hostname` | string | _none_ | `"www.example.com"` |
| `ingress.coxswain-labs.dev/redirect-port` | integer | _none_ | `"443"` |
| `ingress.coxswain-labs.dev/redirect-path` | string | _none_ | `"/v2"` |
| `ingress.coxswain-labs.dev/redirect-status-code` | integer | `302` | `"301"` |
| `ingress.coxswain-labs.dev/ssl-redirect` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/ssl-redirect-code` | integer | `308` | `"301"` |
| `ingress.coxswain-labs.dev/max-body-size` | size | _none_ | `"8m"` |
| `ingress.coxswain-labs.dev/mirror-target` | `svc.ns[:port]` | _none_ | `"echo-b.default.svc:3000"` |
| `ingress.coxswain-labs.dev/allow-source-range` | cidr-list | _none_ | `"10.0.0.0/8,192.168.1.0/24"` |
| `ingress.coxswain-labs.dev/deny-source-range` | cidr-list | _none_ | `"1.2.3.0/24,5.6.7.8/32"` |
| `ingress.coxswain-labs.dev/trust-forwarded-for` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/forwarded-for-header` | string | `X-Forwarded-For` | `"CF-Connecting-IP"` |
| `ingress.coxswain-labs.dev/forwarded-for-trusted-cidrs` | cidr-list | _none_ (unconditional) | `"10.0.0.0/8"` |
| `ingress.coxswain-labs.dev/session-affinity` | `cookie` or `header` | _none_ | `"cookie"` |
| `ingress.coxswain-labs.dev/session-cookie-name` | string | `__coxswain_session` | `"SESSIONID"` |
| `ingress.coxswain-labs.dev/session-header` | string | _none_ | `"X-Session-Id"` |
| `ingress.coxswain-labs.dev/rate-limit-rps` | integer | _none_ (disabled) | `"100"` |
| `ingress.coxswain-labs.dev/rate-limit-burst` | integer | `0` | `"50"` |
| `ingress.coxswain-labs.dev/rate-limit-by` | `ip` or `header:Name` | `"ip"` | `"header:X-Api-Key"` |
| `ingress.coxswain-labs.dev/auth-url` | URL | _none_ | `"http://auth.ns.svc/auth"` |
| `ingress.coxswain-labs.dev/auth-timeout` | duration | `"2s"` | `"500ms"` |
| `ingress.coxswain-labs.dev/auth-response-headers` | csv | _none_ | `"X-Auth-User"` |
| `ingress.coxswain-labs.dev/auth-always-set-cookie` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/auth-basic-secret` | `namespace/name` | _none_ | `"my-ns/my-htpasswd"` |
| `ingress.coxswain-labs.dev/compression-gzip` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/compression-brotli` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/compression-level` | integer 1–9 | `6` | `"5"` |
| `ingress.coxswain-labs.dev/compression-types` | csv of MIME types | see below | `"text/html,application/json"` |
| `ingress.coxswain-labs.dev/compression-min-size` | size | `1024` | `"4k"` |
| `ingress.coxswain-labs.dev/auth-tls-secret` | `namespace/name` | _none_ | `"my-ns/my-ca"` |
| `ingress.coxswain-labs.dev/auth-tls-verify-depth` | integer | `1` | `"2"` |
| `ingress.coxswain-labs.dev/auth-tls-pass-certificate-to-upstream` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/load-balance` | `round_robin`, `least_conn`, `ewma`, `ip_hash`, `hash:uri`, `hash:source-ip`, `hash:header=<name>`, `hash:cookie=<name>` | `round_robin` | `"hash:uri"` |
| `ingress.coxswain-labs.dev/path-normalize` | `base`, `merge-slashes`, `decode-and-merge-slashes` | `base` | `"merge-slashes"` |
| `ingress.coxswain-labs.dev/circuit-breaker-threshold` | integer 1–100 | _none_ (disabled) | `"50"` |
| `ingress.coxswain-labs.dev/circuit-breaker-window` | duration | `10s` | `"30s"` |
| `ingress.coxswain-labs.dev/circuit-breaker-open-duration` | duration | `5s` | `"10s"` |
| `ingress.coxswain-labs.dev/circuit-breaker-min-requests` | integer | `10` | `"5"` |
| `ingress.coxswain-labs.dev/circuit-breaker-max-open-duration` | duration | _none_ (constant) | `"60s"` |
| `ingress.coxswain-labs.dev/upstream-keepalive-timeout` | duration | _none_ (LRU eviction) | `"60s"` |

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/connect-timeout: "5s"
    ingress.coxswain-labs.dev/read-timeout: "60s"
    ingress.coxswain-labs.dev/max-retries: "2"
    ingress.coxswain-labs.dev/retry-on: "connect-failure,timeout"
    ingress.coxswain-labs.dev/rewrite-target: "/v2"
```

## Timeouts

**Duration format** — All timeout annotations accept Go `time.ParseDuration` strings: one or more `<number><unit>` pairs without spaces. Supported units: `ns`, `us` (`µs`), `ms`, `s`, `m`, `h`. Examples: `"5s"`, `"500ms"`, `"1m30s"`. Zero values (`"0"`, `"0s"`) are treated as absent.

### `connect-timeout`

Maximum time to establish a TCP connection to the upstream pod. Overrides any controller-wide default. Corresponds to Pingora's `connection_timeout`.

### `read-timeout`

Maximum time for the upstream to send the first response byte after the full request has been sent. When an HTTPRoute `backendRequest` timeout is also configured, the more restrictive of the two applies.

### `send-timeout`

Maximum time to write the full request to the upstream. Corresponds to Pingora's `write_timeout`.

## Retries

### `max-retries`

Maximum number of _additional_ attempts after the first (not counting the initial attempt). With `max-retries: 2`, Coxswain makes up to 3 total connection attempts. Retries are tried against randomly selected endpoints in the same backend group; there is no per-endpoint pinning.

Setting `max-retries` without `retry-on` has no effect — at least one condition must be specified.

Each retry attempt (not counting the final failing attempt) increments `coxswain_proxy_upstream_retries_total{condition=...}`. Use this to confirm retries are firing and to alert on unexpectedly high retry rates that indicate a flapping backend.

### `retry-on`

Comma-separated list of retry conditions; whitespace around commas is ignored. Valid tokens:

| Token | Meaning |
|-------|---------|
| `connect-failure` | Retry on upstream TCP connect failure (ECONNREFUSED, EHOSTUNREACH) |
| `timeout` | Retry when the upstream connect attempt times out |
| `5xx` | Retry when the upstream returns a 5xx status (only when the request body has not been partially sent) |

!!! note
    `5xx` retries require the full request body to be buffered. Requests whose bodies are too large or were only partially received cannot be retried and pass through to the client as-is.

## `rewrite-target`

Replaces the upstream request path entirely with the given literal string. The rewrite applies before the request is forwarded; the original client-side path is not visible to the upstream pod.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/rewrite-target: /v2
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /api        # client sends GET /api/users
            pathType: Prefix
            backend:
              service:
                name: api-v2  # upstream receives GET /v2
                port:
                  number: 80
```

### Capture-group substitution

On a **regex path** (`pathType: ImplementationSpecific` with [`use-regex: "true"`](#use-regex)), `rewrite-target` may reference capture groups from the path pattern with `$1`…`$n`. The groups are expanded against the matched request path:

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/use-regex: "true"
    ingress.coxswain-labs.dev/rewrite-target: /$1        # GET /svc/users/42 → upstream GET /users/42
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /svc/(.*)            # paths must start with "/" (no leading ^)
            pathType: ImplementationSpecific
            backend:
              service:
                name: api
                port:
                  number: 80
```

A `$n` with no corresponding group expands to the empty string. On a non-regex path (`Prefix`/`Exact`) `rewrite-target` is always a literal replacement — `$1` is treated as the literal text `$1`, not a capture reference.

!!! note
    `rewrite-target` is a single per-Ingress value shared by every path in the Ingress. Two paths in one Ingress cannot have different rewrite templates — split them across Ingresses, or use a Gateway API `HTTPRoute` (which has per-rule filters), if you need that.

## `use-regex`

Opt in to **regular-expression path matching** for this Ingress's `pathType: ImplementationSpecific` rules. With `use-regex: "true"`, the `path` of each such rule is compiled and matched as a regular expression (the same engine as Gateway API `HTTPRoute` `RegularExpression` matches); without it (the default), `ImplementationSpecific` paths collapse to `Prefix` matching, so existing manifests are unchanged.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/use-regex: "true"
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /item/[0-9]+        # regex: matches /item/42, not /item/abc
            pathType: ImplementationSpecific
            backend:
              service:
                name: items
                port:
                  number: 80
```

**Per-path, not per-host.** `use-regex` is an Ingress-wide *enable*; the per-path lever is the standard `pathType` field. Only `ImplementationSpecific` rules become regex — `Prefix` and `Exact` rules in the same Ingress are unaffected. This differs from nginx-ingress, where `use-regex` (or `rewrite-target`) on any path forces regex matching across **all** paths of the host; Coxswain never does this.

**Matching semantics.** The pattern is matched unanchored and is evaluated **after** exact and prefix routes on the same host — a literal `Prefix`/`Exact` rule that also matches wins over a regex rule. The Kubernetes API server requires every Ingress path to start with `/`, so a regex path is always rooted there (`/svc/(.*)`, not `^/svc/(.*)`); use `$` to anchor the end.

**Invalid patterns.** A path whose value is not a valid regular expression is skipped with a controller `WARN`; the rest of the Ingress (and the routing table) is unaffected.

**Migrating from nginx-ingress.** The canonical nginx pairing — `nginx.ingress.kubernetes.io/use-regex` + `nginx.ingress.kubernetes.io/rewrite-target: /$2` with `pathType: ImplementationSpecific` — maps directly onto the Coxswain annotations of the same names. See [capture-group substitution](#capture-group-substitution).

## `path-normalize`

Controls how request paths are normalised before routing and before being forwarded upstream. Coxswain mirrors [Envoy/Istio's `pathNormalization`](https://istio.io/latest/docs/reference/config/istio.mesh.v1alpha1/#MeshConfig-ProxyPathNormalization) — with `base` as the secure default. Normalisation cannot be disabled: `base` is the floor.

Normalisation runs **before** the routing lookup; the canonical path is used for the path match _and_ is sent to the upstream unchanged by a `rewrite-target` (if one is configured, it is applied on top of the normalised path).

**Gateway API `HTTPRoute` resources always use `base` normalization.** There is no per-`HTTPRoute` override annotation; the behaviour is controlled at the infrastructure level, matching Istio's model.

| Level | Transformations applied |
|-------|------------------------|
| `base` _(default)_ | Percent-decode unreserved characters (`%2e`→`.`, `%2d`→`-`, etc.); convert `\` to `/`; remove dot segments (`.` and `..`, RFC 3986 §5.2.4). `%2f` and `%5c` are **not** decoded — they remain encoded to prevent path-traversal bypasses. |
| `merge-slashes` | Everything in `base`, plus collapse consecutive slashes (`//` → `/`). |
| `decode-and-merge-slashes` | Everything in `merge-slashes`, plus decode `%2f`→`/` and `%5c`→`\` before the rest of the pipeline. Use only when your backend expects literal `/` from encoded segments and you understand the security trade-off. |

Each level includes all transformations of the levels before it.

!!! warning "Migration: `none` was removed"
    The `none` value (which disabled normalization entirely) was dropped because it re-opened route-match bypass and path-traversal attacks — a request could dodge a path-based route or `allow-source-range` rule with `..`, `%2e%2e`, or duplicate slashes. An Ingress that still sets `path-normalize: none` is **not rejected**: the controller logs a `WARN`, emits a `Warning` Event, and silently upgrades the level to `base`. If you previously relied on raw-path passthrough, expect normalized paths upstream now and remove any dependency on the un-normalized form.

```yaml
metadata:
  annotations:
    # Collapse // produced by client-side path joining.
    ingress.coxswain-labs.dev/path-normalize: "merge-slashes"
spec:
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /api/v1
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 80
```

**Conflict resolution.** Multiple Ingresses can share the same host (using the standard Ingress host/path merging). When they set different `path-normalize` levels for the same host, the **first Ingress** (ordered by `creationTimestamp`, namespace/name for ties) wins; subsequent conflicting levels are ignored with a controller `WARN`. Setting the same level on two Ingresses sharing a host is not a conflict.

**Performance.** Paths that are already in canonical form take a single linear scan and allocate nothing; allocation only occurs when the path actually changes, and then it is bounded by the path length. The common case (clean paths through `base`) is effectively free.

!!! warning
    `decode-and-merge-slashes` decodes `%2f`/`%5c` before routing, which allows a request for `/api%2fv1` to match the `/api/v1` prefix. Only enable this level if your backend requires it — it removes the URL-encoding layer that prevents path-traversal via encoded slashes.

## Request header modification

Three annotations control the request headers forwarded to the upstream pod. All three are applied together in a single pass — order within a pass is: set, add, then remove.

### `request-header-set`

Overwrites the named header(s) on the upstream request, regardless of what the client sent. The annotation value is a **newline-separated** list of `Name: Value` pairs (one per line). This format preserves comma-bearing values such as `Cache-Control: no-cache, no-store`.

```yaml
ingress.coxswain-labs.dev/request-header-set: |
  X-Via: coxswain
  X-Forwarded-Proto: https
```

### `request-header-add`

Appends the named header(s) on the upstream request without removing any existing value. Same newline-separated `Name: Value` format as `request-header-set`.

```yaml
ingress.coxswain-labs.dev/request-header-add: "X-Tag: v2"
```

### `request-header-remove`

Removes the named header(s) from the upstream request before forwarding. The annotation value is a **comma-separated** list of header names (names never contain commas).

```yaml
ingress.coxswain-labs.dev/request-header-remove: "X-Real-IP, X-Forwarded-For"
```

!!! note
    An invalid header name or value in `request-header-set` / `request-header-add` causes the entire `RequestHeaderModifier` (all three keys combined) to be silently dropped with a controller warning; the Ingress itself is not rejected and still routes normally.

## Response header modification

Mirror of the request header annotations, applied to the downstream response before delivery to the client. Apply order is the same: set, add, remove.

### `response-header-set`

Overwrites the named header(s) on the downstream response. Newline-separated `Name: Value` pairs.

```yaml
ingress.coxswain-labs.dev/response-header-set: |
  Cache-Control: no-store
  X-Content-Type-Options: nosniff
```

### `response-header-add`

Appends the named header(s) to the downstream response.

```yaml
ingress.coxswain-labs.dev/response-header-add: "X-Frame-Options: DENY"
```

### `response-header-remove`

Removes the named header(s) from the downstream response. Comma-separated header names.

```yaml
ingress.coxswain-labs.dev/response-header-remove: "Server, X-Powered-By"
```

## Request redirect

Six annotations configure an HTTP redirect response. Any combination of the fields below may be omitted; omitted fields are inherited from the original request (hostname is preserved, path is preserved, etc.). The redirect fires at the proxy layer — the upstream backend is never reached.

| Annotation | Value | Notes |
|------------|-------|-------|
| `redirect-scheme` | `http` or `https` | |
| `redirect-hostname` | hostname string | replaces the Host header |
| `redirect-port` | port integer | explicit port in the Location |
| `redirect-path` | absolute path | full path replacement |
| `redirect-status-code` | `301`, `302`, `307`, `308` | defaults to `302` |

```yaml
ingress.coxswain-labs.dev/redirect-scheme: "https"
ingress.coxswain-labs.dev/redirect-hostname: "www.example.com"
ingress.coxswain-labs.dev/redirect-status-code: "301"
```

!!! note
    `redirect-*` annotations and `ssl-redirect` are mutually exclusive. If any `redirect-*` key is present, `ssl-redirect` is ignored. This avoids emitting two `RequestRedirect` filters on the same route.

## Force-HTTPS redirect (`ssl-redirect`)

### `ssl-redirect`

When set to `"true"`, every request on the **HTTP listener** for this Ingress receives a redirect to the same URL rewritten to `https://`. The HTTPS listener entry is unaffected — requests already over TLS are served normally.

```yaml
ingress.coxswain-labs.dev/ssl-redirect: "true"
```

### `ssl-redirect-code`

Overrides the redirect status code issued by `ssl-redirect`. Accepted values: `301`, `302`, `307`, `308`. Defaults to `308` (Permanent Redirect, preserves the request method).

```yaml
ingress.coxswain-labs.dev/ssl-redirect: "true"
ingress.coxswain-labs.dev/ssl-redirect-code: "301"
```

!!! note
    `ssl-redirect` is a shortcut for a scheme-only `RequestRedirect` filter scoped to the HTTP listener port. It is equivalent to setting `redirect-scheme: https` with `redirect-status-code: 308`, but only fires on port 80 (or whichever HTTP port the controller is configured with). Requests already arriving on the TLS listener are not redirected, regardless of the annotation.

## Backend wire protocol (`appProtocol`)

Coxswain has no `backend-protocol` annotation. The upstream wire protocol is taken
from the backend **Service port `appProtocol`** field — the Gateway API mechanism
([GEP-1911](https://gateway-api.sigs.k8s.io/geps/gep-1911/)), which applies to both
Ingress and Gateway API backends:

| `appProtocol` | Behaviour |
|---------------|-----------|
| _absent_ | Cleartext HTTP/1.1 (the default) |
| `kubernetes.io/h2c` | Cleartext HTTP/2 prior-knowledge (`h2c`); suitable for gRPC without TLS |

```yaml
apiVersion: v1
kind: Service
metadata:
  name: grpc-backend
spec:
  ports:
    - port: 50051
      appProtocol: kubernetes.io/h2c   # cleartext HTTP/2 for gRPC backends
```

!!! note
    **Upstream TLS** is configured with a `BackendTLSPolicy` ([GEP-1897](gateway-api.md)), the sole Gateway API mechanism for originating TLS to a backend. There is no protocol-hint shortcut for upstream TLS.

## `max-body-size`

Caps the request body size. A request whose body exceeds the limit is rejected with **413 Payload Too Large** and never reaches the upstream.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/max-body-size: "8m"
```

The value is a byte count, optionally suffixed with a binary unit (case-insensitive):

| Value | Bytes |
|-------|-------|
| `"10485760"` | 10485760 (bare byte count) |
| `"512k"` | 512 × 1024 |
| `"8m"` | 8 × 1024² |
| `"1g"` | 1 × 1024³ |

Units are **binary** (`k` = 1024, `m` = 1024², `g` = 1024³), matching nginx-ingress's `proxy-body-size`.

Enforcement is two-layered and never buffers the whole body:

- When the request declares a `Content-Length` larger than the limit, it is rejected up front — before any upstream connection is opened. This applies to both HTTP/1.x and HTTP/2.
- For chunked or streaming uploads with no `Content-Length`, the proxy counts bytes as they arrive and aborts with 413 the moment the running total crosses the limit **on HTTP/1.x only**. A streaming **HTTP/2** upload without `Content-Length` is not capped mid-stream (it fails open) — returning a rejection mid-body over HTTP/2 deadlocks the client under `pingora-proxy` ([#509](https://github.com/coxswain-labs/coxswain/issues/509)); faithful HTTP/2 enforcement awaits pingora request-body buffering.

Omitting the annotation imposes no limit. An unparseable value (e.g. `"8mb"`, `"lots"`) emits a controller warning and is treated as absent — the route serves with no body cap rather than being rejected (**fail-open**).

## `mirror-target`

Sends a **fire-and-forget copy** of every matched request to a secondary backend while the primary request completes normally. The mirror response is discarded entirely — the client only ever sees the primary backend's response. Mirror failures (connect error, timeout, bad response) are logged at `WARN` level and do not affect the primary.

**Typical use cases**: shadow-testing a new service version under live traffic, capturing request patterns for offline analysis, dark-launch evaluation.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/mirror-target: "echo-b.my-namespace.svc:3000"
```

The value is `<service>.<namespace>[.svc[.cluster.local]]:<port>`:

| Form | Example |
|------|---------|
| Short | `echo-b.my-namespace:3000` |
| `.svc` suffix | `echo-b.my-namespace.svc:3000` |
| FQDN | `echo-b.my-namespace.svc.cluster.local:3000` |

The mirror target is resolved to pod endpoints at reconcile time (not per-request). If the Service does not exist or has no ready endpoints, a controller warning is emitted and the mirror is **silently disabled** — the primary route still serves. The Ingress is never rejected.

**The target namespace must match the Ingress namespace.** Cross-namespace references are rejected at reconcile time (controller warning + mirror disabled). An Ingress author can only shadow traffic to Services they own — they must not be able to send mirrored requests (which include request headers) to Services in other namespaces.

### Body mirroring

The proxy streams the full request body to the mirror backend **as chunks arrive**, concurrent with primary forwarding — no intermediate buffering and no dependency on `max-body-size`. A minimal annotation is all that is needed:

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/mirror-target: "shadow-svc.my-namespace.svc:8080"
```

**Backpressure:** each mirror task receives body chunks via a bounded internal channel. If the mirror upstream falls behind, the current chunk is dropped rather than stalling the primary path. The mirror body may be truncated for slow mirror backends, which is expected and acceptable for a fire-and-forget shadow.

`max-body-size` can still be set independently to cap and reject oversized primary request bodies with 413 — but it is not required for body mirroring.

### Observability

Every mirror sub-request appears in the **proxy access log** as a separate row with `mirror = true`. The row carries the same fields as a primary row (`host`, `path`, `upstream`, `status`) so mirror traffic is visible in any log aggregation pipeline.

A mirror timeout of 5 s is applied per sub-request; the primary never waits for the mirror to finish.

`Authorization`, `Cookie`, and `Proxy-Authorization` headers are **always stripped** from mirror sub-requests. The mirror backend is a shadow endpoint whose trustworthiness is not guaranteed; forwarding user credentials to it would make it a credential-harvesting surface.

## `allow-source-range`

Restricts the Ingress to a set of client source IPs. A request whose client IP falls outside **every** listed range is rejected with **403 Forbidden** before any upstream connection is opened — the equivalent of nginx-ingress's `whitelist-source-range`.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/allow-source-range: "10.0.0.0/8,192.168.1.0/24"
```

The value is a comma-separated list of IPv4/IPv6 CIDR blocks. A bare address without a prefix (`10.0.0.1`, `2001:db8::1`) is accepted as a host route (`/32` / `/128`). Whitespace around entries is trimmed.

**Which IP is matched.** When the proxy sits behind a load balancer speaking the [PROXY protocol](../reference/configuration.md) (`--proxy-accept-proxy-protocol`), the match uses the **real client IP** carried in the PROXY header. Otherwise it uses the L4 peer address of the connection. Deploy behind a PROXY-protocol-aware load balancer (or set `externalTrafficPolicy: Local`) so the proxy observes real client IPs rather than the LB's address. When `trust-forwarded-for` is also set, see the [Trusted proxy headers](#trust-forwarded-for) section — the effective client IP may come from a forwarded header instead.

**Matching is strict.** CIDR membership is exact per address family — an IPv4-mapped IPv6 client (`::ffff:10.0.0.1`) does **not** match an IPv4 CIDR. List both families if your clients can arrive over either.

**Failure handling:**

- An invalid CIDR token emits a controller warning and is **skipped**; the remaining valid ranges still apply.
- If **every** token is invalid (or the annotation is absent/empty), the allow-list is treated as absent — **all** source IPs are admitted (**fail-open** at parse time, so a typo never locks out all traffic).
- Once an allow-list is in effect, a request whose source IP cannot be determined is **denied** (**fail-closed** at request time) — an un-attributable client must not pass a security control.

## `deny-source-range`

Blocks a set of client source IPs. A request whose client IP falls inside **any** listed range is rejected with **403 Forbidden** before any upstream connection is opened. All other clients are admitted (unless an `allow-source-range` annotation is also set — see below).

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/deny-source-range: "1.2.3.0/24,5.6.7.8/32"
```

The value is a comma-separated list of IPv4/IPv6 CIDR blocks. A bare address without a prefix (`10.0.0.1`, `2001:db8::1`) is accepted as a host route (`/32` / `/128`). Whitespace around entries is trimmed.

**Which IP is matched.** Same as `allow-source-range`: the real client IP from the PROXY protocol when available, otherwise the L4 peer address. When `trust-forwarded-for` is also set, the effective client IP may come from a forwarded header — see [Trusted proxy headers](#trust-forwarded-for).

**Matching is strict.** CIDR membership is exact per address family — an IPv4-mapped IPv6 client (`::ffff:10.0.0.1`) does **not** match an IPv4 CIDR.

**Evaluation order.** `deny-source-range` is evaluated **before** `allow-source-range`. When both annotations are set, a client IP that falls inside the deny list is rejected with 403 even if the allow-list would have admitted it.

**Unattributable client IP.** If the client's IP cannot be determined, the deny-list does **not** block the request — a block list only acts on IPs it can positively attribute to a listed range. (This is the inverse of `allow-source-range`'s fail-closed behaviour.)

**Failure handling:**

- An invalid CIDR token emits a controller warning and is **skipped**; the remaining valid ranges still apply.
- If **every** token is invalid (or the annotation is absent/empty), the block list is treated as absent — **no** source IPs are blocked (**fail-open** at parse time, so a typo never silently blocks all traffic).

## `trust-forwarded-for`

Lets the proxy extract the **real client IP** from a forwarded-for header — necessary when Coxswain sits behind a cloud LB or CDN that terminates the connection and puts the original client IP in a header like `X-Forwarded-For` or `CF-Connecting-IP`.

Without this annotation, IP-based features (`allow-source-range`, `deny-source-range`, `rate-limit-by: ip`) always see the **L4 peer address** (the LB's IP), making per-client controls ineffective behind a proxy.

**Master switch — disabled by default** to prevent header injection by untrusted peers:

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/trust-forwarded-for: "true"
```

### IP resolution algorithm

When `trust-forwarded-for: "true"` is set, the proxy resolves the effective client IP once per request (after route matching) using this four-step algorithm:

1. **L4 base IP** — real client addr from PROXY protocol if present, otherwise the TCP peer addr.
2. **No config** — if the Ingress has no `trust-forwarded-for`, use the L4 base IP (current behavior unchanged).
3. **CIDR gate** — if `forwarded-for-trusted-cidrs` is non-empty AND the L4 base IP is **not** in any listed CIDR, the forwarded header is ignored (anti-spoofing) and the L4 base IP is used.
4. **Header parse** — parse the configured header (default `X-Forwarded-For`), scan the comma-separated IP list left-to-right, and use the **first non-private IP** found. If no non-private IP is found, fall back to the L4 base IP.

"Private/reserved" means RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`), ULA (`fc00::/7`), and unspecified.

### `forwarded-for-header`

Which header to read the forwarded IP from. Defaults to `X-Forwarded-For`. Override for CDNs that use a proprietary header:

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/trust-forwarded-for: "true"
    ingress.coxswain-labs.dev/forwarded-for-header: "CF-Connecting-IP"
```

Header lookup is case-insensitive. The value is trimmed of surrounding whitespace. If the annotation is absent or empty, `X-Forwarded-For` is used.

### `forwarded-for-trusted-cidrs`

The anti-spoofing gate: only trust the forwarded header when the **L4 peer address** is inside one of the listed CIDRs. A request from a peer outside this list is treated as if `trust-forwarded-for` were off — the forwarded header is silently ignored and the L4 IP is used instead.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/trust-forwarded-for: "true"
    ingress.coxswain-labs.dev/forwarded-for-trusted-cidrs: "10.0.0.0/8,172.16.0.0/12"
```

The value is a comma-separated list of IPv4/IPv6 CIDR blocks (same format as `allow-source-range`). Whitespace is trimmed.

**When absent or empty**, the forwarded header is trusted unconditionally for **every** L4 peer — only do this when the deployment topology guarantees that only a trusted proxy can reach Coxswain directly.

**Security note.** Always set `forwarded-for-trusted-cidrs` to the IP range of your load balancer or CDN edge nodes. Without it, any client that can reach the proxy port can forge the forwarded header and bypass IP-based controls.

**Failure handling:**

- An invalid CIDR token emits a controller warning and is skipped.
- If every token is invalid, the CIDR list is treated as absent (unconditional trust) and a controller warning is emitted.

## Session affinity (sticky sessions)

Pins each client to the same backend pod, so stateful workloads (in-memory sessions, WebSocket connections) keep reaching the endpoint that holds their state. A backend without these annotations stays on the default weighted round-robin.

Affinity is **stateless** — there is no server-side session table. The pin is carried entirely in the request, so it works the same across proxy replicas and needs no coordination. Two modes:

### `session-affinity: cookie`

The proxy injects a cookie on the first response identifying the chosen pod, and routes subsequent requests bearing that cookie back to it.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/session-affinity: "cookie"
    ingress.coxswain-labs.dev/session-cookie-name: "SESSIONID"   # optional
```

- The first request (no cookie) is load-balanced normally, then pinned: the response carries `Set-Cookie: <name>=<token>; Path=/; HttpOnly`. The token encodes the endpoint; no raw pod IP is exposed.
- `session-cookie-name` sets the cookie name (default `__coxswain_session`). A name that is not a valid cookie token warns and falls back to the default.
- The cookie is a **session cookie** (no `Max-Age`); it lives for the browser session.

### `session-affinity: header`

The value of a request header is hashed to consistently select a pod — no cookie is issued. Use this when the client already carries a stable identifier (a session token, an API key).

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/session-affinity: "header"
    ingress.coxswain-labs.dev/session-header: "X-Session-Id"
```

- `session-header` is **required** in header mode; if it is missing or not a valid header name, affinity is disabled (warning) and the route round-robins.
- Selection uses **rendezvous (HRW) hashing** over the live endpoints, so a header value keeps its pod as long as that pod exists, and only the keys of a removed pod are redistributed.
- A request that does not carry the header round-robins (and never receives a cookie).

### Recovery and limits

- If a pinned pod is **removed or scaled away**, the next request from that client no longer resolves to a live endpoint: it falls back to round-robin and (in cookie mode) re-establishes affinity with a fresh cookie.
- An unknown `session-affinity` value (anything other than `cookie`/`header`) warns and disables affinity — the Ingress still serves.

!!! note
    The Gateway API binding for session persistence is not yet implemented: the only Gateway API surface for session persistence in the pinned crate is experimental-only (which Coxswain never compiles into release images), and the `BackendLBPolicy` resource originally proposed is not an upstream Gateway API type. Today the `session-*` annotations are the Ingress-only entry point.

## Circuit breaker

The per-upstream-endpoint circuit breaker trips when a backend pod's **error rate** exceeds a threshold, returning fail-fast **503** responses to clients until the pod shows signs of recovery. This is the Ingress equivalent of Envoy/Istio **outlier detection**: a single degraded pod trips only its own breaker; healthy pods serving the same Ingress keep accepting traffic.

The breaker is implemented with [failsafe](https://docs.rs/failsafe)'s EWMA (exponentially weighted moving average) success-rate policy. Breaker state is tracked per `(route, endpoint-IP:port)` pair — one state machine per upstream pod, per route.

**State machine:**

1. **Closed** (initial) — requests flow normally; errors accumulate against the EWMA window.
2. **Open** — error rate exceeded `threshold` after `min-requests` samples; requests fail-fast 503 without reaching the upstream. The breaker stays Open for `open-duration` (or exponentially longer, up to `max-open-duration`, on repeated trips).
3. **HalfOpen** — after `open-duration` one probe request is let through. If it succeeds, the breaker closes; if it fails, it re-opens for another `open-duration`.

**Observability** — three Prometheus series on the proxy admin `/metrics` endpoint:

- `coxswain_proxy_circuit_breaker_state{route, upstream}` — `0` = closed, `1` = open, `2` = half-open.
- `coxswain_proxy_circuit_breaker_rejected_total{route, upstream}` — count of fail-fast 503s issued while the breaker was open.
- `coxswain_proxy_circuit_breaker_transitions_total{route, upstream, to}` — cumulative state transitions; `to` is `"open"`, `"half_open"`, or `"closed"`.

### `circuit-breaker-threshold`

**Required.** Error-rate percentage (1–100) that trips the breaker. Absent or invalid → breaker disabled (fail-open).

Maps to `failsafe`'s `required_success_rate = 1 - threshold/100`. A value of `50` trips the breaker when fewer than 50% of requests succeed.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/circuit-breaker-threshold: "50"
```

### `circuit-breaker-window`

EWMA sliding window over which the success rate is measured. Duration string (e.g. `"10s"`). Default: `10s`.

### `circuit-breaker-open-duration`

How long the breaker stays Open before allowing a half-open probe. Duration string. Default: `5s`.

When `circuit-breaker-max-open-duration` is absent this is a **constant** backoff (every trip stays Open for exactly this duration). When `max-open-duration` is set this is the **initial** duration and the window grows exponentially across repeated trips.

### `circuit-breaker-min-requests`

Minimum number of requests that must have been observed in the current window before the policy evaluates and can trip the breaker. Prevents a single early failure on a low-traffic route from opening the breaker. Integer ≥ 1. Default: `10`.

### `circuit-breaker-max-open-duration`

**Optional.** Upper bound for exponential backoff. When set, each successive trip doubles the open-duration (starting from `circuit-breaker-open-duration`) up to this cap. Absent → constant backoff (each trip uses the same `open-duration`).

### Example

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/circuit-breaker-threshold: "50"
    ingress.coxswain-labs.dev/circuit-breaker-window: "10s"
    ingress.coxswain-labs.dev/circuit-breaker-open-duration: "5s"
    ingress.coxswain-labs.dev/circuit-breaker-min-requests: "10"
    ingress.coxswain-labs.dev/circuit-breaker-max-open-duration: "60s"
```

**Fail-fast behaviour:** when the breaker is Open, the proxy returns 503 immediately without connecting to the upstream. The client sees 503; other healthy pods serving the same route continue accepting traffic via load-balancing.

**Invalid values** (zero threshold, unparseable duration, non-integer min-requests) emit a controller warning and disable the breaker for that route (**fail-open**) — a misconfigured annotation never blocks all traffic.

---

## Rate limiting

Caps the request rate accepted from each client before forwarding to the upstream. Over-limit requests are rejected with **429 Too Many Requests** and a `Retry-After` header (in whole seconds) telling the client when to retry. See the [Rate limiting guide](rate-limiting.md) for full semantics and Gateway API usage.

### `rate-limit-rps`

Sustained request rate in requests per second, per client. Must be a positive integer >= 1. Absent or invalid values disable rate limiting for the route (**fail-open**).

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/rate-limit-rps: "100"
```

### `rate-limit-burst`

Number of requests above the sustained rate that a client may send in a short burst when it has been idle. The total burst capacity is `rps + burst` — a client that has accumulated headroom can send that many requests before being throttled. Defaults to `0` (no burst above sustained rate).

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/rate-limit-rps: "10"
    ingress.coxswain-labs.dev/rate-limit-burst: "50"
```

### `rate-limit-by`

Selects the dimension used to identify each client for its own rate-limit bucket. Two modes:

| Value | Behaviour |
|-------|-----------|
| `"ip"` (default) | One bucket per real client IP (or L4 peer when not behind a PROXY-protocol LB) |
| `"header:Name"` | One bucket per unique value of the named request header |

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/rate-limit-rps: "5"
    ingress.coxswain-labs.dev/rate-limit-by: "header:X-Api-Key"
```

When the keying dimension is not available for a request (undeterminable IP, or absent header on a header-keyed route) the request is **admitted without counting** (**fail-open**) — a missing key never blocks traffic.

An unrecognised `rate-limit-by` value emits a controller warning and falls back to `"ip"`.

!!! warning "Header keying allows rate-limit bypass"
    `header:Name` allocates one bucket per **unique value** of the named header. A client that rotates the header value (e.g. sends a different `X-Api-Key` on each request) starts with a full bucket every time, bypassing the per-key limit entirely.

    Mitigate by:

    - combining with `auth-url` or `auth-basic-secret` so the header value is authenticated before being trusted as a rate-limit key, or
    - using `rate-limit-by: ip` as the primary limit and treating header keying as an optional secondary signal only.

    The controller emits a `Warning` Event on the Ingress when `header:*` keying is configured without an auth annotation, so operators are notified at reconcile time.

## Authentication

Coxswain supports two authentication modes on Ingresses: **external auth** (HTTP sub-request) and **basic auth** (htpasswd Secret). Both are enforced at the proxy before any upstream connection; a failure never reaches the backend.

`auth-url` and `auth-basic-secret` are mutually exclusive. If both are present, `auth-url` wins and a controller warning is emitted.

### `auth-url`

Forwards a sub-request to an external authorization service before proxying. If the service returns **2xx** the original request is forwarded; any other status code is returned to the client as-is (body + headers), and the upstream is never hit.

The sub-request is sent to the configured URL using the **original request method and Host header**, carrying the client's headers (`Authorization`, `Cookie`, etc.) — the auth service sees the genuine request context. No body is forwarded. On a network error or timeout (configurable via `auth-timeout`), the proxy returns **503** and blocks the request (fail-closed).

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/auth-url: "http://oauth2-proxy.oauth.svc.cluster.local/oauth2/auth"
    ingress.coxswain-labs.dev/auth-timeout: "2s"
    ingress.coxswain-labs.dev/auth-response-headers: "X-Auth-User,X-Auth-Groups"
    ingress.coxswain-labs.dev/auth-always-set-cookie: "true"
```

### `auth-timeout`

Maximum time to wait for the auth sub-request to respond. Accepts any duration string (e.g. `"500ms"`, `"5s"`). Default: `2s`. On timeout the proxy returns **503** (fail-closed).

### `auth-response-headers`

Comma-separated list of header names to copy from a **2xx auth response** onto the **upstream request** (so the backend sees e.g. `X-Auth-User`). The echo backend reflects them back in its JSON body, making this assertion testable end-to-end.

### `auth-always-set-cookie`

When `"true"`, any `Set-Cookie` header present in the auth **deny response** is forwarded to the client. This enables login-redirect flows where the IdP sets a session cookie on the 302 response. Default: `false`.

### `auth-basic-secret`

Enables **HTTP Basic Authentication** backed by an htpasswd Secret. Value is `namespace/name` of a `Secret` resource with:

- **Type**: `Opaque`
- **Key**: `auth`
- **Value**: standard htpasswd content (one `username:hash` line per credential)
- **Supported hash algorithms**: **bcrypt** (`$2a$`, `$2b$`, `$2y$`) is the required minimum — use `htpasswd -B` to generate bcrypt hashes. `SHA1` (`{SHA}base64`) is accepted for compatibility with existing files but is **not recommended**: SHA1 is unsalted and trivially crackable offline. The controller emits a `Warning` Event naming each affected username. Lines using other schemes (MD5, crypt) are skipped with a controller warning.

**The Secret must carry the `ingress.coxswain-labs.dev/auth-basic: "true"` label.** The proxy watches only labeled Secrets (the data-plane read-only invariant — the proxy never holds cluster-wide Secret access). A referenced Secret that is absent or unlabeled causes the proxy to return **503** for every request to that Ingress (**fail-closed**). This is intentional: misconfigured auth silences traffic rather than silently bypassing it.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-htpasswd
  namespace: my-app
  labels:
    ingress.coxswain-labs.dev/auth-basic: "true"
type: Opaque
data:
  # alice:secret (bcrypt)  bob:secret (SHA1)
  auth: |
    YWxpY2U6JDJ5JDA0JHdyUkZRU0NCZXpZTFR5V1hKS1dldXVPaHRGdWtyQWo3UHpQWXRRc09ORWg4ck9PampJTGFLCmJvYjp7U0hBfTVlbjZHNk1lelJyb1QzWEtxa2RQT21ZL0JmUT0K
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  namespace: my-app
  annotations:
    ingress.coxswain-labs.dev/auth-basic-secret: "my-app/my-htpasswd"
spec:
  ingressClassName: coxswain
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-api
                port:
                  number: 8080
```

Requests without credentials receive **401** with a `WWW-Authenticate: Basic realm="coxswain"` header. Invalid credentials also receive **401**.

!!! tip "Hardening"
    Always generate credentials with `htpasswd -B` (bcrypt). Avoid `htpasswd -s` (`{SHA}`) — SHA1 is unsalted and can be cracked offline in seconds with commodity hardware.

    Credential hashes are zeroed from memory when the credential list is replaced at reconcile time (`zeroize`). The Helm chart already ships `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, and `capabilities.drop: ALL` by default. For the remaining defense-in-depth, configure nodes with `vm.swappiness=0` so hashes can't be paged to disk — this is a node-level kernel parameter that Kubernetes cannot enforce per-pod.

## Client certificate mTLS

Requires clients to present a valid TLS certificate during the handshake — **mutual TLS (mTLS)**. When enabled, the proxy aborts the handshake if the client presents no certificate or one not signed by the configured CA. This matches the semantics of Istio's `tls.mode: MUTUAL`: enforcement is at the TLS layer, not HTTP, so there is no 400/403 response — the connection simply does not complete.

**Enforcement model.** The proxy aborts the TLS handshake (BoringSSL `FAIL_IF_NO_PEER_CERT`). Clients that present no cert or a cert from an unknown CA receive a TLS alert; HTTP never starts. The backend pod is never reached.

**HTTP listener.** Plain-HTTP (port 80) requests to an mTLS host are not affected by these annotations. If you want to prevent clients from sending plain-HTTP requests at all, combine `auth-tls-secret` with `ssl-redirect: "true"` on the same Ingress.

**Cross-SNI guard.** On a shared TLS connection whose SNI selected a different (non-mTLS) host, a `Host:` header naming an mTLS host returns `421 Misdirected Request` — the connection never verified a client cert and cannot be reused to access the mTLS resource.

**Fail-closed on bad CA.** If the referenced Secret is absent, unlabeled, missing the `ca.crt` key, or its PEM is unparseable, the proxy installs an empty verify store for that host. Every TLS handshake to that host is aborted until the Secret is corrected. This matches the `auth-basic-secret` fail-closed policy.

### `auth-tls-secret`

Reference to a Kubernetes `Opaque` Secret in `namespace/name` form whose `ca.crt` key holds one or more PEM-encoded CA certificates used to verify the client certificate chain.

**The Secret must carry the `ingress.coxswain-labs.dev/auth-tls: "true"` label.** The data-plane proxy watches only labeled Secrets (the read-only-proxy invariant — the proxy never holds cluster-wide Secret access). An unlabeled or missing Secret causes every TLS handshake to the Ingress host to be aborted (**fail-closed**).

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-client-ca
  namespace: my-app
  labels:
    ingress.coxswain-labs.dev/auth-tls: "true"
type: Opaque
data:
  ca.crt: <base64-encoded PEM CA cert(s)>
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  namespace: my-app
  annotations:
    ingress.coxswain-labs.dev/auth-tls-secret: "my-app/my-client-ca"
spec:
  ingressClassName: coxswain
  tls:
    - hosts:
        - api.example.com
      secretName: api-server-cert
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-api
                port:
                  number: 8080
```

### `auth-tls-verify-depth`

Maximum TLS certificate chain verification depth. With depth `1` (the default) only a direct CA-signed leaf is accepted — no intermediate CAs. With depth `2`, one intermediate CA is allowed. Must be a positive integer >= 1. Absent or invalid values warn and fall back to `1`.

```yaml
ingress.coxswain-labs.dev/auth-tls-verify-depth: "2"
```

### `auth-tls-pass-certificate-to-upstream`

When `"true"`, the verified client certificate PEM is URL-encoded and injected on the upstream request as the `X-SSL-Client-Cert` header. The backend can decode it for audit logging, identity extraction, or further authorization. Default: `false`.

```yaml
ingress.coxswain-labs.dev/auth-tls-pass-certificate-to-upstream: "true"
```

The header value is the raw PEM of the client leaf certificate, percent-encoded (all non-alphanumeric characters encoded). Backends decode it with a standard URL-decode.

!!! note "v1 limitation"
    `auth-tls-*` annotations are read directly off `Ingress.metadata.annotations`. They do not inherit class-level defaults from a `CoxswainIngressClassParameters` resource. Per-class mTLS defaults are tracked for a future release.

## `upstream-keepalive-timeout`

Controls how long Pingora keeps an idle upstream connection in its keepalive pool before evicting it.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/upstream-keepalive-timeout: "60s"
```

**Format**: a Go `time.ParseDuration` string, e.g. `"30s"`, `"2m"`, `"90s"`. Absent or invalid values warn and fall back to Pingora's default (connections are evicted by LRU capacity pressure, not by age).

**Observability**: the `coxswain_proxy_upstream_connections_total{state="reused"}` counter increments every time a request reuses a pooled connection. Compare it with `{state="new"}` to gauge keepalive efficiency for a route.

**Global pool size**: the total number of idle upstream connections across all routes is bounded by `--proxy-upstream-keepalive-pool-size` (default: 128). Set it via the Helm value `proxy.shared.upstreamKeepalivePoolSize` or the env var `COXSWAIN_PROXY_UPSTREAM_KEEPALIVE_POOL_SIZE`. Raise it for deployments with many distinct upstream hosts/ports; lower it to reduce file-descriptor usage.

## `compression-*`

Opt-in, per-Ingress on-the-fly response compression. The proxy compresses upstream responses before
forwarding them to the client, negotiated against the client's `Accept-Encoding` header. Nothing is
compressed unless at least one codec is explicitly enabled.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/compression-gzip: "true"
    ingress.coxswain-labs.dev/compression-brotli: "true"
    ingress.coxswain-labs.dev/compression-level: "6"
    ingress.coxswain-labs.dev/compression-types: "text/html,text/plain,text/css,application/json,application/javascript"
    ingress.coxswain-labs.dev/compression-min-size: "1024"
```

| Annotation | Type | Default |
|---|---|---|
| `compression-gzip` | boolean | `false` |
| `compression-brotli` | boolean | `false` |
| `compression-level` | integer, 1–9 | `6` |
| `compression-types` | CSV of MIME types | `text/html,text/plain,text/css,application/json,application/javascript` |
| `compression-min-size` | byte count (suffixes `k`/`m`/`g` accepted) | `1024` |

### `compression-gzip` / `compression-brotli`

Enable the respective codec. Both are `false` by default — no compression is applied to any Ingress
unless at least one is set to `"true"`. Setting both to `"true"` enables dual-codec support: brotli
is preferred when the client advertises `br` in `Accept-Encoding`; gzip is used otherwise.

### `compression-level`

Compression effort on a 1–9 scale (1 = fastest/least compression, 9 = slowest/best compression).
The same level is applied to both gzip and brotli. Values outside the 1–9 range emit a warning and
fall back to `6`. The default of `6` is a good balance for most workloads.

### `compression-types`

Comma-separated list of MIME types to compress. Only responses whose `Content-Type` header matches
an entry in this list (the media type before any `;parameters`) are compressed. Matching is
case-insensitive. The default list covers the most common compressible types:

```
text/html, text/plain, text/css, application/json, application/javascript
```

An empty or entirely-invalid list falls back to the default. Responses with binary types such as
`image/png`, `video/mp4`, or `application/octet-stream` are passed through unmodified regardless of
this setting.

### `compression-min-size`

Minimum response body size, in bytes, before compression is attempted. Responses whose
`Content-Length` is present and smaller than this threshold are passed through without compression.
When `Content-Length` is absent (chunked transfer encoding), the response is always eligible —
the proxy cannot know the full size without buffering.

The default is `1024` bytes (1 KiB). The value accepts the `k`/`m`/`g` suffix for convenience
(`"4k"` = 4096, `"1m"` = 1048576). Invalid values warn and fall back to `1024`.

### Behaviour

Compression is applied only when **all** of the following hold:

1. At least one codec (`compression-gzip` or `compression-brotli`) is enabled.
2. The client advertises the codec in `Accept-Encoding`.
3. The upstream response does not already have a `Content-Encoding` header — pre-compressed
   responses (e.g. assets served pre-compressed by the upstream) are forwarded unchanged.
4. The response `Content-Type` (before `;`) matches an entry in `compression-types`.
5. Either `Content-Length` is absent, or its value is ≥ `compression-min-size`.
6. The response status is a normal body-bearing code (1xx, 204, and 304 responses are passed through).

When compression fires, the proxy:
- Sets `Content-Encoding: gzip` or `Content-Encoding: br`.
- Appends `Accept-Encoding` to the `Vary` header (or creates it), so downstream caches serve the
  correct variant.
- Removes `Content-Length` (the compressed size differs from the original) and `Accept-Ranges`
  (byte-range requests are incompatible with on-the-fly compression).

!!! note "q-values"
    q-values in `Accept-Encoding` are not arbitrated — presence of a codec token is sufficient to
    select it. This matches Pingora's own behaviour. When both codecs are enabled and the client
    sends both `br` and `gzip`, brotli always wins regardless of q-values.

## `load-balance`

Selects the algorithm used to pick an upstream endpoint for each request within the backend group of a route.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/load-balance: "least_conn"
```

| Value | Description |
|-------|-------------|
| `round_robin` | _(default)_ Weighted round-robin using the GCD-reduced slot array. Zero per-request overhead. |
| `least_conn` | Routes to the endpoint with the fewest in-flight requests. Maintains an atomic in-flight counter per endpoint; the counter is incremented on selection and decremented when the response completes (or when a retry selects a different endpoint). |
| `ewma` | Routes to the endpoint with the lowest exponentially-weighted moving-average response latency (α = 1/8). Unsampled endpoints (active=0) are probed first. Latency is folded in at end-of-request. |
| `ip_hash` | Alias for `hash:source-ip` (backward-compatible). |
| `hash:uri` | Consistent hash on the full request URI (path + query string). Requests to the same URI always land on the same endpoint. Falls back to round-robin if the path is empty. |
| `hash:source-ip` | Consistent hash on the resolved client IP (see [`trust-forwarded-for`](#trust-forwarded-for) for how the IP is resolved). Requests from the same IP always land on the same endpoint; unlike cookie affinity, no state is injected into the response. Falls back to round-robin if the client IP is unavailable. |
| `hash:header=<name>` | Consistent hash on the value of the named request header (e.g. `hash:header=x-user-id`). An empty or absent header falls back to round-robin. |
| `hash:cookie=<name>` | Consistent hash on the value of the named cookie (e.g. `hash:cookie=session`). An absent or empty cookie falls back to round-robin. |

All `hash:*` values (and `ip_hash`) use **rendezvous (HRW) hashing**: when an endpoint is removed, only its keys are redistributed; all other keys remain on their existing endpoints. This is strictly better than modulo hashing, which reshuffles nearly every key on a membership change.

Unknown values warn and fall back to `round_robin`; routing is never interrupted.

### Mapping to Gateway API / Istio

`load-balance` maps to `DestinationRule.trafficPolicy.loadBalancer` in Istio:

| Coxswain value | Istio / Envoy equivalent |
|----------------|--------------------------|
| `round_robin` | `ROUND_ROBIN` |
| `least_conn` | `LEAST_REQUEST` |
| `ewma` | `LEAST_REQUEST` with latency-weighted selection |
| `ip_hash` / `hash:source-ip` | `CONSISTENT_HASH` (`useSourceIp: true`) |
| `hash:uri` | `CONSISTENT_HASH` (HTTP URI — closest analogue) |
| `hash:header=<name>` | `CONSISTENT_HASH` (`httpHeaderName: <name>`) |
| `hash:cookie=<name>` | `CONSISTENT_HASH` (`httpCookie.name: <name>`) |

### `hash:source-ip` and forwarded-for

When [`trust-forwarded-for`](#trust-forwarded-for) is enabled, `hash:source-ip` (and its alias `ip_hash`) uses the resolved client IP (the first non-private address from the forwarded header, gated by [`forwarded-for-trusted-cidrs`](#forwarded-for-trusted-cidrs) if set). This means a load balancer that rewrites the source IP still produces consistent upstream pinning based on the real client address.

### Performance

All algorithms run on the hot path without locks. `round_robin` allocates nothing per request. `least_conn` and `ewma` perform a linear scan over the endpoint list (typically 1–10 pods per Service) using relaxed atomics, which is negligible compared to I/O. `hash:*` values extract and hash the relevant request attribute with FNV-1a, then perform a linear rendezvous scan — negligible. The `hash:uri` path allocates a single joined `path?query` string only when a query string is present; all other hash sources are allocation-free on the hot path.

## Class-level defaults

Any of the annotations above can be defaulted for **every Ingress claiming an IngressClass** by pointing the class at a `CoxswainIngressClassParameters` resource via `IngressClass.spec.parameters`. This is the GitOps-friendly way to set a baseline policy (timeouts, retries, upstream protocol) once per class instead of repeating it on each Ingress.

```yaml
apiVersion: ingress.coxswain-labs.dev/v1alpha1
kind: CoxswainIngressClassParameters
metadata:
  name: public-defaults
  namespace: coxswain-system
spec:
  defaultAnnotations:
    ingress.coxswain-labs.dev/connect-timeout: "10s"
    ingress.coxswain-labs.dev/retry-on: "connect-failure,5xx"
    ingress.coxswain-labs.dev/max-retries: "2"
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: coxswain
spec:
  controller: coxswain-labs.dev/gateway-controller
  parameters:
    apiGroup: ingress.coxswain-labs.dev
    kind: CoxswainIngressClassParameters
    name: public-defaults
    namespace: coxswain-system
    scope: Namespace
```

**Precedence** (highest wins, per key):

1. The annotation set on the Ingress itself.
2. The class default from `spec.defaultAnnotations`.
3. The built-in Coxswain default.

The merge is per-key: an Ingress that sets only `connect-timeout` still inherits the class's `retry-on` and `max-retries`. The keys and value formats in `defaultAnnotations` are exactly the per-Ingress ones; an invalid value emits a warning and falls back to the built-in default, the same as if it were set directly on an Ingress (an empty string `""` is **not** an "unset" override — it parses, warns, and falls back).

### `spec.accessLog` — per-class access-log control

In addition to `spec.defaultAnnotations`, `CoxswainIngressClassParameters` exposes a typed field for access-log control:

```yaml
spec:
  accessLog: false   # suppress access-log lines for this class's routes
```

Unlike `defaultAnnotations`, `accessLog` is **not** a per-Ingress override — it is class-scoped only. All Ingresses claiming the class share the same setting; individual Ingresses cannot override it per-resource. Set `accessLog: false` when you want to suppress noisy health-check or synthetic-monitor traffic without affecting the rest of the log stream.

Error logs and Prometheus metrics are never suppressed by `accessLog: false`. `accessLog: false` is a downward-only override — it never force-enables logging when `--access-log` is already off globally. See [Observability → Per-class suppression](../reference/observability.md#per-class-suppression) for the full usage example.

!!! note
    `CoxswainIngressClassParameters` is namespaced, so `spec.parameters` must set `scope: Namespace` and a `namespace`. A reference that is missing, names a different kind, or omits its namespace is logged as a warning and ignored — affected Ingresses still route with built-in defaults rather than being rejected. Because `IngressClass` has no status subresource, this condition is surfaced in the controller log, not on the object.
