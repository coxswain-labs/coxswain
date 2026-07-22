# Ingress annotations

Coxswain supports the `ingress.coxswain-labs.dev/*` annotation namespace for per-Ingress configuration. All annotations are optional and are set once per Ingress; most apply uniformly to every rule and path (`use-regex` additionally keys off each rule's `pathType`).

**Admission-time validation.** On Kubernetes ≥ 1.30, Coxswain installs a `ValidatingAdmissionPolicy` that rejects Ingresses with invalid annotation values at `kubectl apply` time, surfacing the error immediately. On older clusters, or when `vap.enabled=false` is set in the Helm values, invalid values are handled fail-open: the controller emits a warning and treats the annotation as absent, so traffic is never blocked. Disable the VAP only if your cluster does not support `admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy`.

**Runtime diagnostics.** When the VAP is absent or an annotation slips through, the controller emits a Kubernetes `Warning` Event (`reason: InvalidAnnotation`) directly on the Ingress. Run `kubectl describe ingress <name>` to see it inline. See the [Observability reference — Kubernetes Events](../reference/observability.md#kubernetes-events) for details on deduplication and querying.

## Quick reference

<div class="nowrap-col1" markdown>

| Annotation | Type | Default | Example |
|------------|------|---------|---------|
| `ingress.coxswain-labs.dev/read-timeout` | duration | _none_ | `"60s"` |
| `ingress.coxswain-labs.dev/send-timeout` | duration | _none_ | `"60s"` |
| `ingress.coxswain-labs.dev/retry` | `namespace/name` | _none_ | `"my-ns/my-retry"` |
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
| `ingress.coxswain-labs.dev/ip-access-control` | `namespace/name` | _none_ | `"my-ns/my-policy"` |
| `ingress.coxswain-labs.dev/trust-forwarded-for` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/forwarded-for-header` | string | `X-Forwarded-For` | `"CF-Connecting-IP"` |
| `ingress.coxswain-labs.dev/forwarded-for-trusted-cidrs` | cidr-list | _none_ (unconditional) | `"10.0.0.0/8"` |
| `ingress.coxswain-labs.dev/rate-limit` | `namespace/name` | _none_ | `"my-ns/my-limit"` |
| `ingress.coxswain-labs.dev/ext-auth` | `namespace/name` | _none_ | `"my-ns/my-extauth"` |
| `ingress.coxswain-labs.dev/auth-basic-secret` | `namespace/name` | _none_ | `"my-ns/my-htpasswd"` |
| `ingress.coxswain-labs.dev/auth-jwt` | `namespace/name` | _none_ | `"my-ns/my-jwt"` |
| `ingress.coxswain-labs.dev/compression` | `namespace/name` | _none_ | `"my-ns/my-compression"` |
| `ingress.coxswain-labs.dev/auth-tls-secret` | `namespace/name` | _none_ | `"my-ns/my-ca"` |
| `ingress.coxswain-labs.dev/auth-tls-verify-depth` | integer | `1` | `"2"` |
| `ingress.coxswain-labs.dev/auth-tls-pass-certificate-to-upstream` | boolean | `false` | `"true"` |
| `ingress.coxswain-labs.dev/path-normalize` | `base`, `merge-slashes`, `decode-and-merge-slashes` | `base` | `"merge-slashes"` |

</div>

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/read-timeout: "60s"
    ingress.coxswain-labs.dev/retry: "my-ns/my-retry"
    ingress.coxswain-labs.dev/rewrite-target: "/v2"
```

## CR-backed annotations

Eight annotations — `retry`, `rate-limit`, `ext-auth`, `auth-basic-secret`, `auth-jwt`, `auth-tls-secret`, `ip-access-control`, and `compression` — take a `namespace/name` value pointing at a Kubernetes resource: a Coxswain CRD, or a `Secret` for the auth ones. You set the annotation on the Ingress `metadata.annotations` (as in the example above), so the sections below show only the referenced resource. The same resource backs the equivalent Gateway API `ExtensionRef` filter, so one CR serves an Ingress and an HTTPRoute/GRPCRoute identically.

**Missing-reference behaviour** — a missing, unlabeled, or unparseable reference fails **open** (the feature is skipped, traffic flows) for every CR-backed annotation **except** the auth checks (`ext-auth`, `auth-basic-secret`, `auth-jwt`) and client-cert mTLS (`auth-tls-secret`), which fail **closed** (`503`, or an aborted handshake for mTLS) — a stale or typo'd auth reference must not silently disable enforcement.

## Backend connection settings are not annotations

If you're looking for `connect-timeout`, `upstream-keepalive-timeout`, `load-balance`, `circuit-breaker-*`, or `session-affinity` and don't see them in the table above: these five settings moved out of the annotation namespace entirely. They now live on a separate Kubernetes resource, [`CoxswainBackendPolicy`](../gateway-api/backend-policy.md), which you attach to the **backend `Service`** rather than the Ingress.

Why the different shape? These five settings all describe the *connection to the upstream pod* — not anything about routing or the request itself — so they belong to the Service the Ingress points at, not to the Ingress. That also means:

- You write no annotation on the Ingress at all for these. You create a `CoxswainBackendPolicy` naming the Service, and it applies automatically.
- The same policy applies identically whether the Service is reached via an Ingress, an `HTTPRoute`, or a `GRPCRoute` — one place to configure it, no matter how traffic gets there.
- If two Ingresses (or an Ingress and an HTTPRoute) point at the same Service, they share the same connection policy. That's intentional — connection pooling, load-balancing, and circuit-breaking happen per-Service, not per-route.

See the [Gateway API guide's `CoxswainBackendPolicy` section](../gateway-api/backend-policy.md) for the full field list, a copy-pasteable example, and how each setting behaves.

## Timeouts

**Duration format** — All timeout annotations accept Go `time.ParseDuration` strings: one or more `<number><unit>` pairs without spaces. Supported units: `ns`, `us` (`µs`), `ms`, `s`, `m`, `h`. Examples: `"5s"`, `"500ms"`, `"1m30s"`. Zero values (`"0"`, `"0s"`) are treated as absent.

These are per-*request* timeouts. Upstream connect timeout is per-backend connection policy — see [`CoxswainBackendPolicy`](../gateway-api/backend-policy.md).

### `read-timeout`

Maximum time for the upstream to send the first response byte after the full request has been sent. When an HTTPRoute `backendRequest` timeout is also configured, the more restrictive of the two applies.

### `send-timeout`

Maximum time to write the full request to the upstream. Corresponds to Pingora's `write_timeout`.

## `retry`

The Ingress surface for the [`RetryPolicy` CRD](../operations/retries.md). The field shape follows the Gateway API retry model (`attempts` / `codes` / `backoff`). See the [Retries guide](../operations/retries.md) for the full model, including gRPC. Ingress is HTTP-only, so a referenced CR's `grpcCodes` field is ignored.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: RetryPolicy
metadata:
  name: default-retry
  namespace: my-app
spec:
  attempts: 2
  codes: [502, 503, 504]
  backoff: 100ms
```

`attempts` is the gate: absent or `0` disables retrying entirely, regardless of `codes`/`backoff`. With `attempts: 2`, Coxswain makes up to 3 total attempts, tried against randomly selected endpoints in the same backend group (no per-endpoint pinning). When `attempts >= 1`, **connection failures and connect-timeouts are always retried** (they are safe — no request bytes were sent); `codes` additionally selects which upstream _responses_ trigger a retry — omitted defaults to `[502, 503, 504]` (`500` is excluded: the application ran, and a retry risks double execution), an explicit empty list opts out of response-code retries. `backoff` is a minimum delay before each retried attempt; absent means immediate retry.

Each retry attempt (not counting the final failing attempt) increments `coxswain_proxy_upstream_retries_total{condition=...}`. Use this to confirm retries are firing and to alert on unexpectedly high retry rates that indicate a flapping backend.

!!! note
    Response-code retries require the full request body to be buffered. Requests whose bodies are too large or were only partially received cannot be retried and pass through to the client as-is.

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

**Per-path, not per-host.** `use-regex` is an Ingress-wide *enable*; the per-path lever is the standard `pathType` field. Only `ImplementationSpecific` rules become regex — `Prefix` and `Exact` rules in the same Ingress are unaffected. Enabling `use-regex` never forces regex matching onto paths that did not opt in via `pathType`.

**Matching semantics.** The pattern is matched unanchored and is evaluated **after** exact and prefix routes on the same host — a literal `Prefix`/`Exact` rule that also matches wins over a regex rule. The Kubernetes API server requires every Ingress path to start with `/`, so a regex path is always rooted there (`/svc/(.*)`, not `^/svc/(.*)`); use `$` to anchor the end.

**Invalid patterns.** A path whose value is not a valid regular expression is skipped with a controller `WARN`; the rest of the Ingress (and the routing table) is unaffected.

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
    The `none` value (which disabled normalization entirely) was dropped because it re-opened route-match bypass and path-traversal attacks — a request could dodge a path-based route or `ip-access-control` rule with `..`, `%2e%2e`, or duplicate slashes. An Ingress that still sets `path-normalize: none` is **not rejected**: the controller logs a `WARN`, emits a `Warning` Event, and silently upgrades the level to `base`. If you previously relied on raw-path passthrough, expect normalized paths upstream now and remove any dependency on the un-normalized form.

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

<div class="nowrap-col1" markdown>

| Annotation | Value | Notes |
|------------|-------|-------|
| `redirect-scheme` | `http` or `https` | |
| `redirect-hostname` | hostname string | replaces the Host header |
| `redirect-port` | port integer | explicit port in the Location |
| `redirect-path` | absolute path | full path replacement |
| `redirect-status-code` | `301`, `302`, `307`, `308` | defaults to `302` |

</div>

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
from the backend **Service port `appProtocol`** field — the Gateway API mechanism,
which applies to both Ingress and Gateway API backends:

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
    **Upstream TLS** is configured with a `BackendTLSPolicy`, the sole Gateway API mechanism for originating TLS to a backend. There is no protocol-hint shortcut for upstream TLS.

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

Units are **binary** (`k` = 1024, `m` = 1024², `g` = 1024³).

Enforcement is two-layered and never buffers the whole body:

- When the request declares a `Content-Length` larger than the limit, it is rejected up front — before any upstream connection is opened. This applies to both HTTP/1.x and HTTP/2.
- For chunked or streaming uploads with no `Content-Length`, the proxy counts bytes as they arrive and aborts with 413 the moment the running total crosses the limit **on HTTP/1.x only**. A streaming **HTTP/2** upload without `Content-Length` is not capped mid-stream (it fails open) — returning a rejection mid-body over HTTP/2 deadlocks the client under `pingora-proxy`; faithful HTTP/2 enforcement awaits pingora request-body buffering.

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

## `ip-access-control`

The Ingress surface for the [`IpAccessControl` CRD](../gateway-api/route-extensions.md#ip-access-control), same idiom as `ext-auth`/`auth-jwt`/`compression`/`retry`/`rate-limit`. Value is `namespace/name` of an `IpAccessControl` resource; both surfaces resolve the same CR to the same runtime config, so one `IpAccessControl` can back an Ingress and an HTTPRoute/GRPCRoute `ExtensionRef` filter identically. A request whose client IP falls inside `deny`, or outside every `allow` range when `allow` is non-empty, is rejected with **403 Forbidden** before any upstream connection is opened.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: IpAccessControl
metadata:
  name: office-only
spec:
  deny:                       # evaluated FIRST
    - 203.0.113.5/32
  allow:                      # then the allow-list
    - 203.0.113.0/24
    - 2001:db8::/32
```

The `allow` / `deny` values are lists of IPv4/IPv6 CIDR blocks. A bare address without a prefix (`10.0.0.1`, `2001:db8::1`) is accepted as a host route (`/32` / `/128`).

**Which IP is matched.** When the proxy sits behind a load balancer speaking the [PROXY protocol](../reference/configuration.md) (`--proxy-accept-proxy-protocol`), the match uses the **real client IP** carried in the PROXY header. Otherwise it uses the L4 peer address of the connection. Deploy behind a PROXY-protocol-aware load balancer (or set `externalTrafficPolicy: Local`) so the proxy observes real client IPs rather than the LB's address. When `trust-forwarded-for` is also set, see the [Trusted proxy headers](#trust-forwarded-for) section — the effective client IP may come from a forwarded header instead.

**Matching is strict.** CIDR membership is exact per address family — an IPv4-mapped IPv6 client (`::ffff:10.0.0.1`) does **not** match an IPv4 CIDR. List both families if your clients can arrive over either.

**Evaluation order.** `deny` is evaluated **before** `allow`. A client IP that falls inside the deny list is rejected with 403 even if the allow-list would have admitted it. An empty `allow` list imposes no allow-list restriction (only `deny` applies); empty `allow` **and** empty `deny` performs no filtering.

**Unattributable client IP.** A client whose IP cannot be determined is **denied** against a non-empty `allow` list (**fail-closed** — an un-attributable client must not pass a security control), but is **not** blocked by `deny` alone (a block list only acts on IPs it can positively attribute to a listed range).

Invalid CIDR tokens are logged and skipped rather than rejecting the whole policy.

## `trust-forwarded-for`

Lets the proxy extract the **real client IP** from a forwarded-for header — necessary when Coxswain sits behind a cloud LB or CDN that terminates the connection and puts the original client IP in a header like `X-Forwarded-For` or `CF-Connecting-IP`.

Without this annotation, IP-based features (`ip-access-control`, IP-keyed `rate-limit`) always see the **L4 peer address** (the LB's IP), making per-client controls ineffective behind a proxy.

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
3. **CIDR gate (fail-closed)** — the forwarded header is honored **only** when the L4 base IP is inside one of the `forwarded-for-trusted-cidrs`. If the list is empty, or the L4 peer is not in it, the header is ignored (anti-spoofing) and the L4 base IP is used. An empty list trusts **no** peer — you must configure your load balancer's CIDR to enable header trust.
4. **Rightmost-untrusted parse** — parse the configured header (default `X-Forwarded-For`) and scan the comma-separated list **right-to-left**, skipping addresses that are themselves trusted-proxy hops (in `forwarded-for-trusted-cidrs`) or private/reserved. The first address that is neither is the effective client IP. Everything to its left is client-controlled and ignored, so a forged leftmost token cannot spoof the client IP. If no untrusted address is found, fall back to the L4 base IP.

All addresses are canonicalized before matching, so an IPv4-mapped IPv6 form (`::ffff:a.b.c.d`) is treated as its IPv4 address — it cannot slip past an IPv4 `ip-access-control` allow/deny CIDR.

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

The value is a comma-separated list of IPv4/IPv6 CIDR blocks (same format as `forwarded-for-trusted-cidrs` itself — a bare address is accepted as a host route). Whitespace is trimmed.

**When absent or empty**, the forwarded header is trusted unconditionally for **every** L4 peer — only do this when the deployment topology guarantees that only a trusted proxy can reach Coxswain directly.

**Security note.** Always set `forwarded-for-trusted-cidrs` to the IP range of your load balancer or CDN edge nodes. Without it, any client that can reach the proxy port can forge the forwarded header and bypass IP-based controls.

**Failure handling:**

- An invalid CIDR token emits a controller warning and is skipped.
- If every token is invalid, the CIDR list is treated as absent (unconditional trust) and a controller warning is emitted.

## Session affinity, circuit breaker, and load balancing

Session affinity (sticky sessions), the per-upstream-endpoint circuit breaker, and the load-balancing algorithm are **not** Ingress annotations — they are configured by attaching a [`CoxswainBackendPolicy`](../gateway-api/backend-policy.md) to the backend `Service`, identically for Ingress and Gateway API routes. See the [Gateway API guide](../gateway-api/backend-policy.md) for the full field set, the circuit breaker's state machine and Prometheus series, and worked examples.

---

## Rate limiting

The Ingress surface for the [`RateLimit` CRD](../operations/rate-limiting.md#ratelimit-spec-fields), same idiom as `ext-auth`/`auth-jwt`/`compression`/`retry`. Value is `namespace/name` of a `RateLimit` resource; both surfaces resolve the same CR to the same runtime config, so one `RateLimit` can back an Ingress and an HTTPRoute/GRPCRoute `ExtensionRef` filter identically. Over-limit requests are rejected with **429 Too Many Requests** and a `Retry-After` header (in whole seconds) telling the client when to retry. See the [Rate limiting guide](../operations/rate-limiting.md) for the full model, including the GCRA algorithm and Gateway API usage.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: RateLimit
metadata:
  name: default-limit
  namespace: my-app
spec:
  requestsPerSecond: 100
  burst: 50              # optional, default 0
  byHeader: "X-Api-Key"  # optional; absent = limit by client IP
```

`requestsPerSecond` is the sustained rate per client; `burst` (default `0`) is extra headroom above the sustained rate a client that has been idle may spend in a short spike — total burst capacity is `requestsPerSecond + burst`. `byHeader` selects the per-client key: absent (the default) keys by real client IP (or L4 peer when not behind a PROXY-protocol LB); a header name keys by that header's value instead. When the keying dimension is not available for a request (undeterminable IP, or an absent header on a header-keyed route) the request is **admitted without counting** (**fail-open**) — a missing key never blocks traffic.

!!! warning "Header keying allows rate-limit bypass"
    `byHeader` allocates one bucket per **unique value** of the named header. A client that rotates the header value (e.g. sends a different `X-Api-Key` on each request) starts with a full bucket every time, bypassing the per-key limit entirely.

    Mitigate by:

    - combining with `ext-auth` or `auth-basic-secret` so the header value is authenticated before being trusted as a rate-limit key, or
    - omitting `byHeader` (IP-keyed) as the primary limit and treating header keying as an optional secondary signal only.

    The controller emits a `Warning` Event on the Ingress when `byHeader` keying is configured without an auth annotation, so operators are notified at reconcile time.

## Authentication

Coxswain supports three independently additive authentication checks on Ingresses: **external authorization** (`ext_authz`, delegated to an auth service, `ext-auth`), **basic auth** (htpasswd Secret, `auth-basic-secret`), and **JWT** (JWKS bearer-token, `auth-jwt`). All are enforced at the proxy before any upstream connection; a failure never reaches the backend. A route can combine any subset of the three — every configured check must pass.

### `ext-auth`

Enables **external authorization** (`ext_authz`) — the Ingress surface for the [`CoxswainExternalAuth` CRD](../gateway-api/route-extensions.md#external-authorization-ext_authz), same idiom as `auth-jwt`. Value is `namespace/name` of a `CoxswainExternalAuth` resource; both surfaces resolve the same CR to the same runtime config, so one `CoxswainExternalAuth` can back an Ingress and an HTTPRoute `ExtensionRef` filter identically.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainExternalAuth
metadata:
  name: oauth2
  namespace: my-app
spec:
  protocol: HTTP          # or GRPC
  backendRef:
    name: oauth2-proxy
    port: 4180
  timeout: 250ms
  failClosed: true        # deny (503) on auth-service error/timeout (default)
  allowedResponseHeaders: # copied onto the upstream request on allow
    - x-auth-user
```

A **2xx** (HTTP transport) or `OK` (gRPC transport) response from the auth service allows the request; any other status is returned to the client verbatim and the upstream is never hit. A missing `CoxswainExternalAuth` CR fails **closed** (**503**) — matching `auth-basic-secret`/`auth-jwt`: an operator who set `ext-auth` intends the route to require the check, so a stale or typo'd reference must not silently disable it. A present CR whose `backendRef` has no ready endpoints, whose cross-namespace `backendRef` lacks a `ReferenceGrant`, or whose protocol is unsupported also fails **closed**. See the [`CoxswainExternalAuth` CRD reference](../gateway-api/route-extensions.md#external-authorization-ext_authz) for the full spec (transport, timeout, fail-closed posture, response-header forwarding).

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
```

Requests without credentials receive **401** with a `WWW-Authenticate: Basic realm="coxswain"` header. Invalid credentials also receive **401**.

!!! tip "Hardening"
    Always generate credentials with `htpasswd -B` (bcrypt). Avoid `htpasswd -s` (`{SHA}`) — SHA1 is unsalted and can be cracked offline in seconds with commodity hardware.

    Credential hashes are zeroed from memory when the credential list is replaced at reconcile time (`zeroize`). The Helm chart already ships `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, and `capabilities.drop: ALL` by default. For the remaining defense-in-depth, configure nodes with `vm.swappiness=0` so hashes can't be paged to disk — this is a node-level kernel parameter that Kubernetes cannot enforce per-pod.

### `auth-jwt`

Enables **JWT (JWKS bearer-token) validation** — the Ingress surface for the [`JwtAuth` CRD](../gateway-api/route-extensions.md#jwt-authentication), same idiom as `auth-basic-secret`. Value is `namespace/name` of a `JwtAuth` resource; both surfaces resolve the same CR to the same runtime config, so one `JwtAuth` can back an Ingress and an HTTPRoute identically.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: JwtAuth
metadata:
  name: my-jwt
  namespace: my-app
spec:
  issuer: https://issuer.example.com
  audiences:
    - my-api
  jwks:
    remote:
      uri: https://issuer.example.com/.well-known/jwks.json
  claimToHeaders:
    - claim: sub
      header: x-user-id
```

A valid, signed, unexpired, correct-issuer bearer token is admitted; the verified `sub` claim is forwarded as `x-user-id`. A missing/invalid/expired/wrong-issuer/wrong-audience token receives **401** with `WWW-Authenticate: Bearer`. A missing `JwtAuth` CR fails **closed** (**503**) — matching `auth-basic-secret`/`ext-auth`: an operator who set `auth-jwt` intends the route to require a bearer token, so a stale or typo'd reference must not silently disable authentication. An unresolved JWKS also fails **closed** (**503**). See the [`JwtAuth` CRD reference](../gateway-api/route-extensions.md#jwt-authentication) for the full spec (remote vs. inline JWKS, `fromHeaders`, `forwardPayloadHeader`, `forward`).

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
```

The Ingress carries the annotation and must also declare a `spec.tls` server certificate for the host — client-cert verification happens during that TLS handshake, so an mTLS host needs its own server cert.

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

## Upstream keepalive idle timeout

How long Pingora keeps an idle upstream connection in its keepalive pool before evicting it is **not** an Ingress annotation — it is `timeouts.idle` on a [`CoxswainBackendPolicy`](../gateway-api/backend-policy.md) attached to the backend `Service`. Absent or invalid values warn and fall back to Pingora's default (connections are evicted by LRU capacity pressure, not by age).

**Observability**: the `coxswain_proxy_upstream_connections_total{state="reused"}` counter increments every time a request reuses a pooled connection. Compare it with `{state="new"}` to gauge keepalive efficiency for a route.

**Global pool size**: the total number of idle upstream connections across all routes is bounded by `--proxy-upstream-keepalive-pool-size` (default: 128). Set it via the Helm value `proxy.shared.upstreamKeepalivePoolSize` or the env var `COXSWAIN_PROXY_UPSTREAM_KEEPALIVE_POOL_SIZE`. Raise it for deployments with many distinct upstream hosts/ports; lower it to reduce file-descriptor usage.

## `compression`

Opt-in, per-Ingress on-the-fly response compression — the Ingress surface for the
[`Compression` CRD](../gateway-api/route-extensions.md#response-compression), same idiom as `ext-auth`/`auth-jwt`. Value
is `namespace/name` of a `Compression` resource; both surfaces resolve the same CR to the same
runtime config, so one `Compression` can back an Ingress and an HTTPRoute `ExtensionRef` filter
identically.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: Compression
metadata:
  name: default-compression
  namespace: my-app
spec:
  gzip: true
  brotli: true
  level: 6
  minSize: 1024
  types:
    - text/html
    - text/plain
    - text/css
    - application/json
    - application/javascript
```

At least one of `gzip` / `brotli` must be `true` for the CR to have any effect; when both are `false`
(the default) it is a no-op. Brotli is preferred over gzip when both are enabled and the client
advertises `br` in `Accept-Encoding`. `level` (1–9, default `6`), `minSize` (bytes, default `1024`),
and `types` (default: `text/html`, `text/plain`, `text/css`, `application/json`,
`application/javascript`) are documented on the [`Compression` CRD reference](../gateway-api/route-extensions.md#response-compression).

### Behaviour

Compression is applied only when **all** of the following hold:

1. At least one codec (`gzip` or `brotli`) is enabled on the referenced CR.
2. The client advertises the codec in `Accept-Encoding`.
3. The upstream response does not already have a `Content-Encoding` header — pre-compressed
   responses (e.g. assets served pre-compressed by the upstream) are forwarded unchanged.
4. The response `Content-Type` (before `;`) matches an entry in the CR's `types`.
5. Either `Content-Length` is absent, or its value is ≥ the CR's `minSize`.
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

## Load-balancing algorithm

The algorithm used to pick an upstream endpoint for each request is **not** an Ingress annotation — it is `loadBalancer.algorithm` on a [`CoxswainBackendPolicy`](../gateway-api/backend-policy.md) attached to the backend `Service`. See the Gateway API guide for the full value table (`round_robin`, `least_conn`, `ewma`, the `hash:*` consistent-hash forms), the Istio/Envoy equivalence mapping, and performance notes.

`hash:source-ip` (and its alias `ip_hash`) interacts with [`trust-forwarded-for`](#trust-forwarded-for): when enabled, it hashes the resolved client IP (the first non-private address from the forwarded header, gated by [`forwarded-for-trusted-cidrs`](#forwarded-for-trusted-cidrs) if set) rather than the TCP peer address.

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
    ingress.coxswain-labs.dev/read-timeout: "10s"
    ingress.coxswain-labs.dev/retry: "coxswain-system/default-retry"
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

The merge is per-key: an Ingress that sets only `read-timeout` still inherits the class's `retry` reference. The keys and value formats in `defaultAnnotations` are exactly the per-Ingress ones — including `namespace/name` CR references like `retry`/`compression`, which resolve identically whether set directly on an Ingress or inherited from a class default; an invalid value emits a warning and falls back to the built-in default, the same as if it were set directly on an Ingress (an empty string `""` is **not** an "unset" override — it parses, warns, and falls back).

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
