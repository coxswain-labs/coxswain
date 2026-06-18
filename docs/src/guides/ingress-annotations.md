# Ingress annotations

Coxswain supports the `ingress.coxswain-labs.dev/*` annotation namespace for per-Ingress configuration. All annotations are optional and are set once per Ingress; most apply uniformly to every rule and path (`use-regex` additionally keys off each rule's `pathType`). Invalid values emit a controller warning and are treated as absent — the Ingress is never rejected.

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
| `ingress.coxswain-labs.dev/backend-protocol` | string | `HTTP` | `"GRPC"` |
| `ingress.coxswain-labs.dev/max-body-size` | size | _none_ | `"8m"` |
| `ingress.coxswain-labs.dev/mirror-target` | `svc.ns[:port]` | _none_ | `"echo-b.default.svc:3000"` |
| `ingress.coxswain-labs.dev/allow-source-range` | cidr-list | _none_ | `"10.0.0.0/8,192.168.1.0/24"` |
| `ingress.coxswain-labs.dev/cache-enabled` | boolean | `false` | `"true"` |
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

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/connect-timeout: "5s"
    ingress.coxswain-labs.dev/read-timeout: "60s"
    ingress.coxswain-labs.dev/max-retries: "2"
    ingress.coxswain-labs.dev/retry-on: "connect-failure,timeout"
    ingress.coxswain-labs.dev/rewrite-target: "/v2"
    ingress.coxswain-labs.dev/backend-protocol: "GRPC"
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

## `backend-protocol`

Overrides the upstream wire protocol derived from the Service `appProtocol` field. Explicit operator intent always wins over `appProtocol` inference.

| Value | Behaviour |
|-------|-----------|
| `HTTP` | Cleartext HTTP/1.1 (the default) |
| `HTTPS` | TLS to the upstream pod; reuses the same SNI and CA-bundle lookup path as `BackendTLSPolicy` |
| `GRPC` | Cleartext HTTP/2 prior-knowledge (`h2c`); suitable for gRPC without TLS |

!!! note
    `GRPC` maps to cleartext HTTP/2 (`h2c`). For gRPC over TLS, use `backend-protocol: HTTPS` — gRPC-over-TLS support via a single annotation value is tracked separately.

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

- When the request declares a `Content-Length` larger than the limit, it is rejected up front — before any upstream connection is opened.
- For chunked or streaming uploads (no `Content-Length`), the proxy counts bytes as they arrive and aborts with 413 the moment the running total crosses the limit.

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

By default (without `max-body-size`) the mirror receives the request headers and an empty body. To mirror the full request body, set `max-body-size` on the same Ingress — the proxy buffers each request body up to the cap and includes it verbatim in the mirror sub-request:

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/mirror-target: "shadow-svc.my-namespace.svc:8080"
    ingress.coxswain-labs.dev/max-body-size: "1m"
```

`max-body-size` already rejects requests exceeding the cap with 413, so the mirror buffer is inherently bounded — no additional memory risk is introduced.

!!! note "Body-mirroring for large payloads"
    Stream-concurrent mirroring (mirror body as it arrives, no buffering) is planned (#360). Until then, mirror with a body cap is the recommended pattern for production use.

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

**Which IP is matched.** When the proxy sits behind a load balancer speaking the [PROXY protocol](../reference/configuration.md) (`--proxy-accept-proxy-protocol`), the match uses the **real client IP** carried in the PROXY header. Otherwise it uses the L4 peer address of the connection. Deploy behind a PROXY-protocol-aware load balancer (or set `externalTrafficPolicy: Local`) so the proxy observes real client IPs rather than the LB's address.

**Matching is strict.** CIDR membership is exact per address family — an IPv4-mapped IPv6 client (`::ffff:10.0.0.1`) does **not** match an IPv4 CIDR. List both families if your clients can arrive over either.

**Failure handling:**

- An invalid CIDR token emits a controller warning and is **skipped**; the remaining valid ranges still apply.
- If **every** token is invalid (or the annotation is absent/empty), the allow-list is treated as absent — **all** source IPs are admitted (**fail-open** at parse time, so a typo never locks out all traffic).
- Once an allow-list is in effect, a request whose source IP cannot be determined is **denied** (**fail-closed** at request time) — an un-attributable client must not pass a security control.

## `cache-enabled`

Opts the Ingress into RFC 7234 HTTP response caching. When `"true"`, the proxy serves cacheable responses from an in-memory cache instead of contacting the upstream on every request — cutting upstream load and client latency for static assets and public API responses.

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/cache-enabled: "true"
```

**What gets cached.** Caching is conservative by design — only responses the upstream explicitly marks fresh are stored:

- Only `GET` and `HEAD` responses are eligible.
- The response must carry explicit freshness: `Cache-Control: max-age=…` or `Expires`. A response with neither is **not** cached (there is no implicit TTL).
- `Cache-Control: no-store` and `no-cache` on the response are honoured — such responses are never stored.
- `Vary` is respected: responses are keyed by the request values of the listed headers, so content negotiation stays correct.

**Bypass.** Requests carrying an `Authorization` or `Cookie` header bypass the cache entirely — per-user responses must never be served to another client.

**Served-from-cache responses** carry an `Age` header (seconds since the entry was stored), per RFC 7234.

**Cache size.** The cache is shared across all cache-enabled routes in a proxy and bounded by `--cache-max-size` (default `100m`, binary units; `0` disables caching). When full, least-recently-used entries are evicted. See the [configuration reference](../reference/configuration.md).

**Purging.** A cached entry can be evicted on demand via the proxy admin port:

```
DELETE /cache/{host}/{path}
```

For example `DELETE /cache/cache.example.com/assets/app.js` purges the `GET cache.example.com/assets/app.js` entry. The response reports whether an entry was removed (`{"purged": true}`).

!!! note
    The Gateway API binding for caching (an `HTTPRoute` `ExtensionRef` filter pointing at a `CoxswainCachePolicy`) is tracked separately; today `cache-enabled` is the Ingress-only entry point.

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
    The Gateway API binding for session persistence is tracked in [#355](https://github.com/coxswain-labs/coxswain/issues/355). It is deferred because the only Gateway API surface for session persistence in our pinned crate is experimental-only (which Coxswain never compiles into release images), and the `BackendLBPolicy` resource originally proposed is not an upstream Gateway API type. Today the `session-*` annotations are the Ingress-only entry point.

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
- **Supported hash algorithms**: `bcrypt` (`$2a$`, `$2b$`, `$2y$`) and `SHA1` (`{SHA}base64`). Lines using other schemes are skipped with a controller warning.

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
    Credential hashes are zeroed from memory when the credential list is replaced at reconcile time (`zeroize`). The Helm chart already ships `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, and `capabilities.drop: ALL` by default. For the remaining defense-in-depth, configure nodes with `vm.swappiness=0` so hashes can't be paged to disk — this is a node-level kernel parameter that Kubernetes cannot enforce per-pod.

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

!!! note
    `CoxswainIngressClassParameters` is namespaced, so `spec.parameters` must set `scope: Namespace` and a `namespace`. A reference that is missing, names a different kind, or omits its namespace is logged as a warning and ignored — affected Ingresses still route with built-in defaults rather than being rejected. Because `IngressClass` has no status subresource, this condition is surfaced in the controller log, not on the object.
