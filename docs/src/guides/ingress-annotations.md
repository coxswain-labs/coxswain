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
