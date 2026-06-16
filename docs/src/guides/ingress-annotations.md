# Ingress annotations

Coxswain supports the `ingress.coxswain-labs.dev/*` annotation namespace for per-Ingress configuration. All annotations are optional and apply uniformly to every rule and path in the Ingress. Invalid values emit a controller warning and are treated as absent — the Ingress is never rejected.

## Quick reference

| Annotation | Type | Default | Example |
|------------|------|---------|---------|
| `ingress.coxswain-labs.dev/connect-timeout` | duration | _none_ | `"5s"` |
| `ingress.coxswain-labs.dev/read-timeout` | duration | _none_ | `"60s"` |
| `ingress.coxswain-labs.dev/send-timeout` | duration | _none_ | `"60s"` |
| `ingress.coxswain-labs.dev/max-retries` | integer | `0` | `"3"` |
| `ingress.coxswain-labs.dev/retry-on` | csv | _none_ | `"connect-failure,5xx"` |
| `ingress.coxswain-labs.dev/rewrite-target` | string | _none_ | `"/v2"` |
| `ingress.coxswain-labs.dev/backend-protocol` | string | `HTTP` | `"GRPC"` |

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

Regex capture-group substitutions (e.g. `/v2$1`) are not yet supported and are tracked separately.

## `backend-protocol`

Overrides the upstream wire protocol derived from the Service `appProtocol` field. Explicit operator intent always wins over `appProtocol` inference.

| Value | Behaviour |
|-------|-----------|
| `HTTP` | Cleartext HTTP/1.1 (the default) |
| `HTTPS` | TLS to the upstream pod; reuses the same SNI and CA-bundle lookup path as `BackendTLSPolicy` |
| `GRPC` | Cleartext HTTP/2 prior-knowledge (`h2c`); suitable for gRPC without TLS |

!!! note
    `GRPC` maps to cleartext HTTP/2 (`h2c`). For gRPC over TLS, use `backend-protocol: HTTPS` — gRPC-over-TLS support via a single annotation value is tracked separately.

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
