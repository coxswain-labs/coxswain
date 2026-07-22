# Rate limiting

Per-route, per-client rate limiting protects upstream services from traffic spikes and abuse. Over-limit requests are rejected immediately by the proxy with **429 Too Many Requests** and a `Retry-After` header; the upstream never sees them.

Both bindings reference the same `RateLimit` custom resource, resolved through the identical spec→config translation — parity between the two surfaces is guaranteed by construction, not by convention:

| Binding | When to use |
|---------|-------------|
| [Ingress annotation](#ingress-annotation) | Per-Ingress: `ingress.coxswain-labs.dev/rate-limit: "namespace/name"` |
| [Gateway API `ExtensionRef`](#gateway-api-extensionref) | Per-`HTTPRoute` rule, via the same `RateLimit` custom resource |

## Algorithm

Coxswain uses the [GCRA](https://en.wikipedia.org/wiki/Generic_cell_rate_algorithm) (Generic Cell Rate Algorithm), a leaky-bucket variant, provided by the [`governor`](https://docs.rs/governor) crate.

- **Sustained rate** — `requests-per-second` tokens replenish per second per client.
- **Burst** — a client that has been idle accumulates headroom up to `rps + burst` tokens. A burst of 0 (the default) means the client is limited to exactly `rps` in each second.
- **State** — buckets are held in-process, per-proxy-replica. Distributed limiting across replicas is not yet supported.

## Client identity

The rate-limit key determines which bucket a request is counted against.

| Key | How it is derived |
|-----|-------------------|
| `ip` (default) | Real client IP from a PROXY-protocol header (when `--proxy-accept-proxy-protocol` is set) or the L4 peer address. Each distinct IP gets its own bucket. |
| `header:Name` | The value of the named request header. Each distinct header value gets its own bucket. |

**Fail-open**: when the keying dimension is unavailable — undeterminable IP, or an absent header on a header-keyed route — the request is **admitted without counting**. A missing key never blocks traffic.

## Ingress annotation

Reference a `RateLimit` CR — the same one an `HTTPRoute` `ExtensionRef` filter would point at — from the `rate-limit` annotation:

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: RateLimit
metadata:
  name: api-limit
  namespace: my-app
spec:
  requestsPerSecond: 100
  burst: 50              # optional, default 0
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-api
  namespace: my-app
  annotations:
    ingress.coxswain-labs.dev/rate-limit: "my-app/api-limit"
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

**Fail-open**: if the referenced `RateLimit` CR is missing, the route serves with rate limiting disabled (a WARN is logged) rather than failing the route — the same posture as the Gateway API binding below. See the [`RateLimit` spec fields](#ratelimit-spec-fields) below for `requestsPerSecond`/`burst`/`byHeader`.

### Example: 5 req/s per API key header

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: RateLimit
metadata:
  name: per-key-limit
  namespace: my-app
spec:
  requestsPerSecond: 5
  byHeader: "X-Api-Key"
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  namespace: my-app
  annotations:
    ingress.coxswain-labs.dev/rate-limit: "my-app/per-key-limit"
```

!!! warning
    Header keying can be bypassed by rotating the header value. Pair it with `ext-auth` or `auth-basic-secret` to ensure the header is authenticated before being trusted. The controller emits a `Warning` Event on the Ingress when `byHeader` keying is configured without an auth annotation, so operators are notified at reconcile time. See the [rate-limit annotation reference](../ingress/annotations.md#rate-limiting) for details.

See the [Ingress annotations reference](../ingress/annotations.md#rate-limiting) for the full annotation semantics.

## Gateway API ExtensionRef

Attach a rate limit to a single `HTTPRoute` rule by referencing a `RateLimit` custom resource from an `ExtensionRef` filter:

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: RateLimit
metadata:
  name: api-limit
  namespace: my-namespace
spec:
  requestsPerSecond: 100
  burst: 50           # optional, default 0
  byHeader: "X-Api-Key"  # optional; absent = limit by client IP
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api/
      filters:
        - type: ExtensionRef
          extensionRef:
            group: gateway.coxswain-labs.dev
            kind: RateLimit
            name: api-limit
      backendRefs:
        - name: my-api
          port: 8080
```

### `RateLimit` spec fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `requestsPerSecond` | integer ≥ 1 | required | Sustained rate per client (req/s) |
| `burst` | integer ≥ 0 | `0` | Extra burst capacity above sustained rate |
| `byHeader` | string | _absent_ (IP-keyed) | Header name to use as the client key |

The `RateLimit` CR must be in the same namespace as the `HTTPRoute`. A rule can reference at most one `RateLimit` (the first `ExtensionRef` with `group: gateway.coxswain-labs.dev` and `kind: RateLimit` wins).

**Fail-open**: a dangling reference to a non-existent `RateLimit` CR emits a controller warning and installs the route with no rate limiting — traffic is never blocked by a missing CR.

## 429 response format

A rate-limited request receives:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1
```

The `Retry-After` value is the number of whole seconds until the client's bucket has at least one token again (minimum 1). The response body is empty.

## Memory and GC

Bucket state is held in memory per proxy replica. A background sweep runs every ~60 seconds to evict idle per-client entries (GCRA cells whose token count has fully recovered) and drop entries for routes with no active clients. The sweep bounds memory growth under high-cardinality client key spaces (many distinct IPs or header values).

!!! note
    State is not shared across proxy replicas. In a multi-replica deployment each replica enforces the limit independently, so the effective cluster-wide limit is `rps × replica_count`. Distributed limiting is tracked separately.
