# Retries

Coxswain retries failed upstream attempts against another endpoint in the same backend group. Retrying protects clients from transient upstream failures — a refused connection, a connect timeout, or a retriable response from one pod — without surfacing the error.

Two bindings are supported:

| Binding | When to use |
|---------|-------------|
| [Ingress annotations](#ingress-annotations) | Per-Ingress (HTTP only), attached to existing annotation-based config |
| [Gateway API `ExtensionRef`](#gateway-api-extensionref) | Per-`HTTPRoute` / `GRPCRoute` rule, via a `RetryPolicy` custom resource |

The configuration model mirrors Gateway API [GEP-1731](https://gateway-api.sigs.k8s.io/geps/gep-1731/) (`attempts` / `backoff` / `codes`) so that, once GEP-1731 graduates to the Standard channel, the HTTP surface can be moved to the native `HTTPRoute.spec.rules[].retry` field with no behavioural change. gRPC retry has no GEP-1731 equivalent and stays on the `RetryPolicy` CR permanently.

## Model

- **`attempts`** — the number of _additional_ attempts after the first, and the **gate**: when `attempts` is `0` (or absent on an Ingress), retrying is disabled entirely. With `attempts: 2`, Coxswain makes up to 3 total attempts.
- **Connection failures and connect-timeouts are always retried** when `attempts >= 1`. They are safe to replay — no request bytes reached the upstream. There is no separate opt-in (this matches GEP-1731, where connection-error retries are implicit).
- **`codes`** selects which upstream _responses_ retry. See [HTTP](#http-codes) and [gRPC](#grpc-codes) below.
- **`backoff`** — a minimum delay before each retried attempt. Applied as a fixed minimum; exponential backoff and jitter are not yet applied.

**Replay guard**: response retries require the request body to be buffered. Requests whose bodies are too large or were only partially received cannot be retried and pass through to the client as-is.

Each retry increments `coxswain_proxy_upstream_retries_total{condition=...}` (`connect-failure`, `timeout`, `http-code`, `grpc-code`).

### HTTP codes

Retries fire when the upstream response status is in the code set. When omitted, the set defaults to **`502, 503, 504`** — the "gateway could not obtain a processed response" codes, where the request almost certainly did not execute, so a retry is safe. `500` is deliberately **excluded** from the default: the application ran, and retrying risks double execution. An explicit empty set opts out of response-code retries (connection/timeout retries still apply).

### gRPC codes

`GRPCRoute` retries key on the `grpc-status` code, not the HTTP status (a gRPC response is HTTP `200` even on RPC failure). A gRPC response is **only retriable when the status arrives trailers-only** — i.e. the `grpc-status` rides in the response headers with nothing streamed yet. A `grpc-status` delivered as a trailer _after_ a message is not retriable (the response is already in flight), matching Envoy's behaviour.

When omitted, `grpcCodes` defaults to **`[14]`** (`UNAVAILABLE`). A trailers-only `UNAVAILABLE` implies the RPC never executed, so retrying is safe even without idempotency metadata. `DEADLINE_EXCEEDED` (4) and `RESOURCE_EXHAUSTED` (8) are excluded from the default — retrying them compounds latency or worsens overload. An explicit empty set opts out.

## Ingress annotations

Ingress is HTTP-only. Attach retries to every path rule of an Ingress:

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/retry-attempts: "2"
    ingress.coxswain-labs.dev/retry-codes: "503,504"   # optional; default 502,503,504
    ingress.coxswain-labs.dev/retry-backoff: "100ms"   # optional
```

See the [Ingress annotations reference](ingress-annotations.md#retries) for the full annotation semantics.

## Gateway API `ExtensionRef`

Define a `RetryPolicy` custom resource and reference it from an `HTTPRoute` or `GRPCRoute` rule's `filters` with `type: ExtensionRef`.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: RetryPolicy
metadata:
  name: resilient
  namespace: shop
spec:
  attempts: 3
  backoff: 100ms
  codes: [503, 504]        # optional; default [502, 503, 504]
  grpcCodes: [14]          # optional; default [14] (UNAVAILABLE); GRPCRoute only
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: shop
  namespace: shop
spec:
  parentRefs:
    - name: public
  rules:
    - backendRefs:
        - name: shop
          port: 8080
      filters:
        - type: ExtensionRef
          extensionRef:
            group: gateway.coxswain-labs.dev
            kind: RetryPolicy
            name: resilient
```

The same CR works on a `GRPCRoute` rule — the `grpcCodes` field then governs which `grpc-status` outcomes retry. `codes` still applies on a `GRPCRoute` for transport-level HTTP errors.

**Fail-open**: if the referenced `RetryPolicy` CR is missing, the route serves with retrying disabled (a WARN is logged) rather than failing the route.
