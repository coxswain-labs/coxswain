# CoxswainBackendPolicy

`CoxswainBackendPolicy` configures how the proxy talks to the pods behind a `Service` — connection timeouts, the load-balancing algorithm, a circuit breaker, and sticky sessions. Point it at a `Service` by name and every route that sends traffic to that Service picks up the settings — whether that route is an `HTTPRoute`, a `GRPCRoute`, or a classic `Ingress`. Nothing is added to the route itself; the policy attaches to the Service and takes effect automatically.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainBackendPolicy
metadata:
  name: api-backend-policy
spec:
  targetRefs:
    - group: ""
      kind: Service
      name: api          # <- must be a Service in this same namespace
  timeouts:
    connect: 500ms
```

`targetRefs` is the only required field. `timeouts`, `loadBalancer`, `circuitBreaker`, and `sessionPersistence` are independent and optional — set only the ones you need; anything omitted keeps the default connection behavior (immediate connect with no timeout override, weighted round-robin, no circuit breaker, no sticky sessions).

!!! note "Why a separate resource, not a route annotation or filter?"
    These four settings describe the *connection to the upstream Service*, not how a request is routed there — so unlike per-route filters (retry, rate limiting, compression), `CoxswainBackendPolicy` attaches per-Service ([GEP-713](https://gateway-api.sigs.k8s.io/geps/gep-713/) direct policy attachment). Two consequences: (1) if two routes (say an Ingress and an HTTPRoute) both send traffic to the same Service, they share one connection policy — intentional, since connection pooling and circuit breaking are properties of the upstream, not the route; (2) neither `loadBalancer` nor `circuitBreaker` has a stable Gateway API standard to converge toward — Gateway API v1.6.0 covers neither (its closest concept, `BackendLBPolicy`, was replaced by an experimental type that only handles retry budgets and session persistence) — so those two fields are modeled after Envoy's native load-balancing policies and outlier detection instead. `sessionPersistence` does mirror Gateway API's own (experimental) `SessionPersistence` shape, as closely as Coxswain's persistence mechanism supports (see below).

## Fields

| Field | Required? | Description |
|-------|-----------|-------------|
| `targetRefs[]` | **Yes** | The `Service` objects this policy applies to, in the *same namespace* as the policy. Each entry: `{ group: "", kind: Service, name: <service-name> }`. |
| `timeouts.connect` | optional | Upstream TCP-connect timeout (a duration, e.g. `500ms`, `5s`). If the proxy can't establish a connection to a pod within this time, it fails the request with `502` instead of waiting indefinitely. |
| `timeouts.idle` | optional | How long an idle, already-established connection to a pod is kept open in the connection pool before being closed. |
| `loadBalancer.algorithm` | optional | Which algorithm picks a pod for each request. See [Load-balancing algorithm](#load-balancing-algorithm) below for the full list of values. |
| `circuitBreaker.threshold` | optional | Error rate (%, `1`–`100`) that trips the breaker. This is the on/off switch: omit it (or set it out of range) and the circuit breaker is disabled entirely — the other `circuitBreaker.*` fields have no effect on their own. See [Circuit breaker](#circuit-breaker) below. |
| `circuitBreaker.window` | optional | How far back the proxy looks when computing the error rate. Default `10s`. |
| `circuitBreaker.openDuration` | optional | Once tripped, how long the breaker stays open before it lets a test request through. Default `5s`. |
| `circuitBreaker.minRequests` | optional | Don't trip the breaker until at least this many requests have been observed in the window — protects low-traffic routes from tripping on one unlucky failure. Default `10`. |
| `circuitBreaker.maxOpenDuration` | optional | If a pod keeps failing its recovery checks, each re-trip doubles the open duration up to this cap, instead of always waiting the same `openDuration`. Omit for a constant (non-growing) open duration. |
| `sessionPersistence.type` | optional | How to pin a client to one pod: `Cookie` or `Header`. See [Session persistence](#session-persistence) below for guidance on which to pick. |
| `sessionPersistence.sessionName` | conditionally required | The cookie name (`Cookie` mode — optional, defaults to `__coxswain_session`) or the request header to key on (`Header` mode — **required**, no default). |

## Full example

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainBackendPolicy
metadata:
  name: api-backend-policy
spec:
  targetRefs:
    - group: ""
      kind: Service
      name: api
  timeouts:
    connect: 500ms
    idle: 60s
  loadBalancer:
    algorithm: least_conn
  circuitBreaker:
    threshold: 50
    window: 10s
    openDuration: 5s
    minRequests: 10
  sessionPersistence:
    type: Cookie
    sessionName: my-session
```

## Behaviour

- A backend `Service` with no attached policy keeps the default connection behaviour (weighted round-robin, breaker disabled, no session persistence).
- The per-backend `timeouts.connect` takes precedence over the Gateway API `HTTPRoute.timeouts.backendRequest` fallback.
- **Invalid values fail open.** An unparseable duration, an unrecognised `loadBalancer.algorithm`, an out-of-range `circuitBreaker.threshold`, or an unrecognised `sessionPersistence.type` is logged as a warning and ignored — the backend falls back to the default (round-robin / breaker disabled / no persistence), never a connection-level error or a rejected resource. These fields are deliberately not schema-validated so the policy is accepted and the warning surfaces at reconcile time.
- **Conflicts.** If two policies target the same `Service`, the older one (by `creationTimestamp`, ties broken by name) wins; the loser receives `Accepted=False, reason=Conflicted` in its `status.ancestors[]`.

## Load-balancing algorithm

`loadBalancer.algorithm` selects the algorithm used to pick an upstream endpoint for each request within the backend group of a route:

| Value | Description |
|-------|-------------|
| `round_robin` | _(default)_ Weighted round-robin using the GCD-reduced slot array. Zero per-request overhead. |
| `least_conn` | Routes to the endpoint with the fewest in-flight requests. Maintains an atomic in-flight counter per endpoint; the counter is incremented on selection and decremented when the response completes (or when a retry selects a different endpoint). |
| `ewma` | Routes to the endpoint with the lowest exponentially-weighted moving-average response latency (α = 1/8). Unsampled endpoints (active=0) are probed first. Latency is folded in at end-of-request. |
| `ip_hash` | Alias for `hash:source-ip` (backward-compatible). |
| `hash:uri` | Consistent hash on the full request URI (path + query string). Requests to the same URI always land on the same endpoint. Falls back to round-robin if the path is empty. |
| `hash:source-ip` | Consistent hash on the resolved client IP (see [`trust-forwarded-for`](../ingress/annotations.md#trust-forwarded-for) for Ingress, or the equivalent Gateway API resolution). Requests from the same IP always land on the same endpoint; unlike cookie affinity, no state is injected into the response. Falls back to round-robin if the client IP is unavailable. |
| `hash:header=<name>` | Consistent hash on the value of the named request header (e.g. `hash:header=x-user-id`). An empty or absent header falls back to round-robin. |
| `hash:cookie=<name>` | Consistent hash on the value of the named cookie (e.g. `hash:cookie=session`). An absent or empty cookie falls back to round-robin. |

All `hash:*` values (and `ip_hash`) use **rendezvous (HRW) hashing**: when an endpoint is removed, only its keys are redistributed; all other keys remain on their existing endpoints. This is strictly better than modulo hashing, which reshuffles nearly every key on a membership change. Unknown values warn and fall back to `round_robin`; routing is never interrupted.

**Mapping to Istio/Envoy** — `loadBalancer.algorithm` corresponds to `DestinationRule.trafficPolicy.loadBalancer`:

| Coxswain value | Istio / Envoy equivalent |
|----------------|--------------------------|
| `round_robin` | `ROUND_ROBIN` |
| `least_conn` | `LEAST_REQUEST` |
| `ewma` | `LEAST_REQUEST` with latency-weighted selection |
| `ip_hash` / `hash:source-ip` | `CONSISTENT_HASH` (`useSourceIp: true`) |
| `hash:uri` | `CONSISTENT_HASH` (HTTP URI — closest analogue) |
| `hash:header=<name>` | `CONSISTENT_HASH` (`httpHeaderName: <name>`) |
| `hash:cookie=<name>` | `CONSISTENT_HASH` (`httpCookie.name: <name>`) |

**Performance** — all algorithms run on the hot path without locks. `round_robin` allocates nothing per request. `least_conn` and `ewma` do a linear scan over the endpoint list (typically 1–10 pods) using relaxed atomics — negligible against I/O. `hash:*` values hash the relevant request attribute with FNV-1a, then do a linear rendezvous scan; only `hash:uri` allocates, and only when a query string is present.

## Circuit breaker

The per-upstream-endpoint circuit breaker trips when a backend pod's **error rate** exceeds `threshold`, returning fail-fast **503** responses to clients until the pod shows signs of recovery. This is the Coxswain equivalent of Envoy/Istio **outlier detection**: a single degraded pod trips only its own breaker; healthy pods serving the same route keep accepting traffic.

The breaker is implemented with [failsafe](https://docs.rs/failsafe)'s EWMA (exponentially weighted moving average) success-rate policy. Breaker state is tracked per `(route, endpoint-IP:port)` pair — one state machine per upstream pod, per route.

**State machine:**

1. **Closed** (initial) — requests flow normally; errors accumulate against the EWMA window.
2. **Open** — error rate exceeded `threshold` after `minRequests` samples; requests fail-fast 503 without reaching the upstream. The breaker stays Open for `openDuration` (or exponentially longer, up to `maxOpenDuration`, on repeated trips).
3. **HalfOpen** — after `openDuration` one probe request is let through. If it succeeds, the breaker closes; if it fails, it re-opens for another `openDuration`.

**Observability** — three Prometheus series on the proxy admin `/metrics` endpoint:

- `coxswain_proxy_circuit_breaker_state{route, upstream}` — `0` = closed, `1` = open, `2` = half-open.
- `coxswain_proxy_circuit_breaker_rejected_total{route, upstream}` — count of fail-fast 503s issued while the breaker was open.
- `coxswain_proxy_circuit_breaker_transitions_total{route, upstream, to}` — cumulative state transitions; `to` is `"open"`, `"half_open"`, or `"closed"`.

When the breaker is Open the proxy returns 503 immediately without connecting to the upstream; other healthy pods serving the same route keep accepting traffic via load-balancing.

## Session persistence

Session persistence (sticky sessions) keeps every request from the same client landing on the same backend pod, instead of spreading it across pods by the load-balancing algorithm. Use it when a pod holds state a client needs to come back to — an in-memory session, a WebSocket connection, an in-progress upload. A backend with no `sessionPersistence` configured is unaffected: it uses `loadBalancer.algorithm` (or round-robin) as normal.

There's no server-side table of "which client goes to which pod" — the pin is recomputed from the request itself every time, so it works identically across proxy replicas with no coordination. Two ways the proxy identifies the client:

- **`type: Cookie`** — for browser clients. On a client's first request the proxy picks a pod as usual and sets a cookie identifying it (`Set-Cookie: <sessionName>=<token>; Path=/; HttpOnly`); later requests carrying the cookie return to that pod. `sessionName` is optional (defaults to `__coxswain_session`); an invalid cookie name warns and falls back to the default rather than rejecting the policy.
- **`type: Header`** — for API/service clients that already send a stable identifier (an API key, tenant ID, session token) as a request header. The proxy hashes that header's value to consistently pick one pod — no cookie is set. `sessionName` is **required** here (the header name); if omitted, persistence is silently disabled (a warning is logged) and the route falls back to plain round-robin rather than breaking.

**When the pinned pod goes away:** if the pod a client was pinned to is scaled down or replaced, the proxy falls back to round-robin and (in `Cookie` mode) picks a new pod and re-pins with a fresh cookie.

**Not supported yet:** Gateway API's own (experimental) `SessionPersistence` also lets you expire a session after inactivity (`idleTimeout`) or unconditionally (`absoluteTimeout`). Coxswain supports neither — with no server-side session table there's nothing to time out. Real inactivity expiry would mean tracking "when did I last see this client" per pinned session; until then, a session stays pinned for as long as its pod keeps running.

## Status

The controller writes one `status.ancestors[]` entry per targeted `Service` with an `Accepted` condition:

```bash
kubectl describe coxswainbackendpolicy api-backend-policy
```
