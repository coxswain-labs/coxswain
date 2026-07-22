# HTTPRoute

An `HTTPRoute` defines routing rules and attaches them to one or more `Gateway` listeners via `parentRefs`.

## Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway          # name of the Gateway in the same namespace
  hostnames:
    - app.example.com           # only matched requests for this hostname
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      backendRefs:
        - name: api-service
          port: 8080
    - matches:
        - path:
            type: PathPrefix
            value: /             # catch-all rule
      backendRefs:
        - name: frontend-service
          port: 80
```

## Supported fields

| Field | Support |
|-------|---------|
| `spec.parentRefs` | Full (including `sectionName` and `port` for targeting a specific listener) |
| `spec.hostnames` | Full (including wildcards) |
| `spec.rules[].matches[].path` | `PathPrefix`, `Exact`; `RegularExpression` is implementation-specific (see below) |
| `spec.rules[].matches[].headers` | Full |
| `spec.rules[].matches[].method` | Full |
| `spec.rules[].matches[].queryParams` | Full |
| `spec.rules[].filters` | See filter table below |
| `spec.rules[].backendRefs` | Service backends only |
| `spec.rules[].backendRefs[].weight` | Full |
| `spec.rules[].backendRefs[].filters` | `RequestHeaderModifier`, `ResponseHeaderModifier` only |

## Supported filters

| Filter | Support |
|--------|---------|
| `RequestHeaderModifier` | Supported (rule-level and per-backendRef) |
| `ResponseHeaderModifier` | Supported (rule-level and per-backendRef) |
| `URLRewrite` | Supported (hostname and path rewrite) |
| `RequestRedirect` | Supported (scheme, hostname, port, path, status code) |
| `RequestMirror` | Supported — fire-and-forget shadow traffic with optional `percent` or `fraction` sampling; multiple filters per rule for multiple mirrors |
| `ExtensionRef` | The Coxswain-native extensions (`RateLimit`, `PathRewriteRegex`, `IpAccessControl`, `BasicAuth`, `ExternalAuth`, `RequestSizeLimit`, `Compression`, `JwtAuth`) — see [Route extensions](route-extensions.md) |
| `CORS` | Supported — preflight short-circuit and response-header injection |

## Attaching to a Gateway

`parentRefs` selects the Gateway (and optionally a specific listener by `sectionName` or `port`) the route attaches to:

```yaml
parentRefs:
  - name: my-gateway             # attach to the whole Gateway
  - name: my-gateway
    sectionName: https           # attach to the listener named "https" only
  - name: my-gateway
    port: 443                    # attach to the listener on port 443 only
```

The route must be in the same namespace as the Gateway unless the listener's [`allowedRoutes.namespaces.from`](gateway.md#allowedroutesnamespacesfrom) is set to `All` or `Selector`.

## Path matching

| `type` | Behaviour |
|--------|-----------|
| `PathPrefix` | Matches requests whose path starts with the given value |
| `Exact` | Matches only the exact path |
| `RegularExpression` | Anchored full-path match. Implementation-specific — see [below](#implementation-specific-matching). |

```yaml
rules:
  - matches:
      - path:
          type: PathPrefix
          value: /api           # matches /api, /api/users, /api/v2/...
    backendRefs:
      - name: api-service
        port: 8080
  - matches:
      - path:
          type: Exact
          value: /healthz       # matches only /healthz
    backendRefs:
      - name: health-service
        port: 8080
```

## Header matching

```yaml
rules:
  - matches:
      - headers:
          - name: X-Tenant
            value: acme         # only routes requests with this header value
    backendRefs:
      - name: acme-service
        port: 80
```

## Method matching

```yaml
rules:
  - matches:
      - method: GET             # only routes GET requests
    backendRefs:
      - name: read-service
        port: 80
```

## Implementation-specific matching

`RegularExpression` is supported for path, header, and query-parameter matching. These match types are not covered by the Gateway API conformance suite — the spec marks them as implementation-specific and defines no feature flag for them.

**Dialect:** Rust [`regex`](https://docs.rs/regex) crate — RE2-like syntax. No backreferences, no lookaround. Patterns are case-sensitive by default.

**Path regex** — anchored to the full request path (`^(?:pattern)$` internally). Does not match the query string.

```yaml
rules:
  - matches:
      - path:
          type: RegularExpression
          value: "/item/[0-9]+"     # matches /item/42, not /item/abc or /prefix/item/42
    backendRefs:
      - name: api-service
        port: 8080
```

**Header regex** — tested against the full header value, unanchored (matches if the pattern appears anywhere in the value). Use `^` and `$` to anchor explicitly.

```yaml
rules:
  - matches:
      - headers:
          - name: X-Tenant
            type: RegularExpression
            value: "^(acme|globex)$"   # matches exactly "acme" or "globex"
    backendRefs:
      - name: multi-tenant-service
        port: 80
```

**Query param regex** — same unanchored semantics as header regex.

```yaml
rules:
  - matches:
      - queryParams:
          - name: version
            type: RegularExpression
            value: "v[0-9]+"           # matches v1, v2, v12, ...
    backendRefs:
      - name: versioned-service
        port: 80
```

An HTTPRoute with a syntactically invalid regex pattern is rejected: Coxswain sets `Accepted: False` with reason `UnsupportedValue` on the affected parentRef.

## Wildcard hostnames

`*.example.com` in `spec.hostnames` matches any number of leading DNS labels: both `foo.example.com` and `foo.bar.example.com` match. This is the same semantics applied to listener `hostname` fields — Gateway API treats wildcards uniformly across listeners and routes.

```yaml
hostnames:
  - "*.example.com"             # matches foo.example.com and foo.bar.example.com
```

!!! note
    Classic `Ingress` wildcards are more restrictive (single-label only). See the [Ingress guide](../ingress/index.md#wildcard-hostnames) if you also use `Ingress` objects in the cluster.

## Traffic splitting

Distribute traffic across multiple backends using `weight`. Weights are relative and do not need to sum to 100:

```yaml
rules:
  - backendRefs:
      - name: service-v1
        port: 80
        weight: 90              # 90% of traffic
      - name: service-v2
        port: 80
        weight: 10              # 10% of traffic
```

## Cross-namespace backends

By default, an `HTTPRoute` can only reference backends in its own namespace. To allow access to a Service in another namespace, create a `ReferenceGrant` in the namespace where the Service lives:

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-httproute-from-default
  namespace: target-namespace   # namespace of the Service
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: default        # namespace of the HTTPRoute
  to:
    - group: ""
      kind: Service
```

Routes that reference a backend without a matching `ReferenceGrant` are rejected with a `ResolvedRefs: False` condition.

## Request mirroring

The `RequestMirror` filter sends a fire-and-forget copy of every matched request to a secondary backend while the primary response is returned normally to the client. The mirror response is discarded — mirror failures (connect error, timeout, bad response) are logged at `WARN` level and do not affect the primary.

```yaml
rules:
  - filters:
      - type: RequestMirror
        requestMirror:
          backendRef:
            name: echo-mirror
            port: 3000
    backendRefs:
      - name: echo-primary
        port: 3000
```

**Multiple mirrors per rule** — add one `RequestMirror` filter per shadow backend; each fires independently:

```yaml
filters:
  - type: RequestMirror
    requestMirror:
      backendRef: {name: shadow-a, port: 3000}
  - type: RequestMirror
    requestMirror:
      backendRef: {name: shadow-b, port: 3000}
```

**Sampling** — use `percent` (integer, 0–100) or `fraction` (`numerator` / `denominator`) to mirror only a subset of requests:

```yaml
requestMirror:
  backendRef: {name: echo-mirror, port: 3000}
  percent: 20          # mirror 20% of requests
```

```yaml
requestMirror:
  backendRef: {name: echo-mirror, port: 3000}
  fraction:
    numerator: 1
    denominator: 5     # equivalent to 20%
```

**Cross-namespace mirror backends** require a `ReferenceGrant` in the target namespace, just like primary backends (see [Cross-namespace backends](#cross-namespace-backends)).

Mirror traffic is visible in the proxy access log (`mirror: true` field) and counted by the `coxswain_proxy_mirror_requests_total{route, upstream}` Prometheus counter.

## Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The route is attached to a Gateway listener |
| `Programmed` | The route is active in the data plane |
| `ResolvedRefs` | All `backendRefs` resolve to a reachable Service |

Inspect conditions when traffic is not flowing:

```bash
kubectl describe httproute my-route
```
