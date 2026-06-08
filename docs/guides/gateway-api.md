# Gateway API guide

Coxswain implements the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) standard channel. It supports `GatewayClass`, `Gateway`, and `HTTPRoute` resources.

## Supported resources

| Resource | API version | Support |
|----------|-------------|---------|
| `GatewayClass` | `gateway.networking.k8s.io/v1` | Full |
| `Gateway` | `gateway.networking.k8s.io/v1` | HTTP and HTTPS listeners only |
| `HTTPRoute` | `gateway.networking.k8s.io/v1` | Path, header, method, and query matching; weighted traffic split |
| `ReferenceGrant` | `gateway.networking.k8s.io/v1beta1` | Cross-namespace backend and certificate access |

!!! warning "Not supported"
    `TCPRoute`, `TLSRoute`, `UDPRoute`, and `GRPCRoute` are not implemented. `tls.mode: Passthrough` on a listener is rejected. The `RequestMirror`, `ExtensionRef`, and `CORS` filters are silently skipped.

## GatewayClass

A `GatewayClass` identifies a controller implementation. Coxswain claims the class whose `spec.controllerName` matches `coxswain-labs.dev/gateway-controller`.

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: coxswain
spec:
  controller: coxswain-labs.dev/gateway-controller  # must match --controller-name
```

### Verifying the controller claimed it

```bash
kubectl get gatewayclass coxswain
# NAME       CONTROLLER                              ACCEPTED
# coxswain   coxswain-labs.dev/gateway-controller    True
```

### Advertised features

Coxswain writes the full list of supported Gateway API features to `status.supportedFeatures` on the `GatewayClass` object:

```bash
kubectl get gatewayclass coxswain \
  -o jsonpath='{.status.supportedFeatures}' | tr ',' '\n'
```

Implementation-specific capabilities — such as `RegularExpression` path, header, and query matching — are not listed in `supportedFeatures`. The Gateway API spec does not define conformance flags for them; they are supported under Coxswain's own dialect. See [Implementation-specific matching](#implementation-specific-matching).

## Gateway

A `Gateway` object defines one or more listeners, each binding a port and protocol to a set of allowed routes. Only `HTTP` and `HTTPS` listeners are processed; other protocol values are ignored.

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Same        # Same, All, or Selector
```

### Supported fields

| Field | Support |
|-------|---------|
| `spec.gatewayClassName` | Full |
| `spec.listeners[].name` | Full |
| `spec.listeners[].port` | Full |
| `spec.listeners[].protocol` | `HTTP`, `HTTPS` only |
| `spec.listeners[].hostname` | Full (wildcard: any number of labels) |
| `spec.listeners[].allowedRoutes` | Full |
| `spec.listeners[].tls` | `mode: Terminate` only; `Passthrough` rejected |

### TLS

Add an `HTTPS` listener and reference a `kubernetes.io/tls` Secret in the same namespace. Coxswain only supports `tls.mode: Terminate` — `Passthrough` is rejected with a status condition. Coxswain reloads the certificate automatically when the Secret changes. See the [TLS guide](tls.md) for cert-manager integration.

```yaml
spec:
  gatewayClassName: coxswain
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate     # Passthrough is not supported
        certificateRefs:
          - kind: Secret
            name: my-gateway-tls   # must exist in the same namespace
      allowedRoutes:
        namespaces:
          from: Same
```

The referenced Secret must have `type: kubernetes.io/tls` with `tls.crt` and `tls.key`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-gateway-tls
  namespace: default
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded certificate>
  tls.key: <base64-encoded private key>
```

To reference a Secret in a different namespace, create a `ReferenceGrant` in the namespace where the Secret lives:

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-gateway-tls
  namespace: certs-namespace     # namespace of the Secret
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: Gateway
      namespace: default         # namespace of the Gateway
  to:
    - group: ""
      kind: Secret
```

### Listener hostnames

The `hostname` field on a listener filters which requests reach its attached routes. Gateway API wildcard matching allows any number of DNS labels: `*.example.com` matches both `foo.example.com` and `foo.bar.example.com`.

An empty `hostname` accepts requests for any hostname. For SNI-based TLS termination, the listener `hostname` is also used to select the correct certificate when multiple HTTPS listeners share the same port.

!!! note
    Gateway listener wildcard semantics differ from Ingress: `*.example.com` on an `Ingress` matches only a single label (`foo.example.com` yes, `foo.bar.example.com` no). See the [Ingress guide](ingress.md#wildcard-hostnames) for details.

### Load balancer address

Set `--status-address` to the external IP or hostname of your load balancer. Coxswain writes it to `status.addresses` on the `Gateway` object. Without it, the address is left empty.

```bash
kubectl get gateway my-gateway
# NAME         CLASS      ADDRESS         PROGRAMMED
# my-gateway   coxswain   203.0.113.10    True
```

### Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The controller has claimed this Gateway |
| `Programmed` | All listeners are configured and ready |

Per-listener conditions are also written: `Accepted`, `ResolvedRefs`, and `Programmed`. Inspect them when a listener is not serving traffic:

```bash
kubectl describe gateway my-gateway
```

## HTTPRoute

An `HTTPRoute` defines routing rules and attaches them to one or more `Gateway` listeners via `parentRefs`.

### Example

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

### Supported fields

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

### Supported filters

| Filter | Support |
|--------|---------|
| `RequestHeaderModifier` | Supported (rule-level and per-backendRef) |
| `ResponseHeaderModifier` | Supported (rule-level and per-backendRef) |
| `URLRewrite` | Supported (hostname and path rewrite) |
| `RequestRedirect` | Supported (scheme, hostname, port, path, status code) |
| `RequestMirror` | Not supported — silently skipped |
| `ExtensionRef` | Not supported — silently skipped |
| `CORS` | Not supported — silently skipped |

### Attaching to a Gateway

`parentRefs` selects the Gateway (and optionally a specific listener by `sectionName` or `port`) the route attaches to:

```yaml
parentRefs:
  - name: my-gateway             # attach to the whole Gateway
  - name: my-gateway
    sectionName: https           # attach to the listener named "https" only
  - name: my-gateway
    port: 443                    # attach to the listener on port 443 only
```

The route must be in the same namespace as the Gateway, or the Gateway must set `allowedRoutes.namespaces.from: All` (or use a `Selector`).

### Path matching

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

### Header matching

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

### Method matching

```yaml
rules:
  - matches:
      - method: GET             # only routes GET requests
    backendRefs:
      - name: read-service
        port: 80
```

### Implementation-specific matching

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

### Wildcard hostnames

`*.example.com` in `spec.hostnames` matches a single DNS label: `foo.example.com` matches but `foo.bar.example.com` does not.

This is more restrictive than Gateway listener wildcard behaviour, which matches any number of labels. A route with `*.example.com` will only attach to a listener whose hostname intersects — it will not match a listener with `hostname: "*.bar.example.com"` unless the labels overlap.

```yaml
hostnames:
  - "*.example.com"             # matches foo.example.com, not foo.bar.example.com
```

### Traffic splitting

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

### Cross-namespace backends

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

### Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The route is attached to a Gateway listener |
| `Programmed` | The route is active in the data plane |
| `ResolvedRefs` | All `backendRefs` resolve to a reachable Service |

Inspect conditions when traffic is not flowing:

```bash
kubectl describe httproute my-route
```
