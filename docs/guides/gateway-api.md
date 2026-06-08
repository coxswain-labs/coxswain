# Gateway API guide

Coxswain implements the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) standard channel. It supports `GatewayClass`, `Gateway`, and `HTTPRoute` resources.

## Supported resources

| Resource | API version | Support |
|----------|-------------|---------|
| `GatewayClass` | `gateway.networking.k8s.io/v1` | Full |
| `Gateway` | `gateway.networking.k8s.io/v1` | HTTP and HTTPS listeners |
| `HTTPRoute` | `gateway.networking.k8s.io/v1` | Path, header, and method matching; weight-based traffic split |
| `ReferenceGrant` | `gateway.networking.k8s.io/v1beta1` | Cross-namespace backend access |

## Compatibility matrix

| Coxswain | Gateway API |
|----------|-------------|
| v0.1     | v1.5.x      |

Install matching CRDs when upgrading Coxswain.

## GatewayClass

Coxswain claims the `GatewayClass` with `controllerName: coxswain-labs.dev/gateway-controller`. Verify it is accepted:

```bash
kubectl get gatewayclass coxswain
# NAME       CONTROLLER                              ACCEPTED
# coxswain   coxswain-labs.dev/gateway-controller    True
```

## Gateway

A `Gateway` object defines one or more listeners. Each listener specifies a port, protocol, and optional hostname.

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
          from: Same   # or: All, Selector
```

## HTTPRoute

Routes are attached to a `Gateway` via `parentRefs`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
spec:
  parentRefs:
    - name: my-gateway
  hostnames:
    - app.example.com
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
            value: /
      backendRefs:
        - name: frontend-service
          port: 80
```

### Wildcard hostnames

Gateway API wildcard matching follows the spec: `*.example.com` matches any number of DNS labels, so both `foo.example.com` and `foo.bar.example.com` match.

```yaml
hostnames:
  - "*.example.com"
```

This differs from Ingress wildcard behaviour, which matches exactly one label per the Kubernetes spec.

### Path matching types

| `type` | Description |
|--------|-------------|
| `PathPrefix` | Matches requests starting with the given path |
| `Exact` | Matches only the exact path |
| `RegularExpression` | Not supported in v0.1 |

### Header matching

```yaml
rules:
  - matches:
      - headers:
          - name: X-Tenant
            value: acme
    backendRefs:
      - name: acme-service
        port: 80
```

### Method matching

```yaml
rules:
  - matches:
      - method: GET
    backendRefs:
      - name: read-service
        port: 80
```

### Traffic splitting (weighted backends)

Distribute traffic across multiple backends with `weight`:

```yaml
rules:
  - backendRefs:
      - name: service-v1
        port: 80
        weight: 90
      - name: service-v2
        port: 80
        weight: 10
```

Weights are relative — they do not need to sum to 100. Coxswain round-robins across all ready pod addresses from all weighted services.

## Cross-namespace backends

By default, an `HTTPRoute` can only reference backends in the same namespace. To allow cross-namespace access, create a `ReferenceGrant` in the target namespace:

```yaml
# In the target namespace (where the Service lives)
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-httproute-from-default
  namespace: target-namespace
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: default
  to:
    - group: ""
      kind: Service
```

Routes that reference a backend without a `ReferenceGrant` are rejected with a `ResolvedRefs: False` condition.

## Status conditions

Coxswain writes standard Gateway API status conditions. The most important:

| Object | Condition | True when |
|--------|-----------|-----------|
| `GatewayClass` | `Accepted` | The controller has claimed this class |
| `Gateway` | `Programmed` | All listeners are configured |
| `HTTPRoute` | `Accepted` | The route is attached to a gateway |
| `HTTPRoute` | `ResolvedRefs` | All backend refs resolve to a real Service |

Inspect conditions when traffic is not flowing:

```bash
kubectl describe httproute my-route
```

