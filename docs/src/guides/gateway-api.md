# Gateway API guide

Coxswain implements the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) standard channel. It supports `GatewayClass`, `Gateway`, and `HTTPRoute` resources.

## Supported resources

| Resource | API version | Support |
|----------|-------------|---------|
| `GatewayClass` | `gateway.networking.k8s.io/v1` | Full |
| `Gateway` | `gateway.networking.k8s.io/v1` | HTTP and HTTPS listeners only |
| `HTTPRoute` | `gateway.networking.k8s.io/v1` | Path, header, method, and query matching; weighted traffic split |
| `ReferenceGrant` | `gateway.networking.k8s.io/v1beta1` | Cross-namespace backend and certificate access |
| `BackendTLSPolicy` | `gateway.networking.k8s.io/v1` | Upstream TLS configuration referencing a CA `ConfigMap` or `Secret` |

!!! warning "Not supported"
    `TCPRoute`, `TLSRoute`, `UDPRoute`, and `GRPCRoute` are not implemented. `tls.mode: Passthrough` on a listener is rejected. The `RequestMirror`, `ExtensionRef`, and `CORS` filters are skipped with a WARN log line.

## GatewayClass

A `GatewayClass` identifies a controller implementation. Coxswain claims the class whose `spec.controllerName` matches `coxswain-labs.dev/gateway-controller`.

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: coxswain
spec:
  controllerName: coxswain-labs.dev/gateway-controller  # must match --controller-name
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
    Gateway API wildcards (both listener and HTTPRoute hostnames) match any number of labels. Classic `Ingress` is more restrictive: `*.example.com` on an `Ingress` matches only a single label (`foo.example.com` yes, `foo.bar.example.com` no). See the [Ingress guide](ingress.md#wildcard-hostnames) for the Ingress semantics.

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
| `RequestMirror` | Not supported — skipped with a WARN log line |
| `ExtensionRef` | Not supported — skipped with a WARN log line |
| `CORS` | Not supported — skipped with a WARN log line |

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

`*.example.com` in `spec.hostnames` matches any number of leading DNS labels: both `foo.example.com` and `foo.bar.example.com` match. This is the same semantics applied to listener `hostname` fields — Gateway API treats wildcards uniformly across listeners and routes.

```yaml
hostnames:
  - "*.example.com"             # matches foo.example.com and foo.bar.example.com
```

!!! note
    Classic `Ingress` wildcards are more restrictive (single-label only). See the [Ingress guide](ingress.md#wildcard-hostnames) if you also use `Ingress` objects in the cluster.

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

## Dedicated Gateway proxies

By default every `Gateway` is served by the shared proxy pool in `coxswain-system`. A `Gateway` opts into its own dedicated proxy pod by pointing `spec.infrastructure.parametersRef` at a `CoxswainGatewayParameters` object. The controller's provisioning operator renders a `Deployment` / `Service` / `ServiceAccount` in the Gateway's own namespace and reconciles them via server-side apply.

Use this when a Gateway needs hard pod-level isolation: dedicated SLOs, compliance boundaries, expensive workloads that should not share a process with neighbours. For a higher-level overview of when to reach for it vs. the shared pool, see [Deployment models](deployment-models.md).

### Canonical example

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-a
---
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainGatewayParameters
metadata:
  name: tenant-a-defaults
  namespace: tenant-a
spec:
  replicas: 2
  serviceType: ClusterIP
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: tenant-a-gw
  namespace: tenant-a
spec:
  gatewayClassName: coxswain
  infrastructure:
    parametersRef:
      group: gateway.coxswain-labs.dev
      kind: CoxswainGatewayParameters
      name: tenant-a-defaults
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      hostname: tenant-a.local
      allowedRoutes:
        namespaces:
          from: Same
```

Apply, then observe the provisioned resources. They land in the Gateway's namespace, named `<gateway-name>-coxswain`, labelled by the Gateway they serve:

```bash
kubectl get all -n tenant-a \
  -l gateway.networking.k8s.io/gateway-name=tenant-a-gw

# Once the proxy pod is Ready, Gateway.status.Programmed flips to True.
kubectl get gateway tenant-a-gw -n tenant-a \
  -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}'
# True
```

Delete the Gateway and watch the cascade: the provisioned Deployment/Service/ServiceAccount disappear within ~30 seconds via owner-reference garbage collection, and per-namespace `RoleBinding`s the controller created for the proxy SA are cleaned up by the `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer before Kubernetes finalises the Gateway deletion.

### CoxswainGatewayParameters fields

| Field | Type | Effect |
|---|---|---|
| `image` | string (optional) | Override the proxy image. Defaults to the controller's own image so a chart upgrade rolls dedicated proxies on the same cadence as the shared pool. |
| `replicas` | uint32 (optional) | Desired replica count for the provisioned `Deployment`. Defaults to `1`. |
| `serviceType` | enum (optional) | One of `LoadBalancer`, `NodePort`, `ClusterIP`. Defaults to `LoadBalancer`. |
| `resources` | `ResourceRequirements` (optional) | Standard Kubernetes `requests` / `limits` / `claims`, applied to the proxy container. |
| `podTemplate` | partial `PodTemplateSpec` (optional) | Escape hatch for fields not first-classed above — `nodeSelector`, `tolerations`, `env`, sidecar containers, security context. The controller strategic-merges this onto the rendered template (containers match by `name`, container env by `name`, etc.). |

Every field is optional. When `parametersRef` is set on both the `GatewayClass` and the `Gateway`, the operator overlays the two per-field: the Gateway's value wins for each field individually, the GatewayClass's value fills in the rest, and `podTemplate` strategic-merges across both layers.

For the full schema (including the upstream `ResourceRequirements` and `PodTemplateSpec` boilerplate) use:

```bash
kubectl explain coxswaingatewayparameters.spec --recursive
```

### Cluster-wide default via GatewayClass

To make every Gateway of a class dedicated by default — without writing YAML on each Gateway — point the `GatewayClass`'s `parametersRef` at a `CoxswainGatewayParameters`. A `parametersRef` on an individual Gateway then acts as a per-field override on top of the class-level defaults.

### Provisioned RBAC

The dedicated proxy's `ServiceAccount` is bound, namespace-scoped, to the static `coxswain-gateway-proxy-reader` `ClusterRole` (shipped by the Helm chart and `deploy/manifests/dedicated-proxy-clusterrole.yaml`). The controller reconciles one `RoleBinding` per namespace the Gateway's HTTPRoutes route a backend into, gated by `ReferenceGrant` for cross-namespace refs. The proxy then receives `--proxy-watch-namespaces=<ns1>,<ns2>,...` matching exactly the binding set, and runs reflectors scoped to those namespaces only. A compromised dedicated proxy's `ServiceAccount` holds reads only in the namespaces its Gateway routes into — nowhere else, and zero write verbs anywhere.

If a Gateway's listener uses `allowedRoutes.namespaces.from: All` or `Selector`, the operator must explicitly opt in to broader RBAC; the matching CRD fields land in [#229](https://github.com/coxswain-labs/coxswain/issues/229).
