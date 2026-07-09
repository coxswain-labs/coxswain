# Gateway API guide

Coxswain implements the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) standard channel. It supports `GatewayClass`, `Gateway`, `ListenerSet`, `HTTPRoute`, `GRPCRoute`, and `TLSRoute` resources.

## Supported resources

| Resource | API version | Support |
|----------|-------------|---------|
| `GatewayClass` | `gateway.networking.k8s.io/v1` | Full |
| `Gateway` | `gateway.networking.k8s.io/v1` | HTTP, HTTPS, and TLS passthrough listeners |
| `ListenerSet` | `gateway.networking.k8s.io/v1` | Attach listeners to a Gateway across namespaces — see the [ListenerSet guide](listener-sets.md) |
| `HTTPRoute` | `gateway.networking.k8s.io/v1` | Path, header, method, and query matching; weighted traffic split |
| `GRPCRoute` | `gateway.networking.k8s.io/v1` | Service and method matching; cleartext h2c backends |
| `TLSRoute` | `gateway.networking.k8s.io/v1alpha2` | SNI-keyed L4 passthrough; no TLS termination at proxy |
| `ReferenceGrant` | `gateway.networking.k8s.io/v1beta1` | Cross-namespace backend and certificate access |
| `BackendTLSPolicy` | `gateway.networking.k8s.io/v1` | Upstream TLS configuration referencing a CA `ConfigMap` or `Secret` |
| `CoxswainBackendPolicy` | `gateway.coxswain-labs.dev/v1alpha1` | Coxswain-native per-`Service` connection policy: connect/idle timeouts, load-balancing algorithm, circuit breaker — see [below](#coxswainbackendpolicy) |
| `CoxswainExternalAuth` | `gateway.coxswain-labs.dev/v1alpha1` | External authorization (`ext_authz`, HTTP or gRPC) as an HTTPRoute `ExtensionRef` filter or a Gateway-attached `targetRefs` policy — see [below](#external-authorization-ext_authz) |

!!! warning "Not supported"
    `TCPRoute` and `UDPRoute` are not implemented.

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

A `Gateway` object defines one or more listeners, each binding a port and protocol to a set of allowed routes. Coxswain routes the `HTTP`, `HTTPS`, and `TLS` protocols. A listener declaring any other protocol is rejected: it gets `Accepted=False, reason=UnsupportedProtocol` with an empty `supportedKinds`, and the Gateway's own `Accepted` condition rolls up to `reason=ListenersNotValid` (status `False` when *every* listener is unsupported, `True` when at least one listener is still valid).

!!! tip "Dedicated proxy per Gateway"
    A `Gateway` can be opted into its own isolated proxy pool via `spec.infrastructure.parametersRef` pointing at a `CoxswainGatewayParameters`. See [Dedicated proxy pools](dedicated-mode.md) for the full walkthrough. A `parametersRef` targeting any other (unrecognized) kind is rejected with `Accepted=False, reason=InvalidParameters`.

!!! info "Infrastructure metadata propagation (GEP-1867)"
    `spec.infrastructure.labels` and `spec.infrastructure.annotations` propagate onto the resources Coxswain provisions for the Gateway, in **both** deployment models. In dedicated mode they land on the per-Gateway `Deployment`, `Service`, and `ServiceAccount`; in shared mode they land on the per-Gateway VIP `Service` (e.g. cloud load-balancer annotations) and on a per-Gateway identity `ServiceAccount` provisioned in the Gateway's namespace. The four reserved GEP-1762 label keys (`app.kubernetes.io/{name,instance,managed-by,component}` and `gateway.networking.k8s.io/gateway-name`) cannot be overridden — a collision is dropped with a warning, since the Service/Deployment selectors depend on them.

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
          from: Same        # see below
```

#### `allowedRoutes.namespaces.from`

Controls which namespaces may attach `HTTPRoute`s to this listener.

| Value | Behaviour |
|-------|-----------|
| `Same` (default) | Only routes in the Gateway's own namespace can attach. |
| `All` | Routes from any namespace can attach. |
| `Selector` | Routes from namespaces matching `namespaces.selector` (a label selector) can attach. |

`All` and `Selector` cause the controller to automatically grant the dedicated proxy cluster-wide `HTTPRoute` reads. No extra fields on `CoxswainGatewayParameters` are required — the listener spec is the single source of truth. See the [dedicated-mode guide](dedicated-mode.md#cross-namespace-route-attachment-from-all-from-selector) for details.

### Supported fields

| Field | Support |
|-------|---------|
| `spec.gatewayClassName` | Full |
| `spec.listeners[].name` | Full |
| `spec.listeners[].port` | Full |
| `spec.listeners[].protocol` | `HTTP`, `HTTPS`, `TLS` |
| `spec.listeners[].hostname` | Full (wildcard: any number of labels) |
| `spec.listeners[].allowedRoutes` | Full |
| `spec.listeners[].tls` | `mode: Terminate` (HTTPS) and `mode: Passthrough` (TLS) |

### TLS

Add an `HTTPS` listener and reference a `kubernetes.io/tls` Secret in the same namespace. Coxswain reloads the certificate automatically when the Secret changes. See the [TLS guide](tls.md) for cert-manager integration. For TLS passthrough (no termination at the proxy), see [TLSRoute](#tlsroute) below.

```yaml
spec:
  gatewayClassName: coxswain
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
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

### Requesting a static address

Set `spec.addresses` to ask coxswain to bind a specific address rather than letting the cluster auto-assign one (Gateway API `GatewayStaticAddresses`):

```yaml
spec:
  addresses:
    - type: IPAddress
      value: 10.96.0.42
```

Coxswain honors a requested `IPAddress` by provisioning that Gateway's VIP `Service` as a **`ClusterIP`** pinned to the requested address (overriding the default VIP type for that one Gateway). The apiserver assigns the address exactly when it is a free IP inside the cluster's Service CIDR, and rejects it otherwise — giving a deterministic accept/reject on every cluster. The outcome is reflected in the conditions:

| Requested address | `Accepted` | `Programmed` |
|-------------------|-----------|--------------|
| Supported type, bindable value | `True` | `True` — the address appears in `status.addresses` |
| Supported type, value coxswain cannot bind (out of range / in use) | `True` | `False`, reason `AddressNotUsable` — the value is **not** published |
| Unsupported `type` (anything but `IPAddress`/`Hostname`) | `False`, reason `UnsupportedAddress` | `False`, reason `Invalid` |

A request for two distinct IPs is always `AddressNotUsable` — one `Service` binds a single `clusterIP`. Leaving `value` empty keeps the auto-assign behaviour (`GatewayAddressEmpty`).

> Because a static-IP Gateway is bound to a `ClusterIP`, its address is **cluster-internal** — coxswain cannot guarantee an arbitrary externally-routable IP across load-balancer providers. Use a static address when you need a stable, predictable in-cluster address; for external exposure, leave `spec.addresses` empty and let the cluster's load balancer assign one.

### Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The controller has claimed this Gateway |
| `Programmed` | All listeners are configured and the Gateway's address has resolved |

The controller does not stamp `Programmed` as processed for the current `metadata.generation` until the Gateway's own address has resolved into `status.addresses`. Until then `Programmed` stays `False`/`Pending` and its `observedGeneration` trails `metadata.generation`, so a client that waits for the latest conditions never observes `Programmed` claiming a generation while `status.addresses` is still empty — the same reconcile that flips `Programmed=True` also publishes the address. `Accepted` advances immediately. (A *settled* negative such as `AddressNotUsable` is not held back — it is a final answer for the current generation.)

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
| `RequestMirror` | Supported — GEP-3171 fire-and-forget shadow traffic with optional `percent` or `fraction` sampling; multiple filters per rule for multiple mirrors |
| `ExtensionRef` | Supported (for `RateLimit`, `PathRewriteRegex`, `IpAccessControl`, `BasicAuth`, `ExternalAuth`, `RequestSizeLimit`, `Compression`, and `JwtAuth` Coxswain extensions) |
| `CORS` | Supported — GEP-1767 preflight short-circuit and response-header injection |

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

The route must be in the same namespace as the Gateway unless the listener's [`allowedRoutes.namespaces.from`](#allowedroutesnamespacesfrom) is set to `All` or `Selector`.

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

### Request mirroring

The `RequestMirror` filter (GEP-3171) sends a fire-and-forget copy of every matched request to a secondary backend while the primary response is returned normally to the client. The mirror response is discarded — mirror failures (connect error, timeout, bad response) are logged at `WARN` level and do not affect the primary.

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

### IP access control

`IpAccessControl` (`gateway.coxswain-labs.dev/v1alpha1`) restricts a route to a set of source-IP CIDR ranges. Attach it to an `HTTPRouteRule` with an `ExtensionRef` filter — the Gateway API surface for the Ingress [`ip-access-control`](ingress-annotations.md#ip-access-control) annotation. It has no Gateway API standard equivalent; its merit anchor is Envoy's `rbac` CIDR-principal filter / Istio `AuthorizationPolicy` `ipBlocks`/`notIpBlocks`.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: IpAccessControl
metadata:
  name: office-only
spec:
  deny:                       # evaluated FIRST
    - 203.0.113.5/32
  allow:                      # then the allow-list
    - 203.0.113.0/24
    - 2001:db8::/32
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
# ...
    filters:
      - type: ExtensionRef
        extensionRef:
          group: gateway.coxswain-labs.dev
          kind: IpAccessControl
          name: office-only
```

Semantics:

- **`deny` is evaluated before `allow`.** A client inside any `deny` range gets `403` even when `allow` would admit it.
- **`allow` restricts to the listed ranges** — a client outside every `allow` range gets `403`. An empty `allow` list imposes no allow-list restriction (only `deny` applies); empty `allow` **and** empty `deny` performs no filtering.
- **IPv4 and IPv6** CIDRs are both accepted; a bare address (`203.0.113.5`) is treated as a host route (`/32` / `/128`). Invalid CIDR tokens are logged and skipped rather than rejecting the whole policy.
- A **missing** `IpAccessControl` CR fails open (a WARN is logged; the route is not filtered).

The client IP is resolved through the same path as the rest of the data plane: the PROXY-protocol peer when a `ClientTrafficPolicy` enables PROXY protocol on the listener, otherwise the L4 downstream peer. There is no Gateway-side trusted-forwarded-header surface yet, so behind an L7 load balancer that terminates the connection, enable PROXY protocol so the real client IP reaches the filter.

### Basic authentication

`BasicAuth` (`gateway.coxswain-labs.dev/v1alpha1`) validates `Authorization: Basic` credentials against an htpasswd `Secret`. Attach it to an `HTTPRouteRule` with an `ExtensionRef` filter — the Gateway API surface for the Ingress `auth-basic-secret` annotation. HTTP Basic auth is a browser/HTTP idiom, so this filter is **not** supported on `GRPCRoute` (gRPC clients authenticate with bearer tokens or mTLS instead).

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: BasicAuth
metadata:
  name: office-only
spec:
  secretRef:
    name: office-htpasswd
    namespace: default
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
# ...
    filters:
      - type: ExtensionRef
        extensionRef:
          group: gateway.coxswain-labs.dev
          kind: BasicAuth
          name: office-only
```

Semantics:

- The referenced `Secret` **must** carry the label `ingress.coxswain-labs.dev/auth-basic: "true"` and store the htpasswd file under the key `auth` (nginx convention) — the same requirements as the Ingress annotation, so one Secret can back both surfaces.
- Supported hash formats: bcrypt (`$2a$`/`$2b$`/`$2y$`) and Apache SHA1 (`{SHA}`, accepted but logged as weak).
- Valid credentials are forwarded; missing/invalid credentials get `401` with `WWW-Authenticate`.
- A missing, unlabeled, or unparseable Secret — or a missing `BasicAuth` CR's `secretRef` — fails **closed** with `503`, distinct from a missing `BasicAuth` CR itself (which fails open: no auth enforced).
- A `secretRef` whose `namespace` differs from the `BasicAuth` CR's namespace requires a matching `ReferenceGrant` in the Secret's namespace — `from` a `BasicAuth` (`gateway.coxswain-labs.dev`) in the CR's namespace, `to` a core `Secret`. Without the grant the reference fails **closed** (`503`); a tenant cannot bind another namespace's auth Secret. Same-namespace refs need no grant.

```yaml
# In the Secret's namespace, to permit a BasicAuth in namespace `apps`:
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-basicauth-from-apps
spec:
  from:
    - group: gateway.coxswain-labs.dev
      kind: BasicAuth
      namespace: apps
  to:
    - group: ""
      kind: Secret
```

### JWT authentication

`JwtAuth` (`gateway.coxswain-labs.dev/v1alpha1`) validates a bearer token's signature against a JSON Web Key Set (JWKS) — the Coxswain implementation of Envoy's `envoy.filters.http.jwt_authn` `JwtProvider` / Istio's `RequestAuthentication.jwtRules`. Attach it to an `HTTPRouteRule` or `GRPCRouteRule` with an `ExtensionRef` filter — the Gateway API surface for the [Ingress `auth-jwt` annotation](ingress-annotations.md). No Gateway API standard exists for in-proxy JWT validation (GEP-1494 covers *delegated* ext_authz, a different model). Unlike `BasicAuth` (an HTTP/browser idiom), bearer/JWT auth is a common gRPC pattern, so `JwtAuth` is supported on both route kinds.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: JwtAuth
metadata:
  name: my-api
spec:
  issuer: https://issuer.example.com
  audiences:
    - my-api
  jwks:
    remote:
      uri: https://issuer.example.com/.well-known/jwks.json
      refreshInterval: 5m
  claimToHeaders:
    - claim: sub
      header: x-user-id
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
# ...
    filters:
      - type: ExtensionRef
        extensionRef:
          group: gateway.coxswain-labs.dev
          kind: JwtAuth
          name: my-api
```

Semantics:

- `spec.jwks` is exactly one of:
  - `remote.uri` — a JWKS endpoint. **Resolved by the controller, never the proxy** (the Istio model, not Envoy's default proxy-side fetch): the read-only data plane never egresses to an identity provider. `remote.refreshInterval` (default `5m`) bounds the refetch cadence; a shorter upstream `Cache-Control: max-age` is honored instead.
  - `inline.jwks` — a JWKS object given directly in the spec (no controller fetch).
- The bearer token is read from `Authorization: Bearer <token>` by default, or from `fromHeaders` when set.
- Signature verification uses **the key's own declared `alg`**, never the token header's `alg` (prevents algorithm-confusion attacks). Only asymmetric algorithms are supported (RS/PS/ES/EdDSA) — JWKS is inherently asymmetric.
- `iss` must match `spec.issuer`. `aud` is checked against `spec.audiences` only when `audiences` is non-empty.
- On success, `claimToHeaders` copies named claims onto upstream request headers, and `forwardPayloadHeader` (if set) carries the base64url-encoded full claims payload. The original token is stripped from the upstream request unless `forward: true`.
- Missing/invalid/expired/wrong-issuer/wrong-audience tokens get `401` with `WWW-Authenticate: Bearer`.
- An unresolved JWKS (fetch not yet complete, fetch failing, or unparseable/empty) fails **closed** with `503` — an operator who attached this filter expects enforcement.
- A missing `JwtAuth` CR fails **open** (no auth enforced), matching the other `ExtensionRef` auth resolvers.

### External authorization (ext_authz)

`CoxswainExternalAuth` (`gateway.coxswain-labs.dev/v1alpha1`) delegates an allow/deny decision to an external authorization service before a request reaches its upstream — the Coxswain implementation of [GEP-1494] and the Envoy / Istio / kgateway `ext_authz` model. The auth service is named by a **`backendRef`** (a `Service` + port), resolved to pod endpoints and load-balanced like any other backend; there is no URL form.

It is **dual-surface**:

- **Route filter** — reference it from an `HTTPRouteRule` via an `ExtensionRef` filter (like `BasicAuth`).
- **Gateway policy** — attach it to a `Gateway` via `spec.targetRefs` (like `ClientTrafficPolicy`), making it a default applied to **every** HTTPRoute on that Gateway.

Precedence is **additive** (GEP-713 override posture): when both a Gateway-attached policy and a route filter apply, the request must pass **both** checks, and the first hard-deny wins. A route filter can add checks but **cannot** remove a Gateway-level mandate — a platform-admin requirement is not weakenable by a tenant. Two policies targeting the same Gateway conflict: the older (by `creationTimestamp`, ties by name) wins and the loser gets `Accepted=False, reason=Conflicted` in its `status.ancestors[]`.

Two transports, selected by `spec.protocol`:

- **`HTTP`** — forward-auth: the original method, Host, path, and client headers are replayed to the service (no body); **2xx** allows, any other status is returned to the client.
- **`GRPC`** — the Envoy `envoy.service.auth.v3.Authorization/Check` proto: the request context is sent as a `CheckRequest`; an `OK` status allows (copying `allowedResponseHeaders` from the OK response onto the upstream request), any other status denies with the denied response's HTTP status (default `403`), headers, and body.

`CoxswainExternalAuth` is **HTTPRoute-only** (a Gateway-attached policy covers the HTTPRoutes on the Gateway); `GRPCRoute` is not yet supported.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainExternalAuth
metadata:
  name: oauth2
spec:
  protocol: HTTP          # or GRPC
  backendRef:
    name: oauth2-proxy
    port: 4180
  timeout: 250ms
  failClosed: true        # deny (503) on auth-service error/timeout (default)
  allowedResponseHeaders: # copied onto the upstream request on allow
    - x-auth-user
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
# ...
    filters:
      - type: ExtensionRef
        extensionRef:
          group: gateway.coxswain-labs.dev
          kind: ExternalAuth
          name: oauth2
```

To make the check a Gateway-wide mandate instead, add `targetRefs` and omit the route filter:

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainExternalAuth
metadata:
  name: gateway-authn
spec:
  protocol: GRPC
  backendRef:
    name: ext-authz
    port: 9000
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: my-gateway
```

Fail-closed and cross-namespace rules:

- `failClosed: true` (the default) denies with **503** when the auth service is unreachable, errors, or times out; `failClosed: false` fails **open** (request proceeds unauthorized). A `backendRef` that resolves to no ready endpoints — or an unsupported protocol — always fails **closed**, regardless of `failClosed`.
- A `backendRef` whose `namespace` differs from the policy's namespace requires a matching `ReferenceGrant` — `from` a `CoxswainExternalAuth` (`gateway.coxswain-labs.dev`) `to` a core `Service`. Without it the reference fails **closed** (503). Same-namespace refs need no grant.

[GEP-1494]: https://gateway-api.sigs.k8s.io/geps/gep-1494/

### Request size limit

`RequestSizeLimit` (`gateway.coxswain-labs.dev/v1alpha1`) caps the request body size for a route. Attach it to an `HTTPRouteRule` with an `ExtensionRef` filter — the Gateway API surface for the Ingress `max-body-size` annotation. Like `BasicAuth`/`Compression`, this filter is **HTTPRoute-only** and is not enforced on `GRPCRoute` (see [below](#request-size-limit-is-not-enforced-on-grpcroute)).

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: RequestSizeLimit
metadata:
  name: small-uploads
spec:
  maxSize: "8m"
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
# ...
    filters:
      - type: ExtensionRef
        extensionRef:
          group: gateway.coxswain-labs.dev
          kind: RequestSizeLimit
          name: small-uploads
```

Semantics:

- `maxSize` accepts a bare byte count or a `k`/`m`/`g`-suffixed size (binary multipliers, case-insensitive) — the same parser as the Ingress `max-body-size` annotation.
- On HTTP/1.x, requests exceeding the limit are rejected with `413 Payload Too Large`, checked up front against `Content-Length` when present and mid-stream for chunked/streaming bodies.
- On **HTTP/2**, only the up-front `Content-Length` check applies. A streaming HTTP/2 upload that omits `Content-Length` is **not** capped — it fails open (see the note below on why mid-stream HTTP/2 enforcement is deferred).
- A missing `RequestSizeLimit` CR or an unparseable `maxSize` fails open (no limit enforced).

#### Request size limit is not enforced on GRPCRoute

`RequestSizeLimit` attached to a `GRPCRoute` is accepted but **not enforced** — the reconciler skips it and logs a WARN line (as it does for `BasicAuth`/`Compression`). gRPC message sizes are instead governed by the backend's own `max_recv_msg_size` (gRPC servers reject oversized messages with `RESOURCE_EXHAUSTED`; the default receive cap is ~4 MB).

The reason is a `pingora-proxy` limitation: a `request_body_filter` rejection over HTTP/2 is swallowed by pingora's h2 proxy loop and never delivered to the client, deadlocking the request. gRPC never sends `Content-Length`, so the up-front check that guards HTTP/2 elsewhere cannot apply. Faithful edge enforcement for gRPC/HTTP/2 needs buffer-first rejection (as Envoy's `buffer` filter does) and is deferred until pingora ships request-body buffering.

### Response compression

`Compression` (`gateway.coxswain-labs.dev/v1alpha1`) enables gzip/brotli response compression for a route. Attach it to an `HTTPRouteRule` with an `ExtensionRef` filter — the same CRD the Ingress `compression` annotation references (see [Ingress annotations](ingress-annotations.md#compression)). gRPC compresses per-message at the gRPC framing layer (`grpc-encoding`), not via HTTP `Content-Encoding`, so this filter is **not** supported on `GRPCRoute`; the proxy also refuses to compress any response whose `Content-Type` starts with `application/grpc`, even on an HTTPRoute (a gRPC-over-HTTPRoute edge case), regardless of the CR's `types` allow-list.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: Compression
metadata:
  name: default-compression
spec:
  gzip: true
  brotli: true
  level: 6
  minSize: 1024
  types:
    - text/html
    - text/plain
    - text/css
    - application/json
    - application/javascript
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
# ...
    filters:
      - type: ExtensionRef
        extensionRef:
          group: gateway.coxswain-labs.dev
          kind: Compression
          name: default-compression
```

Semantics:

- At least one of `gzip` / `brotli` must be `true` for the CR to have any effect; when both are `false` (the default) it is a no-op.
- Brotli is preferred over gzip when both are enabled and the client advertises `br` in `Accept-Encoding`.
- `level` (1–9, default `6`), `minSize` (bytes, default `1024`), and `types` (default: `text/html`, `text/plain`, `text/css`, `application/json`, `application/javascript`) are the same defaults applied when the Ingress `compression` annotation resolves this CR.
- A missing `Compression` CR fails open (no compression).

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

## GRPCRoute

A `GRPCRoute` routes gRPC traffic attached to a `Gateway` listener. gRPC is HTTP/2 `POST /{ServiceName}/{MethodName}`, so no special listener protocol is required — an ordinary `HTTP` listener on the Gateway accepts gRPC connections.

### Backend requirements

gRPC backends must advertise cleartext HTTP/2 (h2c) by setting `appProtocol: kubernetes.io/h2c` on the Service port. Coxswain uses prior-knowledge h2c to connect to the backend, which preserves gRPC trailers (`grpc-status`, `grpc-message`).

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-grpc-service
spec:
  selector:
    app: my-grpc-app
  ports:
    - port: 50051
      targetPort: 50051
      appProtocol: kubernetes.io/h2c   # required for gRPC backends
```

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: my-grpc-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
  hostnames:
    - grpc.example.com
  rules:
    - matches:
        - method:
            type: Exact
            service: com.example.MyService
            method: SayHello
      backendRefs:
        - name: my-grpc-service
          port: 50051
```

### Method matching

| Spec | Behaviour |
|------|-----------|
| No `matches` (or empty `matches`) | Routes all gRPC traffic on attached listeners |
| `method.type: Exact`, service + method | Routes `/{service}/{method}` exactly |
| `method.type: Exact`, service only | Routes any method under `/{service}/` |
| `method.type: Exact`, method only | Routes the method name on any service |
| `method.type: RegularExpression` | `service` and `method` are RE2 patterns |

Header matching uses the same `Exact` and `RegularExpression` semantics as `HTTPRoute`.

### Supported fields

| Field | Support |
|-------|---------|
| `spec.parentRefs` | Full (including `sectionName` and `port`) |
| `spec.hostnames` | Full (including wildcards) |
| `spec.rules[].matches[].method` | `Exact` and `RegularExpression` |
| `spec.rules[].matches[].headers` | Full |
| `spec.rules[].filters` | `RequestHeaderModifier`, `ResponseHeaderModifier`, `ExtensionRef` (`RateLimit`, `IpAccessControl`, `JwtAuth`) |
| `spec.rules[].backendRefs` | Service backends only |
| `spec.rules[].backendRefs[].weight` | Full |

GRPCRoute supports the protocol-agnostic `ExtensionRef` filters — [`RateLimit`](rate-limiting.md), [`IpAccessControl`](#ip-access-control), and [`JwtAuth`](#jwt-authentication) (bearer/JWT auth is a common gRPC pattern, unlike `BasicAuth`) — which apply identically to gRPC (HTTP/2) traffic. `PathRewriteRegex` is not supported: for gRPC the request path *is* the `/{service}/{method}` RPC address, so rewriting it is meaningless. `BasicAuth` and `Compression` are HTTP-only idioms and are not supported either — gRPC clients authenticate with bearer tokens or mTLS, and gRPC compresses per-message at the framing layer rather than via HTTP `Content-Encoding`. `RequestSizeLimit` is also not enforced on gRPC — a mid-stream body cap over HTTP/2 deadlocks the client under pingora, so gRPC message sizes are left to the backend's `max_recv_msg_size` ([details](#request-size-limit-is-not-enforced-on-grpcroute)). Any other `ExtensionRef` (and `RequestMirror`) is skipped with a WARN log line.

### Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The route is attached to a Gateway listener |
| `Programmed` | The route is active in the data plane |
| `ResolvedRefs` | All `backendRefs` resolve to a reachable Service |

```bash
kubectl describe grpcroute my-grpc-route
```

## CoxswainBackendPolicy

`CoxswainBackendPolicy` configures how the proxy talks to the pods behind a `Service` — connection timeouts, the load-balancing algorithm, a circuit breaker, and sticky sessions. Create one, point it at a `Service` by name, and every route that sends traffic to that Service picks up the settings — whether that route is an `HTTPRoute`, a `GRPCRoute`, or a classic `Ingress`. You do not add anything to the route itself; the policy attaches to the Service and takes effect automatically.

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

`targetRefs` is the only required field. `timeouts`, `loadBalancer`, `circuitBreaker`, and `sessionPersistence` are all independent and optional — set only the ones you need; anything you omit keeps the default connection behavior (immediate connect with no timeout override, weighted round-robin, no circuit breaker, no sticky sessions).

!!! note "Why a separate resource, not a route annotation or filter?"
    These four settings all describe the *connection to the upstream Service*, not anything about how a request is routed there — so unlike filters (retry, rate limiting, compression), which attach per-route, `CoxswainBackendPolicy` attaches per-Service ([GEP-713](https://gateway-api.sigs.k8s.io/geps/gep-713/) direct policy attachment). Two consequences follow: (1) if two routes (say an Ingress and an HTTPRoute) both send traffic to the same Service, they share one connection policy — that's intentional, since connection pooling and circuit breaking are properties of the upstream, not the route; (2) none of `loadBalancer`/`circuitBreaker` has a stable Gateway API standard to converge toward — Gateway API v1.6.0 covers neither (its closest concept, `BackendLBPolicy`, was replaced by an experimental type that only handles retry budgets and session persistence) — so those two fields are intentionally modeled after Envoy's native load-balancing policies and outlier detection instead. `sessionPersistence` does mirror Gateway API's own (experimental) `SessionPersistence` shape, as closely as Coxswain's persistence mechanism supports (see below).

### Fields

| Field | Required? | Description |
|-------|-----------|-------------|
| `targetRefs[]` | **Yes** | The `Service` objects this policy applies to, in the *same namespace* as the policy. Each entry: `{ group: "", kind: Service, name: <service-name> }`. |
| `timeouts.connect` | optional | Upstream TCP-connect timeout ([GEP-2257](https://gateway-api.sigs.k8s.io/geps/gep-2257/) duration, e.g. `500ms`, `5s`). If the proxy can't establish a connection to a pod within this time, it fails the request with `502` instead of waiting indefinitely. |
| `timeouts.idle` | optional | How long an idle, already-established connection to a pod is kept open in the connection pool before being closed. |
| `loadBalancer.algorithm` | optional | Which algorithm picks a pod for each request. See [Load-balancing algorithm](#load-balancing-algorithm) below for the full list of values. |
| `circuitBreaker.threshold` | optional | Error rate (%, `1`–`100`) that trips the breaker. This is the on/off switch: omit it (or set it out of range) and the circuit breaker is disabled entirely — the other `circuitBreaker.*` fields have no effect on their own. See [Circuit breaker](#circuit-breaker) below. |
| `circuitBreaker.window` | optional | How far back the proxy looks when computing the error rate. Default `10s`. |
| `circuitBreaker.openDuration` | optional | Once tripped, how long the breaker stays open before it lets a test request through. Default `5s`. |
| `circuitBreaker.minRequests` | optional | Don't trip the breaker until at least this many requests have been observed in the window — protects low-traffic routes from tripping on one unlucky failure. Default `10`. |
| `circuitBreaker.maxOpenDuration` | optional | If a pod keeps failing its recovery checks, each re-trip doubles the open duration up to this cap, instead of always waiting the same `openDuration`. Omit for a constant (non-growing) open duration. |
| `sessionPersistence.type` | optional | How to pin a client to one pod: `Cookie` or `Header`. See [Session persistence](#session-persistence) below for guidance on which to pick. |
| `sessionPersistence.sessionName` | conditionally required | The cookie name (`Cookie` mode — optional, defaults to `__coxswain_session`) or the request header to key on (`Header` mode — **required**, no default). |

### Full example

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

### Behaviour

- A backend `Service` with no attached policy keeps the default connection behaviour (weighted round-robin, breaker disabled, no session persistence).
- The per-backend `timeouts.connect` takes precedence over the Gateway API `HTTPRoute.timeouts.backendRequest` fallback.
- **Invalid values fail open.** An unparseable duration, an unrecognised `loadBalancer.algorithm`, an out-of-range `circuitBreaker.threshold`, or an unrecognised `sessionPersistence.type` is logged as a warning and ignored — the backend falls back to the default (round-robin / breaker disabled / no persistence), never a connection-level error or a rejected resource. These fields are deliberately not schema-validated so the policy is accepted and the warning surfaces at reconcile time.
- **Conflicts.** If two policies target the same `Service`, the older one (by `creationTimestamp`, ties broken by name) wins; the loser receives `Accepted=False, reason=Conflicted` in its `status.ancestors[]`.

### Load-balancing algorithm

`loadBalancer.algorithm` selects the algorithm used to pick an upstream endpoint for each request within the backend group of a route:

| Value | Description |
|-------|-------------|
| `round_robin` | _(default)_ Weighted round-robin using the GCD-reduced slot array. Zero per-request overhead. |
| `least_conn` | Routes to the endpoint with the fewest in-flight requests. Maintains an atomic in-flight counter per endpoint; the counter is incremented on selection and decremented when the response completes (or when a retry selects a different endpoint). |
| `ewma` | Routes to the endpoint with the lowest exponentially-weighted moving-average response latency (α = 1/8). Unsampled endpoints (active=0) are probed first. Latency is folded in at end-of-request. |
| `ip_hash` | Alias for `hash:source-ip` (backward-compatible). |
| `hash:uri` | Consistent hash on the full request URI (path + query string). Requests to the same URI always land on the same endpoint. Falls back to round-robin if the path is empty. |
| `hash:source-ip` | Consistent hash on the resolved client IP (see [`trust-forwarded-for`](ingress-annotations.md#trust-forwarded-for) for Ingress, or the equivalent Gateway API resolution). Requests from the same IP always land on the same endpoint; unlike cookie affinity, no state is injected into the response. Falls back to round-robin if the client IP is unavailable. |
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

**Performance** — all algorithms run on the hot path without locks. `round_robin` allocates nothing per request. `least_conn` and `ewma` perform a linear scan over the endpoint list (typically 1–10 pods per Service) using relaxed atomics, which is negligible compared to I/O. `hash:*` values extract and hash the relevant request attribute with FNV-1a, then perform a linear rendezvous scan — negligible. The `hash:uri` path allocates a single joined `path?query` string only when a query string is present; all other hash sources are allocation-free on the hot path.

### Circuit breaker

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

**Fail-fast behaviour:** when the breaker is Open, the proxy returns 503 immediately without connecting to the upstream. The client sees 503; other healthy pods serving the same route continue accepting traffic via load-balancing.

### Session persistence

"Session persistence" (also called sticky sessions) means every request from the same client keeps landing on the same backend pod, instead of being spread across all of them by the load-balancing algorithm. Use it when a pod holds state a client needs to come back to — an in-memory session, a WebSocket connection, an in-progress upload. A backend with no `sessionPersistence` configured is unaffected: it uses `loadBalancer.algorithm` (or round-robin) as normal.

There's no server-side table of "which client goes to which pod" — the pin is recomputed from the request itself every time, so it works identically across proxy replicas with no coordination between them needed. There are two ways the proxy identifies which client is which:

- **`type: Cookie`** — pick this for browser clients (regular web traffic). On a client's first request, the proxy picks a pod as usual and sets a cookie identifying it (`Set-Cookie: <sessionName>=<token>; Path=/; HttpOnly`). Every later request that carries the cookie goes back to that same pod. You don't have to do anything client-side — the browser sends the cookie back automatically. `sessionName` is optional here (defaults to `__coxswain_session`); if you set one that isn't a valid cookie name, the proxy warns and falls back to the default rather than rejecting the policy.
- **`type: Header`** — pick this for API/service clients that already send a stable identifier of their own (an API key, a tenant ID, a session token) as a request header. The proxy hashes that header's value to consistently pick one pod — no cookie is set. Unlike `Cookie` mode, `sessionName` is **required** here (it's the name of the header to key on); if you forget it, persistence is silently disabled for that policy (a warning is logged) and the route falls back to plain round-robin rather than breaking.

**What happens when the pinned pod goes away:** if the pod a client was pinned to gets scaled down or replaced, the next request from that client no longer finds it. Rather than failing, the proxy falls back to round-robin and (in `Cookie` mode) picks a new pod and re-pins with a fresh cookie.

**What's intentionally not supported yet:** Gateway API's own (experimental) `SessionPersistence` type also lets you set a timeout after which a session expires from inactivity (`idleTimeout`) or expires unconditionally (`absoluteTimeout`). Coxswain doesn't support either yet — since there's no server-side session table, there's nothing to time out. Adding real inactivity-based expiry would mean giving the proxy a way to track "when did I last see this client" per pinned session, which is real new work. Until then, a session stays pinned for as long as its pod keeps running.

### Status

The controller writes one `status.ancestors[]` entry per targeted `Service` with an `Accepted` condition:

```bash
kubectl describe coxswainbackendpolicy api-backend-timeouts
```

## TLSRoute

A `TLSRoute` routes raw TLS connections by SNI. Coxswain supports three modes, configured via `tls.mode` on the Gateway listener:

- **Passthrough** — the proxy peeks the ClientHello SNI and splices the still-encrypted byte stream directly to the backend. TLS is terminated at the backend pod (GEP-2643).
- **Terminate** — the proxy terminates TLS using the listener certificate, then L4-splices the decrypted stream to a plaintext TCP backend.
- **Mixed** — a single Gateway port carries both Passthrough and Terminate listeners, disambiguated by SNI hostname.

### Gateway listener (Passthrough)

Use `protocol: TLS` with `tls.mode: Passthrough` on the listener. No `certificateRefs` are needed — the proxy never holds or inspects a certificate on this path.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: passthrough
      port: 443
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        namespaces:
          from: Same
```

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: my-tls-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
      sectionName: passthrough
  hostnames:
    - app.example.com       # matched against the TLS ClientHello SNI
  rules:
    - backendRefs:
        - name: my-tls-service
          port: 443
```

The backend Service receives the unmodified TLS stream; its pod terminates TLS and sees the client's original handshake.

### SNI matching

| Hostname format | Behaviour |
|-----------------|-----------|
| `app.example.com` | Exact SNI match |
| `*.example.com` | Wildcard: matches any number of labels (`foo.example.com`, `a.b.example.com`) |
| _(omitted)_ | Catch-all: matches any SNI that no other rule handles |

Matching follows Gateway API hostname precedence: exact before wildcard before catch-all.

!!! note
    Wildcard hostname semantics here are routing-only (not RFC 6125 cert validation — no cert is involved at the proxy). Any number of DNS labels are matched by `*`, consistent with Gateway API's HTTPRoute wildcard semantics.

### Supported fields

| Field | Support |
|-------|---------|
| `spec.parentRefs` | Full (including `sectionName` and `port`) |
| `spec.hostnames` | Full (exact, wildcard, omitted catch-all) |
| `spec.rules[].backendRefs` | Service backends only |
| `spec.rules[].backendRefs[].weight` | Full |

### Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The route is attached to a `TLS/Passthrough` or `TLS/Terminate` listener |
| `ResolvedRefs` | All `backendRefs` resolve to a reachable Service |

```bash
kubectl describe tlsroute my-tls-route
```

---

### Terminate mode

In terminate mode the proxy holds the TLS session. The listener must carry a `certificateRefs` entry pointing to a `kubernetes.io/tls` Secret. Coxswain selects the certificate by SNI using the same mechanism as HTTPS listeners. The TLSRoute backend receives a **plaintext** TCP stream; no TLS certificate is needed at the backend.

#### Gateway listener

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: terminate
      port: 443
      protocol: TLS
      hostname: app.example.com
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: my-tls-cert   # must exist in the same namespace
      allowedRoutes:
        namespaces:
          from: Same
```

#### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: my-terminate-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
      sectionName: terminate
  hostnames:
    - app.example.com
  rules:
    - backendRefs:
        - name: my-plaintext-service  # backend receives decrypted TCP, no TLS required
          port: 8080
```

The proxy performs an SNI peek on accept, looks up the certificate, completes the TLS handshake, then L4-splices the decrypted byte stream to the backend. HTTP-layer parsing does not occur — this is a raw TCP splice post-decryption, not an HTTPS proxy.

---

### Mixed mode

A single Gateway port can carry both a Terminate and a Passthrough TLS listener simultaneously. The proxy disambiguates by SNI hostname: traffic whose SNI matches the Terminate listener's hostname is decrypted at the proxy; traffic whose SNI matches the Passthrough listener's hostname is forwarded encrypted to the backend. The two routing tables are isolated — a miss in one never leaks into the other.

#### Gateway listener

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-mixed-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: tls-terminate
      port: 443
      protocol: TLS
      hostname: terminate.example.com
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: my-tls-cert
      allowedRoutes:
        namespaces:
          from: Same
    - name: tls-passthrough
      port: 443
      protocol: TLS
      hostname: passthrough.example.com
      tls:
        mode: Passthrough
      allowedRoutes:
        namespaces:
          from: Same
```

#### Example

```yaml
# Terminate route — backend is a plaintext TCP service
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: terminate-route
  namespace: default
spec:
  parentRefs:
    - name: my-mixed-gateway
      sectionName: tls-terminate
  hostnames:
    - terminate.example.com
  rules:
    - backendRefs:
        - name: plaintext-service
          port: 8080
---
# Passthrough route — backend terminates TLS itself
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: passthrough-route
  namespace: default
spec:
  parentRefs:
    - name: my-mixed-gateway
      sectionName: tls-passthrough
  hostnames:
    - passthrough.example.com
  rules:
    - backendRefs:
        - name: tls-backend
          port: 8443
```

!!! note
    Both listeners must use distinct hostnames on the shared port. An SNI that matches neither listener is dropped — the proxy never falls through from one table to the other.
