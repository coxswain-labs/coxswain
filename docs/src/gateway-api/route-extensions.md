# Route extensions

Coxswain ships a set of route-level features as CRDs in the `gateway.coxswain-labs.dev/v1alpha1` group. You attach each one to a route rule with a Gateway API `ExtensionRef` filter:

```yaml
    filters:
      - type: ExtensionRef
        extensionRef:
          group: gateway.coxswain-labs.dev
          kind: <Kind>          # the CRD kind — see each extension below
          name: <cr-name>
```

The same CR backs the equivalent Ingress annotation, so one resource serves both surfaces identically. Two things to know:

- **`CoxswainExternalAuth` attaches with `kind: ExternalAuth`** (the short alias), not its full CRD name — every other extension's `ExtensionRef` `kind` equals its CRD kind.
- **Route-kind support varies.** `IpAccessControl` and `JwtAuth` also apply to `GRPCRoute`; `BasicAuth`, `RequestSizeLimit`, `Compression`, and `PathRewriteRegex` are HTTP-only and are skipped (with a WARN) on `GRPCRoute`. Each extension states its own support below.

`RateLimit` and retries have their own guides — see [Rate limiting](../operations/rate-limiting.md) and [Retries](../operations/retries.md).

## Path rewrite

`PathRewriteRegex` rewrites the request path with a regular expression before the request is forwarded upstream — the Gateway API surface for the Ingress `use-regex` + `rewrite-target` pairing. It is **HTTPRoute-only**: for gRPC the path *is* the `/{service}/{method}` RPC address, so rewriting it is meaningless and the filter is skipped on `GRPCRoute`.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: PathRewriteRegex
metadata:
  name: strip-api-prefix
spec:
  pattern: "^/api/(.*)$"      # matched against the request path
  replacement: "/$1"          # $1..$n reference capture groups
```

Semantics:

- `pattern` is a Rust `regex` pattern, compiled once at reconcile (size-bounded) and shared across requests. `replacement` is a template — `$1`…`$n` expand from the pattern's capture groups, and a reference to a missing group expands to empty.
- The pattern is matched against the request path and is **unanchored** unless you anchor it with `^`…`$`. A path that doesn't match is forwarded unchanged.
- An **invalid** `pattern`, or a **missing** `PathRewriteRegex` CR, fails **open**: the filter is skipped (a WARN is logged) and the path is left as-is.

## IP access control

`IpAccessControl` restricts a route to a set of source-IP CIDR ranges — the Gateway API surface for the Ingress [`ip-access-control`](../ingress/annotations.md#ip-access-control) annotation. It has no Gateway API standard equivalent; its merit anchor is Envoy's `rbac` CIDR-principal filter / Istio `AuthorizationPolicy` `ipBlocks`/`notIpBlocks`.

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
```

Semantics:

- **`deny` is evaluated before `allow`.** A client inside any `deny` range gets `403` even when `allow` would admit it.
- **`allow` restricts to the listed ranges** — a client outside every `allow` range gets `403`. An empty `allow` list imposes no allow-list restriction (only `deny` applies); empty `allow` **and** empty `deny` performs no filtering.
- **IPv4 and IPv6** CIDRs are both accepted; a bare address (`203.0.113.5`) is treated as a host route (`/32` / `/128`). Invalid CIDR tokens are logged and skipped rather than rejecting the whole policy.
- A **missing** `IpAccessControl` CR fails open (a WARN is logged; the route is not filtered).

The client IP is resolved through the same path as the rest of the data plane: the PROXY-protocol peer when a `ClientTrafficPolicy` enables PROXY protocol on the listener, otherwise the L4 downstream peer. There is no Gateway-side trusted-forwarded-header surface yet, so behind an L7 load balancer that terminates the connection, enable PROXY protocol so the real client IP reaches the filter.

## Basic authentication

`BasicAuth` validates `Authorization: Basic` credentials against an htpasswd `Secret` — the Gateway API surface for the Ingress `auth-basic-secret` annotation. HTTP Basic auth is a browser/HTTP idiom, so this filter is **not** supported on `GRPCRoute` (gRPC clients authenticate with bearer tokens or mTLS instead).

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: BasicAuth
metadata:
  name: office-only
spec:
  secretRef:
    name: office-htpasswd
    namespace: default
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

## JWT authentication

`JwtAuth` validates a bearer token's signature against a JSON Web Key Set (JWKS) — the Coxswain implementation of Envoy's `envoy.filters.http.jwt_authn` `JwtProvider` / Istio's `RequestAuthentication.jwtRules`, and the Gateway API surface for the [Ingress `auth-jwt` annotation](../ingress/annotations.md). No Gateway API standard exists for in-proxy JWT validation (GEP-1494 covers *delegated* ext_authz, a different model). Unlike `BasicAuth` (an HTTP/browser idiom), bearer/JWT auth is a common gRPC pattern, so `JwtAuth` is supported on both `HTTPRoute` and `GRPCRoute`.

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

## External authorization (ext_authz)

`CoxswainExternalAuth` delegates an allow/deny decision to an external authorization service before a request reaches its upstream — the Coxswain implementation of [GEP-1494] and the Envoy / Istio / kgateway `ext_authz` model. The auth service is named by a **`backendRef`** (a `Service` + port), resolved to pod endpoints and load-balanced like any other backend; there is no URL form.

It is **dual-surface**:

- **Route filter** — reference it from an `HTTPRouteRule` via an `ExtensionRef` filter (attach `kind: ExternalAuth`).
- **Gateway policy** — attach it to a `Gateway` via `spec.targetRefs` (like `ClientTrafficPolicy`), making it a default applied to **every** HTTPRoute on that Gateway.

Precedence is **additive**: when both a Gateway-attached policy and a route filter apply, the request must pass **both** checks, and the first hard-deny wins. A route filter can add checks but **cannot** remove a Gateway-level mandate — a platform-admin requirement is not weakenable by a tenant. Two policies targeting the same Gateway conflict: the older (by `creationTimestamp`, ties by name) wins and the loser gets `Accepted=False, reason=Conflicted` in its `status.ancestors[]`.

Two transports, selected by `spec.protocol`:

- **`HTTP`** — forward-auth: the original method, Host, path, and client headers are replayed to the service (no body); **2xx** allows, any other status is returned to the client.
- **`GRPC`** — the Envoy `envoy.service.auth.v3.Authorization/Check` proto: the request context is sent as a `CheckRequest`; an `OK` status allows (copying `allowedResponseHeaders` from the OK response onto the upstream request), any other status denies with the denied response's HTTP status (default `403`), headers, and body. The `CheckRequest`'s `attributes.request.http.scheme` reflects the real downstream connection — `https` on a TLS listener, `http` on a cleartext one — so an authz policy may key on it.

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

## Request size limit

`RequestSizeLimit` caps the request body size for a route — the Gateway API surface for the Ingress `max-body-size` annotation. Like `BasicAuth`/`Compression`, this filter is **HTTPRoute-only** and is not enforced on `GRPCRoute` (see [below](#request-size-limit-is-not-enforced-on-grpcroute)).

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: RequestSizeLimit
metadata:
  name: small-uploads
spec:
  maxSize: "8m"
```

Semantics:

- `maxSize` accepts a bare byte count or a `k`/`m`/`g`-suffixed size (binary multipliers, case-insensitive) — the same parser as the Ingress `max-body-size` annotation.
- On HTTP/1.x, requests exceeding the limit are rejected with `413 Payload Too Large`, checked up front against `Content-Length` when present and mid-stream for chunked/streaming bodies.
- On **HTTP/2**, only the up-front `Content-Length` check applies. A streaming HTTP/2 upload that omits `Content-Length` is **not** capped — it fails open (see the note below on why mid-stream HTTP/2 enforcement is deferred).
- A missing `RequestSizeLimit` CR or an unparseable `maxSize` fails open (no limit enforced).

### Request size limit is not enforced on GRPCRoute

`RequestSizeLimit` attached to a `GRPCRoute` is accepted but **not enforced** — the reconciler skips it and logs a WARN line (as it does for `BasicAuth`/`Compression`). gRPC message sizes are instead governed by the backend's own `max_recv_msg_size` (gRPC servers reject oversized messages with `RESOURCE_EXHAUSTED`; the default receive cap is ~4 MB).

The reason is a `pingora-proxy` limitation: a `request_body_filter` rejection over HTTP/2 is swallowed by pingora's h2 proxy loop and never delivered to the client, deadlocking the request. gRPC never sends `Content-Length`, so the up-front check that guards HTTP/2 elsewhere cannot apply. Faithful edge enforcement for gRPC/HTTP/2 needs buffer-first rejection (as Envoy's `buffer` filter does) and is deferred until pingora ships request-body buffering.

## Response compression

`Compression` enables gzip/brotli response compression for a route — the same CRD the Ingress `compression` annotation references (see [Ingress annotations](../ingress/annotations.md#compression)). gRPC compresses per-message at the gRPC framing layer (`grpc-encoding`), not via HTTP `Content-Encoding`, so this filter is **not** supported on `GRPCRoute`; the proxy also refuses to compress any response whose `Content-Type` starts with `application/grpc`, even on an HTTPRoute (a gRPC-over-HTTPRoute edge case), regardless of the CR's `types` allow-list.

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
```

Semantics:

- At least one of `gzip` / `brotli` must be `true` for the CR to have any effect; when both are `false` (the default) it is a no-op.
- Brotli is preferred over gzip when both are enabled and the client advertises `br` in `Accept-Encoding`.
- `level` (1–9, default `6`), `minSize` (bytes, default `1024`), and `types` (default: `text/html`, `text/plain`, `text/css`, `application/json`, `application/javascript`) are the same defaults applied when the Ingress `compression` annotation resolves this CR.
- A missing `Compression` CR fails open (no compression).
