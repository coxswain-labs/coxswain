# TLSRoute

A `TLSRoute` routes raw TLS connections by SNI. Coxswain supports three modes, configured via `tls.mode` on the Gateway listener:

- **Passthrough** — the proxy peeks the ClientHello SNI and splices the still-encrypted byte stream directly to the backend. TLS is terminated at the backend pod.
- **Terminate** — the proxy terminates TLS using the listener certificate, then L4-splices the decrypted stream to a plaintext TCP backend.
- **Mixed** — a single Gateway port carries both Passthrough and Terminate listeners, disambiguated by SNI hostname.

## Gateway listener (Passthrough)

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

## Example

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

## SNI matching

| Hostname format | Behaviour |
|-----------------|-----------|
| `app.example.com` | Exact SNI match |
| `*.example.com` | Wildcard: matches any number of labels (`foo.example.com`, `a.b.example.com`) |
| _(omitted)_ | Catch-all: matches any SNI that no other rule handles |

Matching follows Gateway API hostname precedence: exact before wildcard before catch-all.

!!! note
    Wildcard matching here is routing-only (no cert is involved at the proxy on the passthrough path), and follows the same any-number-of-labels semantics as [HTTPRoute wildcards](httproute.md#wildcard-hostnames).

## Supported fields

| Field | Support |
|-------|---------|
| `spec.parentRefs` | Full (including `sectionName` and `port`) |
| `spec.hostnames` | Full (exact, wildcard, omitted catch-all) |
| `spec.rules[].backendRefs` | Service backends only |
| `spec.rules[].backendRefs[].weight` | Full |

## Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The route is attached to a `TLS/Passthrough` or `TLS/Terminate` listener |
| `ResolvedRefs` | All `backendRefs` resolve to a reachable Service |

```bash
kubectl describe tlsroute my-tls-route
```

## Terminate mode

In terminate mode the proxy holds the TLS session. The listener must carry a `certificateRefs` entry pointing to a `kubernetes.io/tls` Secret. Coxswain selects the certificate by SNI using the same mechanism as HTTPS listeners. The TLSRoute backend receives a **plaintext** TCP stream; no TLS certificate is needed at the backend.

### Gateway listener

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

### Example

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

## Mixed mode

A single Gateway port can carry both a Terminate and a Passthrough TLS listener simultaneously. The proxy disambiguates by SNI hostname: traffic whose SNI matches the Terminate listener's hostname is decrypted at the proxy; traffic whose SNI matches the Passthrough listener's hostname is forwarded encrypted to the backend. The two routing tables are isolated — a miss in one never leaks into the other.

### Gateway listener

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

### Example

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
