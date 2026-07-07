# TLS guide

Coxswain terminates TLS at the proxy layer using SNI. It watches all `kubernetes.io/tls` Secrets and hot-reloads TLS material whenever a Secret is created, updated, or deleted — no restart or config reload is required.

## Manual TLS (pre-provisioned Secret)

Create the TLS Secret manually and reference it from your `Ingress` or `Gateway`:

```bash
kubectl create secret tls app-tls \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem
```

=== "Ingress"

    ```yaml
    spec:
      ingressClassName: coxswain
      tls:
        - hosts:
            - app.example.com
          secretName: app-tls
      rules:
        - host: app.example.com
          ...
    ```

=== "Gateway API"

    ```yaml
    spec:
      gatewayClassName: coxswain
      listeners:
        - name: https
          port: 443
          protocol: HTTPS
          hostname: app.example.com
          tls:
            mode: Terminate
            certificateRefs:
              - kind: Secret
                name: app-tls
    ```

## TLS with cert-manager

[cert-manager](https://cert-manager.io) is the de facto standard for automated TLS in Kubernetes. Coxswain integrates transparently — cert-manager creates and renews the Secret; Coxswain picks it up automatically.

### Prerequisites

| Component | Minimum version | Notes |
|-----------|-----------------|-------|
| cert-manager | v1.14 | For Ingress only |
| cert-manager | v1.16 | For Gateway API |
| Gateway API CRDs | v1.0 | For Gateway API usage |

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.0/cert-manager.yaml
kubectl wait --for=condition=Available --timeout=120s \
  deploy/cert-manager deploy/cert-manager-webhook deploy/cert-manager-cainjector \
  -n cert-manager
```

### Issuer types

| Issuer | When to use |
|--------|-------------|
| `SelfSigned` | Local dev and demos only |
| `CA` | Internal PKI with your own root CA |
| `ACME (HTTP-01)` | Production with public domain; cert-manager uses Coxswain to serve the challenge |
| `ACME (DNS-01)` | Production; requires DNS provider integration |

### Ingress with cert-manager

Add the `cert-manager.io/cluster-issuer` annotation and a `spec.tls` entry:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-com
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: coxswain
  tls:
    - hosts:
        - example.com
      secretName: example-com-tls   # cert-manager creates and renews this
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-service
                port:
                  number: 80
```

A ready-to-apply example with a self-signed issuer lives in [`deploy/examples/tls-cert-manager-ingress.yaml`](https://github.com/coxswain-labs/coxswain/blob/main/deploy/examples/tls-cert-manager-ingress.yaml).

#### HTTP-01 challenge passthrough

When using an ACME HTTP-01 solver, cert-manager temporarily creates an `Ingress` with the challenge path `/.well-known/acme-challenge/<token>`, copying the `ingressClassName` from the parent `Ingress`. Coxswain picks up this `Ingress`, routes the challenge to cert-manager's solver pod, and removes the route once the challenge completes. No manual configuration is required beyond setting `--status-address`.

!!! important
    `--status-address` must be set to the proxy's external IP or hostname. Without it, `Ingress.status` is empty and cert-manager cannot locate the challenge endpoint.

### Gateway API with cert-manager

cert-manager v1.16+ supports the Gateway API natively. Add the annotation to the `Gateway`; cert-manager creates a `Certificate` for each HTTPS listener:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: example-com-gateway
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  gatewayClassName: coxswain
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: "example.com"
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: example-com-gateway-tls   # cert-manager creates and renews this
      allowedRoutes:
        namespaces:
          from: Same
```

A ready-to-apply example lives in [`deploy/examples/tls-cert-manager-gateway.yaml`](https://github.com/coxswain-labs/coxswain/blob/main/deploy/examples/tls-cert-manager-gateway.yaml).

#### Older cert-manager (< v1.16)

Enable the Gateway API feature gate on the cert-manager controller:

```yaml
# In your cert-manager Deployment or Helm values:
extraArgs:
  - --feature-gates=ExperimentalGatewayAPISupport=true
```

## Verification

After applying the manifest, wait for the Secret to appear:

```bash
# Ingress
kubectl wait secret example-com-tls \
  --for=jsonpath='{.type}'=kubernetes.io/tls --timeout=60s

# Gateway API
kubectl wait secret example-com-gateway-tls \
  --for=jsonpath='{.type}'=kubernetes.io/tls --timeout=60s
```

Test the TLS endpoint:

```bash
# Self-signed cert (-k ignores verification)
curl --resolve example.com:443:127.0.0.1 -k https://example.com/

# Inspect the served certificate
openssl s_client -connect 127.0.0.1:443 -servername example.com -brief
```

## Gateway frontend client certificate validation (GEP-91)

Coxswain implements **GEP-91** (Standard channel, Gateway API v1.5): gateway-wide TLS client certificate validation configured via `spec.tls.frontend.default.validation` on an HTTPS listener.

### CA bundle

The CA bundle is loaded from a `ConfigMap` in the **same namespace** as the Gateway, under the key `ca.crt` (Core support). The ConfigMap is referenced by name:

```yaml
spec:
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: app.example.com
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: app-tls
        frontend:
          default:
            validation:
              caCertificateRefs:
                - group: ""
                  kind: ConfigMap
                  name: my-ca-bundle   # must have key ca.crt
```

The ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-ca-bundle
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
```

The CA bundle is **hot-reloaded** when the ConfigMap changes — no Gateway or proxy restart required.

If the referenced ConfigMap is missing, does not contain a `ca.crt` key, or is not PEM-encoded, Coxswain falls back to `Unavailable` and **fails closed**: every TLS handshake to that hostname is rejected until the ConfigMap is corrected.

Because frontend validation is gateway-wide, an unresolvable CA ref impacts **every HTTPS listener** on the Gateway, which surfaces it in listener status (HTTP listeners are unaffected and keep serving):

```
ResolvedRefs: False  reason: InvalidCACertificateRef
Accepted:     False  reason: NoValidCACertificate
Programmed:   False
```

### Validation modes

| Mode | Behaviour |
|------|-----------|
| `AllowValidOnly` (default) | Client cert is required and must be signed by the configured CA. Missing or invalid cert → TLS handshake aborted (Istio MUTUAL semantics). |
| `AllowInsecureFallback` | Client cert is requested and validated if present, but the handshake is never aborted. Missing or invalid cert → request passes through; authorization is delegated to the backend. |

```yaml
# AllowInsecureFallback (GEP-91)
frontend:
  default:
    validation:
      mode: AllowInsecureFallback
      caCertificateRefs:
        - group: ""
          kind: ConfigMap
          name: my-ca-bundle
```

### InsecureFrontendValidationMode condition

When `AllowInsecureFallback` is active, the Gateway emits a top-level status condition:

```
type:   InsecureFrontendValidationMode
status: True
reason: ConfigurationChanged
```

This condition is **absent** when the mode is `AllowValidOnly`. Operators can use it to audit cluster state:

```bash
kubectl get gateway <name> -o jsonpath='{.status.conditions[?(@.type=="InsecureFrontendValidationMode")]}'
```

### Out of scope

| Feature | Status |
|---------|--------|
| `perPort` validation overrides | **Supported** — `spec.tls.frontend.perPort[].tls.validation` overrides the gateway `default` for listeners on that port; the resolved config is keyed by the listener's bind port + hostname, so two Gateways sharing a hostname keep independent validation policies |
| Cross-namespace CA refs | **Supported** — a CA `ConfigMap` in another namespace requires a `Gateway → ConfigMap` `ReferenceGrant`; without one the listener surfaces `ResolvedRefs=False/RefNotPermitted` |
| Secret-backed CA refs | Not yet — only `ConfigMap`/`ca.crt` is Core-certified |
| Multiple `caCertificateRefs` | Planned (Extended support); currently only the first ref is used |

A listener whose effective CA ref cannot be resolved fails closed and surfaces the GEP-91 reason on its `ResolvedRefs` condition: `InvalidCACertificateRef` (missing ConfigMap / no `ca.crt` / not PEM), `InvalidCACertificateKind` (ref kind is not `ConfigMap`), or `RefNotPermitted` (cross-namespace without a `ReferenceGrant`).

## Gateway backend client certificate (GEP-3155)

Coxswain implements **GEP-3155**: when a Gateway carries `spec.tls.backend.clientCertificateRef`, the proxy presents that certificate as its client identity when opening TLS connections to upstream pods. This enables backend mutual TLS — the upstream can verify the proxy's identity in addition to the proxy verifying the upstream's certificate.

!!! important
    The backend client cert is **only applied on connections driven by a `BackendTLSPolicy`**. `BackendTLSPolicy` is the sole Gateway API mechanism for originating upstream TLS; without it the connection to the backend is cleartext, and `clientCertificateRef` has no effect.

### Configuration

Store the client certificate in a `kubernetes.io/tls` Secret in the **same namespace** as the Gateway, then reference it from `spec.tls.backend.clientCertificateRef`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
spec:
  gatewayClassName: coxswain
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      ...
  tls:
    backend:
      clientCertificateRef:
        group: ""
        kind: Secret
        name: proxy-client-cert    # kubernetes.io/tls; same namespace as Gateway
```

The Secret must be type `kubernetes.io/tls` with both `tls.crt` (PEM certificate chain) and `tls.key` (PEM private key):

```bash
kubectl create secret tls proxy-client-cert \
  --cert=path/to/client.pem \
  --key=path/to/client.key
```

Pair with a `BackendTLSPolicy` that selects the upstream pods — the policy establishes the upstream TLS context in which the client cert is presented:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: my-service-tls
spec:
  targetRefs:
    - group: ""
      kind: Service
      name: my-service
  validation:
    caCertificateRefs:
      - group: ""
        kind: ConfigMap
        name: my-service-ca
    hostname: my-service.internal
```

### Status conditions

The controller reflects resolution on a gateway-level `ResolvedRefs` condition:

| Outcome | `ResolvedRefs` | Reason |
|---------|---------------|--------|
| Secret found with valid `tls.crt`/`tls.key` | `True` | `ResolvedRefs` |
| `clientCertificateRef` not set | condition absent | — |
| Secret missing | `False` | `InvalidClientCertificateRef` |
| Secret is not type `kubernetes.io/tls` | `False` | `InvalidClientCertificateRef` |
| Unsupported group or kind in the ref | `False` | `InvalidClientCertificateRef` |
| Cross-namespace ref without a `ReferenceGrant` | `False` | `RefNotPermitted` |

When the ref fails to resolve, the proxy **fails closed on that upstream**: any connection to a BackendTLSPolicy-selected backend via this Gateway returns `502`. Connections to non-TLS backends are unaffected.

### Hot-reload

The controller resolves the Secret and pushes the cert bytes to the proxy via the discovery snapshot. When the Secret is updated (e.g. certificate rotation), the controller re-resolves and publishes the new bytes; the proxy picks them up on the next connection without any restart.

Connections already in flight use the cert that was in effect when the connection was opened. New connections after the rotation use the new cert.

### Out of scope

| Feature | Status |
|---------|--------|
| Cross-namespace `clientCertificateRef` | Planned — requires a `ReferenceGrant`; without one the Gateway surfaces `ResolvedRefs=False/RefNotPermitted` |

## BackendTLSPolicy subjectAltNames (GEP-1897 Extended)

`BackendTLSPolicy.spec.validation.subjectAltNames` pins the identity the upstream's leaf
certificate must present, independent of the `hostname` used for SNI and certificate
selection.  This satisfies the GEP-1897 Extended-conformance feature
`BackendTLSPolicySANValidation`.

### How it works

When `subjectAltNames` is set:

- `hostname` is used **only** for SNI and cert selection — not for authentication.
- The proxy verifies the leaf cert's SAN extension against every entry in the list.
- A request is forwarded if **at least one** listed SAN matches a SAN in the presented
  cert (any-of semantics, matching the Gateway API spec).
- If no entry matches, the connection is rejected with **502** and the TLS connection
  is discarded before any HTTP bytes are sent to the backend.
- Chain validation (`verify_cert`) still runs — the cert must chain to the configured CA.

### Configuration

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: my-policy
spec:
  targetRefs:
    - group: ""
      kind: Service
      name: my-service
  validation:
    hostname: my-service.internal        # used for SNI, not for auth
    caCertificateRefs:
      - group: ""
        kind: ConfigMap
        name: my-ca
    subjectAltNames:
      # Match a SPIFFE workload identity (URI SAN)
      - type: URI
        uri: spiffe://cluster.local/ns/my-ns/sa/my-service
      # Optionally also accept a DNS SAN
      - type: Hostname
        hostname: my-service.internal
```

Supported `type` values are `Hostname` (matched against DNS SANs in the leaf cert) and
`URI` (matched byte-for-byte against URI SANs).  DNS matching follows RFC 6125: a
single-label wildcard in the **certificate** (`*.example.com`) matches one non-empty
left-most label of the expected name (`my-service.example.com`).

### Fail-closed behaviour

- **All entries invalid** at reconcile time (empty `subjectAltNames` block that cannot be
  parsed) → the policy is marked `Accepted=False/InvalidSubjectAltNames`; the route
  falls back to cleartext (same behaviour as a missing CA).
- **SAN mismatch at runtime** → 502; the connection is never pooled.
- **No leaf cert or no SANs in cert** → same as a mismatch; the request is rejected.

## Wildcard TLS

For wildcard hostname TLS (e.g. `*.example.com`), the TLS Secret's `tls.crt` must include a wildcard SAN. Coxswain follows RFC 6125 for TLS matching: a single-label wildcard (`*.example.com`) matches `foo.example.com` but not `foo.bar.example.com`.

## Troubleshooting

**Secret never appears**

- `kubectl describe clusterissuer <name>` — check issuer status
- `kubectl get certificate -n <namespace>` — check cert-manager's Certificate object
- `kubectl get certificaterequest -n <namespace>` — check for issuance errors

**Coxswain is not serving the new certificate**

Verify the Secret exists and is a valid TLS type:

```bash
kubectl get secret example-com-tls -o jsonpath='{.type}'
kubectl get secret example-com-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout
```

Check the routing table and logs:

```bash
curl http://localhost:8082/api/v1/routes
curl http://localhost:8082/api/v1/health
```

A missing or malformed Secret produces a warning log but does not affect HTTP routes.
