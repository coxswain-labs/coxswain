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
| Secret-backed CA refs | Not yet — only `ConfigMap`/`ca.crt` is Core-certified |
| Cross-namespace CA refs | Not yet — ReferenceGrant extension; same namespace only |
| `perPort` validation overrides | Not applicable — Coxswain's shared `:443` listener is SNI-keyed, not port-keyed |
| Multiple `caCertificateRefs` | Planned (Extended support); currently only the first ref is used |

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
