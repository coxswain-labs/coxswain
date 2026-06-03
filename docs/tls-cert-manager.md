# TLS with cert-manager

[cert-manager](https://cert-manager.io) is the de facto standard for automated TLS in Kubernetes.
Operators annotate an `Ingress` or `Gateway` with an issuer reference; cert-manager mints a
`kubernetes.io/tls` Secret and keeps it renewed.  Coxswain integrates transparently: it watches
all `kubernetes.io/tls` Secrets and hot-reloads TLS material whenever a Secret changes — no
restart or config reload is required.

## Prerequisites

| Component | Minimum version | Notes |
|---|---|---|
| cert-manager | v1.14 | For Ingress only |
| cert-manager | v1.16 | For Gateway API (stable since v1.16; older versions require `--feature-gates=ExperimentalGatewayAPISupport=true` on the cert-manager controller) |
| Gateway API CRDs | v1.0 | Required for Gateway API usage |

Install cert-manager:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.0/cert-manager.yaml
kubectl wait --for=condition=Available --timeout=120s \
  deploy/cert-manager \
  deploy/cert-manager-webhook \
  deploy/cert-manager-cainjector \
  -n cert-manager
```

## Issuer choices

| Issuer type | When to use |
|---|---|
| `SelfSigned` | Local dev and demos only — no trust chain |
| `CA` | Internal PKI; sign with your own root CA |
| `ACME (HTTP-01)` | Production with a public domain; cert-manager uses Coxswain itself to serve the HTTP-01 challenge |
| `ACME (DNS-01)` | Production; requires DNS provider integration |

## Ingress

cert-manager has built-in Ingress support.  Add the `cert-manager.io/cluster-issuer` annotation
(or `cert-manager.io/issuer` for a namespace-scoped Issuer) and list the desired `secretName`
in `spec.tls`.  cert-manager will create and renew the Secret automatically.

**Coxswain requires no special configuration** — it already watches all `kubernetes.io/tls`
Secrets and hot-reloads when the cert-manager-created Secret appears or is updated.

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
      secretName: example-com-tls   # cert-manager creates/renews this
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

A ready-to-apply example (with a self-signed issuer) lives in
[`deploy/examples/tls-cert-manager-ingress.yaml`](../deploy/examples/tls-cert-manager-ingress.yaml).

### HTTP-01 challenge passthrough

When using an ACME HTTP-01 solver, cert-manager temporarily creates an `Ingress` (or
`IngressRoute`) with the challenge path `/.well-known/acme-challenge/<token>`.  Coxswain picks up
this Ingress, routes the challenge request to cert-manager's solver pod, and removes the route
once the challenge completes.  No manual configuration is required.

## Gateway API

cert-manager v1.16 and later support the Gateway API natively.  Add the
`cert-manager.io/cluster-issuer` annotation to the `Gateway` resource; cert-manager creates a
`Certificate` for each HTTPS listener and populates the Secret named in
`listener.tls.certificateRefs[0].name`.

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
            name: example-com-gateway-tls   # cert-manager creates/renews this
      allowedRoutes:
        namespaces:
          from: Same
```

A ready-to-apply example lives in
[`deploy/examples/tls-cert-manager-gateway.yaml`](../deploy/examples/tls-cert-manager-gateway.yaml).

### Older cert-manager versions (< v1.16)

Enable the Gateway API feature gate on the cert-manager controller:

```yaml
# In your cert-manager Deployment or Helm values:
extraArgs:
  - --feature-gates=ExperimentalGatewayAPISupport=true
```

## Verification

After applying the Ingress or Gateway manifest, wait for the Secret to appear:

```bash
# Ingress
kubectl wait secret example-com-tls \
  --for=jsonpath='{.type}'=kubernetes.io/tls --timeout=60s

# Gateway API
kubectl wait secret example-com-gateway-tls \
  --for=jsonpath='{.type}'=kubernetes.io/tls --timeout=60s
```

Then test the TLS endpoint (adjust the address and port for your cluster):

```bash
# With curl, ignoring self-signed cert warnings (-k):
curl --resolve example.com:443:127.0.0.1 -k https://example.com/

# Inspect the served certificate:
openssl s_client -connect 127.0.0.1:443 -servername example.com -brief
```

## Troubleshooting

**Secret never appears**

- Check `kubectl describe clusterissuer <name>` or `kubectl describe issuer <name>` for errors.
- Check `kubectl get certificate -n <namespace>` — cert-manager creates a `Certificate` object
  and sets conditions on it.
- Check `kubectl get certificaterequest -n <namespace>` for issuance errors.

**Coxswain is not serving the new certificate**

- Verify the Secret exists and has `type: kubernetes.io/tls` with a valid `tls.crt`:

  ```bash
  kubectl get secret example-com-tls -o jsonpath='{.type}'
  kubectl get secret example-com-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout
  ```

- Check Coxswain's admin port to confirm the route is active and the host count increased:

  ```bash
  curl http://localhost:8082/routes
  curl http://localhost:8082/status
  ```

- Check Coxswain logs for `TLS Secret unusable` or `Gateway TLS cert installed` messages.
  A missing or malformed Secret produces a warning but does not affect HTTP routes.
