# Coxswain

[![E2E & Conformance](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml/badge.svg)](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml)

A pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine.

> **Note**: This project is currently in early development and not accepting external contributions. Bug reports and feature requests in issues are welcome; we'll revisit contribution guidelines as the project matures.

**Documentation**: [docs.coxswain-labs.dev/coxswain](https://docs.coxswain-labs.dev/coxswain/) — installation guides, configuration reference, architecture overview, and FAQ.

**Roadmap**: see the [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2) for current scope per milestone.

## Getting started

**Prerequisites**: Kubernetes 1.30+, `kubectl` configured against your cluster, `helm` 3.x.

**1. Install the Gateway API CRDs** (once per cluster):

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
```

**2. Install Coxswain:**

```bash
# Helm (recommended)
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system --create-namespace

# Or: kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/latest/download/install.yaml
```

**3. Create a Gateway and route** (swap `echo.example.com` and the backend service to match your app):

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: example-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: echo-route
spec:
  parentRefs:
    - name: example-gateway
  hostnames:
    - echo.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: echo
          port: 80
```

**4. Verify traffic** (replace `<proxy-address>` with your service's external IP or NodePort):

```bash
curl -H "Host: echo.example.com" http://<proxy-address>/
```

For the complete walkthrough — including a test backend, TLS, and Ingress — see [Getting started](https://docs.coxswain-labs.dev/coxswain/latest/getting-started/).

## Authors

Created and maintained by Matteo Giaccone, under the Coxswain Labs banner.

## License

Apache-2.0 — see [LICENSE](LICENSE).
