# Coxswain

[![E2E & Conformance](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml/badge.svg)](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml)

A pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine.

Coxswain runs as a controller pod plus a horizontally-scalable pool of read-only Pingora proxy pods. The controller is the sole Kubernetes writer (status conditions, provisioning); proxy pods build their routing table directly from Kubernetes watch events and serve traffic with no inter-replica coordination. Gateways can be opted into a dedicated proxy pool for stricter tenant isolation — see [Architecture](https://docs.coxswain-labs.dev/coxswain/latest/architecture/).

> **Pre-1.0:** Coxswain is a work in progress — early adopters are welcome to try it out. The API surface and configuration flags may change between minor releases. Bug reports and feature requests are welcome; external contribution guidelines will follow as the project matures.

**Documentation**: [docs.coxswain-labs.dev/coxswain](https://docs.coxswain-labs.dev/coxswain/) — installation guides, configuration reference, architecture overview, and FAQ.


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

**4. Get the proxy address:**

On a cloud cluster, wait until `EXTERNAL-IP` is assigned and capture it:

```bash
kubectl get svc coxswain-shared-proxy -n coxswain-system
PROXY=$(kubectl get svc coxswain-shared-proxy -n coxswain-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

On a local cluster (kind, minikube, OrbStack) where no LoadBalancer is available, use port-forward instead:

```bash
kubectl port-forward -n coxswain-system svc/coxswain-shared-proxy 8080:80 &
PROXY=localhost:8080
```

**5. Verify traffic:**

```bash
curl -H "Host: echo.example.com" http://$PROXY/
```

For the complete walkthrough — including a test backend, TLS, and Ingress — see [Getting started](https://docs.coxswain-labs.dev/coxswain/latest/getting-started/).

## Authors

Created and maintained by Matteo Giaccone, under the Coxswain Labs banner.

## License

Apache-2.0 — see [LICENSE](LICENSE).
