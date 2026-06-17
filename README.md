# Coxswain

[![E2E & Conformance](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml/badge.svg)](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml)

> **Pre-1.0 — early adopter release.** Coxswain's core proxy is functional and passes the full Gateway API standard conformance suite. The per-Ingress annotation surface is under active development (v0.3). Production use is at your own risk; feedback and contributions are welcome.

A Kubernetes Ingress and Gateway API controller written in Rust, backed by [Pingora](https://github.com/cloudflare/pingora) — Cloudflare's battle-tested proxy library.

- Bridges classic `Ingress` and Gateway API `HTTPRoute` in a single proxy fleet
- Routing changes and TLS certificate rotations take effect without restarting the proxy
- Controller/proxy split with a strict RBAC boundary — proxy pods hold zero write permissions

See [Architecture](https://docs.coxswain-labs.dev/coxswain/latest/architecture/) for the deployment models (shared and dedicated proxy pools) and the RBAC boundary.

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

Wait for the controller, then confirm the `GatewayClass` is accepted:

```bash
kubectl -n coxswain-system wait pod -l app.kubernetes.io/name=coxswain \
  --for=condition=Ready --timeout=90s
kubectl get gatewayclass coxswain
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

**6. Open the operator console:**

The controller serves a built-in web UI on its admin port — cluster health, the live routing table across Gateways and Ingresses, per-pod fleet status, and recent events:

```bash
kubectl port-forward -n coxswain-system svc/coxswain-controller 8082:8082 &
# open http://localhost:8082
```

For the complete walkthrough — including a test backend, TLS, and Ingress — see [Getting started](https://docs.coxswain-labs.dev/coxswain/latest/getting-started/).

## Authors

Created and maintained by Matteo Giaccone.

## License

Apache-2.0 — see [LICENSE](LICENSE).
