# Coxswain

[![E2E & Conformance](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml/badge.svg)](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml)

> **Pre-1.0 — early adopter release.** Coxswain passes the full Gateway API standard conformance suite. Production use is at your own risk; feedback and contributions are welcome.

A Kubernetes Ingress and Gateway API controller written in Rust, backed by [Pingora](https://github.com/cloudflare/pingora) — Cloudflare's battle-tested proxy library.

- `Ingress`, `HTTPRoute`, `GRPCRoute`, `TLSRoute`, and `ListenerSet` in a single proxy fleet
- Routing changes and TLS certificate rotations take effect without restarting the proxy
- Proxies receive compiled routing snapshots over a mandatory-mTLS gRPC stream — zero Kubernetes API credentials on the data plane
- Shared proxy pool for multi-tenant clusters; dedicated per-Gateway proxy for isolation and independent rollout
- Rich Ingress annotation surface: rate limiting, auth (basic + ext_authz), session affinity, circuit breaker, mTLS, mirroring, compression, and more

See [Architecture](https://docs.coxswain-labs.dev/coxswain/latest/architecture/) for the deployment models and RBAC boundary.

**Documentation**: [docs.coxswain-labs.dev/coxswain](https://docs.coxswain-labs.dev/coxswain/) — installation guides, configuration reference, architecture overview, and FAQ.


## Getting started

**Prerequisites**: Kubernetes 1.30+, `kubectl` configured against your cluster, `helm` 3.x.

**1. Install the Gateway API CRDs** (once per cluster):

> **Ingress-only?** Skip this step. The Gateway API CRDs are only required if you plan to use `Gateway` and `HTTPRoute` resources.

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

Wait for the controller to become ready, then confirm the `GatewayClass` is accepted:

```bash
kubectl -n coxswain-system wait pod -l app.kubernetes.io/name=coxswain \
  --for=condition=Ready --timeout=90s
kubectl get gatewayclass coxswain
# NAME       CONTROLLER                              ACCEPTED   AGE
# coxswain   coxswain-labs.dev/gateway-controller    True       ...
```

**3. Deploy a test backend:**

```yaml
# echo-backend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
        - name: echo
          image: gcr.io/k8s-staging-gateway-api/echo-basic:latest
          ports:
            - containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: echo
spec:
  selector:
    app: echo
  ports:
    - port: 80
      targetPort: 3000
```

```bash
kubectl apply -f echo-backend.yaml
```

**4. Route traffic:**

<details>
<summary>Gateway API</summary>

```yaml
# gateway.yaml
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
```

```bash
kubectl apply -f gateway.yaml
kubectl wait gateway/example-gateway --for=condition=Programmed --timeout=30s
```

```yaml
# route.yaml
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

```bash
kubectl apply -f route.yaml
```

</details>

<details>
<summary>Ingress</summary>

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: echo-ingress
spec:
  ingressClassName: coxswain
  rules:
    - host: echo.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: echo
                port:
                  number: 80
```

```bash
kubectl apply -f ingress.yaml
```

</details>

**5. Verify traffic:**

```bash
# Find the proxy service address
kubectl -n coxswain-system get svc coxswain-shared-proxy

# Test via Host header
curl -H "Host: echo.example.com" http://<proxy-address>/
# {"host":"echo.example.com","method":"GET","path":"/", ...}
```

On a local cluster without a LoadBalancer, use port-forward:

```bash
kubectl port-forward -n coxswain-system svc/coxswain-shared-proxy 8080:80 &
curl -H "Host: echo.example.com" http://localhost:8080/
```

**6. Open the operator console:**

The controller serves a built-in web UI on its admin port — cluster health, the live routing table across Gateways and Ingresses, per-pod fleet status, and recent events:

```bash
kubectl port-forward -n coxswain-system svc/coxswain-controller 8082:8082 &
# open http://localhost:8082
```

For the complete walkthrough — including TLS, dedicated mode, and Ingress annotations — see [Getting started](https://docs.coxswain-labs.dev/coxswain/latest/getting-started/).

## Authors

Created and maintained by Matteo Giaccone.

## License

Apache-2.0 — see [LICENSE](LICENSE).
