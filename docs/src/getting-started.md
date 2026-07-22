# Getting started

This guide installs Coxswain into an existing cluster, deploys a test backend, routes traffic using either Gateway API or classic Ingress, and verifies the flow end-to-end. It takes about 10 minutes.

## Prerequisites

- Kubernetes 1.30 or later
- `kubectl` configured against your target cluster
- `helm` 3.x installed

## Step 1 — Install the Gateway API CRDs

> **Ingress-only?** Skip this step. The Gateway API CRDs are only required if you plan to use `Gateway` and `HTTPRoute` resources in Step 4.

The Gateway API CRDs are not bundled with Kubernetes and must be installed once per cluster:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
```

## Step 2 — Install Coxswain

Install with Helm — the recommended path, with values-driven configuration and easy upgrades. See [Installation](installation/index.md) for the Kustomize and raw-manifest alternatives.

```bash
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system --create-namespace
```

!!! note "Local clusters (kind, k3s, OrbStack)"
    These have no cloud load balancer, so each Gateway's per-Gateway VIP `Service` can't be assigned an external address and the `Gateway` stays `Programmed=False`. Add `--set proxy.shared.vipServiceType=ClusterIP` to the install so VIPs get in-cluster addresses instead; reach them (and the shared-proxy Ingress endpoint) with `kubectl port-forward` — see Step 5.

Wait for the controller to become ready:

```bash
kubectl -n coxswain-system wait pod -l app.kubernetes.io/name=coxswain \
  --for=condition=Ready --timeout=90s
```

Verify the `GatewayClass` is accepted:

```bash
kubectl get gatewayclass coxswain
# NAME       CONTROLLER                              ACCEPTED   AGE
# coxswain   coxswain-labs.dev/gateway-controller    True       ...
```

## Step 3 — Deploy a test backend

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

## Step 4 — Route traffic

=== "Gateway API"

    Create a `Gateway` and an `HTTPRoute` that forwards traffic to the echo backend.

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
    kubectl get httproute echo-route
    # NAME         HOSTNAMES              AGE
    # echo-route   ["echo.example.com"]   5s
    ```

=== "Ingress"

    Create an `Ingress` using the `coxswain` class that Coxswain registers at install time.

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
    kubectl get ingress echo-ingress
    # NAME           CLASS      HOSTS              ADDRESS   PORTS   AGE
    # echo-ingress   coxswain   echo.example.com             80      5s
    ```

## Step 5 — Verify traffic

Reach the backend by the address of whichever entry point you configured in Step 4.

=== "Gateway API"

    Each `Gateway` gets its own address (Coxswain provisions a per-Gateway VIP `Service` in `coxswain-system`). Read the address from the Gateway's status:

    ```bash
    kubectl get gateway example-gateway
    # NAME              CLASS      ADDRESS        PROGRAMMED   AGE
    # example-gateway   coxswain   203.0.113.10   True         30s

    curl -H "Host: echo.example.com" http://203.0.113.10/
    # {"host":"echo.example.com","method":"GET","path":"/", ...}
    ```

    On a local cluster without an external load balancer, port-forward the Gateway's VIP `Service` instead (find it with `kubectl -n coxswain-system get svc`), then `curl` `localhost` with the same `Host` header.

=== "Ingress"

    Ingress traffic is served on the shared proxy's fixed `80`/`443` listeners, exposed by the `coxswain-shared-proxy` `Service` (`LoadBalancer` by default):

    ```bash
    kubectl -n coxswain-system get svc coxswain-shared-proxy

    curl -H "Host: echo.example.com" http://<proxy-address>/
    # {"host":"echo.example.com","method":"GET","path":"/", ...}
    ```

    On a local cluster without an external load balancer, `kubectl -n coxswain-system port-forward svc/coxswain-shared-proxy 8080:80` and `curl` `http://localhost:8080/` with the same `Host` header.

## Step 6 — Open the operator console

The controller exposes a built-in web UI on its admin port. Forward it locally:

```bash
kubectl -n coxswain-system port-forward svc/coxswain-controller 8082:8082
```

Then open `http://localhost:8082` in your browser. The console shows cluster health, the live routing table across Gateways and Ingresses, per-pod fleet status, and recent events.

## What's next?

- **Gateway API** — see the [Gateway API guide](gateway-api/index.md) for the full `HTTPRoute` feature surface, TLS listeners, and cross-namespace routing.
- **Ingress** — see the [Ingress guide](ingress/index.md) to use classic `Ingress` resources.
- **TLS** — see the [TLS guide](operations/tls.md) to add HTTPS with cert-manager or a manual Secret.
- **Production** — see [Running in production](operations/running-in-production.md) before going live.
- **Troubleshooting** — if something isn't working, see the [Troubleshooting guide](operations/troubleshooting.md).
