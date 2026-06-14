# FAQ

## General

### Is Coxswain production-ready?

Not yet. Coxswain is pre-1.0: the API surface and configuration flags may change between minor releases. The core architecture — a leader-elected controller pod writing status, backed by one or more read-only Pingora proxy pods — is stable and well-tested.

### Why another Ingress controller?

Coxswain separates the controller (the sole Kubernetes writer) from the proxy (a read-only Pingora data plane). The routing table is built from Kubernetes watch events and exposed to the proxy as an immutable snapshot behind an atomic pointer; TLS certificates are loaded the same way. Proxies have no leader election and scale horizontally with no coordination.

See [Comparison](#comparison) for specific differences against other controllers.

### Does Coxswain support Ingress and Gateway API at the same time?

Yes. Both `Ingress` and `HTTPRoute` objects contribute to the same routing table. You can migrate from Ingress to Gateway API incrementally — both can be active simultaneously.

## Architecture

### Why the controller/proxy split?

Embedding status writes in the proxy would force leader election into the data plane: only one replica could write at a time, and horizontal scaling would require electing more leaders. Making the controller the sole Kubernetes writer keeps proxy pods stateless, eliminates inter-replica coordination, and shrinks the proxy's RBAC surface to zero write verbs — a compromised proxy pod cannot write to the API server at all. The read-only invariant is enforced by RBAC, not by convention.

See [Architecture](architecture.md#deployment-models) for the two macro deployment models (Shared and Dedicated).

### How does Ingress fit?

Classic `Ingress` resources are always served by the shared proxy pool — `Ingress` has no equivalent of `parametersRef`. Gateway API users can opt a `Gateway` into a dedicated proxy (per Gateway) via `parametersRef` on the `GatewayClass` (cluster-wide default) or on the `Gateway` itself; the controller provisions and manages that dedicated proxy automatically. See [Dedicated-mode Gateways](guides/dedicated-mode.md) for the full walkthrough.

## Comparison

Architectural differences only — not performance or quality. All projects below run the Gateway API conformance suite and serve production traffic.

### ingress-nginx vs. Coxswain

| | ingress-nginx | Coxswain |
|---|---|---|
| Process model | Go controller + nginx worker processes in the same container | Split controller pod (leader-elected, K8s writes) + horizontally-scalable read-only Pingora proxy pods; Helm renders a controller + shared proxy by default |
| Config-application model | Controller renders `nginx.conf`; nginx reloads on change | Controller publishes an immutable routing-table snapshot; proxy reads via atomic pointer |
| Gateway API surface | Available via separate [NGINX Gateway Fabric](https://github.com/nginx/nginx-gateway-fabric) project | Same controller manages both; default shared proxy pool serves both |
| Annotation ecosystem | Large catalogue of `nginx.ingress.kubernetes.io/*` annotations | Coxswain reserves `gateway.coxswain-labs.dev/*` for future per-resource configuration; currently minimal |

### Traefik vs. Coxswain

| | Traefik | Coxswain |
|---|---|---|
| Proxy engine | Go `net/http` | Pingora (Rust, Cloudflare) |
| Configuration providers | Pluggable providers (Kubernetes, Consul, file, …) | Kubernetes only |
| Multi-replica state | Replicas coordinate shared state (e.g. ACME) via Traefik Hub or external KV | Only the controller pod elects a leader (Kubernetes `Lease`) for status writes; proxy pods are stateless and need no coordination |
| Gateway API surface | Supported alongside Traefik's native `IngressRoute` CRDs | Supported alongside the Kubernetes `Ingress` resource; no Coxswain-specific CRDs |

### Envoy Gateway vs. Coxswain

| | Envoy Gateway | Coxswain |
|---|---|---|
| Process model | Control-plane Pod translates Gateway API to xDS; Envoy Pods consume xDS | Split controller + read-only Pingora proxy pods; each proxy self-watches Kubernetes rather than consuming xDS |
| Data-plane configuration | xDS over gRPC | In-process atomic pointer swap |
| Proxy engine | Envoy (C++) | Pingora (Rust) |
| Gateway API channel | Standard + experimental | Standard only |

## Troubleshooting

See [Troubleshooting](guides/troubleshooting.md) for step-by-step diagnostic commands. Common dedicated-mode questions:

- **Dedicated proxy pod not starting** — see [Dedicated proxy pod never becomes Ready](guides/troubleshooting.md#dedicated-proxy-pod-never-becomes-ready).
- **`forbidden` errors in proxy logs** — see [RBAC denials in dedicated proxy logs](guides/troubleshooting.md#rbac-denials-in-dedicated-proxy-logs).
- **Provisioned resources left behind after Gateway deletion** — see [Provisioned resources not garbage-collected after Gateway deletion](guides/troubleshooting.md#provisioned-resources-not-garbage-collected-after-gateway-deletion).
- **Controller not reconciling Gateway API resources** — see [Controller stuck in Ingress-only mode](guides/troubleshooting.md#controller-stuck-in-ingress-only-mode).
