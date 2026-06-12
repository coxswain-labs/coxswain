# FAQ

## General

### Is Coxswain production-ready?

Pre-1.0 but architecturally stable. The controller/proxy split is shipped (v0.2), Gateway API conformance passes on the Standard HTTP profile, and routing, TLS, and leader-election internals are well-tested under the e2e suites. The operating model is unlikely to change before 1.0; configuration keys may still ratchet on minor version bumps. Run the e2e suites against your cluster shape before adopting in production, and keep an eye on the [Roadmap](https://github.com/orgs/coxswain-labs/projects/2) for the gap between current scope and 1.0.

### Why another Ingress controller?

Coxswain separates the controller (the sole Kubernetes writer) from the proxy (a read-only Pingora data plane). The routing table is built from Kubernetes watch events and exposed to the proxy as an immutable snapshot behind an atomic pointer; TLS certificates are loaded the same way. Proxies have no leader election and scale horizontally with no coordination.

See [Comparison](#comparison) for specific differences against other controllers.

### Does Coxswain support Ingress and Gateway API at the same time?

Yes. Both `Ingress` and `HTTPRoute` objects contribute to the same routing table. You can migrate from Ingress to Gateway API incrementally — both can be active simultaneously.

## Architecture

For deployment-time guidance see the [Deployment models guide](guides/deployment-models.md). For operational issues see [Troubleshooting](guides/troubleshooting.md).

### Why the controller/proxy split?

Embedding status writes in the proxy would force leader election into the data plane: only one replica could write at a time, and horizontal scaling would require electing more leaders. Making the controller the sole Kubernetes writer keeps proxy pods stateless, eliminates inter-replica coordination, and shrinks the proxy's RBAC surface to zero write verbs — a compromised proxy pod cannot write to the API server at all. The read-only invariant is enforced by RBAC, not by convention.

See [Architecture](architecture.md#deployment-models) for the four operating models.

### How does Ingress fit?

Classic `Ingress` resources are always served by the shared proxy pool — `Ingress` has no equivalent of `parametersRef`. Gateway API users can opt a `Gateway` into a dedicated proxy pod via `parametersRef` on the `GatewayClass` (cluster-wide default) or on the `Gateway` itself; the controller provisions and manages that pod.

## Comparison

Architectural differences only — not performance or quality. All projects below run the Gateway API conformance suite and serve production traffic.

### ingress-nginx vs. Coxswain

| | ingress-nginx | Coxswain |
|---|---|---|
| Process model | Go controller + nginx worker processes in the same container | Split controller pod (leader-elected, K8s writes) + horizontally-scalable read-only Pingora proxy pods; Helm renders a controller + shared-proxy by default |
| Config-application model | Controller renders `nginx.conf`; nginx reloads on change | Controller publishes an immutable routing-table snapshot; proxy reads via atomic pointer |
| Gateway API surface | Available via separate [NGINX Gateway Fabric](https://github.com/nginx/nginx-gateway-fabric) project | Same controller manages both; default shared proxy pool serves both |
| Annotation ecosystem | Large catalogue of `nginx.ingress.kubernetes.io/*` annotations | Coxswain reserves `coxswain-labs.dev/*` for future per-resource configuration; currently minimal |

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
