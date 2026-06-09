# FAQ

## General

### Why another Ingress controller?

Coxswain is a single Rust binary that combines the controller and the proxy in one process. The routing table is built from Kubernetes watch events and exposed to the proxy as an immutable snapshot behind an atomic pointer; updates swap the pointer rather than mutating in place. TLS certificates from `kubernetes.io/tls` Secrets are loaded the same way. The proxy is built on [Pingora](https://github.com/cloudflare/pingora). Multi-replica deployments coordinate only on which replica writes status conditions back to the API server, via a Kubernetes `Lease`; every replica serves traffic at all times.

That design is a particular set of trade-offs — single-binary deployment, no config-file rendering layer, no separate xDS pipeline — and it is not strictly better than every alternative. The comparison tables below describe specific architectural differences against other controllers; pick whichever fits your operational model.

### Is Coxswain production-ready?

Not yet. It is in active development toward a v0.1 release. The core routing, TLS, and leader election logic is solid, but some advanced features are missing and the API surface may change. See the [Roadmap](https://github.com/orgs/coxswain-labs/projects/2).

### Does Coxswain support Ingress and Gateway API at the same time?

Yes. Both `Ingress` and `HTTPRoute` objects contribute to the same routing table. You can migrate from Ingress to Gateway API incrementally — both can be active simultaneously.

## Comparison

These tables compare verifiable architectural choices, not performance or quality. The reference projects all run the Gateway API conformance suite, all support multi-replica deployments, and all serve traffic in production at many organisations. The differences are in how each is built, not in whether each works.

### ingress-nginx vs. Coxswain

| | ingress-nginx | Coxswain |
|---|---|---|
| Process model | Go controller + nginx worker processes in the same container | Single Rust binary; controller and proxy in one process |
| Config-application model | Controller renders `nginx.conf`; nginx reloads on change | Controller publishes an immutable routing-table snapshot; proxy reads via atomic pointer |
| Gateway API surface | Available via separate [NGINX Gateway Fabric](https://github.com/nginx/nginx-gateway-fabric) project | Built into the same binary as Ingress support |
| Annotation ecosystem | Large catalogue of `nginx.ingress.kubernetes.io/*` annotations | Coxswain reserves `coxswain-labs.dev/*` for future per-resource configuration; currently minimal |

### Traefik vs. Coxswain

| | Traefik | Coxswain |
|---|---|---|
| Proxy engine | Go `net/http` | Pingora (Rust, Cloudflare) |
| Configuration providers | Pluggable providers (Kubernetes, Consul, file, …) | Kubernetes only |
| Multi-replica state | Replicas coordinate shared state (e.g. ACME) via Traefik Hub or external KV | Replicas coordinate only status-write leadership via a Kubernetes `Lease`; routing state is independent per replica |
| Gateway API surface | Supported alongside Traefik's native `IngressRoute` CRDs | Supported alongside the Kubernetes `Ingress` resource; no Coxswain-specific CRDs |

### Envoy Gateway vs. Coxswain

| | Envoy Gateway | Coxswain |
|---|---|---|
| Process model | Control-plane Pod translates Gateway API to xDS; Envoy Pods consume xDS | Single Pod containing both controller and proxy |
| Data-plane configuration | xDS over gRPC | In-process atomic pointer swap |
| Proxy engine | Envoy (C++) | Pingora (Rust) |
| Gateway API channel | Standard + experimental | Standard only |
