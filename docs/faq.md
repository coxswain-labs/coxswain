# FAQ

## General

### Why another Ingress controller?

Several popular controllers (nginx Ingress, HAProxy Ingress, Envoy Gateway) are a Go control plane wrapping a C/C++ proxy. Configuration changes typically require a reload or restart — even nginx's "graceful reload" creates a new worker process and drains the old one, which briefly increases memory usage and can drop connections under high load. Traefik is a native Go proxy and avoids that particular reload problem, but it still mutates its routing state rather than swapping an immutable snapshot.

Coxswain's routing table is an immutable snapshot swapped atomically on every change. There is no reload, no worker restart, and no brief connection drop.

It is written in Rust for memory safety without garbage collection — no GC pauses on the request path.

### Is Coxswain production-ready?

Not yet. It is in active development toward a v0.1 release. The core routing, TLS, and leader election logic is solid, but some advanced features are missing and the API surface may change. See the [Roadmap](https://github.com/orgs/coxswain-labs/projects/2).

### Does Coxswain support Ingress and Gateway API at the same time?

Yes. Both `Ingress` and `HTTPRoute` objects contribute to the same routing table. You can migrate from Ingress to Gateway API incrementally — both can be active simultaneously.

## Comparison

### nginx Ingress vs. Coxswain

| | nginx Ingress | Coxswain |
|---|---|---|
| Hot reload | nginx master reloads config (brief worker restart) | Atomic swap, no reload |
| Multi-replica | No — each replica has independent nginx config | Yes — each replica independently builds the same routing table from watch events; leader election only coordinates status writes |
| Gateway API | Beta/experimental support | First-class, conformance-tested |
| Language | Go controller + C nginx | Pure Rust |
| Annotations | Rich `nginx.ingress.kubernetes.io/*` ecosystem | v0.1: minimal (planned for future releases) |

### Traefik vs. Coxswain

| | Traefik | Coxswain |
|---|---|---|
| Hot reload | Dynamic config with polling or watch | Atomic swap, no polling |
| Proxy engine | Go stdlib / fasthttp | Pingora (Cloudflare's Rust proxy) |
| Gateway API | Supported via IngressRoute CRDs | Standard Gateway API (conformance-tested) |
| Leader election | No built-in multi-replica coordination | Lease-based, all replicas serve traffic |

### Envoy Gateway vs. Coxswain

| | Envoy Gateway | Coxswain |
|---|---|---|
| Architecture | xDS control plane + Envoy data plane (2 processes) | Single binary: controller + proxy in one process |
| Memory footprint | Higher (Envoy + control plane overhead) | Lower (Rust, no GC) |
| Gateway API | Full conformance, including alpha features | Standard channel conformance-tested |
| Complexity | High — designed for platform teams | Lower — designed for operators |
