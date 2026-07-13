# Deployment models

Coxswain has two macro deployment models: **Shared** and **Dedicated**. They are not mutually exclusive — a production cluster typically runs a shared proxy pool alongside one or more dedicated proxies for Gateways that need isolation.

## Scope-aware dispatch

Before the two models: both rely on the controller sending each proxy only the routing slice it needs, not the whole cluster's. The controller maintains two snapshot registries for this:

- **`SharedPool`** — the shared routing cells (Ingress table, Gateway table, TLS store, client-cert store, listener health, plus the TLS-passthrough/terminate and TCP/UDP L4 tables). The shared proxy pool subscribes with this scope and receives a snapshot covering all Ingress and non-dedicated Gateway routing.
- **`Gateway { name, namespace }`** — one entry per opted-in Gateway in the `DedicatedRoutingRegistry`. Each dedicated proxy subscribes with its own Gateway identity and receives only that Gateway's slice. Cross-namespace routes (e.g. `from: All`) are resolved controller-side — the controller's cluster-wide reflector sees every namespace's routes and compiles them into the dedicated snapshot before pushing.

A `Subscribe` message with no scope field is treated as `SharedPool`. A scope message with no kind discriminator is rejected as malformed to prevent a zero-value proto from silently escalating to `SharedPool`.

## Shared

One cluster-wide proxy pool serves every `Ingress` and every `Gateway` that has not opted into dedicated mode. This is the Helm chart default: one controller `Deployment` and one shared proxy `Deployment` in `coxswain-system`.

**Shared compute, per-Gateway addressing.** "Shared" describes the proxy *pod* (one set of compute serving everything) — it does not mean Gateways share an address. Each owned `Gateway` still gets its own `Service`/VIP:

- The controller provisions one `Service` per Gateway. That `Service` selects the (single, shared) proxy pod, but maps each of the Gateway's advertised listener ports (e.g. `:443`) to its own distinct internal `targetPort` on that pod.
- The proxy uses the local port a connection arrived on to decide which Gateway's routing/TLS tables apply. That's what keeps two Gateways with overlapping hostnames (both listening on `*.example.com`, say) fully isolated from each other — they're distinguished by port, not just by name.
- Each Gateway still reports its own VIP in `status.addresses`, same as if it had its own dedicated proxy.
- This only relies on standard Kubernetes `Service` `port → targetPort` mapping — no `SO_ORIGINAL_DST`, no conntrack tricks — so it works the same on iptables, IPVS, eBPF, and cloud load balancers alike.

**Per-Gateway infrastructure identity (GEP-1867).** The shared pool's actual compute lives in `coxswain-system`, but each Gateway still needs its own "infrastructure identity" per the Gateway API spec — so the controller also provisions a `ServiceAccount` for each owned Gateway, in that Gateway's *own* namespace. This SA is deliberately inert:

- It carries **zero RBAC** — the proxy pod itself runs under a different ServiceAccount entirely. This one exists purely as an identity object.
- Its job is to be the carrier for `spec.infrastructure.{labels,annotations}` (the GEP-1867 metadata a Gateway can request be applied to its infrastructure) — since in the shared model there's no per-Gateway proxy pod in that namespace for those labels/annotations to land on otherwise.
- It's owner-referenced to the Gateway, so deleting the Gateway garbage-collects it automatically; moving a Gateway into dedicated mode prunes it explicitly instead.
- Infrastructure annotations from this object also propagate onto the Gateway's VIP `Service` — this is how, for example, a cloud load-balancer annotation set on the Gateway reaches the actual `LoadBalancer` Service.

The fixed shared `80`/`443` listeners on the proxy pod are **Ingress-only**: Ingresses legitimately share one address because they merge by host/path and have no per-Ingress isolation. The cost of per-Gateway addressing is **one load-balancer IP per Gateway** in cloud environments — the "one IP for everything" property is intentionally given up; only the proxy compute stays shared. The shared-proxy selector the controller stamps on each VIP `Service` is supplied by the Helm chart via `--shared-proxy-selector` (the chart knows the release name; the controller cannot derive `app.kubernetes.io/instance` itself).

The VIP `Service` type is set by `proxy.shared.vipServiceType` (default `LoadBalancer`), independent of the shared-proxy `Service` itself. `LoadBalancer` gives each Gateway an external address and works on cloud LBs and MetalLB, which assign a distinct IP per `Service` and route `IP:port` independently. It does **not** work on host-port-binding LBs such as k3s/OrbStack `klipper-lb`, where multiple `LoadBalancer` Services advertising the same port (e.g. `:443`) collide on the host and stay `<pending>` — set `vipServiceType: ClusterIP` there to give each Gateway a stable in-cluster VIP (typically fronted by an external ingress/LB). `NodePort` is rejected: it cannot preserve the advertised listener port.

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph cs[coxswain-system]
        C[Controller]
        SP["Proxy pool (shared)"]
    end

    subgraph n1[ns-1]
        A1(app-1)
    end

    subgraph n2[ns-2]
        A2(app-2)
    end

    K8s -->|watch| C
    C -->|status writes| K8s
    C -->|gRPC discovery| SP

    Clients([Clients]) -->|Ingress +\nGateway traffic| SP
    SP --> A1 & A2
```

**Ingress-only (runtime variant):** when Gateway API CRDs are absent at startup, the controller detects their absence, skips Gateway API reconciliation, and the shared proxy pool serves all `Ingress` resources.

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph cs[coxswain-system]
        C[Controller]
        SP["Proxy pool (shared)"]
    end

    subgraph n1[ns-1]
        A1(app-1)
    end

    subgraph n2[ns-2]
        A2(app-2)
    end

    K8s -->|watch\nIngress only| C
    C -->|status writes| K8s
    C -->|gRPC discovery| SP

    Clients([Clients]) -->|Ingress traffic| SP
    SP --> A1 & A2
```

## Dedicated (per Gateway)

When a `Gateway` carries a `parametersRef` pointing at a `CoxswainGatewayParameters` object (either on the Gateway directly or inherited from its `GatewayClass`'s `spec.parametersRef`), the controller provisions a dedicated proxy — its own `Deployment`, `Service`, and `ServiceAccount` — in the Gateway's namespace. Traffic for that Gateway is served exclusively by its dedicated proxy pool; the shared proxy pool continues to serve everything else.

A cluster running some dedicated Gateways alongside the shared pool is the typical mixed arrangement:

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph cs[coxswain-system]
        C[Controller]
        SP["Proxy pool (shared)"]
    end

    subgraph ns[gw-namespace-1]
        GP["Proxy pool (dedicated)"]
        A1(app-1)
    end

    subgraph n1[ns-1]
        A2(app-2)
    end

    subgraph n2[ns-2]
        A3(app-3)
    end

    K8s -->|watch| C
    C -->|status writes| K8s
    C -->|provisions| GP
    C -->|gRPC discovery| SP & GP

    Clients([Clients]) -->|Ingress +\nother Gateways| SP
    Clients -->|gw-namespace-1 Gateway\ntraffic| GP
    SP --> A2 & A3
    GP --> A1
```

When every Gateway opts into dedicated mode and the shared proxy `Deployment` is scaled to `replicas: 0`, each team's Gateway gets a fully isolated data plane. Classic `Ingress` is unavailable in this arrangement.

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph cs[coxswain-system]
        C[Controller]
    end

    subgraph ns_a[gw-namespace-1]
        GPA["Proxy pool (dedicated)"]
        A1(app-1)
    end

    subgraph ns_b[gw-namespace-2]
        GPB["Proxy pool (dedicated)"]
        A2(app-2)
    end

    K8s -->|watch| C
    C -->|status writes| K8s
    C -->|provisions + gRPC discovery| GPA & GPB

    ClientsA([Clients]) --> GPA
    ClientsB([Clients]) --> GPB
    GPA --> A1
    GPB --> A2
```

See [Dedicated proxy pools](../guides/dedicated-mode.md) for the operator-facing walkthrough — opting a Gateway in, tunable fields, and RBAC.
