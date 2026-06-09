# Architecture

Coxswain runs as one or more pods, each in one of four `--mode` values. The controller is the sole Kubernetes writer; proxies are read-only data planes that build their routing table directly from Kubernetes watch events and scale horizontally with no coordination.

```mermaid
flowchart LR
    Clients([Clients])
    K8s[Kubernetes\nAPI Server]

    subgraph cs[coxswain-system]
        SP[Shared-proxy pods]
        C[Controller pod]
    end

    subgraph ns[gateway-namespace]
        GP[Per-Gateway proxy pod]
    end

    Clients --> SP & GP
    K8s -->|watch, read-only| SP & GP
    K8s -->|watch| C
    C -->|status writes\nleader only| K8s
```

## Modes

### `--mode=controller`

Watches Ingress, GatewayClass, Gateway, HTTPRoute, and related resources cluster-wide; writes status conditions back to them; provisions per-Gateway proxy `Deployment` and `Service` objects when a Gateway opts into dedicated mode. Leader-elected via a Kubernetes `Lease` in `coxswain-system` — status writes pause for up to one Lease TTL during a leader transition; traffic is unaffected. Scales vertically (one active replica + optional warm standby).

### `--mode=shared-proxy`

Stateless read-only Pingora data plane. Serves every `Ingress` and every `Gateway` not opted into dedicated mode. Scales horizontally with no leader election and no inter-replica coordination.

### `--mode=gateway-proxy`

Read-only proxy scoped to a single Gateway. Provisioned by the controller in the Gateway's namespace (or a namespace specified via `parametersRef`) with namespace-scoped RBAC. Has its own rollout, failure domain, and `/metrics`.

### `--mode=dev`

Single-process all-in-one combining controller and proxy in one binary, for local development and conformance against `kind` / OrbStack.

!!! warning "Never rendered by Helm"
    Dev mode is a contributor convenience; do not run it in production.

## Deployment models

### Default (split shared pool)

The Helm chart default. One controller `Deployment` and one shared-proxy `Deployment` in `coxswain-system`.

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph cs[coxswain-system]
        C[Controller\npod]
        SP[Shared-proxy\npods]
    end

    K8s -->|watch| C
    C -->|status writes| K8s
    K8s -->|watch| SP

    Clients([Clients]) -->|Ingress +\nGateway traffic| SP
```

### Mixed

The default layout plus per-Gateway proxy pods in user namespaces. Workload teams opt a `Gateway` into dedicated mode via `parametersRef`; the controller provisions the per-Gateway pod automatically.

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph cs[coxswain-system]
        C[Controller\npod]
        SP[Shared-proxy\npods]
    end

    subgraph ns[team-namespace]
        GP[Per-Gateway\nproxy pod]
    end

    K8s -->|watch| C
    C -->|status writes| K8s
    C -->|provisions| GP
    K8s -->|watch| SP
    K8s -->|watch| GP

    Clients([Clients]) -->|Ingress +\nother Gateways| SP
    Clients -->|team Gateway\ntraffic| GP
```

### Strict multi-tenant

Every Gateway gets its own proxy pod; the shared-proxy `Deployment` runs at `replicas: 0`. Classic `Ingress` is unavailable in this model.

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph cs[coxswain-system]
        C[Controller\npod]
    end

    subgraph ns_a[team-a-namespace]
        GPA[Per-Gateway\nproxy — team A]
    end

    subgraph ns_b[team-b-namespace]
        GPB[Per-Gateway\nproxy — team B]
    end

    K8s -->|watch| C
    C -->|status writes| K8s
    C -->|provisions| GPA
    C -->|provisions| GPB
    K8s -->|watch| GPA
    K8s -->|watch| GPB

    ClientsA([Team A clients]) --> GPA
    ClientsB([Team B clients]) --> GPB
```

### Ingress-only

For clusters without Gateway API CRDs. The controller detects their absence at startup and skips Gateway API reconciliation; the shared-proxy pool serves all `Ingress` resources.

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph cs[coxswain-system]
        C[Controller\npod]
        SP[Shared-proxy\npods]
    end

    K8s -->|watch\nIngress only| C
    C -->|status writes| K8s
    K8s -->|watch\nIngress only| SP

    Clients([Clients]) -->|Ingress traffic| SP
```

## State transport

Each proxy pod self-watches Kubernetes directly:

- A **shared-proxy** uses a broad cluster-wide filter covering all routing CRs (HTTPRoute, Ingress, Gateway, Service, EndpointSlice).
- A **gateway-proxy** uses a narrow filter scoped to a single Gateway's label and namespace.

There is no xDS server and no IPC between the controller and any proxy — the controller never pushes data, and a controller crash never disrupts proxy traffic. A future `--source=xds` mode could be added behind the same `RoutingSource` trait boundary without touching proxy code.

## RBAC by mode

| Resource | Verb | `controller` | `shared-proxy` | `gateway-proxy` |
|---|---|:-:|:-:|:-:|
| HTTPRoute, Gateway, GatewayClass, Ingress, IngressClass | list, watch, get | ✓ (cluster) | ✓ (cluster) | ✓ (namespace) |
| Service, EndpointSlice | list, watch, get | ✓ (cluster) | ✓ (cluster) | ✓ (namespace) |
| Secret (`kubernetes.io/tls`) | list, watch, get | ✓ (cluster) | ✓ (cluster) | ✓ (namespace) |
| HTTPRoute, Gateway, Ingress `/status` | update, patch | ✓ (cluster) | — | — |
| Deployment, Service | create, update, delete | ✓ (scoped) | — | — |
| Lease | create, update, get | ✓ (`coxswain-system`) | — | — |

## Admin endpoints by mode

| Endpoint | Controller | Shared-proxy | Per-Gateway proxy |
|---|:-:|:-:|:-:|
| `/healthz`, `/readyz` | ✓ | ✓ | ✓ |
| `/metrics` | ✓ (reconcile counts, leader status) | ✓ (traffic, errors) | ✓ (scoped to this Gateway) |
| `/status` | ✓ (subsystems + counters) | ✓ | ✓ |
| `/routes` | — | ✓ | ✓ |
| `/cluster` | ✓ (all Gateways/Ingresses aggregate) | — | — |

## Request path

```mermaid
flowchart LR
    A([TCP connection]) --> B{TLS?}
    B -->|yes| C[SNI cert\nselection]
    B -->|no| D
    C --> D[Route lookup\nhost + path]
    D -->|no match| E([404 / 503])
    D -->|match| F[Pick upstream]
    F --> G([Forward])
```

The routing table is an immutable snapshot behind an atomic pointer; each request reads it with a single atomic load — no locks, no channels. Reconciles build a new snapshot and swap the pointer atomically; the next request sees the new routing, in-flight requests are unaffected.

TLS works the same way: the TLS store is an atomic snapshot rebuilt on every `kubernetes.io/tls` Secret change. New connections use the new certificate; connections in progress complete with the old one.
