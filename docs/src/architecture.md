# Architecture

Coxswain runs as one or more pods, each invoked with a `serve <role>` subcommand. The controller is the sole Kubernetes writer; proxies are read-only data planes that build their routing table directly from Kubernetes watch events and scale horizontally with no coordination.

```mermaid
flowchart LR
    Clients([Clients])
    K8s[Kubernetes\nAPI Server]

    subgraph cs[coxswain-system]
        SP["Proxy pool (shared)"]
        C[Controller]
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

    Clients --> SP & GP
    K8s -->|watch, read-only| SP & GP
    K8s -->|watch| C
    C -->|status writes\nleader only| K8s
    SP --> A2 & A3
    GP --> A1
    GP -.->|cross-namespace\nvia ReferenceGrant| A2
```

## Roles

### `serve controller`

Watches Ingress, GatewayClass, Gateway, HTTPRoute, and related resources cluster-wide; writes status conditions back to them; provisions per-Gateway proxy `Deployment`, `Service`, and `ServiceAccount` objects when a Gateway opts into dedicated mode. Leader-elected via a Kubernetes `Lease` in `coxswain-system` — status writes pause for up to one Lease TTL during a leader transition; traffic is unaffected. Scales vertically (one active replica + optional warm standby).

The provisioning operator runs as a kube-rs `Controller` alongside the status writer in the same pod. Its reconcile loop resolves each Gateway's effective `CoxswainGatewayParameters` (per-field overlay: Gateway's `parametersRef` wins per-field, GatewayClass's fills the rest; `podTemplate` strategic-merges across both layers) and renders the desired `Deployment` / `Service` / `ServiceAccount`. The `podTemplate` escape hatch is merged onto the rendered Deployment with `kubectl apply` strategic-merge semantics — `containers` merges by `name`, `tolerations` by `(key, operator)`, container-level `env` by `name`, and so on — so sidecar injection and env overlays behave the way operators expect from native K8s tooling.

The same reconcile loop also manages per-namespace `RoleBinding`s for the proxy's `ServiceAccount`: one binding per namespace the Gateway's HTTPRoutes route a backend into (gated by `ReferenceGrant` for cross-namespace refs), each binding the SA to the static `coxswain-gateway-proxy-reader` `ClusterRole`. A finalizer `gateway.coxswain-labs.dev/dedicated-cleanup` on every dedicated Gateway guarantees cross-namespace bindings are removed before K8s finalizes the Gateway deletion (cross-namespace owner references aren't supported by K8s GC for namespaced resources, so cleanup is reconcile-driven via a `managed-by` label selector).

### `serve proxy --shared`

Stateless read-only Pingora data plane. Serves every `Ingress` and every `Gateway` not opted into dedicated mode. Scales horizontally with no leader election and no inter-replica coordination.

### `serve proxy --dedicated`

Read-only proxy scoped to a single Gateway (identified by `--gateway-name` and `--gateway-namespace`). Provisioned by the controller in the Gateway's own namespace. Has its own rollout, failure domain, and `/metrics`.

The dedicated proxy runs with **per-namespace narrowed RBAC**: the controller renders `--proxy-watch-namespaces=<ns1>,<ns2>,...` into the container args, and the proxy spawns one reflector per (resource, namespace) pair scoped to exactly the namespaces the controller has provisioned `RoleBinding`s for. The binding set and the watch set are derived from the same desired-namespace computation in the controller, so they can't drift. The `GatewayClass` watch is dropped on this path — the controller is the authority on "this Gateway is dedicated and mine".

When any listener declares `allowedRoutes.namespaces.from: All` or `from: Selector`, the controller automatically grants the dedicated proxy cluster-wide `HTTPRoute` reads (and cluster-wide `Namespace` reads for `from: Selector`) by creating a `ClusterRoleBinding` to the matching static `ClusterRole`. No operator opt-in field is needed — the Gateway spec is the single source of truth. The controller passes `--allow-cluster-wide-route-read` / `--allow-cluster-wide-namespace-read` into the proxy's container args and the proxy spawns a single cluster-wide `HTTPRoute` reflector instead of the per-namespace one, making cross-namespace routes visible to the routing table builder.

### `serve dev`

Hidden single-process all-in-one combining controller and proxy in one binary, for local development and conformance against `kind` / OrbStack.

!!! warning "Never rendered by Helm"
    Dev mode is a contributor convenience; do not run it in production.

## Deployment models

Coxswain has two macro deployment models: **Shared** and **Dedicated**. They are not mutually exclusive — a production cluster typically runs a shared proxy pool alongside one or more dedicated proxies for Gateways that need isolation.

### Shared

One cluster-wide proxy pool serves every `Ingress` and every `Gateway` that has not opted into dedicated mode. This is the Helm chart default: one controller `Deployment` and one shared proxy `Deployment` in `coxswain-system`.

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
    K8s -->|watch| SP

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
    K8s -->|watch\nIngress only| SP

    Clients([Clients]) -->|Ingress traffic| SP
    SP --> A1 & A2
```

### Dedicated (per Gateway)

When a `Gateway` carries a `parametersRef` pointing at a `CoxswainGatewayParameters` object (either on the Gateway directly or inherited from its `GatewayClass`), the controller provisions a dedicated proxy — its own `Deployment`, `Service`, and `ServiceAccount` — in the Gateway's namespace. Traffic for that Gateway is served exclusively by its dedicated proxy pool; the shared proxy pool continues to serve everything else.

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
    K8s -->|watch| SP
    K8s -->|watch| GP

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
    C -->|provisions| GPA
    C -->|provisions| GPB
    K8s -->|watch| GPA
    K8s -->|watch| GPB

    ClientsA([Clients]) --> GPA
    ClientsB([Clients]) --> GPB
    GPA --> A1
    GPB --> A2
```

## State transport

Each proxy pod self-watches Kubernetes directly:

- A **shared proxy** uses a broad cluster-wide filter covering all routing CRs (HTTPRoute, Ingress, Gateway, Service, EndpointSlice).
- A **dedicated proxy** (`--dedicated`) narrows its routing-table build to a single named Gateway; cross-namespace backends and TLS Secrets resolve via `ReferenceGrant` as usual. It also narrows its **watches** to the namespaces the controller has rendered into `--proxy-watch-namespaces`, matching the per-namespace `RoleBinding`s the same reconcile cycle provisioned for the proxy SA.

There is no xDS server and no IPC between the controller and any proxy — the controller never pushes data, and a controller crash never disrupts proxy traffic. This self-watch model may be revisited in the future for scenarios such as very large clusters, where having every proxy replica watch the full set of resources independently becomes expensive.

## RBAC by mode

| Resource | Verb | `controller` | `shared-proxy` | `dedicated-proxy` |
|---|---|:-:|:-:|:-:|
| HTTPRoute, Gateway, ReferenceGrant, BackendTLSPolicy | list, watch, get | ✓ (cluster) | ✓ (cluster) | ✓ (per-namespace, via `RoleBinding`) |
| GatewayClass, Ingress, IngressClass | list, watch, get | ✓ (cluster) | ✓ (cluster) | — (dropped — Gateway carries its class name) |
| Service, EndpointSlice | list, watch, get | ✓ (cluster) | ✓ (cluster) | ✓ (per-namespace) |
| Secret (`kubernetes.io/tls`), ConfigMap | list, watch, get | ✓ (cluster) | ✓ (cluster) | ✓ (per-namespace) |
| HTTPRoute, Gateway, Ingress `/status` | update, patch | ✓ (cluster) | — | — |
| Gateway | patch | ✓ (cluster — finalizers only) | — | — |
| Deployment, Service, ServiceAccount, RoleBinding | create, update, delete | ✓ (cluster) | — | — |
| Lease | get, create, patch | ✓ (`coxswain-system`) | — | — |

The dedicated-proxy permissions come from a single static `ClusterRole` `coxswain-gateway-proxy-reader` (shipped by the Helm chart and `deploy/manifests/dedicated-proxy-clusterrole.yaml`) bound via per-namespace `RoleBinding`s reconciled by the controller. A compromised dedicated-proxy `ServiceAccount` holds reads only in the namespaces its Gateway has routes into — not in any other namespace, and zero write verbs anywhere.

## Admin endpoints by mode

| Endpoint | Controller | Shared-proxy | Dedicated-proxy |
|---|:-:|:-:|:-:|
| `/healthz`, `/readyz` | ✓ | ✓ | ✓ |
| `/metrics` | ✓ (reconcile counts, leader status) | ✓ (traffic, errors) | ✓ (scoped to this Gateway) |
| `/api/v1/health` | ✓ (subsystem detail, version, leader) | ✓ | ✓ |
| `/routes` | — | ✓ | ✓ |
| `GET /` (operator UI) + `/api/v1/{fleet,routing}/*` | ✓ (cluster-wide aggregate + summaries) | — | — |
| `/api/v1/{problems,events,manifests/*,pods/*/logs}` | ✓ | — | — |

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
