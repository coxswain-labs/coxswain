# Architecture

Coxswain runs as one or more pods, each invoked with a `serve <role>` subcommand. The controller is the sole Kubernetes reader and writer; proxies are read-only data planes that receive compiled routing snapshots from the controller over a mandatory-mTLS gRPC discovery stream and hold zero Kubernetes API credentials.

```mermaid
flowchart LR
    Clients([Clients])
    K8s[Kubernetes\nAPI Server]

    subgraph cs[coxswain-system]
        C[Controller\nreflector · discovery server\nidentity server]
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

    Clients --> SP & GP
    K8s -->|watch| C
    C -->|status writes\nleader only| K8s
    C -->|gRPC discovery\nmTLS| SP & GP
    SP --> A2 & A3
    GP --> A1
    GP -.->|cross-namespace\nvia ReferenceGrant| A2
```

## Roles

### `serve controller`

Watches Ingress, GatewayClass, Gateway, HTTPRoute, and related resources cluster-wide; writes status conditions back to them; provisions dedicated proxy (per Gateway) `Deployment`, `Service`, and `ServiceAccount` objects when a Gateway opts into dedicated mode. Leader-elected via a Kubernetes `Lease` in `coxswain-system` — status writes pause for up to one Lease TTL during a leader transition; traffic is unaffected. Scales vertically (one active replica + optional warm standby).

The controller also runs two gRPC listeners that proxies connect to:

- **Discovery (Stream) listener** (port 50051, mTLS mandatory, **leader-only**) — compiles routing snapshots from K8s resources and pushes them to subscribed proxies. Each snapshot is scoped to the subscriber's declared `Scope` — see [Scope-aware dispatch](architecture/deployment-models.md#scope-aware-dispatch).

    Only the lease holder serves streams. Mechanically: the leader labels its own pod (`discovery.coxswain-labs.dev/leader: "true"`), so the `coxswain-controller-discovery` Service routes dials to it; a standby replica that gets dialled anyway (during a leader transition) rejects the stream with `FAILED_PRECONDITION`, and the proxy fast-retries until it lands on the real leader.

    Why single-replica: it gives every proxy one consistent watch position (no two replicas can disagree about routing state), and it puts each proxy's bound-listener readiness report in the same process that writes `Gateway` status — so `Programmed=True` is a genuine claim that the data plane is actually bound and serving, not just that the controller compiled a snapshot.

- **Bootstrap (Identity) listener** (port 50052, server-auth-only TLS, **every replica**, via the separate `coxswain-controller-discovery-bootstrap` Service) — acts as a certificate authority for new proxies. A fresh proxy presents its ServiceAccount token and a CSR; the controller validates the token via `TokenReview`, signs a short-lived SPIFFE SVID, and returns it. Unlike the Stream listener, every replica can do this (not just the leader) because issuance needs no shared state beyond the one CA Secret all replicas already read — so it keeps working through leader churn. See [Control-plane security](guides/control-plane-security.md).

On a leader change, routing *updates* stall for the brief reconnect window (bounded by the Lease TTL) while every proxy keeps serving its last-good snapshot — no data-plane outage. Status writes race nothing: a demoted leader re-checks its leadership immediately before every status patch, narrowing the residual last-write-wins window to a single request round-trip (accepted; both replicas compute identical status from warm caches).

The provisioning operator reconciles off the controller's single watch fabric (#574): rather than running its own kube-rs `Controller` and Kubernetes client, its reconcile is driven by the same unified status worker that writes Gateway API status, so a dedicated Gateway and its shared-pool siblings share one authoritative set of watches. Its reconcile resolves each Gateway's effective `CoxswainGatewayParameters` (per-field overlay: Gateway's `parametersRef` wins per-field, GatewayClass's fills the rest; `podTemplate` strategic-merges across both layers) and renders the desired `Deployment` / `Service` / `ServiceAccount`. The `podTemplate` escape hatch is merged onto the rendered Deployment with `kubectl apply` strategic-merge semantics — `containers` merges by `name`, `tolerations` by `(key, operator)`, container-level `env` by `name`, and so on — so sidecar injection and env overlays behave the way operators expect from native K8s tooling.

The controller also watches `IngressClass` and its associated `CoxswainIngressClassParameters` objects (the `IngressClass.spec.parameters` reference target). These carry class-level defaults for Ingress routes: `spec.defaultAnnotations` (per-key annotation defaults that per-Ingress annotations can override) and `spec.accessLog` (per-class access-log suppression).

### `serve proxy --shared`

Read-only Pingora data plane. Subscribes to the controller discovery stream with `Scope::SharedPool` and receives a compiled snapshot covering every `Ingress` and every `Gateway` not opted into dedicated mode. Scales horizontally with no leader election and no inter-replica coordination.

Required args: `--discovery-endpoint` (comma-separated controller Stream endpoint(s), `https://` for mTLS). On first start the proxy bootstraps an SVID via `--discovery-bootstrap-endpoint` and then opens the mTLS stream. Routing tables are never cleared across reconnects.

The shared proxy holds **zero Kubernetes API credentials**. Its ServiceAccount exists only as a pod identity; the only token mounted is an audience-scoped projected SA token (`coxswain-discovery` audience) used exclusively for SVID bootstrap. No ClusterRole or RoleBinding is bound to it.

### `serve proxy --dedicated`

Read-only proxy scoped to a single Gateway (identified by `--dedicated --gateway-name=NAME --gateway-namespace=NS`). Provisioned by the controller in the Gateway's own namespace. Has its own rollout, failure domain, and `/metrics`.

The dedicated proxy subscribes with `Scope::Gateway { name, namespace }` and receives only its Gateway's routing snapshot. The controller stamps the expected proxy ServiceAccount name (`{gateway-name}-{gatewayclass-name}`, per GEP-1762) into the Gateway's registry entry at reconcile time. When the subscription arrives, the discovery server verifies that the peer's mTLS SVID matches that expected SA before sending any snapshot — a mismatch yields `PERMISSION_DENIED`.

Like the shared proxy, the dedicated proxy holds **zero Kubernetes API credentials**. Cross-namespace route attachment (`allowedRoutes.namespaces.from: All`/`Selector`) is resolved by the controller at reconcile time — the controller's cluster-wide reflector compiles all cross-namespace routes into the dedicated snapshot before it is pushed. No proxy-side cluster-wide reflector and no proxy-side RBAC are required.

### `serve relay`

A zero-RBAC discovery **cache**: a recursive node that subscribes to an upstream discovery stream (the controller) and re-publishes snapshots to downstream proxies, so the leader's snapshot fan-out scales O(relays) instead of O(nodes). A relay holds the same zero-Kubernetes-credentials invariant as a proxy. `relay --shared` fronts the shared pool; `relay --namespace <NS>` fronts one namespace's dedicated Gateways (controller-provisioned; provenance-authorized). Leaves speak the unchanged protocol and are unaware of the tier. See [Discovery protocol → The relay tier](architecture/discovery-protocol.md#the-relay-tier).

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

The routing table is an immutable snapshot behind an atomic pointer; each request reads it with a single atomic load — no locks, no channels. The discovery supervisor applies each pushed change — a per-resource delta, not a whole-table blob (see [Discovery protocol → wire protocol](architecture/discovery-protocol.md#the-wire-protocol)) — by recompiling only the routing partitions that changed and splicing every unchanged partition's already-compiled router straight into a fresh table, then swaps the pointer atomically; in-flight requests complete against the old snapshot, the next request sees the new routing.

TLS works the same way: the TLS store is an atomic snapshot rebuilt on every push. New connections use the new certificate; connections in progress complete with the old one.

## Where to go next

- **[Deployment models](architecture/deployment-models.md)** — the Shared and Dedicated topologies, how per-Gateway addressing works when compute is shared, and the scope-aware snapshot dispatch that keeps them isolated.
- **[Discovery protocol](architecture/discovery-protocol.md)** — how `Programmed` status is gated on real bind + ack signals, RBAC by role, and which admin endpoints each role exposes.
- **[Control-plane security](guides/control-plane-security.md)** — how the discovery channel is secured (mTLS, SPIFFE SVIDs, CA provisioning), reconnect behaviour, and wire-version compatibility.
