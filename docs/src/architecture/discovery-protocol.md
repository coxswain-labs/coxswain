# Discovery protocol

The controller compiles K8s routing snapshots and pushes them to each subscribed proxy over a mandatory-mTLS gRPC stream. Proxies apply the snapshot to their in-process routing table via an atomic pointer swap — no locks, no channels, no restart. All routing data (routes, upstream addresses, TLS certificates) arrives via the discovery stream; the proxy never reads the Kubernetes API.

!!! note "Securing the channel"
    This page covers the protocol's data-flow and status-gating logic. For how the channel is authenticated (mTLS, SPIFFE SVIDs, CA provisioning modes), reconnect behaviour, and wire-version compatibility, see [Control-plane security](../guides/control-plane-security.md).

## How `Programmed` status is gated

Each proxy reports its **actually-bound listener ports** back over the discovery stream (a `NodeStatus` message, sent on stream open and on every bind change). The leader uses these reports to decide when a Gateway's `Programmed` condition should flip to `True` — and it requires *two* independent signals to both hold, not just one:

1. **Bind** — the port is actually open. For a shared-mode Gateway, this means *every* connected shared-pool proxy has bound that Gateway's VIP ports (its per-Gateway internal `targetPort`s); for a dedicated Gateway, it means that Gateway's own proxy has bound its listener ports.
2. **Ack** — every relevant proxy has also acknowledged a routing snapshot that *contains* the Gateway's current generation (spec version).

Why both are needed: bind alone isn't enough when the ports were already open from a *previous* configuration — e.g. the change was config-only (a new `frontendValidation` block, say), so the port stays bound throughout, but the new config is still propagating to proxies. Bind would report "ready" instantly and mask the fact that some proxies are still serving stale config. Ack closes that gap.

Mechanically: snapshot versions are content hashes (not sequential), so "does this snapshot contain generation N" is tracked separately — each routing rebuild stamps, per Gateway, the publish sequence number at which its current generation first appeared, and each proxy's acknowledgment records the sequence number it had seen as of that ack. Comparing the two tells the leader whether a given proxy is caught up.

Until both bind and ack hold, `Programmed` stays `False/Pending`, `observedGeneration` stays one behind the current generation, and the condition's message names specifically what's still being waited on. Once a generation reaches `Programmed=True`, ordinary pool churn — rollouts, leader failover — never flips it back to `False`; only an actual spec change re-arms the gate.

## RBAC by mode

| Resource | Verb | `controller` | `shared-proxy` | `dedicated-proxy` |
|---|---|:-:|:-:|:-:|
| HTTPRoute, Gateway, ReferenceGrant, BackendTLSPolicy | list, watch, get | ✓ (cluster) | — | — |
| GatewayClass, Ingress, IngressClass | list, watch, get | ✓ (cluster) | — | — |
| Service, EndpointSlice | list, watch, get | ✓ (cluster) | — | — |
| Secret (`kubernetes.io/tls`), ConfigMap | list, watch, get | ✓ (cluster) | — | — |
| HTTPRoute, Gateway, Ingress `/status` | update, patch | ✓ (cluster) | — | — |
| Gateway | patch | ✓ (cluster — finalizers only) | — | — |
| Deployment, Service, ServiceAccount | create, update, delete | ✓ (cluster) | — | — |
| Lease | get, create, patch | ✓ (`coxswain-system`) | — | — |
| TokenReview | create | ✓ (cluster — SVID bootstrap) | — | — |

Both proxy roles hold **zero Kubernetes API credentials**. All routing data arrives via the controller's gRPC discovery stream. Each proxy mounts only a projected ServiceAccount token (audience `coxswain-discovery`) for SVID bootstrap at `/var/run/secrets/coxswain/discovery-token/token` — this is mounted by the kubelet, not via RBAC — and the public trust-bundle ConfigMap at `/var/run/secrets/coxswain/trust-bundle/ca.crt`. Neither mount requires any K8s RBAC grant.

## Admin endpoints by mode

| Endpoint | Controller | Shared proxy | Dedicated proxy |
|---|:-:|:-:|:-:|
| `/healthz`, `/readyz` | ✓ | ✓ | ✓ |
| `/metrics` | ✓ (reconcile counts, leader status) | ✓ (traffic, errors) | ✓ (scoped to this Gateway) |
| `/api/v1/health` | ✓ (subsystem detail, version, leader) | ✓ | ✓ |
| `GET /` (operator UI) + `/api/v1/{fleet,routing}/*` | ✓ (cluster-wide aggregate + summaries, incl. each proxy's compiled routing table at `fleet/proxies/{name}/routes`) | — | — |
| `/api/v1/{problems,events,manifests/*,pods/*/logs}` | ✓ | — | — |

Proxy pods carry no admin query surface beyond `/healthz`/`/readyz`/`/metrics`/`/api/v1/health` — the
controller is the sole reader of Kubernetes state and pushes routing to proxies over the discovery
stream, so it already holds what each proxy serves and answers `fleet/proxies/{name}/routes` from its
own local snapshot rather than fanning out to the pod.
