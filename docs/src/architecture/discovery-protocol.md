# Discovery protocol

The controller compiles K8s routing state and pushes it to each subscribed proxy over a mandatory-mTLS gRPC stream. The wire is **resource-oriented** (`WIRE_VERSION = 2`): the first message of a session is a full snapshot, and every change after it is a per-resource delta — only what moved. Proxies apply each message to their in-process routing tables via atomic pointer swaps, recompiling only the partitions that changed — no locks, no channels, no restart. All routing data (routes, upstream addresses, TLS certificates) arrives via the discovery stream; the proxy never reads the Kubernetes API.

!!! note "Securing the channel"
    This page covers the protocol's data-flow and status-gating logic. For how the channel is authenticated (mTLS, SPIFFE SVIDs, CA provisioning modes), reconnect behaviour, and wire-version compatibility, see [Control-plane security](../guides/control-plane-security.md).

## The wire protocol

Each subscriber gets one full snapshot, then a stream of deltas. The server keeps a per-stream baseline — the set of resources that stream last acknowledged — and every subsequent message is a diff against it: resources whose content changed ride as **upserts**, resources that left the world ride as **tombstones**. Nothing else is re-sent.

```mermaid
sequenceDiagram
    participant P as Proxy (client)
    participant C as Controller (server)
    P->>C: Subscribe(scope, WIRE_VERSION=2)
    C-->>P: Snapshot(full=true, all resources)
    P->>C: Ack(version)
    loop steady state
        Note over C: routing change
        C-->>P: Snapshot(full=false, upserts + tombstones)
        P->>C: Ack(version)
    end
    Note over P,C: apply fails self-check / dangling ref
    P->>C: Nack(version)
    C-->>P: Snapshot(full=true, current world)
    Note over P,C: stream drops (leader change, restart)
    P->>C: Subscribe(...) reconnect
    C-->>P: Snapshot(full=true, current world)
```

Three things always produce a **full** snapshot; everything else is a delta:

- **First subscribe** — the client has no baseline yet.
- **Reconnect** — per-stream baseline is not portable across streams, so a redial re-syncs from scratch.
- **Nack** — if a client cannot apply a message (see the invariants below), it Nacks; the server answers with a fresh full of the current world. This is the protocol's self-healing path: a client can always recover a consistent world without operator action.

One message is in flight at a time (send-after-Ack). Rebuilds that arrive while a message is un-Acked are coalesced — after the Ack the server sends a single delta spanning the acked baseline to the latest world.

### The resource model

The old wire sent a fixed set of whole tables and re-serialized every one of them on every change. The v2 wire is a flat set of independently-addressed **resources**, each with a canonical key and a content hash. A change to one route touches one resource; the rest of the world stays byte-identical on the wire and is never re-sent.

Canonical keys are `|`-separated and name exactly one resource:

- `route|<ingress|gateway>|<port>|<match-kind>[|<host>]` &mdash; one host bucket of an L7 route table.
- `tls|<port>` and `clientcert|<port>` &mdash; per-port TLS material and client-cert config.
- `tlspassthrough|<port>`, `tlsterminate|<port>`, `tcp|<port>`, `udp|<port>` &mdash; per-port L4 routes.
- `listener|<ns>/<name>` &mdash; one Gateway's listener status.
- `endpoints|<ns>/<svc>/<port>` &mdash; one EDS endpoint set (see below).

The full grammar lives in exactly one place in the code (`wire/resource.rs`), so the server (which addresses its per-stream baseline by key) and the client (which keys its resource cache by key) cannot drift.

### EDS-style endpoints, and why

Upstream endpoints are their own resource, keyed `(namespace, service, port)`, and a route's weighted backend carries an **`endpoint_ref`** to one instead of inlining pod IPs. This is the change that makes deltas pay off.

Under the old wire, a rolling deploy — pods coming and going — rewrote every route that referenced the churning Service, because the endpoint IPs were baked into the route. Each rewrite changed the route's hash, so the whole route re-serialized and the client recompiled it. With endpoints split out, a rolling deploy ships **one** `endpoints|…` delta; routes that reference it are untouched on the wire, and the client recompiles only the partitions that actually point at that Service.

Endpoint-derived status is computed **client-side** from the same shared rule the controller would have used: a referenced Service that does not exist yields `500`, and one that exists but has zero ready endpoints yields `503`. Because that status is derived from the endpoint resource rather than baked into the route, draining a backend to zero is again a single endpoint delta — it does not rewrite or re-send the route. Endpoint-independent statuses (fail-closed `502` variants, `500` for a route with no usable backends at all) stay baked on the route where they belong.

### Invariants a client can rely on

1. **Atomic apply.** A message applies in full or not at all. The client stages every change off to the side, runs all its checks, and only then swaps the live routing cells — so a malformed or inconsistent message never partially lands.
2. **Last-good on failure.** If any check fails, the client keeps serving its previous world unchanged and Nacks. Traffic never drops on a bad push.
3. **Self-healing.** A Nack is answered with a fresh full snapshot, so a client that falls out of sync — for any reason — is pulled back to a consistent world without operator intervention.
4. **Referential integrity.** After any message, every `endpoint_ref` a route reaches resolves to an endpoint resource the client holds. The server ships a newly-referenced endpoint set in the same message that first references it, and tombstones one in the same message its last referrer leaves.
5. **Emptiness travels as removal** — with one deliberate exception: an endpoint resource that exists with zero addresses is meaningful (it is the `503` "valid but empty" signal), so it is sent, not tombstoned.
6. **Version self-check.** Each message carries a global `version` — an order-independent hash of the per-resource hashes of the post-apply world. The client recomputes it from what it just staged and refuses to commit on a mismatch (Nack → full resync). This is the same content-hash formula the old whole-table wire used, so the convergence machinery below is unchanged.

### Convergence

The global `version` is a content hash of the whole post-apply world, identical in meaning to the pre-v2 version. `Programmed` gating (below), the `NodeRegistry`, and the ack-tracking that tells the leader whether a proxy has caught up to a given generation all key off it exactly as before — the delta rework changed *how* a world is transmitted, not how convergence to a world is measured.

### Observing the stream

The `coxswain_discovery_*` series expose the delta engine on both ends — server-side on the controller `/metrics`, client-side on each proxy `/metrics`. See the [observability reference](../reference/observability.md#discovery-channel-metrics-coxswain_discovery_) for the full table. In a healthy steady state:

- `snapshot_messages_total{kind="delta"}` (and the client's `client_snapshots_applied_total{kind="delta"}`) climb with routing churn, while `{kind="full"}` stays **flat** — a full is sent only on connect, reconnect, or a Nack-driven resync, so a rising `full` rate points at an unstable control-plane link or repeated self-healing.
- `client_partitions_reused_total` climbs far faster than `client_partitions_recompiled_total` under endpoint churn — a rolling deploy recompiles only the partitions referencing the churning Service and splices the rest.
- `snapshot_resources_sent_total ÷ snapshot_messages_total` (average payload width) collapses toward one during endpoint-only churn — the EDS split working as intended.

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
