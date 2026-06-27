# ListenerSet guide

A `ListenerSet` (GEP-1713) lets an application team attach listeners to a `Gateway`
they do not own — without editing the Gateway object itself. The Gateway is usually
infrastructure-owned and a point of contention; a `ListenerSet` moves listener
ownership to the team that needs the port and hostname, while the Gateway operator
retains control over **whether** and **from where** attachment is allowed.

| Resource | API version | Support |
|----------|-------------|---------|
| `ListenerSet` | `gateway.networking.k8s.io/v1` | HTTP, HTTPS, and TLS passthrough listeners; full cross-namespace attachment |

A `ListenerSet` attaches to exactly **one** parent Gateway via `spec.parentRef`
(singular). Its listeners are merged into the parent's effective listener set and
programmed on the same proxy as the Gateway's own listeners.

## Opting in on the parent Gateway

Attachment is **deny-by-default**. A Gateway accepts no `ListenerSet`s until it sets
`spec.allowedListeners.namespaces.from`:

| Value | Behaviour |
|-------|-----------|
| `None` (default) | No ListenerSets may attach. |
| `Same` | Only ListenerSets in the Gateway's own namespace may attach. |
| `Selector` | Only ListenerSets in namespaces matching `namespaces.selector` (a label selector) may attach. |
| `All` | ListenerSets from any namespace may attach. |

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: shared-gateway
  namespace: infra
spec:
  gatewayClassName: coxswain
  allowedListeners:
    namespaces:
      from: Selector
      selector:
        matchLabels:
          listener-attach: "true"   # only ListenerSets in namespaces with this label
  listeners:
    - name: http
      port: 80
      protocol: HTTP
```

A `ListenerSet` rejected by the gate is marked `Accepted: False` with reason
`NotAllowed`; its listeners are not programmed.

## Defining a ListenerSet

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata:
  name: team-a-listeners
  namespace: team-a
spec:
  parentRef:
    name: shared-gateway
    namespace: infra            # the parent Gateway's namespace
  listeners:
    - name: team-a-http
      port: 8080
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Same
```

Each listener carries the same `name`, `port`, `protocol`, `hostname`, `tls`, and
`allowedRoutes` fields as a Gateway listener. `HTTP`, `HTTPS` (`tls.mode: Terminate`),
and `TLS` (`tls.mode: Passthrough`) are processed; other protocols are ignored.

## Attaching routes

Routes attach to a ListenerSet's listeners by setting `parentRef.kind: ListenerSet`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: team-a-route
  namespace: team-a
spec:
  parentRefs:
    - group: gateway.networking.k8s.io
      kind: ListenerSet
      name: team-a-listeners
      sectionName: team-a-http   # optional: a specific listener by name
  rules:
    - backendRefs:
        - name: team-a-service
          port: 80
```

A `parentRef` without `kind` (or `kind: Gateway`) still attaches to the parent
Gateway's own listeners — only `kind: ListenerSet` targets the ListenerSet.

`HTTPRoute`, `GRPCRoute`, and `TLSRoute` can all attach to a ListenerSet listener:
`HTTPRoute`/`GRPCRoute` to its `HTTP`/`HTTPS` listeners, `TLSRoute` to its
`TLS`/`Passthrough` listeners.

## Precedence and duplicate names

The parent's effective listener set is ordered:

1. the parent Gateway's own listeners, then
2. each attached `ListenerSet`, oldest first by `creationTimestamp`, then
3. ties broken alphabetically by `{namespace}/{name}`.

Listener **names may repeat** across the Gateway and its ListenerSets — this is legal,
and **both listeners are programmed**. A Gateway listener named `web` on port 80 and a
ListenerSet listener named `web` on port 8080 both serve traffic, each attributed to
its own resource's status. Coxswain keys listener health by provenance, so the two
never collide.

`Conflicted: True` is reserved for a genuine **port-compatibility conflict** — two
listeners claiming the same port with incompatible protocols/hostnames. It is set on
the **lower-precedence** listener (the later one in the ordering above), which is not
programmed; the higher-precedence listener wins the port.

## TLS

An `HTTPS` listener on a ListenerSet references its certificate `Secret` in the
**ListenerSet's own namespace**:

```yaml
spec:
  parentRef:
    name: shared-gateway
    namespace: infra
  listeners:
    - name: team-a-https
      port: 8443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: team-a-tls       # resolved in namespace team-a
```

To reference a `Secret` in a different namespace, create a `ReferenceGrant` in the
Secret's namespace whose `from` selects `kind: ListenerSet` (in the ListenerSet's
namespace). Without a matching grant the listener is marked `ResolvedRefs: False`
with reason `RefNotPermitted` and the handshake fails.

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-listenerset-cert
  namespace: certs           # namespace of the Secret
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: ListenerSet
      namespace: team-a      # namespace of the ListenerSet
  to:
    - group: ""
      kind: Secret
```

This mirrors the cross-namespace cert plumbing used by `Gateway` HTTPS listeners
(which use `from: kind: Gateway`) — see the [TLS guide](tls.md).

## Status conditions

`ListenerSet`-level conditions:

| Condition | True when |
|-----------|-----------|
| `Accepted` | The parent Gateway's `allowedListeners` gate permits this ListenerSet |
| `Programmed` | All of its listeners are configured and ready |

Per-listener conditions mirror Gateway listeners — `Accepted`, `ResolvedRefs`,
`Programmed`, and `Conflicted`:

```bash
kubectl describe listenerset team-a-listeners -n team-a
```

## Known limitations

- **Cross-source same-port isolation.** When a Gateway listener and a ListenerSet
  listener share the same port with distinct hostnames, both program and share the
  same bind slot; request isolation is enforced per source. Mixing same-port listeners
  from different owners with overlapping hostnames is not recommended.
