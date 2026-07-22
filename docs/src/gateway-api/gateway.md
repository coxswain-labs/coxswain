# Gateway

A `Gateway` object defines one or more listeners, each binding a port and protocol to a set of allowed routes. Coxswain routes the `HTTP`, `HTTPS`, and `TLS` protocols. A listener declaring any other protocol is rejected: it gets `Accepted=False, reason=UnsupportedProtocol` with an empty `supportedKinds`, and the Gateway's own `Accepted` condition rolls up to `reason=ListenersNotValid` (status `False` when *every* listener is unsupported, `True` when at least one listener is still valid).

!!! tip "Dedicated proxy per Gateway"
    A `Gateway` can be opted into its own isolated proxy pool via `spec.infrastructure.parametersRef` pointing at a `CoxswainGatewayParameters`. See [Dedicated proxy pools](index.md#dedicated-proxy-pools) for the full walkthrough. A `parametersRef` targeting any other (unrecognized) kind is rejected with `Accepted=False, reason=InvalidParameters`.

!!! info "Infrastructure metadata propagation"
    `spec.infrastructure.labels` and `spec.infrastructure.annotations` propagate onto the resources Coxswain provisions for the Gateway, whether it is served by the shared pool or by a dedicated proxy. For a dedicated proxy they land on the per-Gateway `Deployment`, `Service`, and `ServiceAccount`; for a shared-pool Gateway they land on the per-Gateway VIP `Service` (e.g. cloud load-balancer annotations) and on a per-Gateway identity `ServiceAccount` provisioned in the Gateway's namespace. The four reserved label keys (`app.kubernetes.io/{name,instance,managed-by,component}` and `gateway.networking.k8s.io/gateway-name`) cannot be overridden — a collision is dropped with a warning, since the Service/Deployment selectors depend on them.

## Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Same        # see below
```

### `allowedRoutes.namespaces.from`

Controls which namespaces may attach `HTTPRoute`s to this listener.

| Value | Behaviour |
|-------|-----------|
| `Same` (default) | Only routes in the Gateway's own namespace can attach. |
| `All` | Routes from any namespace can attach. |
| `Selector` | Routes from namespaces matching `namespaces.selector` (a label selector) can attach. |

`All` and `Selector` cause the controller to automatically grant the dedicated proxy cluster-wide `HTTPRoute` reads. No extra fields on `CoxswainGatewayParameters` are required — the listener spec is the single source of truth. See the [dedicated-mode guide](index.md#cross-namespace-routes) for details.

## Supported fields

| Field | Support |
|-------|---------|
| `spec.gatewayClassName` | Full |
| `spec.listeners[].name` | Full |
| `spec.listeners[].port` | Full |
| `spec.listeners[].protocol` | `HTTP`, `HTTPS`, `TLS` |
| `spec.listeners[].hostname` | Full (wildcard: any number of labels) |
| `spec.listeners[].allowedRoutes` | Full |
| `spec.listeners[].tls` | `mode: Terminate` (HTTPS) and `mode: Passthrough` (TLS) |

## TLS

Add an `HTTPS` listener and reference a `kubernetes.io/tls` Secret in the same namespace. Coxswain reloads the certificate automatically when the Secret changes. See the [TLS guide](../operations/tls.md) for cert-manager integration. For TLS passthrough (no termination at the proxy), see [TLSRoute](tlsroute.md).

```yaml
spec:
  gatewayClassName: coxswain
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: my-gateway-tls   # must exist in the same namespace
      allowedRoutes:
        namespaces:
          from: Same
```

The referenced Secret must have `type: kubernetes.io/tls` with `tls.crt` and `tls.key`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-gateway-tls
  namespace: default
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded certificate>
  tls.key: <base64-encoded private key>
```

To reference a Secret in a different namespace, create a `ReferenceGrant` in the namespace where the Secret lives:

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-gateway-tls
  namespace: certs-namespace     # namespace of the Secret
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: Gateway
      namespace: default         # namespace of the Gateway
  to:
    - group: ""
      kind: Secret
```

## Listener hostnames

The `hostname` field on a listener filters which requests reach its attached routes. Gateway API wildcard matching allows any number of DNS labels: `*.example.com` matches both `foo.example.com` and `foo.bar.example.com`.

An empty `hostname` accepts requests for any hostname. For SNI-based TLS termination, the listener `hostname` is also used to select the correct certificate when multiple HTTPS listeners share the same port.

!!! note
    Gateway API wildcards match any number of labels; classic `Ingress` matches only a single label. See [HTTPRoute → Wildcard hostnames](httproute.md#wildcard-hostnames).

## Load balancer address

Set `--status-address` to the external IP or hostname of your load balancer. Coxswain writes it to `status.addresses` on the `Gateway` object. Without it, the address is left empty.

```bash
kubectl get gateway my-gateway
# NAME         CLASS      ADDRESS         PROGRAMMED
# my-gateway   coxswain   203.0.113.10    True
```

## Requesting a static address

Set `spec.addresses` to ask coxswain to bind a specific address rather than letting the cluster auto-assign one (Gateway API `GatewayStaticAddresses`):

```yaml
spec:
  addresses:
    - type: IPAddress
      value: 10.96.0.42
```

Coxswain honors a requested `IPAddress` by provisioning that Gateway's VIP `Service` as a **`ClusterIP`** pinned to the requested address (overriding the default VIP type for that one Gateway). The apiserver assigns the address exactly when it is a free IP inside the cluster's Service CIDR, and rejects it otherwise — giving a deterministic accept/reject on every cluster. The outcome is reflected in the conditions:

| Requested address | `Accepted` | `Programmed` |
|-------------------|-----------|--------------|
| Supported type, bindable value | `True` | `True` — the address appears in `status.addresses` |
| Supported type, value coxswain cannot bind (out of range / in use) | `True` | `False`, reason `AddressNotUsable` — the value is **not** published |
| Unsupported `type` (anything but `IPAddress`/`Hostname`) | `False`, reason `UnsupportedAddress` | `False`, reason `Invalid` |

A request for two distinct IPs is always `AddressNotUsable` — one `Service` binds a single `clusterIP`. Leaving `value` empty keeps the auto-assign behaviour (`GatewayAddressEmpty`).

> Because a static-IP Gateway is bound to a `ClusterIP`, its address is **cluster-internal** — coxswain cannot guarantee an arbitrary externally-routable IP across load-balancer providers. Use a static address when you need a stable, predictable in-cluster address; for external exposure, leave `spec.addresses` empty and let the cluster's load balancer assign one.

## Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The controller has claimed this Gateway |
| `Programmed` | All listeners are configured and the Gateway's address has resolved |

The controller does not stamp `Programmed` as processed for the current `metadata.generation` until the Gateway's own address has resolved into `status.addresses`. Until then `Programmed` stays `False`/`Pending` and its `observedGeneration` trails `metadata.generation`, so a client that waits for the latest conditions never observes `Programmed` claiming a generation while `status.addresses` is still empty — the same reconcile that flips `Programmed=True` also publishes the address. `Accepted` advances immediately. (A *settled* negative such as `AddressNotUsable` is not held back — it is a final answer for the current generation.)

Per-listener conditions are also written: `Accepted`, `ResolvedRefs`, and `Programmed`. Inspect them when a listener is not serving traffic:

```bash
kubectl describe gateway my-gateway
```
