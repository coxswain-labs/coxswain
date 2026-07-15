# Control-plane security

Coxswain's data plane (the proxy) never talks to the Kubernetes API. Instead the
**controller** compiles routing snapshots and pushes them to proxies over a gRPC
**discovery** channel. This page explains how that channel is secured: the
controller acts as a certificate authority (CA), a fresh proxy bootstraps its
identity with its Kubernetes ServiceAccount token, and the resulting short-lived
SPIFFE certificate (SVID) authenticates every snapshot stream — with no plaintext
fallback.

## The model

```mermaid
flowchart LR
  subgraph Controller pod
    CA[Controller-as-CA]
    BS[Bootstrap listener<br/>:50052 server-auth TLS]
    ST[Stream listener<br/>:50051 mTLS]
    CA --- BS
    CA --- ST
  end
  subgraph Proxy pod
    P[Proxy]
  end
  P -- "1. SA token + CSR" --> BS
  BS -- "2. signed SVID + trust bundle" --> P
  P -- "3. mTLS stream (SVID)" --> ST
  ST -- "4. routing snapshots" --> P
```

1. **Bootstrap.** A fresh proxy has no certificate. It reads its projected
   ServiceAccount token, generates a keypair locally, and sends the token plus a
   Certificate Signing Request (CSR) to the controller's bootstrap listener over
   server-authenticated TLS (the proxy verifies the controller; it presents no
   client cert — it has none yet).
2. **Issuance.** The controller validates the token with the Kubernetes
   `TokenReview` API (scoped to the `coxswain-discovery` audience), derives the
   proxy's SPIFFE identity (`spiffe://<trust-domain>/ns/<ns>/sa/<sa>`), signs the
   CSR, and returns the SVID plus the public trust bundle. **The proxy's private
   key never leaves the pod, never transits the wire, and never enters controller
   memory.**
3. **Stream.** The proxy opens the mandatory-mTLS stream with its SVID and
   receives routing snapshots. A proxy without a valid CA-signed SVID cannot
   connect — there is no plaintext fallback.
4. **Rotation.** Before the SVID expires the proxy re-bootstraps and reconnects
   with the fresh certificate. Routing never gaps (see
   [SVID rotation](#svid-rotation)).

The trust bundle is a **set** of public CA roots, so CA rotation can trust the
old and new roots during an overlap window.

## CA provisioning modes

The CA lives in a Kubernetes Secret (`type: kubernetes.io/tls` or `Opaque`, keys
`tls.crt` / `tls.key`) in the controller's namespace. How that Secret is created
is the single operator decision, controlled by `discovery.ca.mode`:

### `auto` (default) — self-managed

Nothing to provision. On first start the controller generates a CA and creates
the Secret (race-free across replicas: the first to create wins; the others read
it). It publishes the trust bundle and self-issues its own server certificate.
Zero external tooling.

Inspect the generated CA:

```bash
kubectl -n coxswain-system get secret coxswain-discovery-ca -o yaml
```

### `external` + cert-manager

Set `discovery.ca.mode=external` and let cert-manager author the CA. Coxswain
only **consumes** the resulting Secret and hot-reloads when cert-manager rotates
it — this mirrors how Envoy Gateway and kgateway integrate with cert-manager
(the operator authors the cert; the control plane consumes the Secret). Coxswain
does not render or own the `Certificate`. A copy-pasteable recipe ships at
`deploy/manifests/cert-manager-example.yaml`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: coxswain-discovery-ca
  namespace: coxswain-system
spec:
  isCA: true
  commonName: coxswain-discovery-ca
  secretName: coxswain-discovery-ca   # what discovery.ca.secretName points at
  duration: 8760h
  renewBefore: 720h
  issuerRef:
    name: coxswain-discovery-selfsigned
    kind: Issuer
    group: cert-manager.io
```

(The controller programmatically managing `Certificate` CRs itself — the
istio-csr style — is tracked for a later release.)

### `external` + bring-your-own

Set `discovery.ca.mode=external` and supply the Secret yourself:

```bash
kubectl -n coxswain-system create secret tls coxswain-discovery-ca \
  --cert=ca.crt --key=ca.key
```

In `external` mode the controller **fails closed**: if the Secret is absent it
logs an error and does not serve discovery (it never silently self-signs). With
Helm, `external` mode also omits the namespace-scoped secrets-create Role, so the
controller holds no secrets-write grant at all.

## The read-only-proxy invariant

The proxy mounts only **public** material and holds **zero** Kubernetes write
verbs:

- A **projected ServiceAccount token** (audience `coxswain-discovery`,
  auto-rotated by the kubelet) at
  `/var/run/secrets/coxswain/discovery-token/token`.
- The controller-published **trust-bundle ConfigMap** (`coxswain-discovery-trust`,
  public CA roots only) at `/var/run/secrets/coxswain/trust-bundle/ca.crt`.

Both are mounted by the kubelet — the proxy needs no API access to read them. The
proxy never references the CA Secret (which holds the private key). This is the
load-bearing security property of the controller/proxy split: a compromised proxy
cannot write to Kubernetes and cannot read the CA key.

## SVID rotation

SVIDs are short-lived (`discovery.svidTtl`, default `24h`). The proxy refreshes at
~50 % of the TTL: it re-bootstraps, caches the fresh SVID, and signals the stream
supervisor to reconnect. The proxy's routing tables are **never cleared** across a
reconnect — the last-good snapshot keeps serving traffic throughout — so rotation
causes no routing gap and no dropped requests.

The controller's own server certificate is long-lived and refreshed when the
controller pod restarts.

## SVID identity and Gateway scope binding

Every proxy's SVID is derived from its Kubernetes ServiceAccount — the identity
that the `TokenReview` check validates at bootstrap. The table below shows the
canonical form for each deployment model:

| Proxy role | ServiceAccount | SVID |
|---|---|---|
| Shared-pool proxy | `coxswain-shared-proxy` | `spiffe://<trust-domain>/ns/<ns>/sa/coxswain-shared-proxy` |
| Dedicated proxy (per Gateway) | `<gateway-name>-<gatewayclass-name>` | `spiffe://<trust-domain>/ns/<gateway-ns>/sa/<gateway-name>-<gatewayclass-name>` |
| Relay (discovery cache) | `coxswain-relay` (chart) / provisioned per namespace | `spiffe://<trust-domain>/ns/<relay-ns>/sa/<relay-sa>` |

The dedicated proxy SA name follows [GEP-1762](https://gateway-api.sigs.k8s.io/geps/gep-1762/):
it is the same name the controller uses for the provisioned Deployment, Service,
and ServiceAccount. For example, a Gateway `prod/my-gw` of class `coxswain` runs
as SA `my-gw-coxswain` with SVID
`spiffe://<trust-domain>/ns/prod/sa/my-gw-coxswain`.

### Scope binding enforcement

A dedicated proxy subscribes with `Scope::Gateway { name, namespace }` to
receive only its own Gateway's routing snapshot. The stream handler enforces that
the claimed Gateway matches the peer's authenticated SVID:

1. The controller stamps the expected proxy SA (`{gw}-{class}`) into the
   Gateway's dedicated registry entry at reconcile time.
2. When the proxy's `Subscribe` message arrives, the server extracts the URI SANs
   from the peer's TLS client certificate (injected as request metadata by
   `PeerSvidStream`).
3. If the peer's SVID does not match
   `…/ns/<claimed-namespace>/sa/<expected-sa>` the stream is closed immediately
   with `PERMISSION_DENIED` — before any snapshot is delivered.

The trust-domain prefix is validated at the TLS handshake by
`SpiffeClientCertVerifier`, so the binding check only needs to compare the
namespace and ServiceAccount name. A valid cert from the wrong Gateway is still
rejected.

If mTLS is not established (no peer certificate — test or degraded-mode paths
only), the binding check is skipped and the stream is fail-open. In production
there is no plaintext discovery server; `SpiffeClientCertVerifier` mandates
client auth, so every accepted stream carries a peer cert.

### Relay tier

A [relay](../architecture/discovery-protocol.md#the-relay-tier) is both a
discovery **client** (upstream, to the controller) and a discovery **server**
(downstream, to proxies), so it sits on both sides of the trust model:

- **Upstream**, the relay is an ordinary client: it bootstraps its own SVID from
  the controller (bootstrap is never tiered) and opens the mandatory-mTLS stream
  exactly like a proxy. Its SA holds **zero Kubernetes verbs** — the same
  read-only invariant as a proxy, so the relay never touches the CA Secret,
  trust-bundle ConfigMap, or `TokenReview` the controller's discovery server
  needs.
- **Downstream**, the relay presents that *same rotating bootstrapped SVID* as
  its serving certificate (issued SVIDs already carry the `serverAuth` EKU) and
  uses the mounted trust bundle as its client-CA. It enforces the identical
  `SpiffeClientCertVerifier` trust-domain check and, for `Scope::Gateway`
  subscribes, the identical SVID&harr;Gateway binding above — it reconstructs each
  Gateway's expected proxy SA from the `GatewayMeta` resource on its upstream
  stream. A relay's downstream server **rejects `Namespace` subscribes** (only
  the controller serves that scope).

A leaf placed behind a relay verifies the relay's identity instead of the
controller's — but it is not configured with a static endpoint or expected SA.
Since the routing upstream is **bootstrap-delivered and runtime-directed**
(#601), the controller hands the leaf its upstream `(endpoint, expected_server_sa)`
in the bootstrap response — the relay's Service and the relay's SA when the
namespace is relay-fronted — and the leaf verifies that identity on its stream.
Bootstrap itself always targets the controller (never tiered).

Relay availability is delivered by running ≥2 relay replicas behind the relay
Service. If a relay is nonetheless unreachable (e.g. torn down in a rebalance
race), the leaf **re-bootstraps** to the controller — the always-up anchor — and
is re-pointed at whatever upstream is current. This fallback repoints the
control stream only; the data plane keeps serving its last-good routing snapshot
throughout, so a relay rebalance never disrupts live traffic.

## Configuration

See [Configuration reference](../reference/configuration.md#discovery-control-plane)
for the full flag/value list. The common knobs:

| Helm value | Env var | Default | Meaning |
|---|---|---|---|
| `discovery.ca.mode` | `COXSWAIN_DISCOVERY_CA_MODE` | `auto` | `auto` self-generates; `external` consumes a pre-existing Secret (fail closed). |
| `discovery.ca.secretName` | `COXSWAIN_DISCOVERY_CA_SECRET` | `coxswain-discovery-ca` | CA Secret name (controller namespace). |
| `discovery.svidTtl` | `COXSWAIN_DISCOVERY_SVID_TTL` | `24h` | Proxy SVID lifetime; refresh fires at ~50 %. |
| `discovery.trustDomain` | `COXSWAIN_DISCOVERY_TRUST_DOMAIN` | `cluster.local` | SPIFFE trust domain; must match across controller and proxies. |
| `discovery.port` | `COXSWAIN_DISCOVERY_PORT` | `50051` | mTLS Stream listener port. |
| `discovery.bootstrapPort` | `COXSWAIN_DISCOVERY_BOOTSTRAP_PORT` | `50052` | Server-auth bootstrap listener port. |

## Reconnect and failure modes

The proxy runs a jittered-exponential-backoff reconnect supervisor (250 ms → 30 s):

| State | `/readyz` | Traffic |
|---|---|---|
| Before first snapshot | `503 NotReady` | — (no routing yet) |
| Disconnect after first snapshot | `200 Degraded` | Served from last-good snapshot |
| Reconnect + new snapshot | `200 Ready` | Updated routing |
| Controller down | `200 Degraded` | Last-good snapshot served indefinitely |

Routing tables are **never cleared** during a reconnect window. A controller outage does not disrupt traffic — proxies keep serving their last compiled snapshot until the controller comes back and pushes a new one.

## Wire-version skew

`WIRE_VERSION = 2` (current — the resource-oriented delta protocol; see [Discovery protocol → wire protocol](../architecture/discovery-protocol.md#the-wire-protocol)). Every `Subscribe` message includes this version. The server rejects a client with a different version immediately with `FAILED_PRECONDITION`; the client backs off **permanently** on that status (it does not retry the stream). Recovery: roll back the mismatched component (controller or proxy) to a matching version. There is no runtime negotiation — both ends must agree, and the break from `1` is hard (no back-compat: v1 sent a whole-table snapshot on every change, v2 streams per-resource deltas).

## Troubleshooting

**Proxy stuck `NotReady`.** The proxy reports `NotReady` until it has bootstrapped
an SVID and received its first snapshot. Check, in order:

- **Trust bundle missing.** `kubectl -n coxswain-system get configmap
  coxswain-discovery-trust` must exist. It is published by the controller on
  startup; if the controller never became ready (e.g. `external` mode with no CA
  Secret), the bundle is never written and proxies cannot verify the controller.
- **Wrong token audience.** The projected token's audience must be
  `coxswain-discovery`. A mismatch is rejected at `TokenReview`.
- **`external` Secret absent.** In `external` mode the controller logs
  `CA Secret absent and mode=external` and does not serve discovery. Supply the
  Secret (cert-manager or `kubectl create secret tls`).
- **Wrong `--discovery-bootstrap-endpoint`.** This is the proxy's sole endpoint
  anchor: if it cannot reach the controller's bootstrap listener it never obtains
  an SVID (nor learns its routing upstream) and stays NotReady. Verify the URI and
  that the discovery bootstrap `Service` exists in the controller namespace.

**Proxy `Degraded` after restart.** Normal — the proxy starts `NotReady` until it reconnects and receives its first snapshot from the new controller. If it stays `Degraded` indefinitely, check connectivity to the discovery endpoint.

**Wire-version mismatch.** The proxy logs `FAILED_PRECONDITION` and backs off permanently. Check that the controller and proxy images are from the same release. See [Wire-version skew](#wire-version-skew).

**`BootstrapRejected` events.** When the controller rejects a bootstrap (invalid
or wrong-audience token, malformed CSR), it emits a `BootstrapRejected` Warning
Event in its namespace. The controller is the sole diagnostic emitter — the proxy
never writes events. List them with:

```bash
kubectl -n coxswain-system get events --field-selector reason=BootstrapRejected
```

The event note carries the rejected principal and the reason.
