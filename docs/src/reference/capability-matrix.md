# Gateway API capability matrix

Coxswain runs against Gateway API **v1.4.0 and later**. It does not require the
newest CRD set: at startup it detects which Gateway API kinds and schema fields
the cluster actually serves, and runs with exactly that feature set.

This matters because Gateway API CRDs are **cluster-scoped singletons**. Every
implementation in a cluster shares one installed version, so a co-resident
implementation pinned to an older release pins Coxswain too. Rather than
refusing to start — or wedging readiness on a kind that will never appear —
Coxswain degrades to what is installed and says so.

## What each version provides

| Kind | v1.4.x | v1.5.x | v1.6.x |
|---|---|---|---|
| `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, `BackendTLSPolicy` | ✅ `v1` | ✅ `v1` | ✅ `v1` |
| `ReferenceGrant` | ✅ `v1beta1` only | ✅ `v1` + `v1beta1` | ✅ `v1` + `v1beta1` |
| `ListenerSet`, `TLSRoute` | ❌ | ✅ `v1` | ✅ `v1` |
| `TCPRoute`, `UDPRoute` | ❌ | ❌ | ✅ `v1` |

Two features are gated on a **schema field** rather than a kind, because the
kind exists at every supported version but the field does not:

| Feature | Requires | Absent below |
|---|---|---|
| `HTTPRouteCORS` (GEP-1767) | `HTTPRoute` `spec.rules[].filters[].cors` | v1.5 |
| `GatewayFrontendClientCertificateValidation` and its `…InsecureFallback` sibling (GEP-91) | `Gateway` `spec.tls.frontend` | v1.5 |

## What a downgrade actually disables

On a cluster below the newest version:

- **Absent kinds are not watched.** No reflector is started for them, so they
  consume no watch, no memory and no API-server load.
- **Their readiness checks report `degraded`, not `pending`.** `/readyz` stays
  `200` and the pod serves traffic. A `degraded` check names the reason
  (`Gateway API CRD not installed`) and is visible at
  `/api/v1/health` under `subsystems.controller.checks.<name>`. This is the
  distinction that matters operationally: `degraded` means "deliberately not
  running", `pending` would mean "still starting" and would block readiness
  forever.
- **`GatewayClass.status.supportedFeatures` shrinks to match.** Coxswain never
  advertises a feature the installed CRDs cannot express, so the advertised set
  is always truthful for the cluster it is running on.
- **Routing for present kinds is unaffected.** HTTPRoute traffic on a v1.4
  cluster behaves exactly as it does on v1.6.

The per-kind result is also exported as a metric, `coxswain_gateway_api_capability{kind}`,
`1` when the kind is served and `0` when it is not. Every modelled kind gets a
series — a `0` is meaningfully different from a missing scrape.

## Runtime upgrades

Coxswain re-detects periodically. Installing a Gateway API CRD under a running
controller starts watching that kind and flips its check from `degraded` to
`ready` **without a restart**; the advertised feature set widens on the next
`GatewayClass` reconcile. Once every modelled kind is watched, re-detection
stops — there is nothing further to discover.

The reverse is not handled: **removing** a CRD from a running cluster does not
tear its reflector down. Uninstalling a CRD out from under a running controller
is not a supported operation, and the watch simply fails and retries.

### One exception: `ReferenceGrant`

`ReferenceGrant` is the only kind whose *served version* differs across
supported releases — `v1beta1` only on v1.4, `v1` and `v1beta1` from v1.5.
Coxswain negotiates the version **once per process**, at startup.

A cluster upgraded from v1.4 to v1.5 while the controller is running therefore
keeps watching `v1beta1` until the controller restarts. This is harmless — the
`spec.from` / `spec.to` fields Coxswain reads are identical between the two
versions — but it is a real limit on the otherwise restart-free upgrade story,
and it is the one case where a rolling restart is worth doing after a Gateway
API upgrade.

## Required RBAC

Detection reads CRD definitions, so the controller's `ClusterRole` includes:

```yaml
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["get", "list", "watch"]
```

Read-only, and on the **controller** only — the proxy ServiceAccount still holds
zero write verbs and does not talk to the Kubernetes API at all. The rule is
cluster-scoped because CRDs are, so the namespaced-lockdown install needs it in
its `ClusterRole` too.

Without this grant, detection fails on a cluster that *has* Gateway API
installed and the controller will not become ready — deliberately, because the
alternative is silently advertising an empty feature set on a fully-provisioned
cluster.

## Conformance

Conformance reports are published for every supported version, under
`conformance/reports/<report-dir>/`. A report from a v1.4 cluster claims fewer
profiles and fewer features than one from v1.6 — that is the mechanism working,
not a regression. See [Conformance](conformance.md) for how to reproduce a run.
