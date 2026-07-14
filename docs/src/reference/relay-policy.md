# CoxswainRelayPolicy

`CoxswainRelayPolicy` is a **cluster-scoped** CRD that tunes the controller-provisioned
**namespace relays** of the [discovery relay tier](../architecture/deployment-models.md#discovery-relay-tier)
per namespace. It overlays structured control — enablement, HA, resources, scheduling, and
autoscaling — on top of the install-wide `--relay-*` controller flags.

!!! note "Scope: namespace relays only"
    This CRD applies **only** to the dynamic, per-namespace relays the controller provisions
    for **dedicated** proxies. The **shared-pool relay** is static Helm-managed infrastructure
    — tune it through `relay.shared.*` Helm values, never this CRD.

## Model: override, not activation

Turning the tier on (`--relay-enabled`) already provisions relays automatically wherever they
reduce leader fan-out (the break-even threshold + hysteresis). You do **not** need a policy to
get the optimization. `CoxswainRelayPolicy` is for **overrides and tuning** — force a
namespace on or off, resize it, pin its scheduling, or opt it into autoscaling.

## Selector precedence

The effective policy for a namespace is a two-layer overlay:

1. **Cluster default** — the policy with no `namespaceSelector`. Applies to every
   relay-fronted namespace.
2. **Namespace match** — the most-specific policy whose `namespaceSelector` matches the
   namespace's labels.

Layer 2 overrides Layer 1 per field; unset fields fall through to Layer 1 and then to the
global `--relay-*` defaults. `podTemplate` strategic-merges across layers. "Most-specific" =
more selector terms (`matchLabels` + `matchExpressions`); ties break lexically by policy name.
Ambiguous same-specificity matches (and multiple cluster defaults) are resolved
deterministically and warn-logged by the controller.

## Fields

| Field | Type | Default | Effect |
|---|---|---|---|
| `namespaceSelector` | `LabelSelector` | none (cluster default) | Which namespaces the policy applies to. |
| `enabled` | `bool` | unset (auto) | Tri-state override: unset = controller decides (threshold); `true` = force on (bypass threshold; still GC'd at zero dedicated Gateways); `false` = force off (overrides hysteresis). |
| `replicas` | `int` | `--relay-replicas` (2) | Static relay replica count when autoscaling is off. |
| `resources` | `ResourceRequirements` | `--relay-*-request` / `--relay-memory-limit` | Relay container requests/limits. |
| `podTemplate` | partial `PodTemplateSpec` | none | Scheduling escape hatch strategic-merged onto the relay pod (nodeSelector, tolerations, affinity, topologySpreadConstraints, priorityClassName, …). |
| `autoscaling` | object | off | Controller-driven autoscaling (see below). |

### `autoscaling`

Namespace-relay autoscaling is **controller-driven — there is no `HorizontalPodAutoscaler`**.
The relay is I/O/fan-out-bound (CPU mistracks its load) and each replica opens its own upstream
stream to the leader, so the controller sizes the relay directly from the namespace's
spec-derived dedicated-proxy fan-out:

```
replicas = clamp(ceil(fanout / targetProxiesPerReplica), minReplicas, maxReplicas)
```

| Field | Type | Default | Effect |
|---|---|---|---|
| `enabled` | `bool` | `false` | Opt into controller-driven sizing. |
| `minReplicas` | `int` | effective `replicas` | HA floor. Keep ≥ 2. |
| `maxReplicas` | `int` | — (**required**) | Cap on relay replicas — bounds the upstream fan-out regrowth. **If unset, autoscaling is ignored** (the relay stays at static `replicas`) and the controller warn-logs; an uncapped relay never runs. |
| `targetProxiesPerReplica` | `int` | `8` | Downstream proxies each relay replica should front. |

!!! warning "Keep `maxReplicas` below the fan-out it collapses"
    Each relay replica opens its own upstream `Namespace` stream to the leader. If
    `maxReplicas` approaches the namespace's downstream proxy count, the relay's own streams
    approach the count it exists to collapse and the tier stops paying off.

## Examples

### Cluster default: relay every dedicated namespace

A no-selector policy that turns the automatic threshold into "always on":

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainRelayPolicy
metadata:
  name: cluster-default
spec:
  enabled: true
  replicas: 2
```

### High-scale namespace with autoscaling and dedicated nodes

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainRelayPolicy
metadata:
  name: platform-relays
spec:
  namespaceSelector:
    matchLabels:
      coxswain-labs.dev/relay-tier: high-scale
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      memory: 512Mi
  podTemplate:
    spec:
      tolerations:
        - key: dedicated
          operator: Equal
          value: relay
          effect: NoSchedule
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 8
    targetProxiesPerReplica: 8
```

### Force a namespace off

Keep a namespace direct-to-controller even if it crosses the break-even threshold:

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainRelayPolicy
metadata:
  name: no-relay-legacy
spec:
  namespaceSelector:
    matchLabels:
      team: legacy
  enabled: false
```
