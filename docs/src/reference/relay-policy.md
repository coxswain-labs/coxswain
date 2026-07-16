# CoxswainRelayPolicy

`CoxswainRelayPolicy` is a **namespaced** CRD that tunes the controller-provisioned
**namespace relays** of the [discovery relay tier](../architecture/deployment-models.md#discovery-relay-tier).
The policy in a namespace governs that namespace's relay, overlaying structured control —
enablement, HA, resources, scheduling, and autoscaling — on top of the install-wide
`--relay-*` controller flags.

!!! note "Scope: namespace relays only"
    This CRD applies **only** to the dynamic, per-namespace relays the controller provisions
    for **dedicated** proxies. The **shared-pool relay** is global (one per install) and reads
    the install-wide `--relay-*` flag values directly — it has no per-namespace policy.

## Model: override, not activation

Turning the tier on (`--relay-enabled`) already provisions relays automatically wherever they
reduce leader fan-out (the [control loop](../architecture/deployment-models.md#discovery-relay-tier):
activation at break-even, cooldown deactivation). You do **not** need a policy to get the
optimization. `CoxswainRelayPolicy` is for **overrides and tuning** — force a namespace on or
off, resize it, pin its scheduling, or tune/opt it into autoscaling.

## Resolution

The effective policy for a namespace is simply the `CoxswainRelayPolicy` that lives **in**
that namespace — keyed by the object's own namespace, the same model as the
`CoxswainGatewayParameters` used for [dedicated proxies](../guides/dedicated-mode.md). Every
field is optional; unset fields fall through to the global `--relay-*` controller-flag
defaults. `podTemplate` strategic-merges onto the controller-rendered relay pod.

There is no cluster-wide "default policy" and no label selector: the only install-wide default
is the flat `--relay-*` flags; structured overrides (autoscaling, `podTemplate`, `resources`)
are set per namespace. Keep **at most one** policy per namespace — if several exist the
controller picks the lexically-first by name and warn-logs the ambiguity.

## Fields

| Field | Type | Default | Effect |
|---|---|---|---|
| `enabled` | `bool` | unset (auto) | Tri-state override: unset = controller decides (activation threshold); `true` = force on (bypass threshold; still torn down at zero subscribers); `false` = force off (unconditional, overrides the cooldown). |
| `replicas` | `int` | `--relay-replicas` (2) | Static relay replica count when autoscaling is off. |
| `resources` | `ResourceRequirements` | `--relay-*-request` / `--relay-memory-limit` | Relay container requests/limits. |
| `podTemplate` | partial `PodTemplateSpec` | none | Scheduling escape hatch strategic-merged onto the relay pod (nodeSelector, tolerations, affinity, topologySpreadConstraints, priorityClassName, …). |
| `autoscaling` | object | off | Controller-driven autoscaling (see below). |

### `autoscaling`

Namespace-relay autoscaling is **controller-driven — there is no `HorizontalPodAutoscaler`**.
The relay is I/O/fan-out-bound (CPU mistracks its load) and each replica opens its own upstream
stream to the leader, so the controller re-implements the standard autoscaler loop internally,
sizing the relay from the namespace's **live dedicated-proxy subscriber count**:

```
replicas = clamp(ceil(liveSubscribers / targetProxiesPerReplica), minReplicas, maxReplicas)
```

damped by a relative **tolerance** deadband and an asymmetric **scale-down stabilization**
window (scale up promptly, scale down only on the trailing-window peak).

| Field | Type | Default | Effect |
|---|---|---|---|
| `enabled` | `bool` | `false` | Opt into controller-driven sizing. |
| `minReplicas` | `int` | effective `replicas` | HA floor. Keep ≥ 2. |
| `maxReplicas` | `int` | — (**required**) | Cap on relay replicas — bounds the upstream fan-out regrowth. **If unset, autoscaling is ignored** (the relay stays at static `replicas`) and the controller warn-logs; an uncapped relay never runs. |
| `targetProxiesPerReplica` | `int` | `--relay-target-proxies-per-replica` (250) | **Capacity ratio** — downstream proxies each replica should front. Decoupled from the break-even threshold (a relay is a fan-out cache, so real per-replica capacity is O(100s), not the break-even number). Measured (#603): under one CPU core and p99 fan-out latency under 20ms at 250 subscribers even under sustained 10 changes/sec churn. |
| `scaleDownStabilizationSeconds` | `int` | `--relay-scale-down-stabilization` (300) | Scale-**down** sizes on the max subscriber count over this trailing window; scale-up is prompt. Damps flapping. |
| `cooldownSeconds` | `int` | `--relay-cooldown` (300) | The relay is torn down only after the subscriber count holds **below** break-even for this long. A genuinely drained namespace (no dedicated Gateways) tears down at once; a transient 0 (relay restart/reconnect) waits the cooldown. |
| `tolerance` | `float` | `--relay-tolerance` (0.10) | Relative sizing deadband: the replica count changes only when load deviates from target by more than this fraction. |

!!! warning "Keep `maxReplicas` below the fan-out it collapses"
    Each relay replica opens its own upstream `Namespace` stream to the leader. If
    `maxReplicas` approaches the namespace's downstream proxy count, the relay's own streams
    approach the count it exists to collapse and the tier stops paying off.

## Examples

### Force a namespace's relay on

Turn the automatic threshold into "always on" for `team-a`:

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainRelayPolicy
metadata:
  name: relay
  namespace: team-a
spec:
  enabled: true
  replicas: 2
```

### High-scale namespace with autoscaling and dedicated nodes

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainRelayPolicy
metadata:
  name: relay
  namespace: platform
spec:
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
  name: relay
  namespace: legacy
spec:
  enabled: false
```
