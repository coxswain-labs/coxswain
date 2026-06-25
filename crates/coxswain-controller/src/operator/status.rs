//! Dedicated-mode `Gateway.status` writer (#211).
//!
//! For every Gateway whose `parametersRef` resolves to (or names) a
//! `CoxswainGatewayParameters` object, the operator is the **sole** writer of
//! `Gateway.status` and emits one JSON-merge patch per reconcile carrying:
//!
//! - `Accepted` (`True, reason=Accepted` on success; `False,
//!   reason=InvalidParameters` when the params target is missing — the Gateway
//!   API spec reason for an unresolvable `parametersRef`).
//! - `Programmed` (`True, reason=Programmed` only when there is at least one
//!   Ready dedicated-proxy Pod AND the resolved Service has at least one
//!   address; otherwise `False` with reason `Invalid` /  `Pending` /
//!   `AddressNotAssigned` — see [`programmed_outcome`] for the precedence
//!   ladder).
//! - Per-listener `Accepted` / `ResolvedRefs` / `Programmed`, built via
//!   [`crate::status_common::build_listener_status`] from the same TLS-health
//!   channel the shared-pool writer reads — listener semantics are
//!   pool-independent.
//! - `status.addresses` resolved from the Service:
//!   - **LoadBalancer** → `status.loadBalancer.ingress[*].{ip,hostname}`
//!   - **ClusterIP** → `spec.clusterIP` (skips `None` / empty / headless)
//!   - **NodePort** → enumerated from cluster `Node.status.addresses[*]`,
//!     preferring `ExternalIP`, falling back to `InternalIP`
//! - `gateway.coxswain-labs.dev/DedicatedProxyReady` — the cut-over signal
//!   the shared-proxy reflector consumes to decide whether to keep serving
//!   the Gateway from the shared pool. Flips `True` iff at least one Ready
//!   proxy Pod exists AND `Accepted` is `True`; `False` (reason
//!   `Provisioning`) otherwise.
//!
//! ## Patch-coordination convention
//!
//! The shared-pool status writer in [`crate::controller`] skips dedicated-mode
//! Gateways via a `parametersRef` group/kind check, so this writer is in
//! practice the only one touching the Gateway. Even so, the patch preserves
//! any foreign conditions present on the Gateway (anything whose `type` is
//! neither in our owned set — `Accepted`, `Programmed`,
//! [`DEDICATED_PROXY_READY_CONDITION_TYPE`] — nor written by us elsewhere),
//! mirroring the symmetric convention the shared-pool writer applies for
//! `gateway.coxswain-labs.dev/`-prefixed conditions.
//!
//! ## Generation tracking
//!
//! Every emitted condition carries `observed_generation = gw.metadata.generation`.
//! Pod-readiness transitions do **not** bump `metadata.generation`, so
//! [`dedicated_gateway_needs_status_patch`] compares `(status, reason)` per
//! owned condition — not just `observed_generation` — to detect a status-only
//! transition that nonetheless requires repatching.

use crate::status_common::{
    OPERATOR_OWNED_CONDITION_TYPE_PREFIX, build_listener_status, listener_route_kind_info,
    make_condition,
};
use coxswain_reflector::gw_types::v::gateways::{
    Gateway, GatewayStatusAddresses, GatewayStatusListeners,
};
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::tls::GatewayListenerHealth;
use k8s_openapi::api::core::v1::{Node, Service, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::Client;
use kube::api::{Api, Patch, PatchParams};
use std::collections::BTreeSet;
use std::sync::Arc;

/// `Gateway.status.conditions[type]` value for the dedicated-proxy
/// readiness cut-over signal. The shared-proxy reflector reads this condition
/// (in `coxswain_reflector::reconciler::proxy::gateway_is_cut_over`)
/// to decide whether the shared pool should drop the Gateway from its
/// routing table.
pub(crate) const DEDICATED_PROXY_READY_CONDITION_TYPE: &str =
    "gateway.coxswain-labs.dev/DedicatedProxyReady";

/// `Accepted` reason emitted when the Gateway's resolved
/// `CoxswainGatewayParameters` target is missing. Gateway API canonical
/// reason for an unresolvable `parametersRef`.
const REASON_INVALID_PARAMETERS: &str = "InvalidParameters";
/// `Accepted` reason emitted on the success path. Gateway API canonical.
const REASON_ACCEPTED: &str = "Accepted";
/// `Programmed` reason emitted when the Gateway is fully programmed (Ready
/// pod + address assigned + Accepted).
const REASON_PROGRAMMED: &str = "Programmed";
/// `Programmed` reason emitted when `Accepted` is `False` (Gateway spec is
/// invalid; cannot be programmed). Gateway API canonical.
const REASON_INVALID: &str = "Invalid";
/// `Programmed` reason emitted while waiting for the dedicated-proxy Pod
/// to become Ready. Gateway API canonical.
const REASON_PENDING: &str = "Pending";
/// `Programmed` reason emitted when no Service-resolved address is yet
/// available. Gateway API canonical.
const REASON_ADDRESS_NOT_ASSIGNED: &str = "AddressNotAssigned";
/// `DedicatedProxyReady` reason emitted when the cut-over has fired
/// (Coxswain-internal).
const REASON_READY: &str = "Ready";
/// `DedicatedProxyReady` reason emitted before cut-over (Coxswain-internal).
const REASON_PROVISIONING: &str = "Provisioning";

/// Outcome of resolving the Gateway's `parametersRef`.
///
/// Local to the operator and replaces the deleted cross-task
/// `AcceptedOverrides` map: the operator is now the sole writer for
/// `Gateway.status` on dedicated-mode Gateways, so the coordination state can
/// live in a stack-allocated input bundle instead of a shared `Mutex<HashMap>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptedOutcome {
    /// The Gateway's `parametersRef` resolves to a `CoxswainGatewayParameters`
    /// object — its spec is accepted.
    Accepted,
    /// The Gateway's `parametersRef` is set but the target object does not
    /// exist in the reflector store.
    InvalidParameters,
}

/// Type-tagged address suitable for `Gateway.status.addresses[*]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StatusAddress {
    type_: AddressType,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AddressType {
    /// Per the Gateway API spec — bare IPv4 or IPv6.
    IpAddress,
    /// Per the Gateway API spec — DNS hostname.
    Hostname,
}

impl AddressType {
    fn as_str(self) -> &'static str {
        match self {
            Self::IpAddress => "IPAddress",
            Self::Hostname => "Hostname",
        }
    }
}

/// Bundle of inputs to the status patch builder.
///
/// Constructed once per reconcile from the operator's
/// `ReconcileContext` snapshots so the patch builder and the needs-patch
/// check both see exactly the same data — no risk of a stale snapshot drift
/// between the staleness check and the actual patch.
pub(crate) struct DedicatedGatewayStatusInputs<'a> {
    /// The Gateway under reconcile.
    pub(crate) gw: &'a Gateway,
    /// The provisioned dedicated-proxy Service, if it has been observed via
    /// the operator's Service reflector. `None` on the `InvalidParameters`
    /// path (we never SSA'd anything to look up) — `compute_addresses`
    /// returns an empty list in that case, which keeps the `Programmed`
    /// precedence ladder honest.
    pub(crate) service: Option<&'a Service>,
    /// Snapshot of the operator's Node reflector store. Only consulted when
    /// the Service is `NodePort`-typed; pass `&[]` on other paths.
    pub(crate) nodes: &'a [Arc<Node>],
    /// Listener-health snapshot for this Gateway — read from
    /// `SharedGatewayListenerHealth.load().get(&object_key)`. Pass
    /// `&GatewayListenerHealth::default()` when the reflector hasn't yet
    /// computed an entry; per-listener helpers degrade to healthy defaults.
    pub(crate) tls_health: &'a GatewayListenerHealth,
    /// Ports reserved for the Ingress data plane via the controller's CLI.
    /// Forwarded to `build_listener_status` to detect `PortUnavailable`.
    pub(crate) ingress_ports: IngressPorts,
    /// Result of resolving the Gateway's `parametersRef`.
    pub(crate) accepted: AcceptedOutcome,
    /// Count of dedicated-proxy Pods in the Gateway's namespace whose
    /// `Ready=True` pod-condition is set. Gates `Programmed=True` (must be
    /// `>= 1`) and the `DedicatedProxyReady` cut-over signal.
    pub(crate) ready_pod_count: usize,
}

/// Build the JSON merge patch that sets every owned condition,
/// `status.listeners`, and `status.addresses` in one apiserver round-trip.
///
/// Pure and infallible — given the same inputs produces the same output.
#[must_use]
pub(crate) fn build_dedicated_gateway_status_patch(
    inputs: &DedicatedGatewayStatusInputs<'_>,
    generation: i64,
    now: &Time,
) -> serde_json::Value {
    let addresses = compute_addresses(inputs.service, inputs.nodes);

    let accepted = accepted_outcome(inputs.accepted);
    let programmed = programmed_outcome(inputs.accepted, inputs.ready_pod_count, &addresses);
    let cut_over = cut_over_outcome(inputs.accepted, inputs.ready_pod_count);

    let mut conditions = vec![
        make_condition(
            "Accepted",
            accepted.status,
            accepted.reason,
            accepted.message,
            generation,
            now.clone(),
        ),
        make_condition(
            "Programmed",
            programmed.status,
            programmed.reason,
            programmed.message,
            generation,
            now.clone(),
        ),
        make_condition(
            DEDICATED_PROXY_READY_CONDITION_TYPE,
            cut_over.status,
            cut_over.reason,
            cut_over.message,
            generation,
            now.clone(),
        ),
    ];
    // Preserve any condition NOT owned by this writer. "Owned" =
    //   * the two top-level Gateway-API conditions (`Accepted`, `Programmed`)
    //   * any condition whose type starts with our operator domain prefix.
    // The shared-pool status writer mirrors this convention (it preserves
    // anything prefixed by the operator domain) so the two writers cannot
    // clobber each other even in the brief windows between dedicated-mode
    // toggles.
    if let Some(existing) = inputs
        .gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
    {
        conditions.extend(
            existing
                .iter()
                .filter(|c| {
                    c.type_ != "Accepted"
                        && c.type_ != "Programmed"
                        && !c.type_.starts_with(OPERATOR_OWNED_CONDITION_TYPE_PREFIX)
                })
                .cloned(),
        );
    }

    let listener_statuses: Vec<GatewayStatusListeners> = inputs
        .gw
        .spec
        .listeners
        .iter()
        .map(|l| {
            let info = inputs.tls_health.listeners.get(&l.name);
            build_listener_status(l, info, inputs.ingress_ports, generation, now)
        })
        .collect();

    let address_json: Vec<serde_json::Value> = addresses
        .iter()
        .map(|a| {
            serde_json::json!({
                "type": a.type_.as_str(),
                "value": a.value,
            })
        })
        .collect();

    serde_json::json!({
        "status": {
            "conditions": conditions,
            "listeners": listener_statuses,
            "addresses": address_json,
        }
    })
}

/// Returns true when the Gateway's current `status` does not yet reflect the
/// desired state computed from `inputs`. Prevents redundant patches and
/// watch-feedback loops.
///
/// Compares `(status, reason)` per owned condition — not just
/// `observed_generation` — because pod-readiness transitions don't bump
/// `metadata.generation`, so an observed-gen-only check would miss them.
#[must_use]
pub(crate) fn dedicated_gateway_needs_status_patch(
    inputs: &DedicatedGatewayStatusInputs<'_>,
) -> bool {
    let expected_gen = inputs.gw.metadata.generation.unwrap_or(0);
    let desired_addresses = compute_addresses(inputs.service, inputs.nodes);

    let accepted = accepted_outcome(inputs.accepted);
    let programmed =
        programmed_outcome(inputs.accepted, inputs.ready_pod_count, &desired_addresses);
    let cut_over = cut_over_outcome(inputs.accepted, inputs.ready_pod_count);

    let owned_expected = [
        ("Accepted", accepted.status, accepted.reason),
        ("Programmed", programmed.status, programmed.reason),
        (
            DEDICATED_PROXY_READY_CONDITION_TYPE,
            cut_over.status,
            cut_over.reason,
        ),
    ];

    let current_conditions = inputs
        .gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .unwrap_or(&[]);

    for (type_, want_status, want_reason) in owned_expected {
        let found = current_conditions.iter().find(|c| c.type_ == type_);
        let matches = found.is_some_and(|c: &Condition| {
            c.status == want_status
                && c.reason == want_reason
                && c.observed_generation.unwrap_or(0) >= expected_gen
        });
        if !matches {
            return true;
        }
    }

    let current_listeners = inputs
        .gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_deref())
        .unwrap_or(&[]);
    if current_listeners.len() != inputs.gw.spec.listeners.len() {
        return true;
    }
    for listener in &inputs.gw.spec.listeners {
        let (has_invalid_kinds, _) = listener_route_kind_info(listener);
        let info = inputs.tls_health.listeners.get(&listener.name);
        let desired_healthy =
            !has_invalid_kinds && info.map(|i| i.tls_outcome.is_healthy()).unwrap_or(true);
        let current_listener = current_listeners.iter().find(|sl| sl.name == listener.name);
        let current_resolved = current_listener
            .map(|sl| {
                sl.conditions
                    .iter()
                    .any(|c| c.type_ == "ResolvedRefs" && c.status == "True")
            })
            .unwrap_or(false);
        if desired_healthy != current_resolved {
            return true;
        }
        let desired_attached = info.map(|i| i.attached_routes).unwrap_or(0);
        let current_attached = current_listener.map(|sl| sl.attached_routes).unwrap_or(0);
        if desired_attached != current_attached {
            return true;
        }
        // Generation staleness check for the listener stanza.
        if let Some(sl) = current_listener
            && sl
                .conditions
                .iter()
                .any(|c| c.observed_generation.unwrap_or(0) < expected_gen)
        {
            return true;
        }
    }

    let current_addresses = inputs
        .gw
        .status
        .as_ref()
        .and_then(|s| s.addresses.as_deref())
        .unwrap_or(&[]);
    if current_addresses.len() != desired_addresses.len() {
        return true;
    }
    let current_set: BTreeSet<(String, String)> = current_addresses
        .iter()
        .map(|a: &GatewayStatusAddresses| (a.r#type.clone().unwrap_or_default(), a.value.clone()))
        .collect();
    let desired_set: BTreeSet<(String, String)> = desired_addresses
        .iter()
        .map(|a| (a.type_.as_str().to_string(), a.value.clone()))
        .collect();
    if current_set != desired_set {
        return true;
    }

    false
}

/// Server-side patch entry point: build the merge patch and apply it via the
/// apiserver `/status` subresource.
///
/// Calls [`dedicated_gateway_needs_status_patch`] first; if the current state
/// already matches the desired state, returns `Ok(())` without writing —
/// guards against feedback loops between the operator's Gateway watch and
/// its own patches.
///
/// # Errors
///
/// Returns the underlying [`kube::Error`] if the apiserver rejects the patch
/// (RBAC, resource-version conflict, network).
///
/// # Panics
///
/// Panics if the Gateway has no `metadata.name` or no `metadata.namespace`
/// — both are apiserver invariants on any object reachable through a watch,
/// so a violation indicates a controller bug rather than user input.
pub(crate) async fn patch_dedicated_gateway_status(
    client: &Client,
    inputs: &DedicatedGatewayStatusInputs<'_>,
) -> Result<(), kube::Error> {
    if !dedicated_gateway_needs_status_patch(inputs) {
        return Ok(());
    }
    let name =
        inputs.gw.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    let ns = inputs.gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let generation = inputs.gw.metadata.generation.unwrap_or(0);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let patch = build_dedicated_gateway_status_patch(inputs, generation, &now);
    let api: Api<Gateway> = Api::namespaced(client.clone(), ns);
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    tracing::info!(
        gateway = %format!("{ns}/{name}"),
        accepted = ?inputs.accepted,
        ready_pods = inputs.ready_pod_count,
        listeners = inputs.gw.spec.listeners.len(),
        "operator: patched dedicated Gateway status"
    );
    Ok(())
}

/// Clear every condition this writer owns and reset `status.addresses` on
/// a Gateway that has just transitioned out of dedicated mode (params were
/// removed or now resolve to a different CRD). The shared-pool status writer
/// in [`crate::controller`] takes over on its next Gateway watch event and
/// will re-emit `Accepted=True` / `Programmed=True` from its own perspective.
///
/// Idempotent: if there is nothing to clear, returns `Ok(())` without writing.
///
/// # Errors
///
/// Returns the underlying [`kube::Error`] if the apiserver rejects the patch.
///
/// # Panics
///
/// Panics if the Gateway has no `metadata.name` or no `metadata.namespace`.
pub(crate) async fn clear_dedicated_gateway_status(
    client: &Client,
    gw: &Gateway,
) -> Result<(), kube::Error> {
    let current_conditions = gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .unwrap_or(&[]);
    let preserved: Vec<Condition> = current_conditions
        .iter()
        .filter(|c| {
            c.type_ != "Accepted"
                && c.type_ != "Programmed"
                && c.type_ != DEDICATED_PROXY_READY_CONDITION_TYPE
        })
        .cloned()
        .collect();
    let current_address_count = gw
        .status
        .as_ref()
        .and_then(|s| s.addresses.as_deref())
        .map(<[GatewayStatusAddresses]>::len)
        .unwrap_or(0);
    if preserved.len() == current_conditions.len() && current_address_count == 0 {
        // Nothing to clear — Gateway was either never patched by us or has
        // already been cleared.
        return Ok(());
    }
    let name =
        gw.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    let ns = gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let patch = serde_json::json!({
        "status": {
            "conditions": preserved,
            "addresses": [],
        }
    });
    let api: Api<Gateway> = Api::namespaced(client.clone(), ns);
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

/// One `(status, reason, message)` triple per Gateway-API condition.
#[derive(Debug, Clone, Copy)]
struct ConditionOutcome {
    status: &'static str,
    reason: &'static str,
    message: &'static str,
}

fn accepted_outcome(accepted: AcceptedOutcome) -> ConditionOutcome {
    match accepted {
        AcceptedOutcome::Accepted => ConditionOutcome {
            status: "True",
            reason: REASON_ACCEPTED,
            message: "",
        },
        AcceptedOutcome::InvalidParameters => ConditionOutcome {
            status: "False",
            reason: REASON_INVALID_PARAMETERS,
            message: "parametersRef target CoxswainGatewayParameters object does not exist",
        },
    }
}

/// Precedence ladder for the `Programmed` condition:
/// 1. `Accepted=False` ⇒ `Programmed=False, reason=Invalid`
/// 2. No Ready dedicated-proxy Pod ⇒ `Programmed=False, reason=Pending`
/// 3. No addresses available ⇒ `Programmed=False, reason=AddressNotAssigned`
/// 4. Otherwise ⇒ `Programmed=True, reason=Programmed`
fn programmed_outcome(
    accepted: AcceptedOutcome,
    ready_pod_count: usize,
    addresses: &[StatusAddress],
) -> ConditionOutcome {
    if accepted == AcceptedOutcome::InvalidParameters {
        return ConditionOutcome {
            status: "False",
            reason: REASON_INVALID,
            message: "Gateway spec is invalid; see the Accepted condition for details",
        };
    }
    if ready_pod_count == 0 {
        return ConditionOutcome {
            status: "False",
            reason: REASON_PENDING,
            message: "Awaiting Ready dedicated-proxy Pod",
        };
    }
    if addresses.is_empty() {
        return ConditionOutcome {
            status: "False",
            reason: REASON_ADDRESS_NOT_ASSIGNED,
            message: "Service has no assigned addresses",
        };
    }
    ConditionOutcome {
        status: "True",
        reason: REASON_PROGRAMMED,
        message: "",
    }
}

fn cut_over_outcome(accepted: AcceptedOutcome, ready_pod_count: usize) -> ConditionOutcome {
    if accepted == AcceptedOutcome::Accepted && ready_pod_count >= 1 {
        ConditionOutcome {
            status: "True",
            reason: REASON_READY,
            message: "Dedicated proxy has at least one Ready pod",
        }
    } else {
        ConditionOutcome {
            status: "False",
            reason: REASON_PROVISIONING,
            message: "Dedicated proxy has zero Ready pods",
        }
    }
}

fn compute_addresses(service: Option<&Service>, nodes: &[Arc<Node>]) -> Vec<StatusAddress> {
    let Some(svc) = service else {
        return Vec::new();
    };
    let Some(spec) = svc.spec.as_ref() else {
        return Vec::new();
    };
    match spec.type_.as_deref() {
        Some("LoadBalancer") => compute_lb_addresses(svc),
        Some("NodePort") => compute_nodeport_addresses(nodes),
        Some("ClusterIP") | Some("") | None => compute_clusterip_addresses(spec),
        Some(_) => {
            // Unknown ServiceType — emit no addresses. Programmed will land
            // on AddressNotAssigned until a recognised type is set.
            Vec::new()
        }
    }
}

fn compute_lb_addresses(svc: &Service) -> Vec<StatusAddress> {
    let Some(status) = svc.status.as_ref() else {
        return Vec::new();
    };
    let Some(lb) = status.load_balancer.as_ref() else {
        return Vec::new();
    };
    let Some(ingress) = lb.ingress.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in ingress {
        if let Some(ip) = entry.ip.as_deref().filter(|s| !s.is_empty()) {
            out.push(StatusAddress {
                type_: AddressType::IpAddress,
                value: ip.to_string(),
            });
            continue;
        }
        if let Some(host) = entry.hostname.as_deref().filter(|s| !s.is_empty()) {
            out.push(StatusAddress {
                type_: AddressType::Hostname,
                value: host.to_string(),
            });
        }
    }
    out
}

fn compute_clusterip_addresses(spec: &ServiceSpec) -> Vec<StatusAddress> {
    let Some(ip) = spec.cluster_ip.as_deref() else {
        return Vec::new();
    };
    // `"None"` marks a headless Service; an empty string is the apiserver's
    // pre-allocation transient state. Neither is a usable address.
    if ip.is_empty() || ip == "None" {
        return Vec::new();
    }
    vec![StatusAddress {
        type_: AddressType::IpAddress,
        value: ip.to_string(),
    }]
}

/// Enumerate NodePort-reachable Node IPs.
///
/// Gateway API `status.addresses` carries bare IPs/hostnames, not host:port,
/// so the port part of the NodePort surface is implicit (read from the
/// Service spec). We surface the cluster's Node `ExternalIP`s; if no Node
/// has an `ExternalIP` (common in single-node dev clusters), fall back to
/// `InternalIP` so the address list is non-empty. Both lists are deduped via
/// a `BTreeSet` so the patch is deterministic.
fn compute_nodeport_addresses(nodes: &[Arc<Node>]) -> Vec<StatusAddress> {
    let mut external: BTreeSet<String> = BTreeSet::new();
    let mut internal: BTreeSet<String> = BTreeSet::new();
    for node in nodes {
        let Some(addresses) = node.status.as_ref().and_then(|s| s.addresses.as_ref()) else {
            continue;
        };
        for addr in addresses {
            match addr.type_.as_str() {
                "ExternalIP" => {
                    external.insert(addr.address.clone());
                }
                "InternalIP" => {
                    internal.insert(addr.address.clone());
                }
                _ => {}
            }
        }
    }
    let chosen = if external.is_empty() {
        internal
    } else {
        external
    };
    chosen
        .into_iter()
        .map(|v| StatusAddress {
            type_: AddressType::IpAddress,
            value: v,
        })
        .collect()
}

/// Compose `<gw-name>-<gateway-class>` per GEP-1762 — the rendered Service
/// name to look up in [`crate::operator::reconciler::ReconcileContext::services_store`].
///
/// Mirrored from `super::render::resource_name`; kept inline here so the
/// status writer's contract is self-contained (the renderer's helper is
/// private to its module).
#[must_use]
pub(crate) fn resource_name(gw_name: &str, gateway_class_name: &str) -> String {
    format!("{gw_name}-{gateway_class_name}")
}

#[cfg(test)]
mod tests {
    use super::{
        AcceptedOutcome, DEDICATED_PROXY_READY_CONDITION_TYPE, DedicatedGatewayStatusInputs,
        build_dedicated_gateway_status_patch, dedicated_gateway_needs_status_patch,
    };
    use coxswain_reflector::gw_types::v::gateways::{
        Gateway, GatewayListeners, GatewaySpec, GatewayStatus, GatewayStatusAddresses,
        GatewayStatusListeners,
    };
    use coxswain_reflector::ingress::IngressPorts;
    use coxswain_reflector::tls::GatewayListenerHealth;
    use k8s_openapi::api::core::v1::{
        LoadBalancerIngress, LoadBalancerStatus, Node, NodeAddress, NodeStatus, Service,
        ServiceSpec, ServiceStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
    use kube::api::ObjectMeta;
    use std::sync::Arc;

    fn epoch() -> Time {
        Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH)
    }

    fn gateway(
        generation: i64,
        listeners: Vec<(&str, i32)>,
        status: Option<GatewayStatus>,
    ) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some("my-gw".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(generation),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners: listeners
                    .into_iter()
                    .map(|(name, port)| GatewayListeners {
                        name: name.to_string(),
                        port,
                        protocol: "HTTP".to_string(),
                        hostname: None,
                        tls: None,
                        allowed_routes: None,
                    })
                    .collect(),
                ..Default::default()
            },
            status,
        }
    }

    fn service_loadbalancer(ingress: Vec<LoadBalancerIngress>) -> Service {
        Service {
            metadata: ObjectMeta::default(),
            spec: Some(ServiceSpec {
                type_: Some("LoadBalancer".to_string()),
                ..Default::default()
            }),
            status: Some(ServiceStatus {
                load_balancer: Some(LoadBalancerStatus {
                    ingress: Some(ingress),
                }),
                ..Default::default()
            }),
        }
    }

    fn service_clusterip(cluster_ip: &str) -> Service {
        Service {
            metadata: ObjectMeta::default(),
            spec: Some(ServiceSpec {
                type_: Some("ClusterIP".to_string()),
                cluster_ip: Some(cluster_ip.to_string()),
                ..Default::default()
            }),
            status: None,
        }
    }

    fn service_nodeport() -> Service {
        Service {
            metadata: ObjectMeta::default(),
            spec: Some(ServiceSpec {
                type_: Some("NodePort".to_string()),
                ..Default::default()
            }),
            status: None,
        }
    }

    fn node(addresses: Vec<(&str, &str)>) -> Arc<Node> {
        Arc::new(Node {
            metadata: ObjectMeta::default(),
            spec: None,
            status: Some(NodeStatus {
                addresses: Some(
                    addresses
                        .into_iter()
                        .map(|(type_, addr)| NodeAddress {
                            type_: type_.to_string(),
                            address: addr.to_string(),
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
        })
    }

    fn empty_health() -> &'static GatewayListenerHealth {
        use std::sync::OnceLock;
        static H: OnceLock<GatewayListenerHealth> = OnceLock::new();
        H.get_or_init(GatewayListenerHealth::default)
    }

    fn inputs<'a>(
        gw: &'a Gateway,
        service: Option<&'a Service>,
        nodes: &'a [Arc<Node>],
        health: &'a GatewayListenerHealth,
        accepted: AcceptedOutcome,
        ready_pods: usize,
    ) -> DedicatedGatewayStatusInputs<'a> {
        DedicatedGatewayStatusInputs {
            gw,
            service,
            nodes,
            tls_health: health,
            ingress_ports: IngressPorts::new(None, None),
            accepted,
            ready_pod_count: ready_pods,
        }
    }

    /// Extract a `(status, reason)` pair from the produced patch's
    /// `status.conditions[type=...]` entry.
    fn condition_of(patch: &serde_json::Value, type_: &str) -> Option<(String, String)> {
        patch["status"]["conditions"]
            .as_array()?
            .iter()
            .find(|c| c["type"].as_str() == Some(type_))
            .map(|c| {
                (
                    c["status"].as_str().unwrap_or("").to_string(),
                    c["reason"].as_str().unwrap_or("").to_string(),
                )
            })
    }

    fn addresses_of(patch: &serde_json::Value) -> Vec<(String, String)> {
        patch["status"]["addresses"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|a| {
                        (
                            a["type"].as_str().unwrap_or("").to_string(),
                            a["value"].as_str().unwrap_or("").to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    // ============================================================================
    // compute_addresses — three ServiceType branches
    // ============================================================================

    #[test]
    fn loadbalancer_ingress_ip_becomes_ip_address() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_loadbalancer(vec![LoadBalancerIngress {
            ip: Some("203.0.113.1".to_string()),
            hostname: None,
            ..Default::default()
        }]);
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            addresses_of(&patch),
            vec![("IPAddress".to_string(), "203.0.113.1".to_string())]
        );
    }

    #[test]
    fn loadbalancer_ingress_hostname_becomes_hostname() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_loadbalancer(vec![LoadBalancerIngress {
            ip: None,
            hostname: Some("gw.example.com".to_string()),
            ..Default::default()
        }]);
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            addresses_of(&patch),
            vec![("Hostname".to_string(), "gw.example.com".to_string())]
        );
    }

    #[test]
    fn clusterip_yields_ip_address() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            addresses_of(&patch),
            vec![("IPAddress".to_string(), "10.96.7.42".to_string())]
        );
    }

    #[test]
    fn clusterip_none_drops_to_empty() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_clusterip("None");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert!(addresses_of(&patch).is_empty());
    }

    #[test]
    fn nodeport_prefers_external_ip() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_nodeport();
        let nodes = vec![
            node(vec![
                ("ExternalIP", "198.51.100.1"),
                ("InternalIP", "10.0.0.1"),
            ]),
            node(vec![
                ("ExternalIP", "198.51.100.2"),
                ("InternalIP", "10.0.0.2"),
            ]),
        ];
        let inputs = inputs(
            &gw,
            Some(&svc),
            &nodes,
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        let addrs = addresses_of(&patch);
        assert_eq!(addrs.len(), 2, "addresses: {addrs:?}");
        assert!(addrs.contains(&("IPAddress".to_string(), "198.51.100.1".to_string())));
        assert!(addrs.contains(&("IPAddress".to_string(), "198.51.100.2".to_string())));
        assert!(!addrs.iter().any(|(_, v)| v.starts_with("10.0.0."))); // No InternalIP fallback.
    }

    #[test]
    fn nodeport_falls_back_to_internal_ip() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_nodeport();
        // No ExternalIP on any Node — fallback should kick in.
        let nodes = vec![node(vec![("InternalIP", "10.0.0.1")])];
        let inputs = inputs(
            &gw,
            Some(&svc),
            &nodes,
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            addresses_of(&patch),
            vec![("IPAddress".to_string(), "10.0.0.1".to_string())]
        );
    }

    #[test]
    fn nodeport_dedupes_repeated_addresses() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_nodeport();
        let nodes = vec![
            node(vec![("ExternalIP", "198.51.100.1")]),
            node(vec![("ExternalIP", "198.51.100.1")]), // Duplicate.
        ];
        let inputs = inputs(
            &gw,
            Some(&svc),
            &nodes,
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(addresses_of(&patch).len(), 1);
    }

    // ============================================================================
    // Programmed precedence ladder
    // ============================================================================

    #[test]
    fn programmed_invalid_when_accepted_false() {
        let gw = gateway(1, vec![("http", 80)], None);
        let inputs = inputs(
            &gw,
            None,
            &[],
            empty_health(),
            AcceptedOutcome::InvalidParameters,
            0,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            condition_of(&patch, "Accepted"),
            Some(("False".to_string(), "InvalidParameters".to_string()))
        );
        assert_eq!(
            condition_of(&patch, "Programmed"),
            Some(("False".to_string(), "Invalid".to_string())),
            "InvalidParameters dominates Pending and AddressNotAssigned"
        );
    }

    #[test]
    fn programmed_pending_when_no_ready_pod() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            0,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            condition_of(&patch, "Programmed"),
            Some(("False".to_string(), "Pending".to_string()))
        );
    }

    #[test]
    fn programmed_address_not_assigned_when_no_addresses() {
        let gw = gateway(1, vec![("http", 80)], None);
        // LoadBalancer Service with empty ingress — Pod ready but no address yet.
        let svc = service_loadbalancer(vec![]);
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            condition_of(&patch, "Programmed"),
            Some(("False".to_string(), "AddressNotAssigned".to_string()))
        );
    }

    #[test]
    fn programmed_true_when_pod_ready_and_address_assigned() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            condition_of(&patch, "Accepted"),
            Some(("True".to_string(), "Accepted".to_string()))
        );
        assert_eq!(
            condition_of(&patch, "Programmed"),
            Some(("True".to_string(), "Programmed".to_string()))
        );
    }

    // ============================================================================
    // DedicatedProxyReady cut-over signal — emitted in the same patch
    // ============================================================================

    #[test]
    fn dedicated_proxy_ready_in_same_patch_when_pod_ready() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            2,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            condition_of(&patch, DEDICATED_PROXY_READY_CONDITION_TYPE),
            Some(("True".to_string(), "Ready".to_string())),
            "cut-over condition rides the same patch (not a separate write)"
        );
    }

    #[test]
    fn dedicated_proxy_ready_false_when_no_ready_pod() {
        let gw = gateway(1, vec![("http", 80)], None);
        let inputs = inputs(&gw, None, &[], empty_health(), AcceptedOutcome::Accepted, 0);
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            condition_of(&patch, DEDICATED_PROXY_READY_CONDITION_TYPE),
            Some(("False".to_string(), "Provisioning".to_string()))
        );
    }

    #[test]
    fn dedicated_proxy_ready_false_when_invalid_parameters() {
        let gw = gateway(1, vec![("http", 80)], None);
        // Even with a ready pod, InvalidParameters means the cut-over signal
        // must stay False — the dedicated pool isn't authoritative.
        let inputs = inputs(
            &gw,
            None,
            &[],
            empty_health(),
            AcceptedOutcome::InvalidParameters,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        assert_eq!(
            condition_of(&patch, DEDICATED_PROXY_READY_CONDITION_TYPE),
            Some(("False".to_string(), "Provisioning".to_string()))
        );
    }

    // ============================================================================
    // Foreign-condition preservation
    // ============================================================================

    #[test]
    fn foreign_conditions_preserved_across_patch() {
        let foreign = Condition {
            type_: "external-policy.example.com/Audit".to_string(),
            status: "True".to_string(),
            reason: "Compliant".to_string(),
            message: String::new(),
            observed_generation: Some(1),
            last_transition_time: epoch(),
        };
        let gw = gateway(
            1,
            vec![("http", 80)],
            Some(GatewayStatus {
                conditions: Some(vec![foreign.clone()]),
                ..Default::default()
            }),
        );
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
        let types: Vec<String> = patch["status"]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["type"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(
            types.contains(&"external-policy.example.com/Audit".to_string()),
            "foreign condition must survive a patch: got {types:?}"
        );
        assert!(types.contains(&"Accepted".to_string()));
        assert!(types.contains(&"Programmed".to_string()));
        assert!(types.contains(&DEDICATED_PROXY_READY_CONDITION_TYPE.to_string()));
    }

    // ============================================================================
    // dedicated_gateway_needs_status_patch — idempotence
    // ============================================================================

    fn cond(type_: &str, status: &str, reason: &str, observed_gen: i64) -> Condition {
        Condition {
            type_: type_.to_string(),
            status: status.to_string(),
            reason: reason.to_string(),
            message: String::new(),
            observed_generation: Some(observed_gen),
            last_transition_time: epoch(),
        }
    }

    fn listener_status(
        name: &str,
        observed_gen: i64,
        resolved_refs: bool,
        attached: i32,
    ) -> GatewayStatusListeners {
        GatewayStatusListeners {
            name: name.to_string(),
            attached_routes: attached,
            supported_kinds: None,
            conditions: vec![
                cond("Accepted", "True", "Accepted", observed_gen),
                cond(
                    "ResolvedRefs",
                    if resolved_refs { "True" } else { "False" },
                    "ResolvedRefs",
                    observed_gen,
                ),
                cond("Programmed", "True", "Programmed", observed_gen),
            ],
        }
    }

    #[test]
    fn needs_patch_true_when_no_status() {
        let gw = gateway(1, vec![("http", 80)], None);
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        assert!(dedicated_gateway_needs_status_patch(&inputs));
    }

    #[test]
    fn needs_patch_false_when_fully_in_sync() {
        // Gateway already carries the exact set of conditions + listener +
        // addresses the writer would emit.
        let gw = gateway(
            1,
            vec![("http", 80)],
            Some(GatewayStatus {
                conditions: Some(vec![
                    cond("Accepted", "True", "Accepted", 1),
                    cond("Programmed", "True", "Programmed", 1),
                    cond(DEDICATED_PROXY_READY_CONDITION_TYPE, "True", "Ready", 1),
                ]),
                listeners: Some(vec![listener_status("http", 1, true, 0)]),
                addresses: Some(vec![GatewayStatusAddresses {
                    r#type: Some("IPAddress".to_string()),
                    value: "10.96.7.42".to_string(),
                }]),
                ..Default::default()
            }),
        );
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        assert!(
            !dedicated_gateway_needs_status_patch(&inputs),
            "idempotence: fully-converged Gateway must not repatch"
        );
    }

    #[test]
    fn needs_patch_true_when_status_reason_flips_without_generation_bump() {
        // Critical: pod-readiness transitions don't bump metadata.generation,
        // so an observed-generation-only check would miss this.
        let gw = gateway(
            1,
            vec![("http", 80)],
            Some(GatewayStatus {
                conditions: Some(vec![
                    cond("Accepted", "True", "Accepted", 1),
                    // Old reason was Pending; the new reconcile has a ready pod.
                    cond("Programmed", "False", "Pending", 1),
                    cond(
                        DEDICATED_PROXY_READY_CONDITION_TYPE,
                        "False",
                        "Provisioning",
                        1,
                    ),
                ]),
                listeners: Some(vec![listener_status("http", 1, true, 0)]),
                addresses: Some(vec![GatewayStatusAddresses {
                    r#type: Some("IPAddress".to_string()),
                    value: "10.96.7.42".to_string(),
                }]),
                ..Default::default()
            }),
        );
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        assert!(
            dedicated_gateway_needs_status_patch(&inputs),
            "(status, reason) flip must trigger a repatch even when generation is unchanged"
        );
    }

    #[test]
    fn needs_patch_true_when_addresses_drift() {
        let gw = gateway(
            1,
            vec![("http", 80)],
            Some(GatewayStatus {
                conditions: Some(vec![
                    cond("Accepted", "True", "Accepted", 1),
                    cond("Programmed", "True", "Programmed", 1),
                    cond(DEDICATED_PROXY_READY_CONDITION_TYPE, "True", "Ready", 1),
                ]),
                listeners: Some(vec![listener_status("http", 1, true, 0)]),
                // Stale: a different IP from the current Service spec.
                addresses: Some(vec![GatewayStatusAddresses {
                    r#type: Some("IPAddress".to_string()),
                    value: "10.96.7.99".to_string(),
                }]),
                ..Default::default()
            }),
        );
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        assert!(dedicated_gateway_needs_status_patch(&inputs));
    }

    #[test]
    fn needs_patch_true_when_generation_stale() {
        // GEP-1364: an observed_generation lagging metadata.generation means
        // the spec has moved on — repatch even if (status, reason) match.
        let gw = gateway(
            3, // bumped from 1
            vec![("http", 80)],
            Some(GatewayStatus {
                conditions: Some(vec![
                    cond("Accepted", "True", "Accepted", 1),
                    cond("Programmed", "True", "Programmed", 1),
                    cond(DEDICATED_PROXY_READY_CONDITION_TYPE, "True", "Ready", 1),
                ]),
                listeners: Some(vec![listener_status("http", 1, true, 0)]),
                addresses: Some(vec![GatewayStatusAddresses {
                    r#type: Some("IPAddress".to_string()),
                    value: "10.96.7.42".to_string(),
                }]),
                ..Default::default()
            }),
        );
        let svc = service_clusterip("10.96.7.42");
        let inputs = inputs(
            &gw,
            Some(&svc),
            &[],
            empty_health(),
            AcceptedOutcome::Accepted,
            1,
        );
        assert!(dedicated_gateway_needs_status_patch(&inputs));
    }
}
