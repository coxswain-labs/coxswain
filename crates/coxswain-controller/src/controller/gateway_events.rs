//! Kubernetes API calls that write `Gateway` status patches.

use super::gateway_status::{SharedAddressDecision, build_gateway_status_patch};
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::status::GatewayListenerStatus;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

// Single patch call sets all Gateway conditions, listener statuses, and addresses at once.
// A JSON merge patch replaces the entire conditions array, so splitting calls
// would cause conditions to toggle in a watch-feedback loop.

/// Outcome of one Gateway status patch attempt, driving the caller's requeue
/// choice (#570). The desired status is on the object only for [`Self::Landed`];
/// either failure variant means the caller must requeue (never `await_change`)
/// because relying on the conflicting writer's watch event alone leaves a
/// missed/coalesced event stranding stale conditions indefinitely (observed
/// as conformance gateways stuck at observedGeneration 0). The retry is a
/// fresh reconcile that recomputes the decision from current state — never an
/// in-place resend of this (stale) patch, which would reintroduce the #531
/// clobber.
pub(super) enum GatewayPatchOutcome {
    /// The write landed — or was structurally impossible (no name/generation)
    /// and retrying cannot help.
    Landed,
    /// 409 stale-view conflict: the pinned `resourceVersion` lost the race. A
    /// prompt retry is correct — the conflict itself proves fresh state exists.
    Conflict,
    /// Any other API error (RBAC, webhook rejection, transport). Possibly
    /// persistent: retry on the slow error cadence, not the prompt one, so a
    /// misconfigured install doesn't hammer the apiserver at the deferred
    /// cadence forever (mirrors the operator's persistent-class backoff).
    Failed,
}

pub(super) async fn patch_gateway_status(
    client: &Client,
    gw: &Gateway,
    health: &GatewayListenerStatus,
    decision: &SharedAddressDecision,
    ingress_ports: IngressPorts,
) -> GatewayPatchOutcome {
    let name = match gw.metadata.name.as_deref() {
        Some(n) => n,
        None => return GatewayPatchOutcome::Landed,
    };
    let ns = gw.metadata.namespace.as_deref().unwrap_or("default");
    let Some(generation) = gw.metadata.generation else {
        tracing::warn!(
            name,
            ns,
            "Skipping Gateway status patch: metadata.generation is unset"
        );
        return GatewayPatchOutcome::Landed;
    };
    let api: Api<Gateway> = Api::namespaced(client.clone(), ns);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    // GEP-91 (#86): warn when the frontend CA ref did not resolve so that operators
    // can see the failure in controller logs.  The proxy already fail-closes all
    // handshakes to the affected hostnames until the ConfigMap is corrected.
    if let Some(fv) = health.frontend_validation.as_ref()
        && !fv.resolved_refs
    {
        tracing::warn!(
            name,
            ns,
            message = %fv.message,
            "Gateway frontend CA ref unresolvable — proxy fail-closing mTLS handshakes"
        );
    }
    let mut patch =
        build_gateway_status_patch(gw, health, generation, &now, decision, ingress_ports);
    // Optimistic concurrency (#531): the decision above was computed from a
    // possibly-lagging store object — the work queue can deliver a reconcile
    // holding a pre-latch Gateway AFTER a newer reconcile already published
    // `Programmed=True` + addresses, and an unconditional merge patch from
    // that stale view clobbers the fresh status (observed as `True` with
    // empty `status.addresses` in the conformance GatewayStaticAddresses
    // read window). Pinning the observed `resourceVersion` makes the
    // apiserver reject the stale write with 409 Conflict instead; the very
    // conflict proves a newer object event is on its way, which re-drives
    // this reconcile with fresh state.
    if let Some(rv) = gw.metadata.resource_version.as_deref() {
        patch["metadata"] = serde_json::json!({ "resourceVersion": rv });
    }
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("gateway", started, &result);
    match result {
        Ok(_) => {
            tracing::info!(name, ns, "Gateway status patched");
            GatewayPatchOutcome::Landed
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 409 => {
            tracing::debug!(
                name,
                ns,
                "Gateway status patch skipped: object changed since this reconcile \
                 observed it (stale view); requeueing to recompute from fresh state"
            );
            GatewayPatchOutcome::Conflict
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 => {
            // The Gateway was deleted after this reconcile read it from the
            // (lagging) store. Retrying is not just pointless, it is harmful:
            // a Failed→requeue here self-sustains forever on an object that
            // will never reappear, spamming the apiserver and keeping the
            // work queue hot until the store catches up (observed in CI:
            // deleted conformance fixtures still being patched 20 minutes
            // after deletion). The store's DELETE event is the authoritative
            // terminal signal — report Landed so the caller goes quiet.
            tracing::debug!(
                name,
                ns,
                "Gateway status patch skipped: object deleted; awaiting the store's delete event"
            );
            GatewayPatchOutcome::Landed
        }
        Err(e) => {
            tracing::warn!(name, ns, error = %e, "Failed to patch Gateway status");
            GatewayPatchOutcome::Failed
        }
    }
}
