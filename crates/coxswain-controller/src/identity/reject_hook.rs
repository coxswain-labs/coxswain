//! [`BootstrapRejectHook`] — emits a `BootstrapRejected` Kubernetes Warning Event
//! when the bootstrap listener rejects a proxy certificate request.
//!
//! Implements [`coxswain_discovery::RejectHook`].  The controller is the sole
//! diagnostic emitter per crate charter; `coxswain-discovery` itself never
//! touches the Kubernetes API.
//!
//! # Implementation
//!
//! `on_reject` is a synchronous trait method, but publishing a K8s Event is
//! async.  We clone the `Recorder` (cheap — it wraps `kube::Client` which is
//! `Arc`-backed) and spawn a fire-and-forget Tokio task.  A failed publish
//! only logs a warning; it does not fail the bootstrap path or abort the
//! controller.

use k8s_openapi::api::core::v1::ObjectReference;
use kube::runtime::events::{Event, EventType, Recorder};

use coxswain_discovery::RejectHook;

// ── BootstrapRejectHook ───────────────────────────────────────────────────────

/// Emits a `BootstrapRejected` Warning Event for every rejected bootstrap.
///
/// The `reference` is set to the controller Pod so `kubectl describe pod <name>`
/// and `kubectl get events` in the controller namespace both surface rejections.
#[non_exhaustive]
pub struct BootstrapRejectHook {
    recorder: Recorder,
    /// `ObjectReference` pointing at the controller Pod (populated from
    /// `POD_NAME` / `POD_NAMESPACE` downward-API env vars at startup).
    pod_ref: ObjectReference,
}

impl BootstrapRejectHook {
    /// Create a hook that publishes events via `recorder` referencing `pod_ref`.
    #[must_use]
    pub fn new(recorder: Recorder, pod_ref: ObjectReference) -> Self {
        Self { recorder, pod_ref }
    }
}

impl RejectHook for BootstrapRejectHook {
    fn on_reject(&self, principal: &str, reason: &str) {
        let recorder = self.recorder.clone();
        let pod_ref = self.pod_ref.clone();
        let note = format!("Bootstrap rejected for '{principal}': {reason}");
        tokio::spawn(async move {
            if let Err(e) = recorder
                .publish(
                    &Event {
                        action: "BootstrapRejected".into(),
                        reason: "BootstrapRejected".into(),
                        note: Some(note),
                        type_: EventType::Warning,
                        secondary: None,
                    },
                    &pod_ref,
                )
                .await
            {
                tracing::warn!(error = %e, "Failed to publish BootstrapRejected Warning Event");
            }
        });
    }
}
