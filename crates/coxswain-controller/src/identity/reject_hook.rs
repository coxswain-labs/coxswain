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
use kube::Client;
use kube::runtime::events::{Event, EventType, Recorder, Reporter};

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

    /// Build a hook from a `kube::Client` and the controller's identity.
    ///
    /// Constructs the event [`Recorder`] (with a [`Reporter`] tagged by
    /// `controller_name`/`pod_name`) and the controller-Pod [`ObjectReference`]
    /// internally, so the bin layer needs no `kube::runtime::events` /
    /// `k8s-openapi` imports of its own.
    #[must_use]
    pub fn from_client(
        client: Client,
        controller_name: impl Into<String>,
        pod_name: String,
        pod_namespace: String,
    ) -> Self {
        let reporter = Reporter {
            controller: controller_name.into(),
            instance: Some(pod_name.clone()),
        };
        let recorder = Recorder::new(client, reporter);
        let pod_ref = ObjectReference {
            // `regarding` must carry apiVersion + kind or the events.k8s.io/v1
            // API rejects the Event as invalid and `Recorder::publish` fails —
            // the Warning never appears. Pods are core/v1.
            api_version: Some("v1".to_owned()),
            kind: Some("Pod".to_owned()),
            name: Some(pod_name),
            namespace: Some(pod_namespace),
            ..Default::default()
        };
        Self::new(recorder, pod_ref)
    }
}

impl RejectHook for BootstrapRejectHook {
    async fn on_reject(&self, principal: &str, reason: &str) {
        let note = format!("Bootstrap rejected for '{principal}': {reason}");
        // Awaited inline by the bootstrap handler (see [`RejectHook::on_reject`]).
        // The discovery server runs as a Pingora background service whose runtime
        // does not reliably drive orphaned tasks, so a detached `tokio::spawn`
        // here can silently never publish — the publish must run on the handler's
        // own task.
        if let Err(e) = self
            .recorder
            .publish(
                &Event {
                    action: "BootstrapRejected".into(),
                    reason: "BootstrapRejected".into(),
                    note: Some(note),
                    type_: EventType::Warning,
                    secondary: None,
                },
                &self.pod_ref,
            )
            .await
        {
            tracing::warn!(error = %e, "Failed to publish BootstrapRejected Warning Event");
        }
    }
}
