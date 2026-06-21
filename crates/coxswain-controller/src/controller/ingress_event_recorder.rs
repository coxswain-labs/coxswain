//! Consumer task for Ingress diagnostic events emitted by the reconciler.
//!
//! Receives [`IngressEvent`]s from the shared-proxy reconciler rebuild path
//! and emits Kubernetes `Warning` Events on the affected Ingress objects.
//! Deduplication is handled by the kube [`Recorder`]'s internal per-process
//! cache, so a resync storm does not create duplicate `kubectl describe` entries.
//!
//! RBAC: the controller `ClusterRole` must include
//! `apiGroups: ["events.k8s.io"], resources: ["events"], verbs: ["create","patch"]`.

use coxswain_reflector::IngressEvent;
use k8s_openapi::api::core::v1::ObjectReference;
use kube::{
    Client,
    runtime::events::{Event, EventType, Recorder, Reporter},
};
use tokio::sync::mpsc;

/// Drive the Ingress event recorder loop until the channel is closed.
///
/// Emits a Kubernetes `Warning` Event on the affected Ingress for each received
/// [`IngressEvent`]. Runs as a long-lived task inside [`crate::Controller`];
/// returns when the sender side of the channel is dropped (reconciler shutdown).
pub(super) async fn run(client: Client, reporter: Reporter, mut rx: mpsc::Receiver<IngressEvent>) {
    let recorder = Recorder::new(client, reporter);

    while let Some(event) = rx.recv().await {
        match event {
            IngressEvent::Conflict {
                namespace,
                name,
                ref winner_route_id,
                ref host,
                ref path,
            } => {
                tracing::warn!(
                    ingress = %format!("{namespace}/{name}"),
                    winner = %winner_route_id,
                    %host,
                    %path,
                    "Route conflict: Ingress shadowed by an earlier rule"
                );
                let reference = ObjectReference {
                    api_version: Some("networking.k8s.io/v1".into()),
                    kind: Some("Ingress".into()),
                    name: Some(name),
                    namespace: Some(namespace),
                    ..Default::default()
                };
                if let Err(e) = recorder
                    .publish(
                        &Event {
                            action: "RouteConflict".into(),
                            reason: "RouteConflict".into(),
                            note: Some(format!(
                                "Route on host {host} path {path} is shadowed by {winner_route_id}"
                            )),
                            type_: EventType::Warning,
                            secondary: None,
                        },
                        &reference,
                    )
                    .await
                {
                    tracing::warn!(error = %e, "Failed to publish RouteConflict Warning Event");
                }
            }
            IngressEvent::InvalidAnnotation {
                namespace,
                name,
                annotation,
                ref message,
            } => {
                tracing::warn!(
                    ingress = %format!("{namespace}/{name}"),
                    %annotation,
                    %message,
                    "Invalid annotation on Ingress"
                );
                let reference = ObjectReference {
                    api_version: Some("networking.k8s.io/v1".into()),
                    kind: Some("Ingress".into()),
                    name: Some(name),
                    namespace: Some(namespace),
                    ..Default::default()
                };
                if let Err(e) = recorder
                    .publish(
                        &Event {
                            action: "InvalidAnnotation".into(),
                            reason: "InvalidAnnotation".into(),
                            note: Some(format!("{annotation}: {message}")),
                            type_: EventType::Warning,
                            secondary: None,
                        },
                        &reference,
                    )
                    .await
                {
                    tracing::warn!(error = %e, "Failed to publish InvalidAnnotation Warning Event");
                }
            }
            _ => {}
        }
    }
}
