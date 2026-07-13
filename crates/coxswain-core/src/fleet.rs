//! Fleet discovery: live snapshot of every coxswain pod in the cluster.
//!
//! The controller's reflector pipeline maintains a [`SharedFleet`] cell that is
//! updated on every `Pod` watch event (no debounce — pod IP / annotation changes are
//! infrequent and low-latency matters for operator tooling). Downstream users such as
//! the admin REST API (#249, #251) load the snapshot via [`SharedFleet::load`].
//!
//! The pure snapshot-building logic lives in [`build_snapshot`], which is
//! intentionally separated from the reflector store so it can be exercised in
//! unit tests without a running Kubernetes watch.

use crate::shared::Shared;
use k8s_openapi::api::core::v1::Pod;
use std::net::IpAddr;
use std::time::Instant;

// ── label / annotation keys ──────────────────────────────────────────────────

/// Label key carrying the pod role (`controller` / `shared-proxy` /
/// `dedicated-proxy` / `relay`).
pub const COMPONENT_LABEL: &str = "app.kubernetes.io/component";

/// Annotation key carrying the admin server port for this pod.
pub const ADMIN_PORT_ANNOTATION: &str = "gateway.coxswain-labs.dev/admin-port";

/// Label key present on dedicated-proxy pods that identifies the owning Gateway name.
pub const GATEWAY_NAME_LABEL: &str = "gateway.networking.k8s.io/gateway-name";

// ── Component ────────────────────────────────────────────────────────────────

/// The role a coxswain pod plays in the cluster.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// A controller-role pod (`serve controller`).
    Controller,
    /// A shared-pool proxy pod (`serve proxy --shared`).
    SharedProxy,
    /// A per-Gateway dedicated proxy pod (`serve proxy --dedicated`).
    DedicatedProxy,
    /// A relay-tier discovery cache pod (`serve relay`): subscribes upstream to
    /// the controller and re-serves the snapshot stream downstream to proxies.
    Relay,
}

impl Component {
    fn from_label(s: &str) -> Option<Self> {
        match s {
            "controller" => Some(Self::Controller),
            "shared-proxy" => Some(Self::SharedProxy),
            "dedicated-proxy" => Some(Self::DedicatedProxy),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

// ── FleetEntry / FleetSnapshot ────────────────────────────────────────────────

/// A single pod in the coxswain fleet.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FleetEntry {
    /// Value of `metadata.name`.
    pub pod_name: String,
    /// Value of `metadata.namespace`.
    pub pod_namespace: String,
    /// Parsed `status.podIP`.
    pub pod_ip: IpAddr,
    /// Admin server port, from the [`ADMIN_PORT_ANNOTATION`] annotation.
    pub admin_port: u16,
    /// Role this pod plays in the cluster.
    pub component: Component,
    /// For [`Component::DedicatedProxy`] pods: the owning Gateway name (from
    /// [`GATEWAY_NAME_LABEL`]). `None` for all other components.
    pub gateway_ref: Option<String>,
    /// Node the pod is scheduled on (`spec.nodeName`); `None` until scheduled.
    pub node: Option<String>,
    /// Total container restarts (`sum(status.containerStatuses[].restartCount)`) —
    /// the crash-loop signal.
    pub restarts: i32,
    /// Pod phase (`status.phase`), e.g. `"Running"`.
    pub phase: Option<String>,
    /// Pod creation timestamp (`metadata.creationTimestamp`) as RFC3339, for age.
    pub created_at: Option<String>,
    /// Wall-clock time at which this entry was last observed (i.e. when the
    /// snapshot that contains it was built).
    pub last_seen: Instant,
}

/// Snapshot of the entire coxswain fleet, bucketed by [`Component`].
///
/// Published into a [`SharedFleet`] on every `Pod` watch event by the
/// controller's reflector pipeline.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct FleetSnapshot {
    /// Controller-role pods.
    pub controllers: Vec<FleetEntry>,
    /// Shared-pool proxy pods.
    pub shared_proxies: Vec<FleetEntry>,
    /// Per-Gateway dedicated proxy pods.
    pub dedicated_proxies: Vec<FleetEntry>,
    /// Relay-tier discovery cache pods.
    pub relays: Vec<FleetEntry>,
}

/// Lock-free shared handle to the latest [`FleetSnapshot`].
///
/// Cheaply cloneable; callers load the snapshot via [`Shared::load`] and write
/// via [`Shared::store`]. The controller's reflector pipeline is the sole writer.
pub type SharedFleet = Shared<FleetSnapshot>;

// ── build_snapshot ────────────────────────────────────────────────────────────

/// Build a [`FleetSnapshot`] from an iterable of `Pod` references.
///
/// Per pod:
/// - Pods without `status.podIP` are **silently skipped** (not yet scheduled
///   or running).
/// - Pods with a missing or unparseable [`ADMIN_PORT_ANNOTATION`] emit a
///   `tracing::warn!` and are skipped.
/// - Pods with an unknown `app.kubernetes.io/component` label value are
///   skipped with a warning.
/// - All other pods are inserted into the appropriate bucket.
///
/// The function is pure and allocation-only — no I/O, no async.
pub fn build_snapshot<'a>(pods: impl IntoIterator<Item = &'a Pod>) -> FleetSnapshot {
    let now = Instant::now();
    let mut snapshot = FleetSnapshot::default();

    for pod in pods {
        let pod_name = pod.metadata.name.as_deref().unwrap_or_default().to_owned();
        let pod_namespace = pod
            .metadata
            .namespace
            .as_deref()
            .unwrap_or_default()
            .to_owned();

        // Skip pods that haven't been assigned an IP yet.
        let pod_ip_str = match pod.status.as_ref().and_then(|s| s.pod_ip.as_deref()) {
            Some(ip) => ip,
            None => continue,
        };
        let pod_ip: IpAddr = match pod_ip_str.parse() {
            Ok(ip) => ip,
            Err(e) => {
                tracing::warn!(pod = %pod_name, error = %e, "fleet: skipping pod with unparseable IP");
                continue;
            }
        };

        // Read the admin port from the annotation.
        let admin_port: u16 = match pod
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(ADMIN_PORT_ANNOTATION))
        {
            Some(raw) => match raw.parse() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        pod = %pod_name,
                        annotation = ADMIN_PORT_ANNOTATION,
                        value = %raw,
                        error = %e,
                        "fleet: skipping pod with invalid admin-port annotation"
                    );
                    continue;
                }
            },
            None => {
                tracing::warn!(
                    pod = %pod_name,
                    annotation = ADMIN_PORT_ANNOTATION,
                    "fleet: skipping pod missing admin-port annotation"
                );
                continue;
            }
        };

        // Determine component from the label.
        let component_str = pod
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(COMPONENT_LABEL))
            .map(String::as_str);
        let component = match component_str.and_then(Component::from_label) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    pod = %pod_name,
                    component = ?component_str,
                    "fleet: skipping pod with unknown component label"
                );
                continue;
            }
        };

        // For dedicated proxies, capture the owning Gateway name.
        let gateway_ref = if matches!(component, Component::DedicatedProxy) {
            pod.metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(GATEWAY_NAME_LABEL))
                .cloned()
        } else {
            None
        };

        // Runtime fields straight off the Pod (the watch already holds it).
        let node = pod.spec.as_ref().and_then(|s| s.node_name.clone());
        let restarts = pod
            .status
            .as_ref()
            .and_then(|s| s.container_statuses.as_ref())
            .map(|cs| cs.iter().map(|c| c.restart_count).sum())
            .unwrap_or(0);
        let phase = pod.status.as_ref().and_then(|s| s.phase.clone());
        let created_at = pod
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| t.0.to_string()); // jiff::Timestamp Display is RFC 3339

        let entry = FleetEntry {
            pod_name,
            pod_namespace,
            pod_ip,
            admin_port,
            component,
            gateway_ref,
            node,
            restarts,
            phase,
            created_at,
            last_seen: now,
        };
        match component {
            Component::Controller => snapshot.controllers.push(entry),
            Component::SharedProxy => snapshot.shared_proxies.push(entry),
            Component::DedicatedProxy => snapshot.dedicated_proxies.push(entry),
            Component::Relay => snapshot.relays.push(entry),
        }
    }

    snapshot
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Pod, PodStatus};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    fn make_pod(
        name: &str,
        component: &str,
        pod_ip: Option<&str>,
        admin_port: Option<&str>,
        gateway_name: Option<&str>,
    ) -> Pod {
        let mut labels = BTreeMap::new();
        labels.insert(COMPONENT_LABEL.to_string(), component.to_string());
        if let Some(gw) = gateway_name {
            labels.insert(GATEWAY_NAME_LABEL.to_string(), gw.to_string());
        }

        let mut annotations = BTreeMap::new();
        if let Some(port) = admin_port {
            annotations.insert(ADMIN_PORT_ANNOTATION.to_string(), port.to_string());
        }

        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(labels),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: None,
            status: pod_ip.map(|ip| PodStatus {
                pod_ip: Some(ip.to_string()),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn pod_missing_annotation_is_skipped() {
        let pod = make_pod("ctrl-0", "controller", Some("10.0.0.1"), None, None);
        let snap = build_snapshot([&pod]);
        assert!(snap.controllers.is_empty());
        assert!(snap.shared_proxies.is_empty());
        assert!(snap.dedicated_proxies.is_empty());
    }

    #[test]
    fn pod_missing_ip_is_skipped_silently() {
        let pod = make_pod("ctrl-0", "controller", None, Some("8082"), None);
        let snap = build_snapshot([&pod]);
        assert!(snap.controllers.is_empty());
    }

    #[test]
    fn controller_pods_bucketed_correctly() {
        let pod = make_pod("ctrl-0", "controller", Some("10.0.0.1"), Some("8082"), None);
        let snap = build_snapshot([&pod]);
        assert_eq!(snap.controllers.len(), 1);
        assert_eq!(snap.controllers[0].pod_name, "ctrl-0");
        assert_eq!(snap.controllers[0].admin_port, 8082);
        assert_eq!(
            snap.controllers[0].pod_ip,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert!(snap.shared_proxies.is_empty());
        assert!(snap.dedicated_proxies.is_empty());
    }

    #[test]
    fn shared_proxy_pods_bucketed_correctly() {
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            Some("10.0.0.2"),
            Some("8082"),
            None,
        );
        let snap = build_snapshot([&pod]);
        assert_eq!(snap.shared_proxies.len(), 1);
        assert_eq!(snap.shared_proxies[0].pod_name, "proxy-0");
        assert!(snap.controllers.is_empty());
        assert!(snap.dedicated_proxies.is_empty());
    }

    #[test]
    fn dedicated_proxy_gateway_ref_populated() {
        let pod = make_pod(
            "ded-0",
            "dedicated-proxy",
            Some("10.0.0.3"),
            Some("8082"),
            Some("my-gateway"),
        );
        let snap = build_snapshot([&pod]);
        assert_eq!(snap.dedicated_proxies.len(), 1);
        assert_eq!(
            snap.dedicated_proxies[0].gateway_ref.as_deref(),
            Some("my-gateway")
        );
        assert!(snap.controllers.is_empty());
        assert!(snap.shared_proxies.is_empty());
    }

    #[test]
    fn non_dedicated_pods_have_no_gateway_ref() {
        let ctrl = make_pod("ctrl-0", "controller", Some("10.0.0.1"), Some("8082"), None);
        let snap = build_snapshot([&ctrl]);
        assert!(snap.controllers[0].gateway_ref.is_none());
    }

    #[test]
    fn unknown_component_is_skipped() {
        let pod = make_pod("unk-0", "frobnicator", Some("10.0.0.4"), Some("8082"), None);
        let snap = build_snapshot([&pod]);
        assert!(snap.controllers.is_empty());
        assert!(snap.shared_proxies.is_empty());
        assert!(snap.dedicated_proxies.is_empty());
    }

    #[test]
    fn invalid_admin_port_annotation_is_skipped() {
        let pod = make_pod(
            "ctrl-0",
            "controller",
            Some("10.0.0.1"),
            Some("not-a-port"),
            None,
        );
        let snap = build_snapshot([&pod]);
        assert!(snap.controllers.is_empty());
    }

    #[test]
    fn unparseable_pod_ip_is_skipped() {
        let pod = make_pod(
            "ctrl-0",
            "controller",
            Some("not-an-ip"),
            Some("8082"),
            None,
        );
        let snap = build_snapshot([&pod]);
        assert!(snap.controllers.is_empty());
    }

    #[test]
    fn multiple_pods_bucketed_into_correct_buckets() {
        let ctrl = make_pod("ctrl-0", "controller", Some("10.0.0.1"), Some("8082"), None);
        let shared = make_pod(
            "proxy-0",
            "shared-proxy",
            Some("10.0.0.2"),
            Some("8082"),
            None,
        );
        let ded = make_pod(
            "ded-0",
            "dedicated-proxy",
            Some("10.0.0.3"),
            Some("8082"),
            Some("gw"),
        );
        let snap = build_snapshot([&ctrl, &shared, &ded]);
        assert_eq!(snap.controllers.len(), 1);
        assert_eq!(snap.shared_proxies.len(), 1);
        assert_eq!(snap.dedicated_proxies.len(), 1);
    }
}
