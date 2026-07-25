//! The security envelope every controller-rendered pod is filtered back into
//! after a tenant `podTemplate` overlay is strategic-merged onto it.
//!
//! ## Why this exists
//!
//! The controller is cluster-privileged and creates pods *on behalf of* tenants.
//! Both overlay sources are tenant-writable and namespaced —
//! `CoxswainGatewayParameters.spec.podTemplate` resolves in the Gateway's own
//! namespace, `CoxswainRelayPolicy.spec.podTemplate` in the relay's — so without
//! this filter a namespace tenant can hand the controller
//! `securityContext: {privileged: true}` plus a `hostPath: /` volume and have the
//! *controller* create that pod. That is a confused deputy: the pod escapes to the
//! node with the controller's privileges, not the tenant's.
//!
//! ## Filter, not reject
//!
//! The merge stays permissive and the *result* is filtered. The guarantee is
//! therefore structural — every controller-owned field is re-asserted from the
//! rendered base, so an overlay path nobody anticipated cannot route around it —
//! rather than an enumerated deny-list that is one Kubernetes release away from
//! being incomplete. Rejecting the whole overlay instead would also discard the
//! operator's legitimate `nodeSelector`/`tolerations` over a single bad key, and
//! `CoxswainRelayPolicy` has no status subresource to report the rejection on.
//!
//! What the tenant asked for and did not get is returned in a `HardeningReport`
//! and surfaced as a `Warning` Event by `emit_sanitized_event`, so the override is
//! visible in `kubectl describe` instead of silently vanishing.
//!
//! ## The envelope
//!
//! Controller-owned, restored from the base verbatim:
//! `spec.securityContext`, `spec.serviceAccountName`,
//! `spec.automountServiceAccountToken`, `spec.hostNetwork`/`hostPID`/`hostIPC`,
//! every base container's `securityContext`, every base volume, and the reserved
//! pod-template labels.
//!
//! Volumes the overlay *adds* must use a source the Pod Security Standards
//! `restricted` profile allows — an allowlist, because the node-reaching volume
//! types are not one field (`hostPath` mounts the node's filesystem, `gitRepo`
//! has the kubelet clone a tenant repository as root on the node, `nfs`/`iscsi`/
//! `cephfs`/`flexVolume` attach storage the controller never vetted). Anything
//! else is dropped along with the mounts referencing it. `hostPort` is stripped
//! from every container port.
//!
//! `spec.ephemeralContainers` is cleared outright: it is a container list, and a
//! pod *template* may not carry one at all — the apiserver rejects the Deployment,
//! so an overlay setting it would wedge provisioning rather than escalate.
//!
//! Containers the base did not render (tenant sidecars, init containers) keep
//! their own image, command, mounts, and writable root filesystem but get
//! `sidecar_security_context` — the escalation-blocking subset. A sidecar cannot
//! be the escape hatch that the coxswain container no longer is; it can still be a
//! normal sidecar. One needing a writable path mounts an `emptyDir`.
//!
//! The coarse granularity is deliberate: "the controller owns these fields" is a
//! sentence an operator can audit, where field-level surgery (keep `fsGroup`, drop
//! `runAsUser: 0`) is more code and more places to be subtly wrong. The cost is
//! that a benign `fsGroup` overlay is dropped too — if that is ever wanted it gets
//! first-classed as a params field, not smuggled through the escape hatch.

use super::render::RESERVED_LABEL_KEYS;
use k8s_openapi::api::core::v1::{
    Capabilities, Container, ObjectReference, PodSpec, PodTemplateSpec, SecurityContext, Volume,
};
use kube::runtime::events::{Event, EventType, Recorder};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The fields an overlay set that the envelope took back, in the order they were
/// found. Empty means the overlay asked for nothing it wasn't allowed to have —
/// the overwhelmingly common case, and the one that emits no Event.
///
/// Entries are JSON-path-ish strings (`spec.containers[coxswain].securityContext`)
/// so the Event note names exactly what the tenant must remove from their YAML.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct HardeningReport {
    fields: Vec<String>,
}

impl HardeningReport {
    /// Whether the overlay stayed inside the envelope. Callers skip the Event and
    /// the WARN log entirely when this is `true`.
    pub(super) fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The overwritten field paths, in the order the envelope walked them.
    pub(super) fn fields(&self) -> &[String] {
        &self.fields
    }

    /// Comma-separated field paths for a single-line log field or Event note.
    pub(super) fn summary(&self) -> String {
        self.fields().join(", ")
    }

    fn record(&mut self, field: impl Into<String>) {
        self.fields.push(field.into());
    }
}

/// The escalation-blocking security context forced onto every container the base
/// did not render.
///
/// Deliberately narrower than the coxswain container's own hardening: it blocks
/// privilege escalation and nothing else, leaving a tenant sidecar its writable
/// root filesystem and its choice of UID. `readOnlyRootFilesystem` is hygiene
/// rather than an escalation control, and forcing it would break ordinary
/// sidecars for no security gain.
pub(super) fn sidecar_security_context() -> SecurityContext {
    SecurityContext {
        privileged: Some(false),
        allow_privilege_escalation: Some(false),
        run_as_non_root: Some(true),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_string()]),
            add: None,
        }),
        ..Default::default()
    }
}

/// Filter `merged` — a base pod template with a tenant overlay already merged onto
/// it — back into the envelope defined by `base`, returning what was taken back.
///
/// Total by construction: every controller-owned field is assigned from `base`
/// regardless of what the overlay did to it, so the post-condition ("the applied
/// pod is no less hardened than the rendered base") holds for overlay shapes this
/// function has never seen. Called unconditionally inside
/// `super::render::merge_pod_template`, which is the only way to obtain a merged
/// pod template — so the rule needs no lint or check script to stay enforced.
pub(super) fn enforce(base: &PodTemplateSpec, merged: &mut PodTemplateSpec) -> HardeningReport {
    let mut report = HardeningReport::default();

    restore_reserved_labels(base, merged, &mut report);

    let Some(base_spec) = base.spec.as_ref() else {
        // A controller-rendered base always carries a `spec`; with nothing to
        // restore from, leaving `merged` untouched is the only honest option.
        return report;
    };
    let Some(spec) = merged.spec.as_mut() else {
        // The overlay nulled `spec` outright (RFC 7396 delete semantics leak
        // through the type-mismatch arm of the merge). Restore it wholesale —
        // the base is by definition inside the envelope.
        merged.spec = base.spec.clone();
        report.record("spec");
        return report;
    };

    restore(
        &mut spec.security_context,
        &base_spec.security_context,
        "spec.securityContext",
        &mut report,
    );
    restore(
        &mut spec.service_account_name,
        &base_spec.service_account_name,
        "spec.serviceAccountName",
        &mut report,
    );
    restore(
        &mut spec.automount_service_account_token,
        &base_spec.automount_service_account_token,
        "spec.automountServiceAccountToken",
        &mut report,
    );
    restore(
        &mut spec.host_network,
        &base_spec.host_network,
        "spec.hostNetwork",
        &mut report,
    );
    restore(
        &mut spec.host_pid,
        &base_spec.host_pid,
        "spec.hostPID",
        &mut report,
    );
    restore(
        &mut spec.host_ipc,
        &base_spec.host_ipc,
        "spec.hostIPC",
        &mut report,
    );

    let dropped_volumes = restore_volumes(spec, base_spec, &mut report);
    harden_containers(
        &mut spec.containers,
        &base_spec.containers,
        "spec.containers",
        &dropped_volumes,
        &mut report,
    );
    if let Some(init) = spec.init_containers.as_mut() {
        let base_init = base_spec.init_containers.as_deref().unwrap_or(&[]);
        harden_containers(
            init,
            base_init,
            "spec.initContainers",
            &dropped_volumes,
            &mut report,
        );
    }

    // The third container list. It has no place in a *pod template* at all — the
    // apiserver rejects a Deployment carrying one outright ("ephemeral containers
    // not allowed in pod template"), so an overlay that sets it would wedge this
    // Gateway's provisioning on every reconcile forever. Clearing it is both the
    // security answer (it is a container list, and an unhardened container escapes
    // as well from there as from anywhere) and the availability one.
    if spec.ephemeral_containers.take().is_some() {
        report.record("spec.ephemeralContainers");
    }

    report
}

/// Assign `base`'s value over whatever the overlay left behind, recording the
/// path only when the two actually differed — so the report is exactly "what the
/// tenant asked for and didn't get", never a list of untouched fields.
fn restore<T: Clone + PartialEq>(
    field: &mut T,
    base: &T,
    path: &'static str,
    report: &mut HardeningReport,
) {
    if field != base {
        field.clone_from(base);
        report.record(path);
    }
}

/// Volume sources a tenant overlay may add to a controller-created pod: the set
/// the Pod Security Standards `restricted` profile allows, and nothing else.
///
/// An allowlist, not a `hostPath` deny-list, because the node-reaching volume
/// types are not one field. `gitRepo` has the kubelet clone a tenant-supplied
/// repository *as root on the node*, running repo-supplied git hooks; `nfs`,
/// `iscsi`, `cephfs`, `fc`, `glusterfs`, and `flexVolume` each hand the pod
/// storage the controller never vetted. Enumerating those is the deny-list this
/// module exists to avoid — the allowlist stays correct when Kubernetes adds a
/// volume type, because a new type is simply not on it.
const ALLOWED_VOLUME_SOURCES: &[&str] = &[
    "configMap",
    "csi",
    "downwardAPI",
    "emptyDir",
    "ephemeral",
    "persistentVolumeClaim",
    "projected",
    "secret",
];

fn is_allowed_volume_source(v: &Volume) -> bool {
    // Read the populated sources off the serialized form rather than testing the
    // struct field by field: `Volume` is `name` plus one field per source type,
    // all `skip_serializing_if = "Option::is_none"`, so the JSON keys minus `name`
    // ARE the populated sources — and a source type added by a future
    // `k8s-openapi` is automatically not on the allowlist rather than silently
    // slipping past a hand-written field list.
    let Ok(serde_json::Value::Object(fields)) = serde_json::to_value(v) else {
        return false;
    };
    let mut sources = fields.keys().filter(|k| k.as_str() != "name");
    let Some(source) = sources.next() else {
        // No source at all: not a usable volume, and not something to carry into
        // a pod the controller signs its name to.
        return false;
    };
    // Exactly one source, and it must be allowed. `{emptyDir: {}, hostPath: {…}}`
    // satisfies "has an allowed source" while still carrying the hostPath — the
    // apiserver then rejects the whole Deployment ("may not specify more than 1
    // volume type"), which would wedge provisioning for that Gateway forever.
    sources.next().is_none() && ALLOWED_VOLUME_SOURCES.contains(&source.as_str())
}

/// Restore the base's own volumes and drop any tenant-added volume outside
/// [`is_allowed_volume_source`], returning the dropped names so the mounts
/// referencing them can be dropped too (a `volumeMount` naming a volume that no
/// longer exists makes the pod unschedulable — stripping one without the other
/// would trade an escalation for an outage).
///
/// Restoring by name matters as much as the allowlist: the strategic merge joins
/// `spec.volumes` on `name`, so an overlay entry named after a controller volume
/// merges *into* it. Filtering that merged element out would delete the base's
/// own volume — for the proxy that is the projected discovery token, without
/// which the pod can never bootstrap an SVID.
fn restore_volumes(
    spec: &mut PodSpec,
    base_spec: &PodSpec,
    report: &mut HardeningReport,
) -> Vec<String> {
    let base_volumes = base_spec.volumes.as_deref().unwrap_or_default();
    let mut volumes = spec.volumes.take().unwrap_or_default();
    let mut dropped = Vec::new();

    for volume in &mut volumes {
        if let Some(base) = base_volumes.iter().find(|b| b.name == volume.name)
            && volume != base
        {
            volume.clone_from(base);
            report.record(format!("spec.volumes[{}]", volume.name));
        }
    }

    volumes.retain(|v| {
        if base_volumes.iter().any(|b| b.name == v.name) || is_allowed_volume_source(v) {
            return true;
        }
        dropped.push(v.name.clone());
        false
    });
    for name in &dropped {
        report.record(format!("spec.volumes[{name}]"));
    }

    // An overlay that nulls `spec.volumes`, or replaces the list wholesale with a
    // shape the merge couldn't join, must not cost the pod its own volumes.
    for base in base_volumes {
        if !volumes.iter().any(|v| v.name == base.name) {
            volumes.push(base.clone());
            report.record(format!("spec.volumes[{}]", base.name));
        }
    }

    spec.volumes = (!volumes.is_empty()).then_some(volumes);
    dropped
}

/// Force the envelope onto one container list: base containers get their rendered
/// `securityContext` back, tenant-added ones get `sidecar_security_context`, and
/// every container loses its `hostPort`s and any mount of a stripped volume.
fn harden_containers(
    containers: &mut [Container],
    base: &[Container],
    path: &str,
    dropped_volumes: &[String],
    report: &mut HardeningReport,
) {
    for container in containers.iter_mut() {
        match base.iter().find(|b| b.name == container.name) {
            // A container the controller rendered: its securityContext is
            // controller-owned, restored verbatim.
            Some(base_container) => {
                if container.security_context != base_container.security_context {
                    container
                        .security_context
                        .clone_from(&base_container.security_context);
                    report.record(format!("{path}[{}].securityContext", container.name));
                }
            }
            // A container the tenant added: it gets the escalation-blocking
            // envelope either way, but only a container that *asked* for its own
            // securityContext had a request to overrule. Reporting the common
            // case — a plain sidecar with no securityContext at all — would tell
            // the tenant to remove a field they never wrote.
            None => {
                let asked = container.security_context.take();
                container.security_context = Some(sidecar_security_context());
                if asked.is_some() && asked != container.security_context {
                    report.record(format!("{path}[{}].securityContext", container.name));
                }
            }
        }

        if let Some(ports) = container.ports.as_mut() {
            for port in ports.iter_mut() {
                if port.host_port.take().is_some() {
                    report.record(format!(
                        "{path}[{}].ports[{}].hostPort",
                        container.name, port.container_port
                    ));
                }
            }
        }

        if !dropped_volumes.is_empty()
            && let Some(mounts) = container.volume_mounts.as_mut()
        {
            mounts.retain(|m| !dropped_volumes.contains(&m.name));
        }
    }
}

/// Restore the reserved pod-template labels from the base.
///
/// Not an escalation vector, but the same class of defect: the Deployment's
/// selector joins on `app.kubernetes.io/name` + `app.kubernetes.io/instance`, so
/// an overlay that rewrites or nulls them produces a Deployment whose selector
/// does not match its own template. The apply is rejected and the reconcile wedges
/// — the pod-template equivalent of the collision guard `super::render` already
/// applies to `Gateway.spec.infrastructure.labels`.
fn restore_reserved_labels(
    base: &PodTemplateSpec,
    merged: &mut PodTemplateSpec,
    report: &mut HardeningReport,
) {
    let Some(base_labels) = base.metadata.as_ref().and_then(|m| m.labels.as_ref()) else {
        return;
    };
    let merged_meta = merged.metadata.get_or_insert_with(Default::default);
    let Some(labels) = merged_meta.labels.as_mut() else {
        // The overlay nulled the label map; the selector cannot match without it.
        merged_meta.labels = Some(base_labels.clone());
        report.record("metadata.labels");
        return;
    };
    restore_reserved_keys(labels, base_labels, report);
}

/// Per-key restore of the reserved label set: a rewritten key is put back, and a
/// reserved key the base never set is removed (it can only widen the selector's
/// blast radius).
fn restore_reserved_keys(
    labels: &mut BTreeMap<String, String>,
    base_labels: &BTreeMap<String, String>,
    report: &mut HardeningReport,
) {
    for key in RESERVED_LABEL_KEYS {
        match base_labels.get(*key) {
            Some(want) if labels.get(*key) != Some(want) => {
                labels.insert((*key).to_string(), want.clone());
                report.record(format!("metadata.labels[{key}]"));
            }
            None if labels.contains_key(*key) => {
                labels.remove(*key);
                report.record(format!("metadata.labels[{key}]"));
            }
            _ => {}
        }
    }
}

/// Publish the `Warning` Event telling the tenant which of their `podTemplate`
/// fields the envelope overwrote, on the object they'd edit to fix it (the
/// `Gateway` for a dedicated proxy, the `CoxswainRelayPolicy` for a relay).
///
/// Best-effort, exactly like the operator's other emitters: a publish failure is
/// logged and swallowed, never propagated — a diagnostic that blocked
/// provisioning would be a worse outage than the one it describes. The shared
/// pool has no tenant-owned object to attach to (its overlay is an install-time
/// Helm value), so that path logs without calling this.
pub(super) async fn emit_sanitized_event(
    recorder: &Recorder,
    target: &ObjectReference,
    report: &HardeningReport,
) {
    if let Err(e) = recorder
        .publish(
            &Event {
                action: "RenderPodTemplate".into(),
                reason: "PodTemplateSanitized".into(),
                note: Some(event_note(report)),
                type_: EventType::Warning,
                secondary: None,
            },
            target,
        )
        .await
    {
        tracing::warn!(error = %e, "Failed to publish PodTemplateSanitized Event");
    }
}

/// The Event `note`, bounded to what `events.k8s.io/v1` accepts.
///
/// The apiserver rejects a `note` over 1024 characters, and the field paths embed
/// tenant-chosen container and volume names from an
/// `x-kubernetes-preserve-unknown-fields` blob — so a pathological overlay (many
/// sidecars, or one container with a kilobyte name) could push the note past the
/// limit and lose the whole diagnostic to a 422. Dropping the tail keeps the
/// message the tenant actually needs.
fn event_note(report: &HardeningReport) -> String {
    const PREFIX: &str = "podTemplate overlay ignored on controller-owned fields: ";
    // Well under the 1024-character API limit, with room for the suffix.
    const BUDGET: usize = 800;

    let mut note = String::from(PREFIX);
    let mut written = 0;
    for field in report.fields() {
        if note.len() + field.len() + 2 > BUDGET {
            break;
        }
        if written > 0 {
            note.push_str(", ");
        }
        note.push_str(field);
        written += 1;
    }
    let remaining = report.fields().len() - written;
    if remaining > 0 {
        if written > 0 {
            note.push_str(", ");
        }
        let _ = write!(note, "and {remaining} more");
    }
    note
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        ContainerPort, EmptyDirVolumeSource, EphemeralContainer, GitRepoVolumeSource,
        HostPathVolumeSource, PodSecurityContext, SeccompProfile, VolumeMount,
    };
    use kube::api::ObjectMeta;

    /// A base close enough to what the three renderers produce: hardened pod +
    /// coxswain container, pinned SA, one projected volume, reserved labels.
    fn base() -> PodTemplateSpec {
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
        labels.insert("app.kubernetes.io/instance".to_string(), "gw".to_string());
        PodTemplateSpec {
            metadata: Some(ObjectMeta {
                labels: Some(labels),
                ..Default::default()
            }),
            spec: Some(PodSpec {
                service_account_name: Some("gw-coxswain".to_string()),
                automount_service_account_token: Some(false),
                security_context: Some(PodSecurityContext {
                    run_as_non_root: Some(true),
                    seccomp_profile: Some(SeccompProfile {
                        type_: "RuntimeDefault".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                containers: vec![Container {
                    name: "coxswain".to_string(),
                    security_context: Some(SecurityContext {
                        allow_privilege_escalation: Some(false),
                        read_only_root_filesystem: Some(true),
                        capabilities: Some(Capabilities {
                            drop: Some(vec!["ALL".to_string()]),
                            add: None,
                        }),
                        ..Default::default()
                    }),
                    volume_mounts: Some(vec![VolumeMount {
                        name: "discovery-token".to_string(),
                        mount_path: "/var/run/secrets/coxswain/discovery-token".to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                volumes: Some(vec![Volume {
                    name: "discovery-token".to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        }
    }

    fn spec_of(pt: &PodTemplateSpec) -> &PodSpec {
        pt.spec.as_ref().expect("pod spec")
    }

    fn container_named<'a>(pt: &'a PodTemplateSpec, name: &str) -> &'a Container {
        spec_of(pt)
            .containers
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("container {name} present"))
    }

    #[test]
    fn benign_overlay_is_left_untouched_and_reports_nothing() {
        let base = base();
        let mut merged = base.clone();
        let spec = merged.spec.as_mut().expect("spec");
        let mut node_selector = BTreeMap::new();
        node_selector.insert("pool".to_string(), "edge".to_string());
        spec.node_selector = Some(node_selector.clone());
        spec.priority_class_name = Some("high".to_string());

        let report = enforce(&base, &mut merged);

        assert!(
            report.is_empty(),
            "a scheduling-only overlay asks for nothing owned; got {:?}",
            report.fields()
        );
        assert_eq!(
            spec_of(&merged).node_selector.as_ref(),
            Some(&node_selector),
            "the envelope must not undo benign overlay fields — it filters, it does not reject"
        );
        assert_eq!(
            spec_of(&merged).priority_class_name.as_deref(),
            Some("high")
        );
    }

    #[test]
    fn privileged_coxswain_container_is_restored_to_the_rendered_context() {
        let base = base();
        let mut merged = base.clone();
        merged.spec.as_mut().expect("spec").containers[0].security_context =
            Some(SecurityContext {
                privileged: Some(true),
                allow_privilege_escalation: Some(true),
                run_as_user: Some(0),
                ..Default::default()
            });

        let report = enforce(&base, &mut merged);

        assert_eq!(
            container_named(&merged, "coxswain").security_context,
            container_named(&base, "coxswain").security_context,
            "the coxswain container's securityContext is controller-owned"
        );
        assert_eq!(
            report.fields(),
            ["spec.containers[coxswain].securityContext"],
            "the overwritten field must be named for the tenant"
        );
    }

    #[test]
    fn tenant_sidecar_keeps_itself_but_loses_privilege() {
        let base = base();
        let mut merged = base.clone();
        merged
            .spec
            .as_mut()
            .expect("spec")
            .containers
            .push(Container {
                name: "sidecar".to_string(),
                image: Some("registry.invalid/sidecar:v1".to_string()),
                security_context: Some(SecurityContext {
                    privileged: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            });

        let report = enforce(&base, &mut merged);

        let sidecar = container_named(&merged, "sidecar");
        assert_eq!(
            sidecar.security_context,
            Some(sidecar_security_context()),
            "a container the base never rendered gets the escalation-blocking envelope"
        );
        assert_eq!(
            sidecar.image.as_deref(),
            Some("registry.invalid/sidecar:v1"),
            "the sidecar itself survives — only its privilege is taken away"
        );
        assert_eq!(
            sidecar
                .security_context
                .as_ref()
                .and_then(|sc| sc.read_only_root_filesystem),
            None,
            "the sidecar keeps a writable root filesystem; that is not an escalation control"
        );
        assert_eq!(
            report.fields(),
            ["spec.containers[sidecar].securityContext"]
        );
    }

    #[test]
    fn init_container_added_by_the_overlay_is_hardened_too() {
        let base = base();
        let mut merged = base.clone();
        merged.spec.as_mut().expect("spec").init_containers = Some(vec![Container {
            name: "setup".to_string(),
            security_context: Some(SecurityContext {
                privileged: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }]);

        let report = enforce(&base, &mut merged);

        let init = &spec_of(&merged).init_containers.as_ref().expect("init")[0];
        assert_eq!(
            init.security_context,
            Some(sidecar_security_context()),
            "initContainers are a container list too — an unhardened one escapes just as well"
        );
        assert_eq!(
            report.fields(),
            ["spec.initContainers[setup].securityContext"]
        );
    }

    #[test]
    fn host_path_volume_and_its_mount_are_both_stripped() {
        let base = base();
        let mut merged = base.clone();
        let spec = merged.spec.as_mut().expect("spec");
        spec.volumes.as_mut().expect("volumes").push(Volume {
            name: "host-root".to_string(),
            host_path: Some(HostPathVolumeSource {
                path: "/".to_string(),
                type_: None,
            }),
            ..Default::default()
        });
        spec.containers[0]
            .volume_mounts
            .as_mut()
            .expect("mounts")
            .push(VolumeMount {
                name: "host-root".to_string(),
                mount_path: "/host".to_string(),
                ..Default::default()
            });

        let report = enforce(&base, &mut merged);

        assert!(
            spec_of(&merged)
                .volumes
                .as_ref()
                .expect("volumes")
                .iter()
                .all(|v| v.host_path.is_none()),
            "a hostPath volume is the node's filesystem; it never survives the envelope"
        );
        assert!(
            container_named(&merged, "coxswain")
                .volume_mounts
                .as_ref()
                .expect("mounts")
                .iter()
                .all(|m| m.name != "host-root"),
            "the mount must go with the volume, or the pod is unschedulable"
        );
        assert_eq!(report.fields(), ["spec.volumes[host-root]"]);
        assert!(
            spec_of(&merged)
                .volumes
                .as_ref()
                .expect("volumes")
                .iter()
                .any(|v| v.name == "discovery-token"),
            "the base's own volumes are untouched"
        );
    }

    /// `hostPath` is not the only volume source that reaches the node: `gitRepo`
    /// has the kubelet clone a tenant-supplied repository as root on the host,
    /// running repo-supplied git hooks. The envelope allowlists sources rather
    /// than enumerating the dangerous ones.
    #[test]
    fn volume_source_outside_the_allowlist_is_dropped() {
        let base = base();
        let mut merged = base.clone();
        let spec = merged.spec.as_mut().expect("spec");
        spec.volumes.as_mut().expect("volumes").extend([
            Volume {
                name: "repo".to_string(),
                git_repo: Some(GitRepoVolumeSource {
                    repository: "https://example.invalid/evil.git".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Volume {
                name: "scratch".to_string(),
                empty_dir: Some(EmptyDirVolumeSource::default()),
                ..Default::default()
            },
        ]);

        let report = enforce(&base, &mut merged);

        let volumes = spec_of(&merged).volumes.as_ref().expect("volumes");
        assert!(
            volumes.iter().all(|v| v.name != "repo"),
            "gitRepo clones on the node as root — it is not an allowed source"
        );
        assert!(
            volumes.iter().any(|v| v.name == "scratch"),
            "an emptyDir is exactly what a sidecar needing a writable path should use"
        );
        assert_eq!(report.fields(), ["spec.volumes[repo]"]);
    }

    /// A volume carrying two sources satisfies "has an allowed source" while the
    /// disallowed one rides along. The apiserver then rejects the whole Deployment
    /// ("may not specify more than 1 volume type") on every reconcile, so a
    /// has-one check would trade the escalation for a permanent provisioning wedge.
    #[test]
    fn volume_with_an_allowed_and_a_disallowed_source_is_dropped() {
        let base = base();
        let mut merged = base.clone();
        merged
            .spec
            .as_mut()
            .expect("spec")
            .volumes
            .as_mut()
            .expect("volumes")
            .push(Volume {
                name: "smuggled".to_string(),
                empty_dir: Some(EmptyDirVolumeSource::default()),
                host_path: Some(HostPathVolumeSource {
                    path: "/".to_string(),
                    type_: None,
                }),
                ..Default::default()
            });

        let report = enforce(&base, &mut merged);

        assert!(
            spec_of(&merged)
                .volumes
                .as_ref()
                .expect("volumes")
                .iter()
                .all(|v| v.name != "smuggled"),
            "a volume is allowed only when its single source is on the allowlist"
        );
        assert_eq!(report.fields(), ["spec.volumes[smuggled]"]);
    }

    /// A pod template may not carry ephemeral containers at all — the apiserver
    /// rejects the Deployment — so leaving them in place would wedge provisioning
    /// for this Gateway on every reconcile.
    #[test]
    fn ephemeral_containers_are_cleared() {
        let base = base();
        let mut merged = base.clone();
        merged.spec.as_mut().expect("spec").ephemeral_containers = Some(vec![EphemeralContainer {
            name: "debugger".to_string(),
            ..Default::default()
        }]);

        let report = enforce(&base, &mut merged);

        assert_eq!(
            spec_of(&merged).ephemeral_containers,
            None,
            "an ephemeral container in a pod template is rejected by the apiserver"
        );
        assert_eq!(report.fields(), ["spec.ephemeralContainers"]);
    }

    /// The strategic merge joins volumes by `name`, so an overlay entry named
    /// after a controller volume merges *into* it. Filtering the merged element
    /// out would delete the base's own volume — for the proxy that is the
    /// projected discovery token, without which it can never bootstrap an SVID.
    #[test]
    fn overlay_cannot_delete_a_base_volume_by_reusing_its_name() {
        let base = base();
        let mut merged = base.clone();
        let spec = merged.spec.as_mut().expect("spec");
        let volume = spec
            .volumes
            .as_mut()
            .expect("volumes")
            .iter_mut()
            .find(|v| v.name == "discovery-token")
            .expect("base volume");
        volume.host_path = Some(HostPathVolumeSource {
            path: "/".to_string(),
            type_: None,
        });

        let report = enforce(&base, &mut merged);

        assert_eq!(
            spec_of(&merged).volumes,
            spec_of(&base).volumes,
            "the base volume is restored verbatim, not deleted along with the hostPath"
        );
        assert!(
            container_named(&merged, "coxswain")
                .volume_mounts
                .as_ref()
                .expect("mounts")
                .iter()
                .any(|m| m.name == "discovery-token"),
            "and its mount survives — dropping it would break SVID bootstrap"
        );
        assert_eq!(report.fields(), ["spec.volumes[discovery-token]"]);
    }

    #[test]
    fn nulled_volume_list_is_restored_from_the_base() {
        let base = base();
        let mut merged = base.clone();
        merged.spec.as_mut().expect("spec").volumes = None;

        let report = enforce(&base, &mut merged);

        assert_eq!(
            spec_of(&merged).volumes,
            spec_of(&base).volumes,
            "an overlay that nulls spec.volumes must not cost the pod its own volumes"
        );
        assert_eq!(report.fields(), ["spec.volumes[discovery-token]"]);
    }

    /// The most common legitimate use of the escape hatch. It gets the envelope
    /// like any tenant container, but it never *asked* for a securityContext, so
    /// telling its author that one was ignored would be false.
    #[test]
    fn plain_sidecar_is_hardened_without_being_reported() {
        let base = base();
        let mut merged = base.clone();
        merged
            .spec
            .as_mut()
            .expect("spec")
            .containers
            .push(Container {
                name: "log-shipper".to_string(),
                image: Some("registry.invalid/log-shipper:v1".to_string()),
                ..Default::default()
            });

        let report = enforce(&base, &mut merged);

        assert_eq!(
            container_named(&merged, "log-shipper").security_context,
            Some(sidecar_security_context()),
            "the envelope still applies to a container that asked for nothing"
        );
        assert!(
            report.is_empty(),
            "nothing was overruled, so nothing is reported; got {}",
            report.summary()
        );
    }

    #[test]
    fn host_namespaces_and_host_ports_are_taken_back() {
        let base = base();
        let mut merged = base.clone();
        let spec = merged.spec.as_mut().expect("spec");
        spec.host_network = Some(true);
        spec.host_pid = Some(true);
        spec.host_ipc = Some(true);
        spec.containers[0].ports = Some(vec![ContainerPort {
            container_port: 8080,
            host_port: Some(80),
            ..Default::default()
        }]);

        let report = enforce(&base, &mut merged);

        let spec = spec_of(&merged);
        assert_eq!(spec.host_network, None, "hostNetwork is controller-owned");
        assert_eq!(spec.host_pid, None, "hostPID is controller-owned");
        assert_eq!(spec.host_ipc, None, "hostIPC is controller-owned");
        assert_eq!(
            container_named(&merged, "coxswain")
                .ports
                .as_ref()
                .expect("ports")[0]
                .host_port,
            None,
            "a hostPort binds the node's network namespace"
        );
        assert_eq!(
            report.fields(),
            [
                "spec.hostNetwork",
                "spec.hostPID",
                "spec.hostIPC",
                "spec.containers[coxswain].ports[8080].hostPort",
            ]
        );
    }

    #[test]
    fn pod_security_context_and_identity_fields_are_taken_back() {
        let base = base();
        let mut merged = base.clone();
        let spec = merged.spec.as_mut().expect("spec");
        spec.security_context = Some(PodSecurityContext {
            run_as_non_root: Some(false),
            run_as_user: Some(0),
            ..Default::default()
        });
        spec.service_account_name = Some("cluster-admin-sa".to_string());
        spec.automount_service_account_token = Some(true);

        let report = enforce(&base, &mut merged);

        let spec = spec_of(&merged);
        assert_eq!(
            spec.security_context,
            spec_of(&base).security_context,
            "runAsNonRoot must survive an overlay that turns it off"
        );
        assert_eq!(
            spec.service_account_name.as_deref(),
            Some("gw-coxswain"),
            "pinning the SA is what keeps the pod's RBAC to the zero-verb identity"
        );
        assert_eq!(spec.automount_service_account_token, Some(false));
        assert_eq!(
            report.fields(),
            [
                "spec.securityContext",
                "spec.serviceAccountName",
                "spec.automountServiceAccountToken",
            ]
        );
    }

    #[test]
    fn nulled_spec_falls_back_to_the_rendered_base() {
        let base = base();
        let mut merged = base.clone();
        merged.spec = None;

        let report = enforce(&base, &mut merged);

        assert_eq!(
            merged.spec, base.spec,
            "an overlay that nulls spec gets the base back, not an empty pod"
        );
        assert_eq!(report.fields(), ["spec"]);
    }

    #[test]
    fn rewritten_selector_labels_are_restored() {
        let base = base();
        let mut merged = base.clone();
        let labels = merged
            .metadata
            .as_mut()
            .expect("metadata")
            .labels
            .as_mut()
            .expect("labels");
        labels.insert(
            "app.kubernetes.io/name".to_string(),
            "not-coxswain".to_string(),
        );
        labels.insert(
            "app.kubernetes.io/component".to_string(),
            "squatted".to_string(),
        );
        labels.insert("tier".to_string(), "edge".to_string());

        let report = enforce(&base, &mut merged);

        let labels = merged
            .metadata
            .as_ref()
            .expect("metadata")
            .labels
            .as_ref()
            .expect("labels");
        assert_eq!(
            labels.get("app.kubernetes.io/name").map(String::as_str),
            Some("coxswain"),
            "the Deployment selector joins on this key; an overlay rewrite wedges the apply"
        );
        assert!(
            !labels.contains_key("app.kubernetes.io/component"),
            "a reserved key the base never set is removed, not kept"
        );
        assert_eq!(
            labels.get("tier").map(String::as_str),
            Some("edge"),
            "non-reserved labels are the operator's to set"
        );
        assert_eq!(
            report.fields(),
            [
                "metadata.labels[app.kubernetes.io/name]",
                "metadata.labels[app.kubernetes.io/component]",
            ]
        );
    }

    #[test]
    fn nulled_labels_are_restored_wholesale() {
        let base = base();
        let mut merged = base.clone();
        merged.metadata.as_mut().expect("metadata").labels = None;

        let report = enforce(&base, &mut merged);

        assert_eq!(
            merged.metadata.as_ref().expect("metadata").labels,
            base.metadata.as_ref().expect("metadata").labels,
            "a template with no labels can never match its Deployment's selector"
        );
        assert_eq!(report.fields(), ["metadata.labels"]);
    }

    #[test]
    fn report_summary_names_every_overwritten_field() {
        let mut report = HardeningReport::default();
        report.record("spec.securityContext");
        report.record("spec.volumes[host-root]");
        assert_eq!(
            report.summary(),
            "spec.securityContext, spec.volumes[host-root]"
        );
    }

    /// Field paths embed tenant-chosen container and volume names out of an
    /// unvalidated blob, so a pathological overlay must not push the note past the
    /// apiserver's 1024-character limit and lose the diagnostic to a 422.
    #[test]
    fn event_note_stays_within_the_api_limit() {
        let mut report = HardeningReport::default();
        for i in 0..200 {
            report.record(format!(
                "spec.containers[{}].securityContext",
                "x".repeat(i)
            ));
        }
        let note = event_note(&report);
        assert!(
            note.len() < 1024,
            "note must fit the events.k8s.io/v1 limit, got {} bytes",
            note.len()
        );
        assert!(
            note.contains("more"),
            "a truncated note must say how many fields it dropped: {note}"
        );
    }

    #[test]
    fn event_note_lists_every_field_when_it_fits() {
        let mut report = HardeningReport::default();
        report.record("spec.securityContext");
        report.record("spec.hostNetwork");
        assert_eq!(
            event_note(&report),
            "podTemplate overlay ignored on controller-owned fields: \
             spec.securityContext, spec.hostNetwork"
        );
    }
}
