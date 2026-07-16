//! Render the per-namespace **relay** `Deployment` / `Service` /
//! `ServiceAccount` (#584, slice C of the relay-tier epic #384).
//!
//! A namespace relay is controller-provisioned discovery infrastructure — one
//! per tenant namespace that holds ≥1 dedicated Gateway while relay tiering is
//! enabled. It subscribes `Scope::Namespace` upstream to the controller and
//! re-serves the per-Gateway routing worlds downstream to that namespace's
//! dedicated proxies, so the leader fans out one stream per relay instead of one
//! per proxy replica.
//!
//! ## Not owner-referenced
//!
//! Unlike the dedicated-proxy trio (owner-ref'd to their Gateway so a Gateway
//! delete cascades), a relay outlives any single Gateway and is not owned by
//! one. It carries **no owner reference**; its lifecycle is driven by explicit
//! convergence in [`super::reconciler`] — provisioned on the first dedicated
//! Gateway in the namespace, deleted on the last.
//!
//! ## Identity + zero verbs
//!
//! The relay reuses the dedicated proxy's SVID-bootstrap wiring verbatim
//! ([`super::render::discovery_volumes`] / [`super::render::discovery_volume_mounts`]):
//! it bootstraps a rotating SVID from the controller and presents it both
//! upstream (client) and downstream (serving cert). Its ServiceAccount holds
//! **zero** Kubernetes verbs (no RoleBinding), the same read-only invariant as
//! the shared proxy, so a forged `Namespace` label can never buy K8s API access.
//! The SVID is `spiffe://<trust-domain>/ns/<ns>/sa/<RELAY_NAME>` — exactly the
//! identity the controller's provenance authorizer
//! ([`coxswain_discovery::ProvisionedRelayAuthorizer`]) matches.

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, PodSpec, PodTemplateSpec, ResourceRequirements, Service,
    ServiceAccount, ServicePort, ServiceSpec,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use std::collections::BTreeMap;

use super::render::{
    container_hardening_security_context, discovery_volume_mounts, discovery_volumes,
    http_get_probe, merge_pod_template, pod_hardening_security_context,
};

/// Fixed name of every per-namespace relay `ServiceAccount` / `Deployment` /
/// `Service`. One relay per namespace, so a constant name is unambiguous (no
/// GEP-1762 per-Gateway qualifier). This is the ServiceAccount half of the relay
/// SVID the provenance authorizer authorizes; re-exported from the crate root as
/// [`crate::RELAY_SERVICE_ACCOUNT`] so `coxswain-bin` shares the single source.
pub(crate) use crate::RELAY_SERVICE_ACCOUNT as RELAY_NAME;

/// Fixed name of the single controller-provisioned **shared-pool** relay's
/// `ServiceAccount` / `Deployment` / `Service` (#605). Re-exported from the crate
/// root as [`crate::SHARED_RELAY_SERVICE_ACCOUNT`] so render, the discovery
/// upstream resolver, and the pool's `expected_server_sa` share one source.
pub(crate) use crate::SHARED_RELAY_SERVICE_ACCOUNT as SHARED_RELAY_NAME;

/// `app.kubernetes.io/component` value stamped on every per-namespace relay resource.
const RELAY_COMPONENT: &str = "namespace-relay";

/// `app.kubernetes.io/component` value stamped on every shared-pool relay resource
/// (#605) — distinct from [`RELAY_COMPONENT`] so the two tiers' resources never
/// collide on a selector.
const SHARED_RELAY_COMPONENT: &str = "relay-shared";

/// Which relay tier to render (#605): the per-namespace dedicated relay or the
/// single shared-pool relay. Selects the name, component label, deploy namespace,
/// and upstream-subscribe scope arg — everything else (identity/hardening/probes/
/// resources) is identical across tiers.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RelayVariant<'a> {
    /// Per-namespace dedicated relay: `coxswain-relay` in the tenant namespace,
    /// subscribing `--namespace=<ns>`.
    Namespace { namespace: &'a str },
    /// Shared-pool relay: `coxswain-relay-shared` in the install namespace,
    /// subscribing `--shared`.
    Shared { install_namespace: &'a str },
}

impl<'a> RelayVariant<'a> {
    /// Fixed resource name (`coxswain-relay` / `coxswain-relay-shared`).
    fn name(self) -> &'static str {
        match self {
            RelayVariant::Namespace { .. } => RELAY_NAME,
            RelayVariant::Shared { .. } => SHARED_RELAY_NAME,
        }
    }

    /// `app.kubernetes.io/component` value.
    fn component(self) -> &'static str {
        match self {
            RelayVariant::Namespace { .. } => RELAY_COMPONENT,
            RelayVariant::Shared { .. } => SHARED_RELAY_COMPONENT,
        }
    }

    /// Namespace the relay's objects are deployed into.
    fn deploy_namespace(self) -> &'a str {
        match self {
            RelayVariant::Namespace { namespace } => namespace,
            RelayVariant::Shared { install_namespace } => install_namespace,
        }
    }

    /// The upstream-subscribe scope arg: `--namespace=<ns>` (aggregate a tenant
    /// namespace) or `--shared` (subscribe the shared pool's flat world).
    fn scope_arg(self) -> String {
        match self {
            RelayVariant::Namespace { namespace } => format!("--namespace={namespace}"),
            RelayVariant::Shared { .. } => "--shared".to_string(),
        }
    }
}

/// Downstream discovery port the relay serves leaves on (mirrors the controller
/// discovery Stream port). Dedicated proxies in a relay-fronted namespace dial
/// `coxswain-relay.<ns>.svc:<RELAY_DISCOVERY_PORT>`. The `i32` k8s-manifest form
/// of the crate-root [`crate::RELAY_DISCOVERY_PORT`] — one source of truth.
pub(crate) const RELAY_DISCOVERY_PORT: i32 = crate::RELAY_DISCOVERY_PORT as i32;

/// Health port the relay's `/readyz` (readiness) and `/healthz` (liveness)
/// probes target. Matches the binary's `--health-port` default (8081); the relay
/// container is not passed `--health-port`, so it binds this port by default.
const RELAY_HEALTH_PORT: i32 = 8081;

/// Inputs the operator threads into relay rendering: the discovery-client fields
/// the relay's upstream subscription needs, minus anything Gateway-specific.
/// Borrowed straight from the reconcile context.
pub(crate) struct RelayRenderInputs<'a> {
    /// Which tier to render (#605): per-namespace dedicated or shared-pool. Selects
    /// the name, component, deploy namespace, and upstream-subscribe scope arg.
    pub variant: RelayVariant<'a>,
    /// Replica count for the relay Deployment (`--relay-replicas`, min 1). A relay
    /// is a rollout-time SPOF for every leaf behind it at replica 1, so the
    /// operator default is 2 (HA); small clusters can pin it to 1.
    pub replicas: i32,
    /// Container image (the controller's own image, version-pinned).
    pub controller_image: &'a str,
    /// Controller bootstrap endpoint for SVID issuance (`https://…:50052`).
    /// Bootstrap is never tiered — the relay bootstraps directly from the
    /// controller like any other node, and (#601) learns its own routing upstream
    /// (always the controller — relays never tier) from the bootstrap response, so
    /// no `--discovery-endpoint` is rendered.
    pub discovery_bootstrap_endpoint: &'a str,
    /// Projected SA-token path (`--discovery-sa-token-path`).
    pub discovery_sa_token_path: &'a str,
    /// CA trust-bundle path (`--discovery-ca-bundle-path`).
    pub discovery_ca_bundle_path: &'a str,
    /// SPIFFE trust domain (`--discovery-trust-domain`).
    pub discovery_trust_domain: &'a str,
    /// Container resource requests/limits, either from a `CoxswainRelayPolicy`
    /// override (#589) or built from the controller's `--relay-cpu-request` /
    /// `--relay-memory-request` / `--relay-memory-limit` (#584) by [`relay_resources`].
    /// `None` leaves the container BestEffort (no v1 default omits it).
    pub resources: Option<ResourceRequirements>,
    /// Optional partial `PodTemplateSpec` strategic-merged onto the rendered relay pod —
    /// the `CoxswainRelayPolicy.spec.podTemplate` scheduling escape hatch (#589). `None`
    /// leaves the controller-rendered pod untouched.
    pub pod_template: Option<&'a serde_json::Value>,
    /// The replica *ceiling* used for the PDB decision (#589): a relay gets a
    /// `PodDisruptionBudget` (maxUnavailable: 1) when the most replicas it may run is ≥2.
    /// It equals the autoscaling `maxReplicas` when autoscaling is on, otherwise the static
    /// `replicas`. Gating on the ceiling (not the current/floor count) means an autoscaling
    /// relay that can reach ≥2 replicas keeps its PDB even while momentarily scaled to 1.
    pub pdb_replica_ceiling: i32,
}

/// The rendered relay objects. No HPA — relay autoscaling is controller-driven
/// (`Deployment.spec.replicas` is set directly; see the operator's `reconciler`). A PDB
/// is rendered when the effective replica floor is ≥2 (#589).
pub(crate) struct RenderedRelay {
    /// Zero-verb pod identity (no RoleBinding).
    pub service_account: ServiceAccount,
    /// Downstream discovery ClusterIP the namespace's dedicated proxies dial.
    pub service: Service,
    /// The relay Deployment running `serve relay --namespace=<ns>`.
    pub deployment: Deployment,
    /// `PodDisruptionBudget` protecting the relay during voluntary disruptions —
    /// `Some` only when [`RelayRenderInputs::pdb_replica_ceiling`] ≥ 2. Applied-or-deleted by
    /// [`super::apply::apply_relay`].
    pub pdb: Option<PodDisruptionBudget>,
}

/// Label selector matching every **dedicated** (per-namespace) relay resource
/// cluster-wide, joining `app.kubernetes.io/name` + `app.kubernetes.io/component`
/// (the same keys the Deployment/Service select on). Single source for the startup
/// rehydration `LIST` in [`super::reconciler`] so the query can never drift from
/// the labels [`relay_labels`] stamps.
pub(super) fn relay_component_label_selector() -> String {
    component_label_selector(RELAY_COMPONENT)
}

fn component_label_selector(component: &str) -> String {
    format!("app.kubernetes.io/name=coxswain,app.kubernetes.io/component={component}")
}

/// The reserved label set every relay resource carries. The Service/Deployment
/// selectors join on `app.kubernetes.io/name` + `app.kubernetes.io/component`,
/// which uniquely identifies the relay's pods within its namespace.
fn relay_labels(component: &str) -> BTreeMap<String, String> {
    let mut labels = relay_selector_labels(component);
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "coxswain".to_string(),
    );
    labels
}

/// The subset of [`relay_labels`] the Deployment/Service select on. Kept in sync
/// with `relay_labels` by construction (a subset of the same keys).
fn relay_selector_labels(component: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
    labels.insert(
        "app.kubernetes.io/component".to_string(),
        component.to_string(),
    );
    labels
}

fn relay_metadata(variant: RelayVariant<'_>) -> ObjectMeta {
    ObjectMeta {
        name: Some(variant.name().to_string()),
        namespace: Some(variant.deploy_namespace().to_string()),
        labels: Some(relay_labels(variant.component())),
        // No owner reference: a relay outlives any single Gateway (dedicated) or is
        // the install's shared infra (shared) — its lifecycle is explicit convergence.
        ..Default::default()
    }
}

/// Render the bare, zero-verb relay `ServiceAccount`. Like the shared proxy, the
/// relay disables the default token automount — it presents only the explicit,
/// audience-scoped projected token from [`discovery_volumes`].
fn render_relay_service_account(variant: RelayVariant<'_>) -> ServiceAccount {
    ServiceAccount {
        metadata: relay_metadata(variant),
        automount_service_account_token: Some(false),
        ..Default::default()
    }
}

/// Render the downstream discovery `Service` (ClusterIP) that the relay's leaves
/// dial for routing snapshots.
fn render_relay_service(variant: RelayVariant<'_>) -> Service {
    Service {
        metadata: relay_metadata(variant),
        spec: Some(ServiceSpec {
            selector: Some(relay_selector_labels(variant.component())),
            ports: Some(vec![ServicePort {
                name: Some("discovery".to_string()),
                port: RELAY_DISCOVERY_PORT,
                target_port: Some(IntOrString::Int(RELAY_DISCOVERY_PORT)),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: None,
    }
}

/// Render the relay `Deployment` (`serve relay {--namespace=<ns>|--shared}`, ≥2
/// replicas).
fn render_relay_deployment(inputs: &RelayRenderInputs<'_>) -> Deployment {
    let variant = inputs.variant;
    let component = variant.component();
    let args = vec![
        "serve".to_string(),
        "relay".to_string(),
        // `--namespace=<ns>` (dedicated) or `--shared` (shared-pool) (#605).
        variant.scope_arg(),
        // No `--discovery-endpoint` (#601): the relay learns its own routing
        // upstream (always the controller) from its bootstrap response.
        format!(
            "--discovery-bootstrap-endpoint={}",
            inputs.discovery_bootstrap_endpoint
        ),
        format!(
            "--discovery-sa-token-path={}",
            inputs.discovery_sa_token_path
        ),
        format!(
            "--discovery-ca-bundle-path={}",
            inputs.discovery_ca_bundle_path
        ),
        format!("--discovery-trust-domain={}", inputs.discovery_trust_domain),
        format!("--discovery-port={RELAY_DISCOVERY_PORT}"),
        "--log-format=json".to_string(),
    ];

    let container = Container {
        name: "coxswain".to_string(),
        image: Some(inputs.controller_image.to_string()),
        args: Some(args),
        // Per-pod identity: each relay replica MUST have a unique discovery
        // `node_id`, or their `RosterReport`s collide in the controller registry
        // and the leaf-less replica evicts the other's folded subtree (#585).
        env: Some(super::render::pod_identity_env()),
        ports: Some(vec![
            ContainerPort {
                name: Some("discovery".to_string()),
                container_port: RELAY_DISCOVERY_PORT,
                ..Default::default()
            },
            ContainerPort {
                name: Some("health".to_string()),
                container_port: RELAY_HEALTH_PORT,
                ..Default::default()
            },
        ]),
        // Readiness gates the Service endpoint on the relay actually caching a
        // routing world and serving downstream (`routing_table_loaded` +
        // `downstream_serving` subsystems). A relay whose upstream subscribe is
        // rejected (or whose shared world never caches) never marks
        // `routing_table_loaded` Ready, so it stays out of the Service — the
        // sad-path signal.
        readiness_probe: Some(http_get_probe("/readyz", RELAY_HEALTH_PORT)),
        liveness_probe: Some(http_get_probe("/healthz", RELAY_HEALTH_PORT)),
        // The relay binds only high ports (discovery 50051, health 8081), so no
        // NET_BIND_SERVICE is needed for the non-root runtime.
        security_context: Some(container_hardening_security_context(false)),
        resources: inputs.resources.clone(),
        volume_mounts: Some(discovery_volume_mounts()),
        ..Default::default()
    };

    let base_pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(relay_labels(component)),
            ..Default::default()
        }),
        spec: Some(PodSpec {
            service_account_name: Some(variant.name().to_string()),
            security_context: Some(pod_hardening_security_context()),
            containers: vec![container],
            volumes: Some(discovery_volumes()),
            ..Default::default()
        }),
    };

    // Apply the operator's `CoxswainRelayPolicy.spec.podTemplate` scheduling overlay
    // (#589) with the same strategic-merge semantics as the dedicated proxy — the base
    // coxswain container survives, scheduling fields (nodeSelector/tolerations/affinity/
    // topologySpreadConstraints/priorityClassName) layer on. The shared relay carries
    // no per-object podTemplate (no namespaced policy), so this is inert there.
    let pod_template = match inputs.pod_template {
        Some(overlay) => {
            merge_pod_template(&base_pod_template, overlay, variant.deploy_namespace())
        }
        None => base_pod_template,
    };

    Deployment {
        metadata: relay_metadata(variant),
        spec: Some(DeploymentSpec {
            replicas: Some(inputs.replicas.max(1)),
            selector: LabelSelector {
                match_labels: Some(relay_selector_labels(component)),
                ..Default::default()
            },
            template: pod_template,
            ..Default::default()
        }),
        status: None,
    }
}

/// Build the relay container's [`ResourceRequirements`] from the controller's
/// resource flags (#584). Any empty string omits that entry; an all-empty set
/// yields `None` (BestEffort). CPU carries a request but no limit on purpose — a
/// CPU limit would throttle the delta-fan-out path — while memory carries both
/// (it's the OOM risk that must be bounded to protect the node).
pub(crate) fn relay_resources(
    cpu_request: &str,
    memory_request: &str,
    memory_limit: &str,
) -> Option<ResourceRequirements> {
    let mut requests = BTreeMap::new();
    if !cpu_request.is_empty() {
        requests.insert("cpu".to_string(), Quantity(cpu_request.to_string()));
    }
    if !memory_request.is_empty() {
        requests.insert("memory".to_string(), Quantity(memory_request.to_string()));
    }
    let mut limits = BTreeMap::new();
    if !memory_limit.is_empty() {
        limits.insert("memory".to_string(), Quantity(memory_limit.to_string()));
    }
    if requests.is_empty() && limits.is_empty() {
        return None;
    }
    Some(ResourceRequirements {
        requests: (!requests.is_empty()).then_some(requests),
        limits: (!limits.is_empty()).then_some(limits),
        ..Default::default()
    })
}

/// Render a `PodDisruptionBudget` protecting the relay Deployment (#589).
///
/// Returns `Some` (maxUnavailable: 1) only when the relay's replica ceiling
/// (`inputs.pdb_replica_ceiling`) is ≥ 2. A PDB over a relay that can only ever run a
/// single replica either blocks node drain permanently or provides no protection — both
/// wrong. Selector joins the relay's two-key label set, matching the Deployment/Service.
fn render_relay_pdb(inputs: &RelayRenderInputs<'_>) -> Option<PodDisruptionBudget> {
    if inputs.pdb_replica_ceiling < 2 {
        return None;
    }
    Some(PodDisruptionBudget {
        metadata: relay_metadata(inputs.variant),
        spec: Some(PodDisruptionBudgetSpec {
            max_unavailable: Some(IntOrString::Int(1)),
            selector: Some(LabelSelector {
                match_labels: Some(relay_selector_labels(inputs.variant.component())),
                ..Default::default()
            }),
            ..Default::default()
        }),
        status: None,
    })
}

/// Render all relay objects for `inputs.variant`.
pub(crate) fn render_relay(inputs: &RelayRenderInputs<'_>) -> RenderedRelay {
    RenderedRelay {
        service_account: render_relay_service_account(inputs.variant),
        service: render_relay_service(inputs.variant),
        deployment: render_relay_deployment(inputs),
        pdb: render_relay_pdb(inputs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> RelayRenderInputs<'static> {
        inputs_for(RelayVariant::Namespace {
            namespace: "team-a",
        })
    }

    fn shared_inputs() -> RelayRenderInputs<'static> {
        inputs_for(RelayVariant::Shared {
            install_namespace: "coxswain-system",
        })
    }

    fn inputs_for(variant: RelayVariant<'static>) -> RelayRenderInputs<'static> {
        RelayRenderInputs {
            variant,
            replicas: 2,
            controller_image: "ghcr.io/coxswain-labs/coxswain:test",
            discovery_bootstrap_endpoint: "https://coxswain-controller-discovery-bootstrap.coxswain-system.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            resources: relay_resources("50m", "64Mi", "256Mi"),
            pod_template: None,
            pdb_replica_ceiling: 2,
        }
    }

    #[test]
    fn relay_resources_omits_empty_and_keeps_cpu_request_only() {
        let r = relay_resources("50m", "64Mi", "256Mi").expect("some");
        let req = r.requests.expect("requests");
        assert_eq!(req.get("cpu").map(|q| q.0.as_str()), Some("50m"));
        assert_eq!(req.get("memory").map(|q| q.0.as_str()), Some("64Mi"));
        let lim = r.limits.expect("limits");
        assert_eq!(lim.get("memory").map(|q| q.0.as_str()), Some("256Mi"));
        assert!(
            !lim.contains_key("cpu"),
            "a CPU limit must never be set — it would throttle the fan-out path"
        );
        assert!(
            relay_resources("", "", "").is_none(),
            "an all-empty resource set leaves the container BestEffort (None)"
        );
    }

    #[test]
    fn deployment_carries_resource_requests() {
        let d = render_relay_deployment(&inputs());
        let container = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let req = container
            .resources
            .as_ref()
            .and_then(|r| r.requests.as_ref())
            .expect("relay container must carry resource requests, not run BestEffort");
        assert!(req.contains_key("cpu") && req.contains_key("memory"));
    }

    #[test]
    fn service_account_is_zero_verb_and_disables_automount() {
        let sa = render_relay_service_account(RelayVariant::Namespace {
            namespace: "team-a",
        });
        assert_eq!(sa.metadata.name.as_deref(), Some(RELAY_NAME));
        assert_eq!(sa.metadata.namespace.as_deref(), Some("team-a"));
        assert_eq!(
            sa.automount_service_account_token,
            Some(false),
            "relay SA must disable the default token automount (only the explicit projected token is mounted)"
        );
    }

    #[test]
    fn no_owner_reference_on_any_relay_object() {
        let r = render_relay(&inputs());
        assert!(
            r.service_account.metadata.owner_references.is_none(),
            "relay is per-namespace, not owned by any Gateway"
        );
        assert!(r.service.metadata.owner_references.is_none());
        assert!(r.deployment.metadata.owner_references.is_none());
    }

    #[test]
    fn shared_variant_renders_serve_relay_shared_in_install_namespace() {
        let r = render_relay(&shared_inputs());
        assert_eq!(
            r.service_account.metadata.name.as_deref(),
            Some(SHARED_RELAY_NAME)
        );
        assert_eq!(
            r.deployment.metadata.namespace.as_deref(),
            Some("coxswain-system"),
            "the shared relay lives in the install namespace"
        );
        // Component label distinguishes the tier so selectors never collide.
        assert_eq!(
            r.deployment
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get("app.kubernetes.io/component"))
                .map(String::as_str),
            Some(SHARED_RELAY_COMPONENT)
        );
        let spec = r.deployment.spec.expect("deployment spec");
        let pod = spec.template.spec.expect("pod spec");
        assert_eq!(pod.service_account_name.as_deref(), Some(SHARED_RELAY_NAME));
        let args = pod.containers[0].args.clone().expect("args");
        assert_eq!(&args[0..2], ["serve", "relay"]);
        assert!(
            args.iter().any(|a| a == "--shared"),
            "shared relay subscribes --shared: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a.starts_with("--namespace")),
            "shared relay carries no --namespace: {args:?}"
        );
        assert!(
            r.deployment.metadata.owner_references.is_none()
                && r.service_account.metadata.owner_references.is_none(),
            "the shared relay is install infra, not owner-ref'd"
        );
    }

    #[test]
    fn shared_and_namespace_variants_carry_distinct_selectors() {
        let ns = render_relay(&inputs());
        let shared = render_relay(&shared_inputs());
        let component = |d: &Deployment| {
            d.spec
                .as_ref()
                .and_then(|s| s.selector.match_labels.as_ref())
                .and_then(|l| l.get("app.kubernetes.io/component"))
                .cloned()
        };
        assert_ne!(
            component(&ns.deployment),
            component(&shared.deployment),
            "the two tiers must select on distinct components so their pods never mix"
        );
    }

    #[test]
    fn deployment_runs_serve_relay_for_the_namespace() {
        let d = render_relay_deployment(&inputs());
        let spec = d.spec.expect("deployment spec");
        assert_eq!(spec.replicas, Some(2), "a relay is HA (≥2 replicas)");
        let container = &spec.template.spec.expect("pod spec").containers[0];
        let args = container.args.clone().expect("container args");
        assert_eq!(args[0], "serve");
        assert_eq!(args[1], "relay");
        assert!(
            args.iter().any(|a| a == "--namespace=team-a"),
            "relay must aggregate its own namespace: {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--discovery-port=50051"),
            "relay must serve downstream on the discovery port: {args:?}"
        );
        assert_eq!(
            container
                .args
                .as_ref()
                .unwrap()
                .iter()
                .filter(|a| a.starts_with("--gateway-name"))
                .count(),
            0,
            "a relay is namespace-scoped and must carry no --gateway-name"
        );
    }

    #[test]
    fn replicas_clamp_to_at_least_one() {
        let mut i = inputs();
        i.replicas = 0;
        let d = render_relay_deployment(&i);
        assert_eq!(
            d.spec.unwrap().replicas,
            Some(1),
            "a relay must never render 0 replicas (0 = leave --relay-enabled off)"
        );
    }

    #[test]
    fn relay_pod_is_hardened_without_net_bind_service() {
        let d = render_relay_deployment(&inputs());
        let pod = d.spec.unwrap().template.spec.unwrap();
        assert_eq!(
            pod.security_context.and_then(|s| s.run_as_non_root),
            Some(true),
            "relay pod must run as non-root"
        );
        let sc = pod.containers[0]
            .security_context
            .as_ref()
            .expect("container security context");
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        assert_eq!(
            sc.capabilities.as_ref().unwrap().drop.as_deref(),
            Some(&["ALL".to_string()][..])
        );
        assert!(
            sc.capabilities.as_ref().unwrap().add.is_none(),
            "the relay binds only high ports; no NET_BIND_SERVICE"
        );
    }

    #[test]
    fn deployment_gates_readiness_on_relay_health() {
        let d = render_relay_deployment(&inputs());
        let container = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let probe = container.readiness_probe.as_ref().expect("readiness probe");
        let get = probe.http_get.as_ref().expect("http get");
        assert_eq!(get.path.as_deref(), Some("/readyz"));
        assert_eq!(get.port, IntOrString::Int(RELAY_HEALTH_PORT));
    }

    #[test]
    fn pod_template_overlay_merges_scheduling_and_keeps_coxswain_container() {
        let overlay = serde_json::json!({
            "spec": {
                "nodeSelector": {"zone": "eu-1"},
                "tolerations": [{"key": "relay", "operator": "Exists"}],
                "priorityClassName": "high"
            }
        });
        let mut i = inputs();
        i.pod_template = Some(&overlay);
        let d = render_relay_deployment(&i);
        let spec = d.spec.expect("spec").template.spec.expect("pod spec");
        assert_eq!(
            spec.node_selector
                .as_ref()
                .and_then(|n| n.get("zone"))
                .map(String::as_str),
            Some("eu-1"),
            "scheduling overlay applied"
        );
        assert_eq!(
            spec.priority_class_name.as_deref(),
            Some("high"),
            "priorityClassName overlay applied"
        );
        assert!(
            spec.containers.iter().any(|c| c.name == "coxswain"),
            "base coxswain container survives the strategic merge"
        );
    }

    #[test]
    fn malformed_pod_template_overlay_degrades_to_base_without_panic() {
        // `containers` patched into a non-array can't deserialize back into a
        // PodTemplateSpec; the relay must render its base pod (coxswain container
        // intact) rather than crash the reconcile.
        let overlay = serde_json::json!({"spec": {"containers": "not-an-array"}});
        let mut i = inputs();
        i.pod_template = Some(&overlay);
        let d = render_relay_deployment(&i);
        let spec = d.spec.expect("spec").template.spec.expect("pod spec");
        assert!(
            spec.containers.iter().any(|c| c.name == "coxswain"),
            "malformed overlay is ignored; the base relay container survives"
        );
    }

    #[test]
    fn pdb_rendered_at_ceiling_two_absent_below() {
        let mut i = inputs();
        i.pdb_replica_ceiling = 2;
        let r = render_relay(&i);
        let pdb = r.pdb.expect("PDB at ceiling 2");
        assert_eq!(
            pdb.spec.and_then(|s| s.max_unavailable),
            Some(IntOrString::Int(1))
        );
        i.pdb_replica_ceiling = 1;
        assert!(
            render_relay(&i).pdb.is_none(),
            "no PDB when the relay can only ever run a single replica (counterproductive)"
        );
    }

    #[test]
    fn service_targets_the_downstream_discovery_port() {
        let svc = render_relay_service(RelayVariant::Namespace {
            namespace: "team-a",
        });
        let spec = svc.spec.expect("service spec");
        let port = &spec.ports.expect("ports")[0];
        assert_eq!(port.port, RELAY_DISCOVERY_PORT);
        assert_eq!(
            spec.selector
                .expect("selector")
                .get("app.kubernetes.io/component")
                .map(String::as_str),
            Some(RELAY_COMPONENT)
        );
    }
}
