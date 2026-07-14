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
    Container, ContainerPort, HTTPGetAction, PodSpec, PodTemplateSpec, Probe, ResourceRequirements,
    Service, ServiceAccount, ServicePort, ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use std::collections::BTreeMap;

use super::render::{discovery_volume_mounts, discovery_volumes};

/// Fixed name of every per-namespace relay `ServiceAccount` / `Deployment` /
/// `Service`. One relay per namespace, so a constant name is unambiguous (no
/// GEP-1762 per-Gateway qualifier). This is the ServiceAccount half of the relay
/// SVID the provenance authorizer authorizes; re-exported from the crate root as
/// [`crate::RELAY_SERVICE_ACCOUNT`] so `coxswain-bin` shares the single source.
pub(crate) use crate::RELAY_SERVICE_ACCOUNT as RELAY_NAME;

/// `app.kubernetes.io/component` value stamped on every relay resource.
const RELAY_COMPONENT: &str = "namespace-relay";

/// Downstream discovery port the relay serves leaves on (mirrors the controller
/// discovery Stream port). Dedicated proxies in a relay-fronted namespace dial
/// `coxswain-relay.<ns>.svc:<RELAY_DISCOVERY_PORT>`.
pub(crate) const RELAY_DISCOVERY_PORT: i32 = 50051;

/// Health port the relay's `/readyz` (readiness) and `/healthz` (liveness)
/// probes target. Matches the binary's `--health-port` default (8081); the relay
/// container is not passed `--health-port`, so it binds this port by default.
const RELAY_HEALTH_PORT: i32 = 8081;

/// Inputs the operator threads into relay rendering: the discovery-client fields
/// the relay's upstream subscription needs, minus anything Gateway-specific.
/// Borrowed straight from the reconcile context.
pub(crate) struct RelayRenderInputs<'a> {
    /// Tenant namespace the relay is provisioned into and aggregates.
    pub namespace: &'a str,
    /// Replica count for the relay Deployment (`--relay-replicas`, min 1). A relay
    /// is a rollout-time SPOF for every leaf behind it at replica 1, so the
    /// operator default is 2 (HA); small clusters can pin it to 1.
    pub replicas: i32,
    /// Container image (the controller's own image, version-pinned).
    pub controller_image: &'a str,
    /// Controller discovery Stream endpoint the relay subscribes upstream to
    /// (`https://…:50051`, mTLS).
    pub discovery_endpoint: &'a str,
    /// Controller bootstrap endpoint for SVID issuance (`https://…:50052`).
    /// Bootstrap is never tiered — the relay bootstraps directly from the
    /// controller like any other node.
    pub discovery_bootstrap_endpoint: &'a str,
    /// Projected SA-token path (`--discovery-sa-token-path`).
    pub discovery_sa_token_path: &'a str,
    /// CA trust-bundle path (`--discovery-ca-bundle-path`).
    pub discovery_ca_bundle_path: &'a str,
    /// SPIFFE trust domain (`--discovery-trust-domain`).
    pub discovery_trust_domain: &'a str,
    /// Container resource requests/limits (#584), built from the controller's
    /// `--relay-cpu-request` / `--relay-memory-request` / `--relay-memory-limit`
    /// by [`relay_resources`]. `None` leaves the container BestEffort (no v1
    /// default omits it). Per-namespace overrides arrive with `CoxswainRelayPolicy`.
    pub resources: Option<ResourceRequirements>,
}

/// The three rendered relay objects. No HPA/PDB in v1 (fixed ≥2 replicas; HA is
/// the replica floor, not autoscaling).
pub(crate) struct RenderedRelay {
    /// Zero-verb pod identity (no RoleBinding).
    pub service_account: ServiceAccount,
    /// Downstream discovery ClusterIP the namespace's dedicated proxies dial.
    pub service: Service,
    /// The relay Deployment running `serve relay --namespace=<ns>`.
    pub deployment: Deployment,
}

/// The reserved label set every relay resource carries. The Service/Deployment
/// selectors join on `app.kubernetes.io/name` + `app.kubernetes.io/component`,
/// which uniquely identifies the (single) relay's pods within a namespace.
fn relay_labels() -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
    labels.insert(
        "app.kubernetes.io/component".to_string(),
        RELAY_COMPONENT.to_string(),
    );
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "coxswain".to_string(),
    );
    labels
}

/// The subset of [`relay_labels`] the Deployment/Service select on. Kept in sync
/// with `relay_labels` by construction (a subset of the same keys).
fn relay_selector_labels() -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
    labels.insert(
        "app.kubernetes.io/component".to_string(),
        RELAY_COMPONENT.to_string(),
    );
    labels
}

fn relay_metadata(namespace: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(RELAY_NAME.to_string()),
        namespace: Some(namespace.to_string()),
        labels: Some(relay_labels()),
        // No owner reference: a relay is per-namespace, not per-Gateway.
        ..Default::default()
    }
}

/// Render the bare, zero-verb relay `ServiceAccount`. Like the shared proxy, the
/// relay disables the default token automount — it presents only the explicit,
/// audience-scoped projected token from [`discovery_volumes`].
fn render_relay_service_account(namespace: &str) -> ServiceAccount {
    ServiceAccount {
        metadata: relay_metadata(namespace),
        automount_service_account_token: Some(false),
        ..Default::default()
    }
}

/// Render the downstream discovery `Service` (ClusterIP) that the namespace's
/// dedicated proxies dial for routing snapshots.
fn render_relay_service(namespace: &str) -> Service {
    Service {
        metadata: relay_metadata(namespace),
        spec: Some(ServiceSpec {
            selector: Some(relay_selector_labels()),
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

/// Render the relay `Deployment` (`serve relay --namespace=<ns>`, ≥2 replicas).
fn render_relay_deployment(inputs: &RelayRenderInputs<'_>) -> Deployment {
    let args = vec![
        "serve".to_string(),
        "relay".to_string(),
        format!("--namespace={}", inputs.namespace),
        format!("--discovery-endpoint={}", inputs.discovery_endpoint),
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
        // `downstream_serving` subsystems). A relay whose upstream `Namespace`
        // subscribe is rejected never marks `routing_table_loaded` Ready, so it
        // stays out of the Service — the sad-path signal.
        readiness_probe: Some(relay_probe("/readyz")),
        liveness_probe: Some(relay_probe("/healthz")),
        resources: inputs.resources.clone(),
        volume_mounts: Some(discovery_volume_mounts()),
        ..Default::default()
    };

    let pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(relay_labels()),
            ..Default::default()
        }),
        spec: Some(PodSpec {
            service_account_name: Some(RELAY_NAME.to_string()),
            containers: vec![container],
            volumes: Some(discovery_volumes()),
            ..Default::default()
        }),
    };

    Deployment {
        metadata: relay_metadata(inputs.namespace),
        spec: Some(DeploymentSpec {
            replicas: Some(inputs.replicas.max(1)),
            selector: LabelSelector {
                match_labels: Some(relay_selector_labels()),
                ..Default::default()
            },
            template: pod_template,
            ..Default::default()
        }),
        status: None,
    }
}

/// An HTTP GET probe against `path` on the health port.
fn relay_probe(path: &str) -> Probe {
    Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path.to_string()),
            port: IntOrString::Int(RELAY_HEALTH_PORT),
            ..Default::default()
        }),
        ..Default::default()
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

/// Render all three relay objects for `inputs.namespace`.
pub(crate) fn render_relay(inputs: &RelayRenderInputs<'_>) -> RenderedRelay {
    RenderedRelay {
        service_account: render_relay_service_account(inputs.namespace),
        service: render_relay_service(inputs.namespace),
        deployment: render_relay_deployment(inputs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> RelayRenderInputs<'static> {
        RelayRenderInputs {
            namespace: "team-a",
            replicas: 2,
            controller_image: "ghcr.io/coxswain-labs/coxswain:test",
            discovery_endpoint: "https://coxswain-controller-discovery.coxswain-system.svc:50051",
            discovery_bootstrap_endpoint: "https://coxswain-controller-discovery-bootstrap.coxswain-system.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            resources: relay_resources("50m", "64Mi", "256Mi"),
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
        let sa = render_relay_service_account("team-a");
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
    fn deployment_gates_readiness_on_relay_health() {
        let d = render_relay_deployment(&inputs());
        let container = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let probe = container.readiness_probe.as_ref().expect("readiness probe");
        let get = probe.http_get.as_ref().expect("http get");
        assert_eq!(get.path.as_deref(), Some("/readyz"));
        assert_eq!(get.port, IntOrString::Int(RELAY_HEALTH_PORT));
    }

    #[test]
    fn service_targets_the_downstream_discovery_port() {
        let svc = render_relay_service("team-a");
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
