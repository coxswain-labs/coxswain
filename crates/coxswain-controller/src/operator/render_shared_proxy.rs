//! Render the controller-owned **shared proxy pool** — the base Ingress/Gateway
//! data plane (#604).
//!
//! Historically the shared proxy Deployment was Helm-owned static infrastructure.
//! #604 **moves** ownership to the controller so it can repoint the pool the same
//! way it already repoints dedicated proxies and namespace relays (#605), without
//! stealing fields from Helm's field manager or fighting every `helm upgrade`.
//!
//! ## Base data plane, not per-Gateway
//!
//! Unlike the dedicated-proxy trio (provisioned per-Gateway, owner-ref'd so a
//! Gateway delete cascades) or a namespace relay (provisioned per tenant
//! namespace), the shared pool is the install's **base data plane** and must
//! exist from install with **zero Gateways**. It carries **no owner reference**;
//! its lifecycle is driven by the config-keyed install reconcile in
//! [`super::shared_install`], not by any Kubernetes object.
//!
//! ## Selector bridge
//!
//! The pods carry exactly the label set the install passes as
//! `--shared-proxy-selector` (threaded in via [`SharedProxyRenderInputs::selector`]).
//! The Deployment's own `spec.selector`, the retained Helm-owned Ingress LoadBalancer Service, and
//! every per-Gateway shared-mode VIP Service ([`super::render_shared`]) all select
//! on that same set — so moving ownership never changes which pods answer traffic.
//!
//! ## Identity + zero verbs
//!
//! Reuses the dedicated proxy's SVID-bootstrap wiring verbatim
//! ([`super::render::discovery_volumes`] / [`super::render::discovery_volume_mounts`]):
//! it bootstraps a rotating SVID from the controller and receives its routing
//! upstream at bootstrap (the shared relay if one fronts the pool, else the
//! controller — resolved by the discovery server's `Scope::SharedPool` arm, #601),
//! so **no** `--discovery-endpoint` is rendered. Its ServiceAccount holds **zero**
//! Kubernetes verbs and disables the default token automount — the same read-only
//! invariant as the relay.

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::autoscaling::v2::{
    CrossVersionObjectReference, HorizontalPodAutoscaler, HorizontalPodAutoscalerSpec, MetricSpec,
    MetricTarget, ResourceMetricSource,
};
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

use coxswain_core::fleet::ADMIN_PORT_ANNOTATION;

use super::render::{
    container_hardening_security_context, discovery_volume_mounts, discovery_volumes,
    http_get_probe, merge_pod_template, pod_hardening_security_context, pod_identity_env,
};

/// The tuning + sizing knobs for the controller-owned shared proxy pool (#604).
///
/// Constructed field-by-field in `coxswain-bin` from the `--shared-proxy-*` CLI
/// flags and carried on [`super::OperatorConfig`]. Every value is already in its
/// render-ready form (durations/CIDRs/enums pre-formatted to strings by the bin)
/// so this crate stays free of `humantime`/`ipnet` and the renderer is pure
/// string interpolation. Ports, ingress/gateway-api enablement, and the discovery
/// bootstrap material come from the controller's own config (shared install-wide),
/// not from here.
#[derive(Clone, Debug)]
pub struct ProxyPoolConfig {
    /// Whether the controller provisions the shared pool at all
    /// (`--shared-proxy-enabled`, default true). `false` short-circuits the
    /// install reconcile before any apply.
    pub enabled: bool,
    /// Name shared by the Deployment / ServiceAccount / HPA / PDB, and the stem
    /// of the internal Service (`<name>-internal`). Chart-supplied, release-name
    /// prefixed (e.g. `coxswain-shared-proxy`).
    pub name: String,
    /// Static replica count. Ignored (the field is omitted so the HPA owns it)
    /// when [`Self::autoscaling_enabled`].
    pub replicas: u32,
    /// Container CPU request (raw quantity string, e.g. `100m`). Empty omits it.
    pub cpu_request: String,
    /// Container memory request (e.g. `128Mi`). Empty omits it.
    pub memory_request: String,
    /// Container CPU limit (e.g. `500m`). Empty omits it. Unlike the relay, the
    /// shared proxy carries a CPU limit — it is a request/response data plane, not
    /// the delta-fan-out path a CPU limit would throttle.
    pub cpu_limit: String,
    /// Container memory limit (e.g. `256Mi`). Empty omits it.
    pub memory_limit: String,
    /// Provision a traffic-scaling `HorizontalPodAutoscaler` over the pool.
    pub autoscaling_enabled: bool,
    /// HPA `minReplicas`.
    pub autoscaling_min_replicas: u32,
    /// HPA `maxReplicas`.
    pub autoscaling_max_replicas: u32,
    /// HPA target average CPU utilization percentage.
    pub autoscaling_target_cpu: u32,
    /// `--proxy-threads` (0 = auto).
    pub threads: usize,
    /// `--proxy-upstream-keepalive-pool-size`.
    pub upstream_keepalive_pool_size: usize,
    /// `--proxy-shutdown-grace-period` (humantime form, e.g. `30s`).
    pub shutdown_grace_period: String,
    /// `--proxy-shutdown-timeout`.
    pub shutdown_timeout: String,
    /// `--proxy-listener-drain-timeout`.
    pub listener_drain_timeout: String,
    /// `--proxy-default-request-timeout`. `None` omits the flag (no default).
    pub default_request_timeout: Option<String>,
    /// `--proxy-default-backend-request-timeout`. `None` omits the flag.
    pub default_backend_request_timeout: Option<String>,
    /// `--ingress-accept-proxy-protocol`.
    pub accept_proxy_protocol: bool,
    /// `--ingress-proxy-trusted-sources` (CIDR strings). Empty omits the flag.
    pub trusted_sources: Vec<String>,
    /// `--ingress-default-backend` (`ns/svc:port`). `None` omits the flag.
    pub ingress_default_backend: Option<String>,
    /// `--access-log` (rendered as `--access-log=true|false`; the flag uses
    /// `ArgAction::Set` and needs an explicit value).
    pub access_log: bool,
    /// `--access-log-path-mode` (`full`|`pattern`|`none`).
    pub access_log_path_mode: String,
    /// Optional partial `PodTemplateSpec` (JSON) strategic-merged onto the rendered
    /// pool pod — the scheduling / pod-metadata / pull-secret escape hatch built by
    /// the chart from `proxy.shared.{podLabels,podAnnotations,nodeSelector,
    /// tolerations,affinity,topologySpreadConstraints,priorityClassName,pullSecrets}`.
    /// `None` leaves the controller-rendered pod untouched. The SA name, security
    /// context, discovery volumes, and coxswain container are controller-managed and
    /// survive the merge.
    pub pod_template: Option<serde_json::Value>,
}

/// The install-wide, environment-derived inputs the renderer needs beyond
/// [`ProxyPoolConfig`] — borrowed straight from the reconcile context so the
/// shared pool inherits the controller's own ports, enablement, image, and
/// discovery bootstrap material (one install, one source of truth).
pub(crate) struct SharedProxyRenderInputs<'a> {
    /// The proxy-specific knob bundle.
    pub config: &'a ProxyPoolConfig,
    /// The selector bridge (`--shared-proxy-selector`): the label set stamped on
    /// the pool's pods and used as the Deployment/internal-Service/PDB
    /// `spec.selector`. The same map backs the per-Gateway VIP Services and the
    /// retained Ingress LB Service, so all agree. Sourced from the reconcile
    /// context's `shared_proxy_selector` — one source, not duplicated on the config.
    pub selector: &'a BTreeMap<String, String>,
    /// Install namespace the pool is provisioned into (the controller's own).
    pub namespace: &'a str,
    /// Container image (the controller's own image, version-pinned).
    pub controller_image: &'a str,
    /// Controller bootstrap endpoint for SVID issuance + upstream delivery.
    pub discovery_bootstrap_endpoint: &'a str,
    /// Projected SA-token path (`--discovery-sa-token-path`).
    pub discovery_sa_token_path: &'a str,
    /// CA trust-bundle path (`--discovery-ca-bundle-path`).
    pub discovery_ca_bundle_path: &'a str,
    /// SPIFFE trust domain (`--discovery-trust-domain`).
    pub discovery_trust_domain: &'a str,
    /// Ingress HTTP port the pool binds (`None` = no static HTTP listener). Also
    /// the `http`-named container port the retained LB Service targets.
    pub ingress_http_port: Option<u16>,
    /// Ingress HTTPS port (`None` = no static HTTPS listener).
    pub ingress_https_port: Option<u16>,
    /// Health server port (`/readyz`, `/healthz`).
    pub health_port: u16,
    /// Admin/metrics port.
    pub admin_port: u16,
    /// Whether the Ingress surface is enabled install-wide (mirrors the
    /// controller's `--disable-ingress`).
    pub enable_ingress: bool,
    /// Whether the Gateway API surface is enabled install-wide (mirrors the
    /// controller's `--disable-gateway-api`).
    pub enable_gateway_api: bool,
}

/// The rendered shared-pool objects. Applied-or-deleted by
/// [`super::apply::apply_shared_proxy`]. The external Ingress LoadBalancer
/// Service is **not** here — it stays Helm-owned (no SSA conflict, selects the
/// same pods).
pub(crate) struct RenderedSharedProxy {
    /// Zero-verb pod identity (no RoleBinding, automount disabled).
    pub service_account: ServiceAccount,
    /// The shared-proxy Deployment running `serve proxy --shared`.
    pub deployment: Deployment,
    /// Traffic-scaling HPA — `Some` only when autoscaling is enabled.
    pub hpa: Option<HorizontalPodAutoscaler>,
    /// PDB protecting the pool — `Some` only when the effective replica ceiling ≥ 2.
    pub pdb: Option<PodDisruptionBudget>,
    /// Internal ClusterIP Service exposing the health + admin ports.
    pub internal_service: Service,
}

/// Metadata labels for shared-pool resources: the install's selector set plus a
/// controller `managed-by` marker. The selector set is a subset, so it can back
/// the Deployment/Service `spec.selector` while `managed-by` rides along on
/// metadata only.
fn shared_proxy_labels(selector: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut labels = selector.clone();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "coxswain".to_string(),
    );
    labels
}

fn shared_proxy_metadata(
    name: &str,
    namespace: &str,
    selector: &BTreeMap<String, String>,
) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.to_string()),
        namespace: Some(namespace.to_string()),
        labels: Some(shared_proxy_labels(selector)),
        // No owner reference: the shared pool is the base data plane, not owned by
        // any Gateway. Its lifecycle is the config-keyed install reconcile.
        ..Default::default()
    }
}

/// The internal Service name: `<name>-internal` (matches the Helm convention).
fn internal_service_name(config: &ProxyPoolConfig) -> String {
    format!("{}-internal", config.name)
}

/// Render the zero-verb shared-proxy `ServiceAccount` with token automount off.
fn render_shared_proxy_service_account(inputs: &SharedProxyRenderInputs<'_>) -> ServiceAccount {
    ServiceAccount {
        metadata: shared_proxy_metadata(&inputs.config.name, inputs.namespace, inputs.selector),
        automount_service_account_token: Some(false),
        ..Default::default()
    }
}

/// Build the shared-proxy container's [`ResourceRequirements`]. Any empty string
/// omits that entry; an all-empty set yields `None` (BestEffort). Unlike the
/// relay, the shared proxy may carry a CPU limit (it is not the fan-out path).
fn shared_proxy_resources(config: &ProxyPoolConfig) -> Option<ResourceRequirements> {
    let mut requests = BTreeMap::new();
    if !config.cpu_request.is_empty() {
        requests.insert("cpu".to_string(), Quantity(config.cpu_request.clone()));
    }
    if !config.memory_request.is_empty() {
        requests.insert(
            "memory".to_string(),
            Quantity(config.memory_request.clone()),
        );
    }
    let mut limits = BTreeMap::new();
    if !config.cpu_limit.is_empty() {
        limits.insert("cpu".to_string(), Quantity(config.cpu_limit.clone()));
    }
    if !config.memory_limit.is_empty() {
        limits.insert("memory".to_string(), Quantity(config.memory_limit.clone()));
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

/// Build the `serve proxy --shared` container args from the config + env-derived
/// inputs. The routing upstream is bootstrap-delivered (#601), so no
/// `--discovery-endpoint` is emitted.
fn shared_proxy_container_args(inputs: &SharedProxyRenderInputs<'_>) -> Vec<String> {
    let config = inputs.config;
    let mut args = vec![
        "serve".to_string(),
        "proxy".to_string(),
        "--shared".to_string(),
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
        "--log-format=json".to_string(),
        format!("--health-port={}", inputs.health_port),
        format!("--admin-port={}", inputs.admin_port),
    ];

    if inputs.enable_ingress {
        if let Some(port) = inputs.ingress_http_port {
            args.push(format!("--ingress-http-port={port}"));
        }
        if let Some(port) = inputs.ingress_https_port {
            args.push(format!("--ingress-https-port={port}"));
        }
    } else {
        args.push("--disable-ingress".to_string());
    }
    if !inputs.enable_gateway_api {
        args.push("--disable-gateway-api".to_string());
    }

    args.push(format!("--proxy-threads={}", config.threads));
    args.push(format!(
        "--proxy-upstream-keepalive-pool-size={}",
        config.upstream_keepalive_pool_size
    ));
    args.push(format!(
        "--proxy-shutdown-grace-period={}",
        config.shutdown_grace_period
    ));
    args.push(format!(
        "--proxy-shutdown-timeout={}",
        config.shutdown_timeout
    ));
    args.push(format!(
        "--proxy-listener-drain-timeout={}",
        config.listener_drain_timeout
    ));
    if config.accept_proxy_protocol {
        args.push("--ingress-accept-proxy-protocol".to_string());
    }
    if !config.trusted_sources.is_empty() {
        args.push(format!(
            "--ingress-proxy-trusted-sources={}",
            config.trusted_sources.join(",")
        ));
    }
    if let Some(t) = &config.default_request_timeout {
        args.push(format!("--proxy-default-request-timeout={t}"));
    }
    if let Some(t) = &config.default_backend_request_timeout {
        args.push(format!("--proxy-default-backend-request-timeout={t}"));
    }
    if let Some(b) = &config.ingress_default_backend {
        args.push(format!("--ingress-default-backend={b}"));
    }
    args.push(format!("--access-log={}", config.access_log));
    args.push(format!(
        "--access-log-path-mode={}",
        config.access_log_path_mode
    ));

    args
}

/// The container ports the pool exposes: the named `http`/`https` ports the
/// retained Ingress LB Service targets (only when Ingress is enabled and a port
/// is configured), plus the always-present `health`/`admin` ports the internal
/// Service targets.
fn shared_proxy_container_ports(inputs: &SharedProxyRenderInputs<'_>) -> Vec<ContainerPort> {
    let mut ports = Vec::new();
    if inputs.enable_ingress {
        if let Some(port) = inputs.ingress_http_port {
            ports.push(ContainerPort {
                name: Some("http".to_string()),
                container_port: i32::from(port),
                ..Default::default()
            });
        }
        if let Some(port) = inputs.ingress_https_port {
            ports.push(ContainerPort {
                name: Some("https".to_string()),
                container_port: i32::from(port),
                ..Default::default()
            });
        }
    }
    ports.push(ContainerPort {
        name: Some("health".to_string()),
        container_port: i32::from(inputs.health_port),
        ..Default::default()
    });
    ports.push(ContainerPort {
        name: Some("admin".to_string()),
        container_port: i32::from(inputs.admin_port),
        ..Default::default()
    });
    ports
}

/// Render the shared-proxy `Deployment` (`serve proxy --shared`).
fn render_shared_proxy_deployment(inputs: &SharedProxyRenderInputs<'_>) -> Deployment {
    let config = inputs.config;

    let container = Container {
        name: "coxswain".to_string(),
        image: Some(inputs.controller_image.to_string()),
        args: Some(shared_proxy_container_args(inputs)),
        ports: Some(shared_proxy_container_ports(inputs)),
        // Per-pod identity: each replica MUST have a unique discovery `node_id`.
        env: Some(pod_identity_env()),
        // Readiness gates the Service (the retained LB + the internal one) on the
        // pool actually serving, so a rollout never routes to a proxy that hasn't
        // loaded routing yet.
        readiness_probe: Some(http_get_probe("/readyz", i32::from(inputs.health_port))),
        liveness_probe: Some(http_get_probe("/healthz", i32::from(inputs.health_port))),
        resources: shared_proxy_resources(config),
        security_context: Some(container_hardening_security_context(
            needs_net_bind_service(inputs),
        )),
        volume_mounts: Some(discovery_volume_mounts()),
        ..Default::default()
    };

    // The admin-port annotation is load-bearing: the fleet snapshot
    // (`coxswain_core::fleet::build_snapshot`) skips any pod that lacks it, so the
    // shared pool must carry it to appear in the operator's data-plane view.
    let mut annotations = BTreeMap::new();
    annotations.insert(
        ADMIN_PORT_ANNOTATION.to_string(),
        inputs.admin_port.to_string(),
    );

    let base_pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(shared_proxy_labels(inputs.selector)),
            annotations: Some(annotations),
            ..Default::default()
        }),
        spec: Some(PodSpec {
            service_account_name: Some(config.name.clone()),
            automount_service_account_token: Some(false),
            security_context: Some(pod_hardening_security_context()),
            containers: vec![container],
            volumes: Some(discovery_volumes()),
            ..Default::default()
        }),
    };

    // Strategic-merge the operator's `proxy.shared.podTemplate` overlay (scheduling
    // + pod metadata + pull secrets) onto the base, same semantics as the dedicated
    // proxy's `CoxswainGatewayParameters.spec.podTemplate`. The controller-managed
    // fields (SA name, security context, discovery volumes, the coxswain container)
    // survive; `merge_pod_template` degrades to the base on a malformed overlay.
    let pod_template = match config.pod_template.as_ref() {
        Some(overlay) => merge_pod_template(&base_pod_template, overlay, &config.name),
        None => base_pod_template,
    };

    // Under autoscaling the HPA is the sole authority on replica count; omitting
    // `replicas` leaves the field unmanaged by SSA so the HPA owns it (same
    // discipline as the dedicated renderer).
    let replicas = if config.autoscaling_enabled {
        None
    } else {
        Some(i32::try_from(config.replicas).unwrap_or(1))
    };

    Deployment {
        metadata: shared_proxy_metadata(&config.name, inputs.namespace, inputs.selector),
        spec: Some(DeploymentSpec {
            replicas,
            selector: LabelSelector {
                match_labels: Some(inputs.selector.clone()),
                ..Default::default()
            },
            template: pod_template,
            ..Default::default()
        }),
        status: None,
    }
}

/// Whether the pool binds a privileged (`<1024`) Ingress listener port and so
/// needs `NET_BIND_SERVICE` to bind it as non-root.
fn needs_net_bind_service(inputs: &SharedProxyRenderInputs<'_>) -> bool {
    inputs.enable_ingress
        && [inputs.ingress_http_port, inputs.ingress_https_port]
            .into_iter()
            .flatten()
            .any(|p| p < 1024)
}

/// Render the internal ClusterIP `Service` exposing the health + admin ports.
fn render_shared_proxy_internal_service(inputs: &SharedProxyRenderInputs<'_>) -> Service {
    Service {
        metadata: shared_proxy_metadata(
            &internal_service_name(inputs.config),
            inputs.namespace,
            inputs.selector,
        ),
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".to_string()),
            selector: Some(inputs.selector.clone()),
            ports: Some(vec![
                ServicePort {
                    name: Some("health".to_string()),
                    port: i32::from(inputs.health_port),
                    target_port: Some(IntOrString::Int(i32::from(inputs.health_port))),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("admin".to_string()),
                    port: i32::from(inputs.admin_port),
                    target_port: Some(IntOrString::Int(i32::from(inputs.admin_port))),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        status: None,
    }
}

/// Render the traffic-scaling `HorizontalPodAutoscaler` — `Some` only when
/// autoscaling is enabled. Mirrors the dedicated renderer's single-CPU-metric HPA
/// but takes the min/max/target primitives directly (the shared pool has no
/// `EffectiveParams`).
fn render_shared_proxy_hpa(
    inputs: &SharedProxyRenderInputs<'_>,
) -> Option<HorizontalPodAutoscaler> {
    let config = inputs.config;
    if !config.autoscaling_enabled {
        return None;
    }
    let metrics = vec![MetricSpec {
        type_: "Resource".to_string(),
        resource: Some(ResourceMetricSource {
            name: "cpu".to_string(),
            target: MetricTarget {
                type_: "Utilization".to_string(),
                average_utilization: Some(
                    i32::try_from(config.autoscaling_target_cpu).unwrap_or(i32::MAX),
                ),
                ..Default::default()
            },
        }),
        ..Default::default()
    }];
    Some(HorizontalPodAutoscaler {
        metadata: shared_proxy_metadata(&config.name, inputs.namespace, inputs.selector),
        spec: HorizontalPodAutoscalerSpec {
            scale_target_ref: CrossVersionObjectReference {
                api_version: Some("apps/v1".to_string()),
                kind: "Deployment".to_string(),
                name: config.name.clone(),
            },
            min_replicas: Some(i32::try_from(config.autoscaling_min_replicas).unwrap_or(1)),
            max_replicas: i32::try_from(config.autoscaling_max_replicas).unwrap_or(i32::MAX),
            metrics: Some(metrics),
            ..Default::default()
        },
        status: None,
    })
}

/// Render a `PodDisruptionBudget` (maxUnavailable: 1) protecting the pool —
/// `Some` only when the effective replica ceiling is ≥ 2. The ceiling is the HPA
/// `maxReplicas` under autoscaling, otherwise the static `replicas`. Gating on the
/// ceiling keeps a PDB over an autoscaling pool that can reach ≥2 even while
/// momentarily scaled to 1.
fn render_shared_proxy_pdb(inputs: &SharedProxyRenderInputs<'_>) -> Option<PodDisruptionBudget> {
    let config = inputs.config;
    let ceiling = if config.autoscaling_enabled {
        config.autoscaling_max_replicas
    } else {
        config.replicas
    };
    if ceiling < 2 {
        return None;
    }
    Some(PodDisruptionBudget {
        metadata: shared_proxy_metadata(&config.name, inputs.namespace, inputs.selector),
        spec: Some(PodDisruptionBudgetSpec {
            max_unavailable: Some(IntOrString::Int(1)),
            selector: Some(LabelSelector {
                match_labels: Some(inputs.selector.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        status: None,
    })
}

/// Render every controller-owned shared-pool object.
pub(crate) fn render_shared_proxy(inputs: &SharedProxyRenderInputs<'_>) -> RenderedSharedProxy {
    RenderedSharedProxy {
        service_account: render_shared_proxy_service_account(inputs),
        deployment: render_shared_proxy_deployment(inputs),
        hpa: render_shared_proxy_hpa(inputs),
        pdb: render_shared_proxy_pdb(inputs),
        internal_service: render_shared_proxy_internal_service(inputs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `app.kubernetes.io/component` value the shared pool selects on — matches
    /// the label the retained Ingress LB Service and per-Gateway VIP Services use.
    const SHARED_PROXY_COMPONENT: &str = "shared-proxy";

    fn selector() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
        m.insert(
            "app.kubernetes.io/instance".to_string(),
            "coxswain".to_string(),
        );
        m.insert(
            "app.kubernetes.io/component".to_string(),
            SHARED_PROXY_COMPONENT.to_string(),
        );
        m
    }

    fn config() -> ProxyPoolConfig {
        ProxyPoolConfig {
            enabled: true,
            name: "coxswain-shared-proxy".to_string(),
            replicas: 1,
            cpu_request: "100m".to_string(),
            memory_request: "128Mi".to_string(),
            cpu_limit: "500m".to_string(),
            memory_limit: "256Mi".to_string(),
            autoscaling_enabled: false,
            autoscaling_min_replicas: 2,
            autoscaling_max_replicas: 10,
            autoscaling_target_cpu: 80,
            threads: 0,
            upstream_keepalive_pool_size: 128,
            shutdown_grace_period: "30s".to_string(),
            shutdown_timeout: "5s".to_string(),
            listener_drain_timeout: "30s".to_string(),
            default_request_timeout: None,
            default_backend_request_timeout: None,
            accept_proxy_protocol: false,
            trusted_sources: Vec::new(),
            ingress_default_backend: None,
            access_log: true,
            access_log_path_mode: "full".to_string(),
            pod_template: None,
        }
    }

    fn inputs(config: &ProxyPoolConfig) -> SharedProxyRenderInputs<'_> {
        // Leak a selector so the returned inputs can borrow it for the test's
        // lifetime without threading a separate binding through every call site.
        let selector: &'static BTreeMap<String, String> = Box::leak(Box::new(selector()));
        SharedProxyRenderInputs {
            config,
            selector,
            namespace: "coxswain-system",
            controller_image: "ghcr.io/coxswain-labs/coxswain:test",
            discovery_bootstrap_endpoint: "https://coxswain-controller-discovery-bootstrap.coxswain-system.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            ingress_http_port: Some(8080),
            ingress_https_port: Some(8443),
            health_port: 8081,
            admin_port: 8082,
            enable_ingress: true,
            enable_gateway_api: true,
        }
    }

    #[test]
    fn container_args_carry_shared_invocation_without_discovery_endpoint() {
        let c = config();
        let d = render_shared_proxy_deployment(&inputs(&c));
        let container = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let args = container.args.clone().expect("container args");
        assert_eq!(args[0], "serve");
        assert_eq!(args[1], "proxy");
        assert!(args.iter().any(|a| a == "--shared"), "{args:?}");
        assert!(
            args.iter()
                .any(|a| a.starts_with("--discovery-bootstrap-endpoint=")),
            "the pool bootstraps its SVID + upstream: {args:?}"
        );
        assert_eq!(
            args.iter()
                .filter(|a| a.starts_with("--discovery-endpoint"))
                .count(),
            0,
            "no static --discovery-endpoint (#601 bootstrap-delivered): {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--ingress-http-port=8080"),
            "{args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--ingress-https-port=8443"),
            "{args:?}"
        );
        assert!(args.iter().any(|a| a == "--access-log=true"), "{args:?}");
        assert!(
            args.iter().any(|a| a == "--access-log-path-mode=full"),
            "{args:?}"
        );
    }

    #[test]
    fn container_args_reproduce_full_tuning_surface() {
        let mut c = config();
        c.threads = 4;
        c.upstream_keepalive_pool_size = 256;
        c.shutdown_grace_period = "45s".to_string();
        c.accept_proxy_protocol = true;
        c.trusted_sources = vec!["10.0.0.0/8".to_string(), "127.0.0.1/32".to_string()];
        c.default_request_timeout = Some("30s".to_string());
        c.default_backend_request_timeout = Some("10s".to_string());
        c.ingress_default_backend = Some("default/fallback:80".to_string());
        c.access_log = false;
        c.access_log_path_mode = "pattern".to_string();
        let d = render_shared_proxy_deployment(&inputs(&c));
        let args = d.spec.unwrap().template.spec.unwrap().containers[0]
            .args
            .clone()
            .unwrap();
        for expected in [
            "--proxy-threads=4",
            "--proxy-upstream-keepalive-pool-size=256",
            "--proxy-shutdown-grace-period=45s",
            "--ingress-accept-proxy-protocol",
            "--ingress-proxy-trusted-sources=10.0.0.0/8,127.0.0.1/32",
            "--proxy-default-request-timeout=30s",
            "--proxy-default-backend-request-timeout=10s",
            "--ingress-default-backend=default/fallback:80",
            "--access-log=false",
            "--access-log-path-mode=pattern",
        ] {
            assert!(
                args.iter().any(|a| a == expected),
                "missing {expected}: {args:?}"
            );
        }
    }

    #[test]
    fn disabled_surfaces_render_disable_flags() {
        let c = config();
        let mut i = inputs(&c);
        i.enable_ingress = false;
        i.enable_gateway_api = false;
        let d = render_shared_proxy_deployment(&i);
        let args = d.spec.unwrap().template.spec.unwrap().containers[0]
            .args
            .clone()
            .unwrap();
        assert!(args.iter().any(|a| a == "--disable-ingress"), "{args:?}");
        assert!(
            args.iter().any(|a| a == "--disable-gateway-api"),
            "{args:?}"
        );
        assert!(
            !args.iter().any(|a| a.starts_with("--ingress-http-port")),
            "no ingress ports when the surface is disabled: {args:?}"
        );
    }

    #[test]
    fn deployment_selector_matches_the_install_selector_exactly() {
        let c = config();
        let d = render_shared_proxy_deployment(&inputs(&c));
        let spec = d.spec.expect("spec");
        assert_eq!(
            spec.selector.match_labels.as_ref(),
            Some(&selector()),
            "the selector bridge: Deployment must select exactly the labels the LB/VIP Services select on"
        );
        // Pod labels must be a superset of the selector so pods actually match.
        let pod_labels = spec.template.metadata.unwrap().labels.unwrap();
        for (k, v) in &selector() {
            assert_eq!(pod_labels.get(k), Some(v), "pod missing selector label {k}");
        }
    }

    #[test]
    fn pod_carries_admin_port_annotation_for_the_fleet_snapshot() {
        let c = config();
        let d = render_shared_proxy_deployment(&inputs(&c));
        let annotations = d
            .spec
            .unwrap()
            .template
            .metadata
            .unwrap()
            .annotations
            .expect("pod annotations");
        assert_eq!(
            annotations.get(ADMIN_PORT_ANNOTATION).map(String::as_str),
            Some("8082"),
            "the fleet snapshot skips pods lacking the admin-port annotation"
        );
    }

    #[test]
    fn service_account_is_zero_verb_and_disables_automount() {
        let c = config();
        let sa = render_shared_proxy_service_account(&inputs(&c));
        assert_eq!(sa.metadata.name.as_deref(), Some("coxswain-shared-proxy"));
        assert_eq!(sa.automount_service_account_token, Some(false));
        let spec = render_shared_proxy_deployment(&inputs(&c))
            .spec
            .unwrap()
            .template
            .spec
            .unwrap();
        assert_eq!(
            spec.automount_service_account_token,
            Some(false),
            "pod spec must also disable automount (defence in depth)"
        );
    }

    #[test]
    fn deployment_gates_readiness_on_the_health_port() {
        let c = config();
        let d = render_shared_proxy_deployment(&inputs(&c));
        let container = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let probe = container.readiness_probe.as_ref().expect("readiness probe");
        let get = probe.http_get.as_ref().expect("http get");
        assert_eq!(get.path.as_deref(), Some("/readyz"));
        assert_eq!(get.port, IntOrString::Int(8081));
        assert!(container.liveness_probe.is_some(), "liveness probe present");
    }

    #[test]
    fn pod_is_hardened_and_binds_privileged_ports_only_with_net_bind_service() {
        // Rootless-style ports (>1024): hardened, no NET_BIND_SERVICE.
        let c = config();
        let d = render_shared_proxy_deployment(&inputs(&c));
        let pod = d.spec.unwrap().template.spec.unwrap();
        assert_eq!(
            pod.security_context
                .as_ref()
                .and_then(|s| s.run_as_non_root),
            Some(true),
            "pool must run as non-root (restricted-PSA admissible)"
        );
        let sc = pod.containers[0]
            .security_context
            .as_ref()
            .expect("container security context");
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        assert_eq!(sc.allow_privilege_escalation, Some(false));
        let caps = sc.capabilities.as_ref().expect("capabilities");
        assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
        assert!(
            caps.add.is_none(),
            "no NET_BIND_SERVICE when binding only unprivileged ports"
        );

        // Privileged Ingress port (80): NET_BIND_SERVICE added so a non-root proxy
        // can bind it.
        let mut i = inputs(&c);
        i.ingress_http_port = Some(80);
        i.ingress_https_port = Some(443);
        let d = render_shared_proxy_deployment(&i);
        let caps = d.spec.unwrap().template.spec.unwrap().containers[0]
            .security_context
            .as_ref()
            .unwrap()
            .capabilities
            .clone()
            .unwrap();
        assert_eq!(
            caps.add.as_deref(),
            Some(&["NET_BIND_SERVICE".to_string()][..]),
            "a non-root proxy needs NET_BIND_SERVICE to bind :80"
        );
    }

    #[test]
    fn pod_template_overlay_merges_scheduling_and_metadata_keeping_controller_fields() {
        let mut c = config();
        c.pod_template = Some(serde_json::json!({
            "metadata": { "annotations": { "prometheus.io/scrape": "true" } },
            "spec": {
                "nodeSelector": { "zone": "eu-1" },
                "priorityClassName": "high",
                "tolerations": [{ "key": "dedicated", "operator": "Exists" }]
            }
        }));
        let d = render_shared_proxy_deployment(&inputs(&c));
        let tmpl = d.spec.unwrap().template;
        let pod = tmpl.spec.expect("pod spec");
        assert_eq!(
            pod.node_selector
                .as_ref()
                .and_then(|n| n.get("zone"))
                .map(String::as_str),
            Some("eu-1"),
            "scheduling overlay applied"
        );
        assert_eq!(pod.priority_class_name.as_deref(), Some("high"));
        assert!(pod.tolerations.is_some(), "tolerations overlay applied");
        // Controller-managed fields survive the merge.
        assert_eq!(
            pod.service_account_name.as_deref(),
            Some("coxswain-shared-proxy")
        );
        assert_eq!(pod.automount_service_account_token, Some(false));
        assert!(
            pod.security_context.is_some(),
            "hardening security context survives the overlay"
        );
        assert!(pod.containers.iter().any(|c| c.name == "coxswain"));
        // Overlay annotation merges alongside the load-bearing admin-port annotation.
        let ann = tmpl.metadata.unwrap().annotations.unwrap();
        assert_eq!(
            ann.get("prometheus.io/scrape").map(String::as_str),
            Some("true")
        );
        assert!(
            ann.contains_key(ADMIN_PORT_ANNOTATION),
            "admin-port annotation not clobbered by the overlay"
        );
    }

    #[test]
    fn malformed_pod_template_overlay_degrades_to_base_without_panic() {
        let mut c = config();
        c.pod_template = Some(serde_json::json!({ "spec": { "containers": "not-an-array" } }));
        let d = render_shared_proxy_deployment(&inputs(&c));
        let pod = d.spec.unwrap().template.spec.unwrap();
        assert!(
            pod.containers.iter().any(|c| c.name == "coxswain"),
            "malformed overlay ignored; base coxswain container survives"
        );
    }

    #[test]
    fn no_owner_reference_on_any_shared_proxy_object() {
        let c = config();
        let r = render_shared_proxy(&inputs(&c));
        assert!(r.service_account.metadata.owner_references.is_none());
        assert!(r.deployment.metadata.owner_references.is_none());
        assert!(r.internal_service.metadata.owner_references.is_none());
    }

    #[test]
    fn replicas_present_static_omitted_under_autoscaling() {
        let mut c = config();
        c.replicas = 3;
        let d = render_shared_proxy_deployment(&inputs(&c));
        assert_eq!(
            d.spec.unwrap().replicas,
            Some(3),
            "static replicas set the Deployment field"
        );
        c.autoscaling_enabled = true;
        let d = render_shared_proxy_deployment(&inputs(&c));
        assert_eq!(
            d.spec.unwrap().replicas,
            None,
            "under autoscaling the replicas field is omitted so the HPA owns it"
        );
    }

    #[test]
    fn hpa_present_only_under_autoscaling() {
        let mut c = config();
        assert!(render_shared_proxy_hpa(&inputs(&c)).is_none());
        c.autoscaling_enabled = true;
        c.autoscaling_min_replicas = 2;
        c.autoscaling_max_replicas = 10;
        c.autoscaling_target_cpu = 75;
        let hpa = render_shared_proxy_hpa(&inputs(&c)).expect("hpa");
        let spec = hpa.spec;
        assert_eq!(spec.min_replicas, Some(2));
        assert_eq!(spec.max_replicas, 10);
        assert_eq!(spec.scale_target_ref.name, "coxswain-shared-proxy");
        let m = &spec.metrics.expect("metrics")[0];
        assert_eq!(
            m.resource.as_ref().unwrap().target.average_utilization,
            Some(75)
        );
    }

    #[test]
    fn pdb_gated_on_replica_ceiling() {
        let mut c = config();
        c.replicas = 1;
        assert!(
            render_shared_proxy_pdb(&inputs(&c)).is_none(),
            "no PDB for a single-replica pool"
        );
        c.replicas = 2;
        assert!(render_shared_proxy_pdb(&inputs(&c)).is_some());
        // Autoscaling ceiling drives the decision even when scaled low.
        c.replicas = 1;
        c.autoscaling_enabled = true;
        c.autoscaling_max_replicas = 5;
        assert!(
            render_shared_proxy_pdb(&inputs(&c)).is_some(),
            "an autoscaling pool that can reach ≥2 keeps its PDB"
        );
    }

    #[test]
    fn internal_service_exposes_health_and_admin() {
        let c = config();
        let svc = render_shared_proxy_internal_service(&inputs(&c));
        assert_eq!(
            svc.metadata.name.as_deref(),
            Some("coxswain-shared-proxy-internal")
        );
        let spec = svc.spec.expect("spec");
        assert_eq!(spec.type_.as_deref(), Some("ClusterIP"));
        assert_eq!(spec.selector.as_ref(), Some(&selector()));
        let names: Vec<_> = spec
            .ports
            .expect("ports")
            .into_iter()
            .filter_map(|p| p.name)
            .collect();
        assert!(names.contains(&"health".to_string()));
        assert!(names.contains(&"admin".to_string()));
    }

    #[test]
    fn resources_carry_requests_and_limits_including_cpu_limit() {
        let c = config();
        let r = shared_proxy_resources(&c).expect("resources");
        assert_eq!(
            r.requests
                .as_ref()
                .and_then(|m| m.get("cpu"))
                .map(|q| q.0.as_str()),
            Some("100m")
        );
        assert_eq!(
            r.limits
                .as_ref()
                .and_then(|m| m.get("cpu"))
                .map(|q| q.0.as_str()),
            Some("500m"),
            "the shared proxy carries a CPU limit (it is not the fan-out path)"
        );
        // All-empty → BestEffort.
        let mut empty = config();
        empty.cpu_request = String::new();
        empty.memory_request = String::new();
        empty.cpu_limit = String::new();
        empty.memory_limit = String::new();
        assert!(shared_proxy_resources(&empty).is_none());
    }
}
