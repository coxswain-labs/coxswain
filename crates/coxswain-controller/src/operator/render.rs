//! Render the desired `Deployment`, `Service`, `ServiceAccount`, optional
//! `HorizontalPodAutoscaler`, and optional `PodDisruptionBudget` for a
//! dedicated-mode Gateway from the merged [`EffectiveParams`].
//!
//! Pure, infallible, side-effect-free — given the same inputs, produces the
//! same outputs. The renderer applies the renderer-level defaults that
//! couldn't be applied at the params-overlay layer (e.g. `replicas`'s
//! built-in default of `1`, `serviceType`'s of `LoadBalancer`).
//!
//! ## GEP-1762 naming and labels
//!
//! - Resource name: `<gateway-name>-<gateway-class-name>` (e.g. for Gateway
//!   `my-gw` in class `coxswain`: `my-gw-coxswain`).
//! - Mandatory labels on every rendered resource (the "reserved set"):
//!   - `gateway.networking.k8s.io/gateway-name: <gateway-name>`
//!   - `app.kubernetes.io/name: coxswain`
//!   - `app.kubernetes.io/instance: <gateway-name>`
//!   - `app.kubernetes.io/managed-by: coxswain`
//!
//! ## GEP-1867 infrastructure overlay (#92)
//!
//! `Gateway.spec.infrastructure.labels` and `.annotations` are merged onto
//! every rendered resource's metadata. The four reserved-set label keys above
//! cannot be overridden by user input — a collision is dropped with a WARN
//! log naming the key — because the Service/Deployment selectors depend on
//! them and a user override would silently detach the Service from its pods.
//! Annotations have no reserved set.
//!
//! ## Owner references
//!
//! Every rendered resource carries a single owner reference back to the
//! parent Gateway with `controller: true` and `blockOwnerDeletion: true`,
//! enabling K8s garbage collection to cascade Gateway deletion to the
//! provisioned resources (Step 9 acceptance criterion).
//!
//! ## Container args
//!
//! `serve proxy --dedicated --gateway-name=<name> --gateway-namespace=<ns>
//! --discovery-endpoint=<endpoint> --discovery-bootstrap-endpoint=<endpoint>
//! --discovery-sa-token-path=<path> --discovery-ca-bundle-path=<path>
//! --discovery-trust-domain=<domain> --log-format=json`. The discovery endpoint
//! is the controller's mTLS gRPC Stream service (`https://…:50051`); the
//! bootstrap endpoint is its server-auth-only SVID issuer (`https://…:50052`).
//! The pod mounts a projected SA token + the CA trust bundle (#423) so it can
//! obtain an SVID and open the mTLS Stream — the same wiring the shared proxy
//! gets from the Helm chart. The proxy subscribes with `Scope::Gateway { name,
//! namespace }` and receives the full routing snapshot — server-side
//! per-gateway scope filtering is a tracked follow-up (v0.6).
//!
//! ## Service ports
//!
//! Each effective listener — the Gateway's own `spec.listeners` plus those
//! merged from attached ListenerSets (GEP-1713, #93) — becomes one entry on the
//! Service, deduplicated on port (the effective set already is, with
//! collision-free names). When the effective set is empty the renderer falls
//! back to `gateway.spec.listeners`. Container ports mirror the Service ports.
//! Protocol is always `TCP` (HTTP/HTTPS/TLS all ride TCP at the Service layer;
//! the proxy distinguishes them at L7 by listener config).

use super::merge::strategic_merge_pod_template;
use super::params::EffectiveParams;
use coxswain_core::crd::ServiceType;
use coxswain_core::naming::gep1762_resource_name;
use coxswain_reflector::EffectiveListenerPort;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::autoscaling::v2::{
    CrossVersionObjectReference, HorizontalPodAutoscaler, HorizontalPodAutoscalerSpec, MetricSpec,
    MetricTarget, ResourceMetricSource,
};
use k8s_openapi::api::core::v1::{
    ConfigMapVolumeSource, Container, ContainerPort, EnvVar, EnvVarSource, ObjectFieldSelector,
    PodSpec, PodTemplateSpec, ProjectedVolumeSource, Service, ServiceAccount,
    ServiceAccountTokenProjection, ServicePort, ServiceSpec, Volume, VolumeMount, VolumeProjection,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use std::collections::{BTreeMap, BTreeSet};

// Shared-mode per-Gateway Service/ServiceAccount rendering lives in the sibling
// `render_shared` module (#472, #482). Re-exported here so existing
// `render::<name>` call paths — `crate::operator::render::shared_gateway_service_name`
// (controller status writer) and the dedicated-proxy render path's
// `requested_static_cluster_ip` — keep resolving without touching callers.
use super::render_shared::requested_static_cluster_ip;
pub(crate) use super::render_shared::shared_gateway_service_name;

#[cfg(test)]
use super::render_shared::{
    SHARED_GATEWAY_SA_COMPONENT, SharedServiceInputs, render_shared_gateway_service,
    render_shared_gateway_service_account, requested_static_cluster_ips,
    shared_gateway_service_account_name,
};

/// Label keys that the controller owns unconditionally. User-supplied
/// `Gateway.spec.infrastructure.labels` collisions on any of these keys are
/// dropped with a WARN log (see [`final_labels`]).
///
/// The Service/Deployment selectors join on `app.kubernetes.io/name` +
/// `app.kubernetes.io/instance`; a user override on either silently detaches
/// the Service from its pods, which is the exact class of bug this list
/// prevents.
const RESERVED_LABEL_KEYS: &[&str] = &[
    "gateway.networking.k8s.io/gateway-name",
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/managed-by",
    "app.kubernetes.io/component",
];

/// Inputs to the renderer.
#[non_exhaustive]
pub(super) struct RenderInputs<'a> {
    /// The Gateway whose dedicated proxy is being rendered.
    pub(super) gateway: &'a Gateway,
    /// The merged parameters from [`super::params::resolve`].
    pub(super) params: &'a EffectiveParams,
    /// Image to use for the proxy container when `params.image` is `None`.
    /// Typically the controller's own image — see [`crate::operator`]
    /// module docs for resolution strategy.
    pub(super) controller_image: &'a str,
    /// Name of the Gateway's GatewayClass (i.e. `gateway.spec.gatewayClassName`).
    /// Used in the GEP-1762 `<NAME>-<GATEWAY CLASS>` resource naming.
    pub(super) gateway_class_name: &'a str,
    /// gRPC endpoint the dedicated proxy connects to for routing snapshots.
    /// Rendered as `--discovery-endpoint=<endpoint>`. Since #423 the Stream
    /// listener is mTLS-only, so this is an `https://` URL.
    pub(super) discovery_endpoint: &'a str,
    /// Server-auth-only bootstrap endpoint the dedicated proxy calls to obtain
    /// its SVID before opening the mTLS Stream. Rendered as
    /// `--discovery-bootstrap-endpoint=<endpoint>` (`https://`).
    pub(super) discovery_bootstrap_endpoint: &'a str,
    /// Filesystem path of the projected ServiceAccount token the proxy presents
    /// to the controller's TokenReview during bootstrap. Rendered as
    /// `--discovery-sa-token-path=<path>`; the token is mounted by the
    /// [`DISCOVERY_TOKEN_VOLUME`] projected volume.
    pub(super) discovery_sa_token_path: &'a str,
    /// Filesystem path of the controller-published CA trust bundle the proxy
    /// verifies the controller against. Rendered as
    /// `--discovery-ca-bundle-path=<path>`; mounted by the
    /// [`DISCOVERY_TRUST_VOLUME`] ConfigMap volume.
    pub(super) discovery_ca_bundle_path: &'a str,
    /// SPIFFE trust domain. Rendered as `--discovery-trust-domain=<domain>`;
    /// the proxy derives the expected controller SPIFFE id from it.
    pub(super) discovery_trust_domain: &'a str,
    /// Admin server port rendered as the `gateway.coxswain-labs.dev/admin-port`
    /// annotation on the pod template so fleet discovery can reach this pod.
    pub(super) admin_port: u16,
    /// Effective listener ports (Gateway's own + attached ListenerSets', GEP-1713)
    /// the dedicated proxy's Service and container expose. Empty falls back to
    /// `gateway.spec.listeners` — so a ListenerSet listener on a new port is
    /// served by the dedicated proxy too.
    pub(super) effective_ports: &'a [EffectiveListenerPort],
    /// Downstream discovery endpoint of the namespace relay when relay tiering is
    /// enabled (#584): `Some("https://coxswain-relay.<ns>.svc:50051")`. The proxy
    /// then subscribes for routing snapshots *through the relay* instead of
    /// directly to the controller — its `--discovery-endpoint` is this value and
    /// it verifies the relay's SVID via an added `--discovery-expected-server-sa`.
    /// **Bootstrap stays the controller** (SVID issuance is never tiered), so
    /// [`Self::discovery_bootstrap_endpoint`] is unchanged. `None` (relay tiering
    /// off) ⇒ the proxy dials the controller directly, exactly as before.
    pub(super) relay_endpoint: Option<&'a str>,
}

/// Name of the projected ServiceAccount-token volume mounted into every
/// dedicated proxy for SVID bootstrap. The token's audience MUST match the
/// value the controller passes to TokenReview (`coxswain-discovery`).
const DISCOVERY_TOKEN_VOLUME: &str = "discovery-token";
/// Directory the projected discovery token is mounted at; the token file lands
/// at `<dir>/token`, matching [`RenderInputs::discovery_sa_token_path`].
const DISCOVERY_TOKEN_MOUNT_DIR: &str = "/var/run/secrets/coxswain/discovery-token";
/// SVID-bootstrap audience the projected token is scoped to.
const DISCOVERY_TOKEN_AUDIENCE: &str = "coxswain-discovery";
/// Name of the trust-bundle ConfigMap volume (public CA roots only — zero
/// proxy RBAC, kubelet mounts it). Optional so a pod that starts before the
/// first publish still boots; the bootstrap loop re-reads until present.
const DISCOVERY_TRUST_VOLUME: &str = "trust-bundle";
/// Directory the trust-bundle ConfigMap is mounted at; the CA file lands at
/// `<dir>/ca.crt`, matching [`RenderInputs::discovery_ca_bundle_path`].
const DISCOVERY_TRUST_MOUNT_DIR: &str = "/var/run/secrets/coxswain/trust-bundle";

/// The rendered resources for one dedicated-mode Gateway.
#[non_exhaustive]
#[derive(Debug)]
pub(super) struct RenderedSpecs {
    /// `ServiceAccount` the proxy pod runs as.
    pub(super) service_account: ServiceAccount,
    /// `Service` exposing the proxy's listeners.
    pub(super) service: Service,
    /// `Deployment` of the proxy pod.
    pub(super) deployment: Deployment,
    /// `HorizontalPodAutoscaler` targeting the proxy Deployment. `Some` only
    /// when `params.autoscaling.enabled` is `true`; the applier deletes any
    /// previously-provisioned HPA when this is `None`.
    pub(super) hpa: Option<HorizontalPodAutoscaler>,
    /// `PodDisruptionBudget` protecting the proxy Deployment during voluntary
    /// disruptions. `Some` only when the effective replica floor (minReplicas
    /// if autoscaling, else replicas) is ≥ 2.
    pub(super) pdb: Option<PodDisruptionBudget>,
}

/// Built-in default for [`EffectiveParams::replicas`].
const DEFAULT_REPLICAS: i32 = 1;

/// Shared metadata threaded through every per-resource render function.
/// Grouping struct so each `render_*` function stays under the
/// `clippy::too_many_arguments` threshold per the workspace lint policy.
struct Common<'a> {
    name: &'a str,
    namespace: &'a str,
    labels: &'a BTreeMap<String, String>,
    annotations: &'a BTreeMap<String, String>,
    owner_ref: &'a OwnerReference,
}

/// Render all three resources for a Gateway.
///
/// # Panics
///
/// Panics if the Gateway has no `metadata.namespace`. This is an apiserver
/// invariant on any object delivered through a watch; its absence indicates
/// a controller bug.
#[must_use]
pub(super) fn render(inputs: &RenderInputs<'_>) -> RenderedSpecs {
    let name = resource_name(inputs.gateway, inputs.gateway_class_name);
    let namespace = inputs
        .gateway
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| {
            panic!("invariant: Gateway has no namespace; the API server requires it")
        });
    let labels = final_labels(inputs.gateway, "dedicated-proxy");
    let annotations = final_annotations(inputs.gateway, inputs.admin_port);
    let owner_ref = gateway_owner_reference(inputs.gateway);
    let common = Common {
        name: &name,
        namespace: &namespace,
        labels: &labels,
        annotations: &annotations,
        owner_ref: &owner_ref,
    };

    RenderedSpecs {
        service_account: render_service_account(&common),
        service: render_service(
            &common,
            inputs.gateway,
            inputs.params,
            inputs.effective_ports,
        ),
        deployment: render_deployment(&common, inputs),
        hpa: render_hpa(&common, inputs.params),
        pdb: render_pdb(&common, inputs.params),
    }
}

/// GEP-1762 names the generated resources `<NAME>-<GATEWAY CLASS>`.
///
/// Shared with the reconciler's migration-cleanup path so the name it deletes
/// is derived from the same single source of truth that provisioning rendered.
/// Delegates to [`coxswain_core::naming::gep1762_resource_name`] — the same
/// formula used by the discovery scope-binding check.
pub(super) fn resource_name(gateway: &Gateway, class_name: &str) -> String {
    let gw_name =
        gateway.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    gep1762_resource_name(gw_name, class_name)
}

/// Reserved-set GEP-1762 labels for one Gateway, stamped with `component` as
/// the `app.kubernetes.io/component` value (e.g. `dedicated-proxy` for the
/// dedicated trio, `shared-gateway-sa` for the shared-mode identity SA). Used
/// internally by [`final_labels`]; not exposed because callers should always go
/// through `final_labels`, which also overlays the user-supplied
/// `Gateway.spec.infrastructure.labels`.
fn standard_labels(gateway: &Gateway, component: &str) -> BTreeMap<String, String> {
    let gw_name = gateway.metadata.name.clone().unwrap_or_default();
    let mut labels = BTreeMap::new();
    labels.insert(
        "gateway.networking.k8s.io/gateway-name".to_string(),
        gw_name.clone(),
    );
    labels.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
    labels.insert("app.kubernetes.io/instance".to_string(), gw_name);
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "coxswain".to_string(),
    );
    labels.insert(
        "app.kubernetes.io/component".to_string(),
        component.to_string(),
    );
    labels
}

/// Reserved annotations placed on every rendered resource. Unlike labels, there
/// is no reserved-annotation enforcement — user-supplied
/// `Gateway.spec.infrastructure.annotations` are overlaid on top so operators
/// can override values when needed.
fn standard_annotations(admin_port: u16) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();
    annotations.insert(
        "gateway.coxswain-labs.dev/admin-port".to_string(),
        admin_port.to_string(),
    );
    annotations
}

/// Merge user-supplied `Gateway.spec.infrastructure.labels` onto the
/// reserved GEP-1762 label set, stamping `component` as the
/// `app.kubernetes.io/component` value. User collisions on a reserved key are
/// dropped with a WARN log — the reserved set is non-negotiable because the
/// Service/Deployment selectors depend on it.
pub(super) fn final_labels(gateway: &Gateway, component: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    if let Some(user_labels) = gateway
        .spec
        .infrastructure
        .as_ref()
        .and_then(|i| i.labels.as_ref())
    {
        for (k, v) in user_labels {
            if RESERVED_LABEL_KEYS.contains(&k.as_str()) {
                tracing::warn!(
                    namespace = gateway.metadata.namespace.as_deref().unwrap_or(""),
                    gateway = gateway.metadata.name.as_deref().unwrap_or(""),
                    key = k.as_str(),
                    "operator: ignoring infrastructure.labels override on reserved key (GEP-1762)"
                );
                continue;
            }
            labels.insert(k.clone(), v.clone());
        }
    }
    labels.extend(standard_labels(gateway, component));
    labels
}

/// Overlay user-supplied `Gateway.spec.infrastructure.annotations` (GEP-1867)
/// onto `base`. User values win on collision — annotations don't drive
/// selectors so overrides are safe. Shared with both the dedicated trio (whose
/// `base` is [`standard_annotations`]) and the shared-mode identity SA / VIP
/// Service (whose `base` is empty — they carry no admin-port annotation).
pub(super) fn overlay_infra_annotations(
    mut base: BTreeMap<String, String>,
    gateway: &Gateway,
) -> BTreeMap<String, String> {
    if let Some(user_annotations) = gateway
        .spec
        .infrastructure
        .as_ref()
        .and_then(|i| i.annotations.as_ref())
    {
        for (k, v) in user_annotations {
            base.insert(k.clone(), v.clone());
        }
    }
    base
}

/// Build the final annotation map for the dedicated trio: start with
/// [`standard_annotations`] (which sets the admin-port annotation) then overlay
/// user-supplied `Gateway.spec.infrastructure.annotations`.
fn final_annotations(gateway: &Gateway, admin_port: u16) -> BTreeMap<String, String> {
    overlay_infra_annotations(standard_annotations(admin_port), gateway)
}

/// Build the `controller=true, blockOwnerDeletion=true` owner reference back
/// to the parent Gateway. Both fields are required for K8s garbage collection
/// to cascade Gateway deletion to the provisioned resources without leaving
/// orphans.
pub(super) fn gateway_owner_reference(gateway: &Gateway) -> OwnerReference {
    let group = <Gateway as kube::Resource>::group(&()).into_owned();
    let version = <Gateway as kube::Resource>::version(&()).into_owned();
    let api_version = format!("{group}/{version}");
    let kind = <Gateway as kube::Resource>::kind(&()).into_owned();
    let name = gateway
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| panic!("invariant: Gateway has no name"));
    let uid = gateway.metadata.uid.clone().unwrap_or_else(|| {
        panic!(
            "invariant: Gateway has no UID; owner references require one and \
             the API server populates it on creation"
        )
    });
    OwnerReference {
        api_version,
        kind,
        name,
        uid,
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Wrap a (labels, annotations, owner_ref) triple in a complete `ObjectMeta`
/// with the right name/namespace. Used uniformly across the three renderers
/// so any future metadata field (finalizers, etc.) gets one source of truth.
fn metadata_for(common: &Common<'_>) -> ObjectMeta {
    ObjectMeta {
        name: Some(common.name.to_string()),
        namespace: Some(common.namespace.to_string()),
        labels: Some(common.labels.clone()),
        annotations: if common.annotations.is_empty() {
            None
        } else {
            Some(common.annotations.clone())
        },
        owner_references: Some(vec![common.owner_ref.clone()]),
        ..Default::default()
    }
}

fn render_service_account(common: &Common<'_>) -> ServiceAccount {
    ServiceAccount {
        metadata: metadata_for(common),
        ..Default::default()
    }
}

fn render_service(
    common: &Common<'_>,
    gateway: &Gateway,
    params: &EffectiveParams,
    effective_ports: &[EffectiveListenerPort],
) -> Service {
    // GatewayStaticAddresses (#260): a requested static IP is honored as a
    // ClusterIP (apiserver-assigned, deterministic on every cluster), so force
    // ClusterIP for a static-IP Gateway regardless of the params service type —
    // the resolved address then IS the requested clusterIP.
    let requested_cluster_ip = requested_static_cluster_ip(gateway);
    let service_type = if requested_cluster_ip.is_some() {
        service_type_to_k8s_string(ServiceType::ClusterIp)
    } else {
        service_type_to_k8s_string(params.service_type.unwrap_or_default())
    };
    let ports = service_ports(gateway, effective_ports);
    // The Service selects pods by the reserved-set `app.kubernetes.io/name` +
    // `instance` labels — narrower than all four, but the canonical operator
    // pattern. Reserved-set means a user infrastructure label cannot break
    // this selector.
    let mut selector = BTreeMap::new();
    selector.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
    if let Some(instance) = common.labels.get("app.kubernetes.io/instance") {
        selector.insert(
            "app.kubernetes.io/instance".to_string(),
            instance.to_string(),
        );
    }

    Service {
        metadata: metadata_for(common),
        spec: Some(ServiceSpec {
            type_: Some(service_type),
            selector: Some(selector),
            ports: Some(ports),
            cluster_ip: requested_cluster_ip.map(|ip| ip.to_string()),
            ..Default::default()
        }),
        status: None,
    }
}

/// Render the K8s string form of a [`ServiceType`] variant. Serde's
/// `Serialize` impl already produces the right strings (`LoadBalancer`,
/// `NodePort`, `ClusterIP`); we route through it so any future variant
/// added to the `#[non_exhaustive]` enum gets the K8s-canonical name
/// without code changes here. Falls back to `LoadBalancer` only if
/// serialisation produces something unexpected (which can't happen for
/// well-formed `ServiceType` values — the fallback is a defensive default,
/// not a forward-compat hatch that would silently misroute traffic).
pub(super) fn service_type_to_k8s_string(t: ServiceType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "LoadBalancer".to_string())
}

/// The listener `(name, port, protocol)` triples a dedicated proxy exposes: the
/// effective set (Gateway's own + attached ListenerSets', GEP-1713) when present,
/// else the Gateway's own `spec.listeners`. Deduplicated on port (the effective set
/// already is, with collision-free names; the fallback dedups here keeping the
/// first name). `protocol` is the raw Gateway API listener protocol string
/// (`HTTP`, `HTTPS`, `TLS`, `TCP`, `UDP`) — see [`k8s_service_protocol`] for the
/// k8s-`ServicePort`/`ContainerPort` mapping.
fn listener_name_ports(
    gateway: &Gateway,
    effective_ports: &[EffectiveListenerPort],
) -> Vec<(String, u16, String)> {
    if !effective_ports.is_empty() {
        return effective_ports
            .iter()
            .map(|l| (l.name.clone(), l.port, l.protocol.clone()))
            .collect();
    }
    let mut seen: BTreeSet<u16> = BTreeSet::new();
    let mut out = Vec::new();
    for listener in &gateway.spec.listeners {
        let Ok(port) = u16::try_from(listener.port) else {
            continue;
        };
        if seen.insert(port) {
            out.push((listener.name.clone(), port, listener.protocol.clone()));
        }
    }
    out
}

/// Map a Gateway API listener `protocol` to its Kubernetes `ServicePort`/
/// `ContainerPort` `protocol`.
///
/// Every listener protocol coxswain routes rides over TCP except `UDP`
/// (UDPRoute, GEP-2645, #506) — kube-proxy's iptables/ipvs rules are keyed by
/// protocol, so a UDP listener's Service and container ports must be declared
/// `UDP` or datagrams are never forwarded to it. Shared with [`super::render_shared`]
/// — both the dedicated-mode and shared-mode Service-port renderers need it.
pub(super) fn k8s_service_protocol(listener_protocol: &str) -> &'static str {
    match listener_protocol {
        "UDP" => "UDP",
        _ => "TCP",
    }
}

/// One ServicePort per effective listener port (Gateway's own + attached
/// ListenerSets', GEP-1713), deduplicated on port. ServicePort names are unique
/// (K8s requires it within a Service). Falls back to `gateway.spec.listeners` when
/// `effective_ports` is empty.
fn service_ports(gateway: &Gateway, effective_ports: &[EffectiveListenerPort]) -> Vec<ServicePort> {
    listener_name_ports(gateway, effective_ports)
        .into_iter()
        .map(|(name, port, protocol)| ServicePort {
            name: Some(name),
            port: i32::from(port),
            target_port: Some(IntOrString::Int(i32::from(port))),
            protocol: Some(k8s_service_protocol(&protocol).to_string()),
            ..Default::default()
        })
        .collect()
}

/// `app.kubernetes.io/component` value stamped on the per-Gateway shared-mode
/// VIP Service (#472) — distinct from the dedicated proxy's `dedicated-proxy`
/// so the controller can label-scope its Services watch to exactly these.
/// Single source of truth in the reflector (also read by `build_tls`).
pub(super) use coxswain_reflector::port_alloc::SHARED_GATEWAY_VIP_COMPONENT;

fn render_deployment(common: &Common<'_>, inputs: &RenderInputs<'_>) -> Deployment {
    let gw_name = inputs.gateway.metadata.name.as_deref().unwrap_or("");
    let image = inputs
        .params
        .image
        .as_deref()
        .unwrap_or(inputs.controller_image)
        .to_string();
    // When an HPA is active it is the sole authority on replica count; setting
    // `replicas` on the Deployment would cause Helm to fight the HPA on every
    // reconcile, so we omit it (`None` leaves the field unmanaged by SSA).
    let replicas = if inputs
        .params
        .autoscaling
        .as_ref()
        .is_some_and(|a| a.enabled)
    {
        None
    } else {
        Some(
            inputs
                .params
                .replicas
                .and_then(|r| i32::try_from(r).ok())
                .unwrap_or(DEFAULT_REPLICAS),
        )
    };

    // Relay tiering (#584): when the namespace is relay-fronted, the proxy
    // subscribes for routing snapshots through the relay and must verify the
    // relay's SVID (its ServiceAccount in this namespace) rather than the
    // controller's. Bootstrap is untouched — SVID issuance is never tiered.
    let stream_endpoint = inputs.relay_endpoint.unwrap_or(inputs.discovery_endpoint);

    let mut args = vec![
        "serve".to_string(),
        "proxy".to_string(),
        "--dedicated".to_string(),
        format!("--gateway-name={gw_name}"),
        format!("--gateway-namespace={}", common.namespace),
        format!("--discovery-endpoint={stream_endpoint}"),
        // SVID bootstrap (#423): the dedicated proxy authenticates with its
        // projected SA token, obtains a short-lived SVID over the server-auth
        // bootstrap listener, then opens the mTLS Stream. Without these the
        // proxy can reach the https Stream endpoint but has no client cert and
        // can never become Ready.
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
    ];
    if inputs.relay_endpoint.is_some() {
        args.push(format!(
            "--discovery-expected-server-sa={}",
            super::render_relay::RELAY_NAME
        ));
    }
    args.push("--log-format=json".to_string());
    // Keepalive pool size: pass through to dedicated proxies so their pools
    // are governed by the same operator-configured default (inherited from the
    // shared proxy Helm value via the controller's own env).
    if let Ok(pool_size) = std::env::var("COXSWAIN_PROXY_UPSTREAM_KEEPALIVE_POOL_SIZE") {
        args.push(format!("--proxy-upstream-keepalive-pool-size={pool_size}"));
    }

    let coxswain_container = Container {
        name: "coxswain".to_string(),
        image: Some(image),
        args: Some(args),
        ports: Some(container_ports(inputs.gateway, inputs.effective_ports)),
        env: Some(pod_identity_env()),
        resources: inputs.params.resources.clone(),
        volume_mounts: Some(discovery_volume_mounts()),
        ..Default::default()
    };

    let base_pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(common.labels.clone()),
            annotations: if common.annotations.is_empty() {
                None
            } else {
                Some(common.annotations.clone())
            },
            ..Default::default()
        }),
        spec: Some(PodSpec {
            service_account_name: Some(common.name.to_string()),
            containers: vec![coxswain_container],
            volumes: Some(discovery_volumes()),
            ..Default::default()
        }),
    };

    let pod_template = match inputs.params.pod_template.as_ref() {
        Some(overlay) => merge_pod_template(&base_pod_template, overlay, gw_name),
        None => base_pod_template,
    };

    let mut selector_labels = BTreeMap::new();
    selector_labels.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
    if let Some(instance) = common.labels.get("app.kubernetes.io/instance") {
        selector_labels.insert(
            "app.kubernetes.io/instance".to_string(),
            instance.to_string(),
        );
    }

    Deployment {
        metadata: metadata_for(common),
        spec: Some(DeploymentSpec {
            replicas,
            selector: LabelSelector {
                match_labels: Some(selector_labels),
                ..Default::default()
            },
            template: pod_template,
            ..Default::default()
        }),
        status: None,
    }
}

/// The two read-only volumes every dedicated proxy needs to bootstrap an SVID:
/// a projected, audience-scoped ServiceAccount token and the controller's
/// public CA trust bundle. Mirrors the shared-proxy Helm template so both proxy
/// roles bootstrap identically. The trust ConfigMap is `optional` so a pod that
/// starts before the operator copies the bundle into its namespace still boots;
/// the bootstrap loop re-reads until the file appears.
pub(super) fn discovery_volumes() -> Vec<Volume> {
    vec![
        Volume {
            name: DISCOVERY_TOKEN_VOLUME.to_string(),
            projected: Some(ProjectedVolumeSource {
                sources: Some(vec![VolumeProjection {
                    service_account_token: Some(ServiceAccountTokenProjection {
                        path: "token".to_string(),
                        audience: Some(DISCOVERY_TOKEN_AUDIENCE.to_string()),
                        expiration_seconds: Some(3600),
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: DISCOVERY_TRUST_VOLUME.to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: crate::identity::publisher::TRUST_BUNDLE_CM_NAME.to_string(),
                optional: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        },
    ]
}

/// Downward-API env giving each pod a **unique** discovery `node_id` (`POD_NAME`)
/// and its real namespace (`POD_NAMESPACE`).
///
/// Load-bearing for the relay tier (#585): the `node_id` defaults to
/// `coxswain-local` when `POD_NAME` is unset (`args.rs`), so without this every
/// replica of a controller-provisioned Deployment would share one identity —
/// two relay replicas would then collide in the controller registry and their
/// `RosterReport`s would clobber each other (the leaf-less replica evicting the
/// other's folded leaf), wedging `Programmed` at `Pending`. Mirrors the
/// `POD_NAME`/`POD_NAMESPACE` env the Helm-rendered shared proxy already sets.
pub(super) fn pod_identity_env() -> Vec<EnvVar> {
    let field_ref = |path: &str| {
        Some(EnvVarSource {
            field_ref: Some(ObjectFieldSelector {
                field_path: path.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        })
    };
    vec![
        EnvVar {
            name: "POD_NAME".to_string(),
            value_from: field_ref("metadata.name"),
            ..Default::default()
        },
        EnvVar {
            name: "POD_NAMESPACE".to_string(),
            value_from: field_ref("metadata.namespace"),
            ..Default::default()
        },
    ]
}

/// Read-only mounts pairing [`discovery_volumes`] to the paths the proxy reads
/// (`--discovery-sa-token-path` / `--discovery-ca-bundle-path`).
pub(super) fn discovery_volume_mounts() -> Vec<VolumeMount> {
    vec![
        VolumeMount {
            name: DISCOVERY_TOKEN_VOLUME.to_string(),
            mount_path: DISCOVERY_TOKEN_MOUNT_DIR.to_string(),
            read_only: Some(true),
            ..Default::default()
        },
        VolumeMount {
            name: DISCOVERY_TRUST_VOLUME.to_string(),
            mount_path: DISCOVERY_TRUST_MOUNT_DIR.to_string(),
            read_only: Some(true),
            ..Default::default()
        },
    ]
}

fn container_ports(
    gateway: &Gateway,
    effective_ports: &[EffectiveListenerPort],
) -> Vec<ContainerPort> {
    let mut seen: BTreeSet<i32> = BTreeSet::new();
    let mut out = Vec::new();
    for (name, port, protocol) in listener_name_ports(gateway, effective_ports) {
        let port = i32::from(port);
        seen.insert(port);
        out.push(ContainerPort {
            name: Some(name),
            container_port: port,
            protocol: Some(k8s_service_protocol(&protocol).to_string()),
            ..Default::default()
        });
    }
    // Expose health (8081) and admin (8082) as named container ports so the
    // PodMonitor template's `port: admin` resolves uniformly across the
    // shared-proxy and operator-rendered dedicated proxies. The ports aren't
    // mapped onto the Service (which would put admin on the LoadBalancer IP);
    // the chart's PodMonitor scrapes the pod IP directly.
    for (name, port) in [("health", 8081), ("admin", 8082)] {
        if seen.insert(port) {
            out.push(ContainerPort {
                name: Some(name.to_string()),
                container_port: port,
                protocol: Some("TCP".to_string()),
                ..Default::default()
            });
        }
    }
    out
}

/// Apply a partial `PodTemplateSpec` overlay to a base via the strategic
/// merge from [`super::merge`]. Round-trips through JSON because the
/// strategic-merge primitive operates on [`serde_json::Value`].
///
/// Shared with [`super::render_relay`] so the namespace relay's `podTemplate`
/// escape hatch (#589) merges with identical semantics to the dedicated proxy's.
///
/// **Never panics.** The overlay is operator-supplied and opaque to the CRD
/// validator (`x-kubernetes-preserve-unknown-fields`), so a malformed overlay
/// (e.g. `containers` patched into a non-array) that makes the merged value fail
/// to deserialize back into a `PodTemplateSpec` is a *runtime-reachable* input,
/// not a bug-only invariant. Rather than crash the reconcile, it degrades to the
/// un-overlaid `base` and warn-logs under `context` (the resource being rendered),
/// so the operator's other fields still apply and the bad overlay is visible.
pub(super) fn merge_pod_template(
    base: &PodTemplateSpec,
    overlay: &serde_json::Value,
    context: &str,
) -> PodTemplateSpec {
    let base_json = match serde_json::to_value(base) {
        Ok(v) => v,
        Err(e) => {
            // A controller-constructed PodTemplateSpec has no runtime-reachable way
            // to fail serialization; degrade rather than crash if it somehow does.
            tracing::warn!(
                context = %context,
                error = %e,
                "podTemplate base failed to serialize; rendering without the overlay"
            );
            return base.clone();
        }
    };
    let merged = strategic_merge_pod_template(&base_json, overlay);
    match serde_json::from_value::<PodTemplateSpec>(merged) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::warn!(
                context = %context,
                error = %e,
                "operator podTemplate overlay produced an invalid PodTemplateSpec; \
                 ignoring the overlay and rendering the base pod spec"
            );
            base.clone()
        }
    }
}

/// Render a `HorizontalPodAutoscaler` targeting the dedicated-proxy Deployment.
///
/// Returns `Some` only when `params.autoscaling.enabled` is `true`. Carries the
/// same GEP-1762 name, labels, and owner reference as the other rendered
/// resources so it can be SSA-applied and GC'd under the same field-manager
/// contract. The Deployment name used by `scaleTargetRef` is `common.name` —
/// the same GEP-1762 name the Deployment was rendered with.
///
/// `minReplicas` and `maxReplicas` are populated only when set in the params;
/// omitting them lets the HPA apply its own Kubernetes defaults.
fn render_hpa(common: &Common<'_>, params: &EffectiveParams) -> Option<HorizontalPodAutoscaler> {
    let autoscaling = params.autoscaling.as_ref().filter(|a| a.enabled)?;

    let metrics = autoscaling.target_cpu_utilization_percentage.map(|pct| {
        vec![MetricSpec {
            type_: "Resource".to_string(),
            resource: Some(ResourceMetricSource {
                name: "cpu".to_string(),
                target: MetricTarget {
                    type_: "Utilization".to_string(),
                    average_utilization: Some(i32::try_from(pct).unwrap_or(i32::MAX)),
                    ..Default::default()
                },
            }),
            ..Default::default()
        }]
    });

    let min_replicas = autoscaling.min_replicas.and_then(|r| i32::try_from(r).ok());
    let max_replicas = autoscaling
        .max_replicas
        .and_then(|r| i32::try_from(r).ok())
        .unwrap_or(i32::MAX);

    Some(HorizontalPodAutoscaler {
        metadata: metadata_for(common),
        spec: HorizontalPodAutoscalerSpec {
            scale_target_ref: CrossVersionObjectReference {
                api_version: Some("apps/v1".to_string()),
                kind: "Deployment".to_string(),
                name: common.name.to_string(),
            },
            min_replicas,
            max_replicas,
            metrics,
            ..Default::default()
        },
        status: None,
    })
}

/// Render a `PodDisruptionBudget` protecting the dedicated-proxy Deployment.
///
/// Returns `Some` (maxUnavailable: 1) only when the effective replica floor
/// is ≥ 2. The floor is `min_replicas` when autoscaling is enabled, otherwise
/// the static `replicas` field (default 1). A PDB with a single-replica
/// Deployment either blocks drain permanently (maxUnavailable: 0) or provides
/// no protection (maxUnavailable ≥ 1) — both wrong.
///
/// Carries the same GEP-1762 name, labels, and owner reference as the other
/// rendered resources; its pod selector joins on the same two-key set the
/// Deployment uses.
fn render_pdb(common: &Common<'_>, params: &EffectiveParams) -> Option<PodDisruptionBudget> {
    let floor: u32 = if let Some(a) = params.autoscaling.as_ref().filter(|a| a.enabled) {
        a.min_replicas.unwrap_or(1)
    } else {
        params.replicas.unwrap_or(1)
    };
    if floor < 2 {
        return None;
    }

    let mut selector_labels = BTreeMap::new();
    selector_labels.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
    if let Some(instance) = common.labels.get("app.kubernetes.io/instance") {
        selector_labels.insert(
            "app.kubernetes.io/instance".to_string(),
            instance.to_string(),
        );
    }

    Some(PodDisruptionBudget {
        metadata: metadata_for(common),
        spec: Some(PodDisruptionBudgetSpec {
            max_unavailable: Some(IntOrString::Int(1)),
            selector: Some(LabelSelector {
                match_labels: Some(selector_labels),
                ..Default::default()
            }),
            ..Default::default()
        }),
        status: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_reflector::gw_types::v::gateways::{
        GatewayInfrastructure, GatewayListeners, GatewaySpec,
    };
    use serde_json::json;

    fn make_gateway(namespace: &str, name: &str, listeners: Vec<(&str, u16, &str)>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(format!("uid-{name}")),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners: listeners
                    .into_iter()
                    .map(|(lname, port, protocol)| GatewayListeners {
                        name: lname.to_string(),
                        port: i32::from(port),
                        protocol: protocol.to_string(),
                        hostname: None,
                        tls: None,
                        allowed_routes: None,
                    })
                    .collect(),
                ..Default::default()
            },
            status: None,
        }
    }

    fn gw_with_addresses(addrs: Vec<(Option<&str>, Option<&str>)>) -> Gateway {
        use coxswain_reflector::gw_types::v::gateways::GatewayAddresses;
        let mut gw = make_gateway("ns", "gw", vec![("http", 80, "HTTP")]);
        gw.spec.addresses = Some(
            addrs
                .into_iter()
                .map(|(t, v)| GatewayAddresses {
                    r#type: t.map(str::to_string),
                    value: v.map(str::to_string),
                })
                .collect(),
        );
        gw
    }

    #[test]
    fn requested_static_cluster_ip_picks_first_ip() {
        // GatewayStaticAddresses (#260): first IPAddress-typed entry wins; the
        // default (no type) is IPAddress.
        let gw = gw_with_addresses(vec![(Some("IPAddress"), Some("10.96.0.10"))]);
        assert_eq!(
            requested_static_cluster_ip(&gw),
            Some("10.96.0.10".parse().unwrap())
        );
        let gw = gw_with_addresses(vec![(None, Some("10.96.0.11"))]);
        assert_eq!(
            requested_static_cluster_ip(&gw),
            Some("10.96.0.11".parse().unwrap())
        );
    }

    #[test]
    fn requested_static_cluster_ips_preserves_spec_order() {
        // The reconciler tries candidates in order and binds the first the
        // apiserver accepts, so a usable address after an unusable one still
        // binds. Ordering must mirror spec.addresses exactly.
        let gw = gw_with_addresses(vec![
            (Some("IPAddress"), Some("192.0.2.1")),
            (Some("Hostname"), Some("gw.example.com")),
            (None, Some("10.96.0.10")),
        ]);
        let want: Vec<std::net::IpAddr> =
            vec!["192.0.2.1".parse().unwrap(), "10.96.0.10".parse().unwrap()];
        assert_eq!(
            requested_static_cluster_ips(&gw),
            want,
            "Hostname is skipped; IPAddress entries keep spec order"
        );
    }

    #[test]
    fn requested_static_cluster_ips_empty_for_unsupported_type() {
        // An unsupported type rejects the whole Gateway, so nothing is provisioned.
        let gw = gw_with_addresses(vec![
            (Some("test/fake"), Some("x")),
            (Some("IPAddress"), Some("10.96.0.10")),
        ]);
        assert!(requested_static_cluster_ips(&gw).is_empty());
        assert_eq!(requested_static_cluster_ip(&gw), None);
    }

    #[test]
    fn requested_static_cluster_ip_skips_hostname_and_empty() {
        let gw = gw_with_addresses(vec![
            (Some("Hostname"), Some("gw.example.com")),
            (Some("IPAddress"), None),
        ]);
        assert_eq!(requested_static_cluster_ip(&gw), None);
        assert!(requested_static_cluster_ips(&gw).is_empty());
    }

    #[test]
    fn dedicated_service_forced_to_clusterip_for_static_ip() {
        // GatewayStaticAddresses (#260): a requested static IP forces the
        // dedicated Service to ClusterIP pinned to that IP, overriding the
        // default LoadBalancer type.
        let mut gw = make_gateway("ns", "gw", vec![("http", 80, "HTTP")]);
        gw.spec.addresses = Some(vec![
            coxswain_reflector::gw_types::v::gateways::GatewayAddresses {
                r#type: Some("IPAddress".to_string()),
                value: Some("10.96.0.42".to_string()),
            },
        ]);
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &EffectiveParams::default(),
            controller_image: "ghcr.io/coxswain-labs/coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://d.default.svc:50051",
            discovery_bootstrap_endpoint: "http://d.default.svc:50052",
            discovery_sa_token_path: "/t",
            discovery_ca_bundle_path: "/ca",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        let spec = result.service.spec.expect("service spec");
        assert_eq!(spec.type_.as_deref(), Some("ClusterIP"));
        assert_eq!(spec.cluster_ip.as_deref(), Some("10.96.0.42"));
    }

    /// GatewayClass-only defaults: replicas defaults to 1, serviceType to
    /// LoadBalancer, image to the controller's, no podTemplate overlay.
    #[test]
    fn renders_with_default_replicas_and_service_type() {
        let gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "ghcr.io/coxswain-labs/coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });

        // Names per GEP-1762.
        assert_eq!(
            result.deployment.metadata.name.as_deref(),
            Some("my-gw-coxswain")
        );
        assert_eq!(
            result.service.metadata.name.as_deref(),
            Some("my-gw-coxswain")
        );
        assert_eq!(
            result.service_account.metadata.name.as_deref(),
            Some("my-gw-coxswain")
        );

        // Replicas default.
        let deploy_spec = result.deployment.spec.expect("deployment spec");
        assert_eq!(deploy_spec.replicas, Some(1));

        // Service type default.
        let svc_spec = result.service.spec.expect("service spec");
        assert_eq!(svc_spec.type_.as_deref(), Some("LoadBalancer"));

        // Image falls back to controller's.
        let container = &deploy_spec.template.spec.expect("pod spec").containers[0];
        assert_eq!(
            container.image.as_deref(),
            Some("ghcr.io/coxswain-labs/coxswain:v0.2")
        );
    }

    /// Per-Gateway override of `replicas` and `serviceType` from the
    /// effective params.
    #[test]
    fn override_replicas_and_service_type() {
        let gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams {
            replicas: Some(5),
            service_type: Some(ServiceType::ClusterIp),
            ..Default::default()
        };
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "irrelevant",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        assert_eq!(result.deployment.spec.unwrap().replicas, Some(5));
        assert_eq!(
            result.service.spec.unwrap().type_.as_deref(),
            Some("ClusterIP")
        );
    }

    /// Container args carry the dedicated-mode invocation, gateway name +
    /// namespace, discovery endpoint, and JSON log format.
    #[test]
    fn container_args_carry_dedicated_invocation() {
        let gw = make_gateway("tenant-a", "team-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.tenant-a.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.tenant-a.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        let pod_spec = result.deployment.spec.unwrap().template.spec.unwrap();
        let container = &pod_spec.containers[0];
        let args = container.args.as_ref().expect("args set");
        assert_eq!(
            args,
            &vec![
                "serve".to_string(),
                "proxy".to_string(),
                "--dedicated".to_string(),
                "--gateway-name=team-gw".to_string(),
                "--gateway-namespace=tenant-a".to_string(),
                "--discovery-endpoint=http://coxswain-controller-discovery.tenant-a.svc:50051"
                    .to_string(),
                "--discovery-bootstrap-endpoint=http://coxswain-controller-discovery.tenant-a.svc:50052"
                    .to_string(),
                "--discovery-sa-token-path=/var/run/secrets/coxswain/discovery-token/token"
                    .to_string(),
                "--discovery-ca-bundle-path=/var/run/secrets/coxswain/trust-bundle/ca.crt"
                    .to_string(),
                "--discovery-trust-domain=cluster.local".to_string(),
                "--log-format=json".to_string(),
            ]
        );

        // SVID-bootstrap volumes + mounts ride alongside the args.
        let vol_names: Vec<&str> = pod_spec
            .volumes
            .as_ref()
            .expect("discovery volumes present")
            .iter()
            .map(|v| v.name.as_str())
            .collect();
        assert!(vol_names.contains(&"discovery-token"));
        assert!(vol_names.contains(&"trust-bundle"));
        let mount_names: Vec<&str> = container
            .volume_mounts
            .as_ref()
            .expect("discovery volume mounts present")
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert!(mount_names.contains(&"discovery-token"));
        assert!(mount_names.contains(&"trust-bundle"));
    }

    /// One Service port per listener.
    #[test]
    fn service_ports_one_per_listener() {
        let gw = make_gateway(
            "default",
            "my-gw",
            vec![("http", 80, "HTTP"), ("https", 443, "HTTPS")],
        );
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        let ports = result.service.spec.unwrap().ports.expect("ports");
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].name.as_deref(), Some("http"));
        assert_eq!(ports[1].port, 443);
        assert_eq!(ports[1].name.as_deref(), Some("https"));
    }

    /// Listeners sharing `(port, protocol)` (e.g. host-based routing on the
    /// same port) dedupe to one Service port.
    #[test]
    fn service_ports_deduplicate_by_port_protocol() {
        let gw = make_gateway(
            "default",
            "my-gw",
            vec![
                ("http-prod", 80, "HTTP"),
                ("http-staging", 80, "HTTP"),
                ("https", 443, "HTTPS"),
            ],
        );
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        let ports = result.service.spec.unwrap().ports.expect("ports");
        assert_eq!(ports.len(), 2, "the two HTTP:80 listeners dedupe");
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].name.as_deref(), Some("http-prod"));
    }

    /// `podTemplate` escape-hatch overlays via strategic merge: a sidecar
    /// container appends without wiping the coxswain container.
    #[test]
    fn pod_template_overlay_appends_sidecar() {
        let gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams {
            pod_template: Some(json!({
                "spec": {
                    "containers": [{"name": "sidecar", "image": "my-sidecar:v1"}],
                    "nodeSelector": {"tier": "edge"}
                }
            })),
            ..Default::default()
        };
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        let pod_spec = result.deployment.spec.unwrap().template.spec.unwrap();
        assert_eq!(pod_spec.containers.len(), 2, "coxswain + sidecar");
        let names: Vec<&str> = pod_spec
            .containers
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert!(names.contains(&"coxswain"));
        assert!(names.contains(&"sidecar"));
        let coxswain_args = pod_spec
            .containers
            .iter()
            .find(|c| c.name == "coxswain")
            .and_then(|c| c.args.as_ref())
            .expect("coxswain container kept its args");
        assert!(
            coxswain_args.iter().any(|a| a == "--dedicated"),
            "coxswain container survives with --dedicated arg"
        );
        assert_eq!(
            pod_spec
                .node_selector
                .as_ref()
                .expect("nodeSelector")
                .get("tier"),
            Some(&"edge".to_string())
        );
    }

    /// A malformed operator `podTemplate` overlay (e.g. `containers` patched into a
    /// non-array) is runtime-reachable — the CRD preserves unknown fields — so it must
    /// degrade to the base pod spec and NOT panic the reconcile.
    #[test]
    fn merge_pod_template_degrades_on_malformed_overlay_without_panic() {
        let base: PodTemplateSpec = serde_json::from_value(json!({
            "spec": {"containers": [{"name": "coxswain", "image": "coxswain:v0.2"}]}
        }))
        .expect("valid base");
        let overlay = json!({"spec": {"containers": "not-an-array"}});
        let merged = merge_pod_template(&base, &overlay, "test-gw");
        let names: Vec<String> = merged
            .spec
            .expect("pod spec")
            .containers
            .iter()
            .map(|c| c.name.clone())
            .collect();
        assert_eq!(
            names,
            vec!["coxswain".to_string()],
            "malformed overlay is ignored; the base coxswain container is preserved"
        );
    }

    /// A well-formed overlay still applies (regression guard for the degrade path).
    #[test]
    fn merge_pod_template_applies_valid_overlay() {
        let base: PodTemplateSpec = serde_json::from_value(json!({
            "spec": {"containers": [{"name": "coxswain"}]}
        }))
        .expect("valid base");
        let overlay = json!({"spec": {"nodeSelector": {"zone": "eu"}}});
        let merged = merge_pod_template(&base, &overlay, "test-gw");
        assert_eq!(
            merged
                .spec
                .expect("pod spec")
                .node_selector
                .expect("nodeSelector")
                .get("zone")
                .map(String::as_str),
            Some("eu")
        );
    }

    /// Standard labels per GEP-1762 are present on every rendered resource.
    #[test]
    fn labels_carry_gep_1762_set() {
        let gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        for labels in [
            result.deployment.metadata.labels.as_ref(),
            result.service.metadata.labels.as_ref(),
            result.service_account.metadata.labels.as_ref(),
        ] {
            let labels = labels.expect("labels");
            assert_eq!(
                labels.get("gateway.networking.k8s.io/gateway-name"),
                Some(&"my-gw".to_string())
            );
            assert_eq!(
                labels.get("app.kubernetes.io/name"),
                Some(&"coxswain".to_string())
            );
            assert_eq!(
                labels.get("app.kubernetes.io/instance"),
                Some(&"my-gw".to_string())
            );
            assert_eq!(
                labels.get("app.kubernetes.io/managed-by"),
                Some(&"coxswain".to_string())
            );
        }
    }

    /// ServiceAccount name matches the Deployment's `serviceAccountName`.
    #[test]
    fn service_account_name_matches_deployment_reference() {
        let gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        let pod_spec = result.deployment.spec.unwrap().template.spec.unwrap();
        assert_eq!(
            pod_spec.service_account_name.as_deref(),
            Some("my-gw-coxswain")
        );
        assert_eq!(
            result.service_account.metadata.name.as_deref(),
            Some("my-gw-coxswain")
        );
    }

    /// Owner reference is set on every rendered resource and points back to
    /// the parent Gateway with `controller=true, blockOwnerDeletion=true`.
    /// Required by the Step 9 GC acceptance criterion.
    #[test]
    fn owner_reference_set_on_every_resource() {
        let gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        for meta in [
            &result.deployment.metadata,
            &result.service.metadata,
            &result.service_account.metadata,
        ] {
            let refs = meta.owner_references.as_ref().expect("owner refs");
            assert_eq!(refs.len(), 1);
            let r = &refs[0];
            assert_eq!(r.kind, "Gateway");
            assert_eq!(r.name, "my-gw");
            assert_eq!(r.uid, "uid-my-gw");
            assert_eq!(r.controller, Some(true));
            assert_eq!(r.block_owner_deletion, Some(true));
            assert!(
                r.api_version.starts_with("gateway.networking.k8s.io/"),
                "api_version: {}",
                r.api_version
            );
        }
    }

    /// `Gateway.spec.infrastructure.labels` non-reserved keys are merged onto
    /// every rendered resource's metadata.
    #[test]
    fn infrastructure_labels_merged_onto_resources() {
        let mut gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let mut user_labels = BTreeMap::new();
        user_labels.insert("team".to_string(), "platform".to_string());
        user_labels.insert("environment".to_string(), "prod".to_string());
        gw.spec.infrastructure = Some(GatewayInfrastructure {
            labels: Some(user_labels),
            ..Default::default()
        });
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &EffectiveParams::default(),
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        for meta in [
            &result.deployment.metadata,
            &result.service.metadata,
            &result.service_account.metadata,
        ] {
            let labels = meta.labels.as_ref().expect("labels");
            assert_eq!(labels.get("team"), Some(&"platform".to_string()));
            assert_eq!(labels.get("environment"), Some(&"prod".to_string()));
            // Reserved set still intact.
            assert_eq!(
                labels.get("app.kubernetes.io/managed-by"),
                Some(&"coxswain".to_string())
            );
        }
    }

    /// User cannot override the GEP-1762 reserved-set label keys; collisions
    /// are dropped and the standard value wins.
    #[test]
    fn reserved_label_keys_cannot_be_overridden() {
        let mut gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let mut user_labels = BTreeMap::new();
        user_labels.insert("app.kubernetes.io/name".to_string(), "evil".to_string());
        user_labels.insert(
            "gateway.networking.k8s.io/gateway-name".to_string(),
            "other-gw".to_string(),
        );
        user_labels.insert("kept".to_string(), "yes".to_string());
        gw.spec.infrastructure = Some(GatewayInfrastructure {
            labels: Some(user_labels),
            ..Default::default()
        });
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &EffectiveParams::default(),
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        let labels = result.deployment.metadata.labels.as_ref().expect("labels");
        assert_eq!(
            labels.get("app.kubernetes.io/name"),
            Some(&"coxswain".to_string()),
            "reserved key must not be overridden"
        );
        assert_eq!(
            labels.get("gateway.networking.k8s.io/gateway-name"),
            Some(&"my-gw".to_string()),
            "reserved key must not be overridden"
        );
        assert_eq!(labels.get("kept"), Some(&"yes".to_string()));
    }

    /// Infrastructure annotations are merged onto every rendered resource
    /// verbatim. No reserved set applies.
    #[test]
    fn infrastructure_annotations_merged_onto_resources() {
        let mut gw = make_gateway("default", "my-gw", vec![("http", 80, "HTTP")]);
        let mut anno = BTreeMap::new();
        anno.insert(
            "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
            "nlb".to_string(),
        );
        gw.spec.infrastructure = Some(GatewayInfrastructure {
            annotations: Some(anno),
            ..Default::default()
        });
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &EffectiveParams::default(),
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
            relay_endpoint: None,
        });
        for meta in [
            &result.deployment.metadata,
            &result.service.metadata,
            &result.service_account.metadata,
        ] {
            let annotations = meta.annotations.as_ref().expect("annotations");
            assert_eq!(
                annotations
                    .get("service.beta.kubernetes.io/aws-load-balancer-type")
                    .map(String::as_str),
                Some("nlb")
            );
        }
    }

    // ── Shared-mode VIP Service (#472) ───────────────────────────────────────

    #[test]
    fn shared_vip_service_lives_in_controller_ns_with_selector_and_maps_ports() {
        let gw = make_gateway("team-a", "gw", vec![("https", 443, "HTTPS")]);
        let internal: BTreeMap<u16, u16> = [(443u16, 30001u16)].into_iter().collect();
        let effective_ports = vec![EffectiveListenerPort {
            name: "https".to_string(),
            port: 443,
            protocol: "HTTPS".to_string(),
        }];
        let mut selector = BTreeMap::new();
        selector.insert(
            "app.kubernetes.io/component".to_string(),
            "shared-proxy".to_string(),
        );
        let svc = render_shared_gateway_service(&SharedServiceInputs {
            gateway: &gw,
            controller_namespace: "coxswain-system",
            shared_proxy_selector: &selector,
            effective_ports: &effective_ports,
            internal_ports: &internal,
            service_type: ServiceType::LoadBalancer,
            requested_cluster_ip: None,
        });
        // Lives WITH the shared proxy pod so the selector resolves + the cloud LB
        // assigns a real address.
        assert_eq!(svc.metadata.namespace.as_deref(), Some("coxswain-system"));
        let spec = svc.spec.expect("spec");
        assert_eq!(
            spec.selector.as_ref(),
            Some(&selector),
            "selects the shared proxy pod"
        );
        let ports = spec.ports.expect("ports");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 443, "advertised spec port");
        assert_eq!(
            ports[0].target_port,
            Some(IntOrString::Int(30001)),
            "maps to the allocated internal target port"
        );
        // No cross-namespace owner ref; the Gateway is recorded via labels.
        assert!(
            svc.metadata.owner_references.is_none(),
            "no cross-namespace owner ref"
        );
        let labels = svc.metadata.labels.expect("labels");
        assert_eq!(
            labels
                .get("gateway.networking.k8s.io/gateway-name")
                .map(String::as_str),
            Some("gw")
        );
        assert_eq!(
            labels
                .get("gateway.coxswain-labs.dev/gateway-namespace")
                .map(String::as_str),
            Some("team-a")
        );
    }

    #[test]
    fn shared_vip_service_overlays_infrastructure_labels_and_annotations() {
        // GEP-1867 (#482): infra labels/annotations land on the VIP Service, but
        // a user infra label cannot detach the owning-Gateway mapping labels the
        // VIP reconciler prunes on.
        let mut gw = make_gateway("team-a", "gw", vec![("https", 443, "HTTPS")]);
        let mut user_labels = BTreeMap::new();
        user_labels.insert("team".to_string(), "platform".to_string());
        // Attempt to hijack the namespace mapping label and a reserved key.
        user_labels.insert(
            "gateway.coxswain-labs.dev/gateway-namespace".to_string(),
            "evil".to_string(),
        );
        user_labels.insert("app.kubernetes.io/name".to_string(), "evil".to_string());
        let mut user_anno = BTreeMap::new();
        user_anno.insert(
            "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
            "nlb".to_string(),
        );
        gw.spec.infrastructure = Some(GatewayInfrastructure {
            labels: Some(user_labels),
            annotations: Some(user_anno),
            ..Default::default()
        });
        let internal: BTreeMap<u16, u16> = [(443u16, 30001u16)].into_iter().collect();
        let effective_ports = vec![EffectiveListenerPort {
            name: "https".to_string(),
            port: 443,
            protocol: "HTTPS".to_string(),
        }];
        let selector = BTreeMap::new();
        let svc = render_shared_gateway_service(&SharedServiceInputs {
            gateway: &gw,
            controller_namespace: "coxswain-system",
            shared_proxy_selector: &selector,
            effective_ports: &effective_ports,
            internal_ports: &internal,
            service_type: ServiceType::LoadBalancer,
            requested_cluster_ip: None,
        });
        let labels = svc.metadata.labels.expect("labels");
        assert_eq!(
            labels.get("team"),
            Some(&"platform".to_string()),
            "infra label applied"
        );
        assert_eq!(
            labels.get("gateway.coxswain-labs.dev/gateway-namespace"),
            Some(&"team-a".to_string()),
            "mapping label inserted last; user override ignored"
        );
        assert_eq!(
            labels.get("app.kubernetes.io/name"),
            Some(&"coxswain".to_string()),
            "reserved key not overridden"
        );
        assert_eq!(
            labels.get("gateway.networking.k8s.io/gateway-name"),
            Some(&"gw".to_string()),
            "owning-Gateway name mapping preserved"
        );
        assert_eq!(
            labels
                .get("app.kubernetes.io/component")
                .map(String::as_str),
            Some(SHARED_GATEWAY_VIP_COMPONENT),
            "VIP component preserved for the prune mapping"
        );
        let anno = svc.metadata.annotations.expect("annotations");
        assert_eq!(
            anno.get("service.beta.kubernetes.io/aws-load-balancer-type")
                .map(String::as_str),
            Some("nlb")
        );
    }

    #[test]
    fn shared_identity_service_account_carries_gateway_label_infra_and_owner_ref() {
        // GEP-1867 (#482): the shared-mode identity SA lives in the Gateway's own
        // namespace, carries the gateway-name label + infra metadata, and is
        // owner-reffed to the Gateway for GC.
        let mut gw = make_gateway("team-a", "gw", vec![("http", 80, "HTTP")]);
        let mut user_labels = BTreeMap::new();
        user_labels.insert("team".to_string(), "platform".to_string());
        user_labels.insert("app.kubernetes.io/name".to_string(), "evil".to_string());
        let mut user_anno = BTreeMap::new();
        user_anno.insert(
            "coxswain.example/owner".to_string(),
            "tenant-team".to_string(),
        );
        gw.spec.infrastructure = Some(GatewayInfrastructure {
            labels: Some(user_labels),
            annotations: Some(user_anno),
            ..Default::default()
        });
        let sa = render_shared_gateway_service_account(&gw);
        assert_eq!(
            sa.metadata.namespace.as_deref(),
            Some("team-a"),
            "in Gateway's namespace"
        );
        let name = sa.metadata.name.expect("name");
        assert!(
            name.ends_with("-shared-sa"),
            "distinct shared-sa suffix: {name}"
        );
        assert!(name.len() <= 63, "within DNS label limit");
        let labels = sa.metadata.labels.expect("labels");
        assert_eq!(
            labels.get("gateway.networking.k8s.io/gateway-name"),
            Some(&"gw".to_string()),
            "conformance lister filters on this label"
        );
        assert_eq!(labels.get("team"), Some(&"platform".to_string()));
        assert_eq!(
            labels.get("app.kubernetes.io/name"),
            Some(&"coxswain".to_string()),
            "reserved key not overridden"
        );
        assert_eq!(
            labels
                .get("app.kubernetes.io/component")
                .map(String::as_str),
            Some(SHARED_GATEWAY_SA_COMPONENT)
        );
        let anno = sa.metadata.annotations.expect("annotations");
        assert_eq!(
            anno.get("coxswain.example/owner"),
            Some(&"tenant-team".to_string())
        );
        // No admin-port annotation (that's a dedicated-pod concern).
        assert!(!anno.contains_key("gateway.coxswain-labs.dev/admin-port"));
        let refs = sa.metadata.owner_references.expect("owner refs");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "gw");
        assert_eq!(refs[0].controller, Some(true));
        assert_eq!(refs[0].block_owner_deletion, Some(true));
    }

    #[test]
    fn shared_identity_sa_name_distinct_from_vip_and_dedicated() {
        let ns = "team-a";
        let name = "gw";
        let sa = shared_gateway_service_account_name(ns, name);
        assert_ne!(
            sa,
            shared_gateway_service_name(ns, name),
            "distinct from VIP name"
        );
        assert_ne!(sa, "gw-coxswain", "distinct from GEP-1762 dedicated name");
        assert!(sa.ends_with("-shared-sa"));
        assert_eq!(
            sa,
            shared_gateway_service_account_name(ns, name),
            "deterministic"
        );
    }

    #[test]
    fn shared_identity_sa_has_no_annotations_when_infra_absent() {
        // No infra annotations → annotations field omitted (legal subset of {} for
        // the conformance check), and no stray admin-port annotation.
        let gw = make_gateway("team-a", "gw", vec![("http", 80, "HTTP")]);
        let sa = render_shared_gateway_service_account(&gw);
        assert!(sa.metadata.annotations.is_none());
    }

    #[test]
    fn shared_vip_service_name_is_namespace_qualified_and_unique() {
        // Same Gateway name in different namespaces → distinct Service names
        // (the VIP Services all live in one namespace, so names must not collide).
        let a = shared_gateway_service_name("team-a", "gw");
        let b = shared_gateway_service_name("team-b", "gw");
        assert_ne!(a, b, "same name, different namespace → distinct VIP names");
        assert!(a.ends_with("-shared-gw"));
        assert!(a.len() <= 63, "within the DNS label limit");
        // Deterministic (the status writer recomputes it).
        assert_eq!(a, shared_gateway_service_name("team-a", "gw"));
    }

    // ── GEP-1713: dedicated proxy exposes effective (ListenerSet) ports ───────

    #[test]
    fn dedicated_ports_include_effective_listener_set_ports_with_spec_fallback() {
        let gw = make_gateway("team-a", "gw", vec![("http", 8000, "HTTP")]);
        let effective = vec![
            EffectiveListenerPort {
                name: "http".to_string(),
                port: 8000,
                protocol: "HTTP".to_string(),
            },
            EffectiveListenerPort {
                name: "ls".to_string(),
                port: 8001,
                protocol: "HTTP".to_string(),
            },
        ];

        // Service exposes both the Gateway port and the ListenerSet's new port.
        let svc_ports = service_ports(&gw, &effective);
        let ports: Vec<i32> = svc_ports.iter().map(|p| p.port).collect();
        assert!(
            ports.contains(&8000) && ports.contains(&8001),
            "dedicated Service must expose the ListenerSet listener port, got {ports:?}"
        );

        // The proxy container binds the ListenerSet port too (plus health/admin).
        let cports = container_ports(&gw, &effective);
        let cp: Vec<i32> = cports.iter().map(|c| c.container_port).collect();
        assert!(
            cp.contains(&8001),
            "container must bind the ListenerSet port"
        );
        assert!(
            cp.contains(&8081) && cp.contains(&8082),
            "health/admin container ports preserved"
        );

        // Empty effective → fall back to spec.listeners (existing behaviour).
        let fallback = service_ports(&gw, &[]);
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].port, 8000);
    }
}
