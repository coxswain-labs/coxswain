//! Render the desired `Deployment`, `Service`, and `ServiceAccount` for a
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
//! --proxy-watch-namespaces=<ns1>,<ns2>,... [--allow-cluster-wide-route-read]
//! [--allow-cluster-wide-namespace-read] --log-format=json`. The
//! `--proxy-watch-namespaces` list mirrors the per-namespace `RoleBinding`s
//! the controller manages for this proxy's `ServiceAccount` (#209); both are
//! derived from [`super::rbac::desired_namespaces_for_gateway`] so they
//! cannot drift. The two cluster-wide flags are derived from the Gateway's
//! listener `allowedRoutes.namespaces.from` field via
//! [`super::rbac::derive_proxy_rbac`] (#229).
//!
//! ## Service ports
//!
//! Each listener in `gateway.spec.listeners` becomes one entry on the
//! Service. Listeners that share a `(port, protocol)` tuple are
//! deduplicated — only the first listener at each unique tuple contributes
//! a port entry (its `name` is used). Container ports mirror the Service
//! ports. Protocol is always `TCP` (HTTP/HTTPS/TLS all ride TCP at the
//! Service layer; the proxy distinguishes them at L7 by listener config).

use super::merge::strategic_merge_pod_template;
use super::params::EffectiveParams;
use coxswain_core::crd::ServiceType;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, PodSpec, PodTemplateSpec, Service, ServiceAccount, ServicePort,
    ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use std::collections::{BTreeMap, BTreeSet};

/// Empty placeholder used by render tests that don't exercise the
/// per-namespace narrowing arg list. Declared here so tests don't have to
/// re-spell the empty literal at every call site.
#[cfg(test)]
const EMPTY_WATCH_NS: &BTreeSet<String> = &BTreeSet::new();

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
    /// Sorted set of namespaces the proxy is permitted to watch backend
    /// resources in. Rendered into the container args as
    /// `--proxy-watch-namespaces=ns1,ns2,...` so it mirrors the per-namespace
    /// `RoleBinding`s the controller has provisioned (#209). Sorted so
    /// reorderings don't produce hash churn or unnecessary Deployment rolls.
    pub(super) watch_namespaces: &'a BTreeSet<String>,
    /// Render `--allow-cluster-wide-route-read` when true. Derived from the
    /// Gateway's listener specs via [`super::rbac::derive_proxy_rbac`] — not
    /// a user-supplied value. Set when any listener has
    /// `allowedRoutes.namespaces.from: All` or `from: Selector`.
    pub(super) allow_cluster_wide_route_read: bool,
    /// Render `--allow-cluster-wide-namespace-read` when true. Same
    /// derivation — set when any listener has `from: Selector`.
    pub(super) allow_cluster_wide_namespace_read: bool,
}

/// The three rendered resources for one dedicated-mode Gateway.
#[non_exhaustive]
#[derive(Debug)]
pub(super) struct RenderedSpecs {
    /// `ServiceAccount` the proxy pod runs as.
    pub(super) service_account: ServiceAccount,
    /// `Service` exposing the proxy's listeners.
    pub(super) service: Service,
    /// `Deployment` of the proxy pod.
    pub(super) deployment: Deployment,
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
    let labels = final_labels(inputs.gateway);
    let annotations = final_annotations(inputs.gateway);
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
        service: render_service(&common, inputs.gateway, inputs.params),
        deployment: render_deployment(&common, inputs),
    }
}

/// GEP-1762 names the generated resources `<NAME>-<GATEWAY CLASS>`.
fn resource_name(gateway: &Gateway, class_name: &str) -> String {
    let gw_name =
        gateway.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    format!("{gw_name}-{class_name}")
}

/// Reserved-set GEP-1762 labels for one Gateway. Used internally by
/// [`final_labels`]; not exposed because callers should always go through
/// `final_labels`, which also overlays the user-supplied
/// `Gateway.spec.infrastructure.labels`.
fn standard_labels(gateway: &Gateway) -> BTreeMap<String, String> {
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
    labels
}

/// Merge user-supplied `Gateway.spec.infrastructure.labels` onto the
/// reserved GEP-1762 label set. User collisions on a reserved key are
/// dropped with a WARN log — the reserved set is non-negotiable because the
/// Service/Deployment selectors depend on it.
fn final_labels(gateway: &Gateway) -> BTreeMap<String, String> {
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
    labels.extend(standard_labels(gateway));
    labels
}

/// Forward user-supplied `Gateway.spec.infrastructure.annotations` verbatim.
/// No reserved set — annotations don't drive selectors or any controller
/// invariant.
fn final_annotations(gateway: &Gateway) -> BTreeMap<String, String> {
    gateway
        .spec
        .infrastructure
        .as_ref()
        .and_then(|i| i.annotations.as_ref())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

/// Build the `controller=true, blockOwnerDeletion=true` owner reference back
/// to the parent Gateway. Both fields are required for K8s garbage collection
/// to cascade Gateway deletion to the provisioned resources without leaving
/// orphans.
fn gateway_owner_reference(gateway: &Gateway) -> OwnerReference {
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

fn render_service(common: &Common<'_>, gateway: &Gateway, params: &EffectiveParams) -> Service {
    let service_type = service_type_to_k8s_string(params.service_type.unwrap_or_default());
    let ports = service_ports(gateway);
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
fn service_type_to_k8s_string(t: ServiceType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "LoadBalancer".to_string())
}

/// One ServicePort per Gateway listener, deduplicated on `(port, protocol)`.
/// Listeners that share a `(port, protocol)` keep only the first one's
/// `name`; this matches K8s's requirement that ServicePort names within a
/// Service be unique and ports be unique by `(port, protocol)`.
fn service_ports(gateway: &Gateway) -> Vec<ServicePort> {
    let mut seen: BTreeSet<(i32, &'static str)> = BTreeSet::new();
    let mut out = Vec::new();
    for listener in &gateway.spec.listeners {
        let port = listener.port;
        let protocol = "TCP";
        if !seen.insert((port, protocol)) {
            continue;
        }
        out.push(ServicePort {
            name: Some(listener.name.clone()),
            port,
            target_port: Some(IntOrString::Int(port)),
            protocol: Some(protocol.to_string()),
            ..Default::default()
        });
    }
    out
}

fn render_deployment(common: &Common<'_>, inputs: &RenderInputs<'_>) -> Deployment {
    let gw_name = inputs.gateway.metadata.name.as_deref().unwrap_or("");
    let image = inputs
        .params
        .image
        .as_deref()
        .unwrap_or(inputs.controller_image)
        .to_string();
    let replicas = inputs
        .params
        .replicas
        .and_then(|r| i32::try_from(r).ok())
        .unwrap_or(DEFAULT_REPLICAS);

    let mut args = vec![
        "serve".to_string(),
        "proxy".to_string(),
        "--dedicated".to_string(),
        format!("--gateway-name={gw_name}"),
        format!("--gateway-namespace={}", common.namespace),
    ];
    // BTreeSet iterates in sorted order — the resulting `--proxy-watch-namespaces`
    // value is deterministic, so the rendered Deployment hash only changes
    // when the namespace SET changes (not when its iteration order would).
    // Omit the arg entirely when the set is empty so the proxy falls back to
    // cluster-wide watches for tests and the legacy half-functional state.
    if !inputs.watch_namespaces.is_empty() {
        let joined = inputs
            .watch_namespaces
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        args.push(format!("--proxy-watch-namespaces={joined}"));
    }
    if inputs.allow_cluster_wide_route_read {
        args.push("--allow-cluster-wide-route-read".to_string());
    }
    if inputs.allow_cluster_wide_namespace_read {
        args.push("--allow-cluster-wide-namespace-read".to_string());
    }
    args.push("--log-format=json".to_string());

    let coxswain_container = Container {
        name: "coxswain".to_string(),
        image: Some(image),
        args: Some(args),
        ports: Some(container_ports(inputs.gateway)),
        resources: inputs.params.resources.clone(),
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
            ..Default::default()
        }),
    };

    let pod_template = match inputs.params.pod_template.as_ref() {
        Some(overlay) => merge_pod_template(&base_pod_template, overlay),
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
            replicas: Some(replicas),
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

fn container_ports(gateway: &Gateway) -> Vec<ContainerPort> {
    let mut seen: BTreeSet<i32> = BTreeSet::new();
    let mut out = Vec::new();
    for listener in &gateway.spec.listeners {
        let port = listener.port;
        if !seen.insert(port) {
            continue;
        }
        out.push(ContainerPort {
            name: Some(listener.name.clone()),
            container_port: port,
            protocol: Some("TCP".to_string()),
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
fn merge_pod_template(base: &PodTemplateSpec, overlay: &serde_json::Value) -> PodTemplateSpec {
    let base_json = serde_json::to_value(base)
        .unwrap_or_else(|e| panic!("invariant: PodTemplateSpec must serialize to JSON: {e}"));
    let merged = strategic_merge_pod_template(&base_json, overlay);
    serde_json::from_value(merged).unwrap_or_else(|e| {
        // Malformed overlay (e.g. patched `containers` into a non-array)
        // would land here. The reconciler logs the rendering failure and
        // skips this Gateway; we choose to surface a clear panic so the bug
        // doesn't slip past tests.
        panic!(
            "invariant: merged PodTemplateSpec must deserialize cleanly; \
             the operator's podTemplate overlay produced an invalid spec: {e}"
        )
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
        });
        assert_eq!(result.deployment.spec.unwrap().replicas, Some(5));
        assert_eq!(
            result.service.spec.unwrap().type_.as_deref(),
            Some("ClusterIP")
        );
    }

    /// Container args carry the dedicated-mode invocation, gateway name +
    /// namespace, and JSON log format. Empty `watch_namespaces` omits the
    /// `--proxy-watch-namespaces` arg entirely (legacy/test fallback).
    #[test]
    fn container_args_carry_dedicated_invocation() {
        let gw = make_gateway("tenant-a", "team-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
        });
        let container = &result
            .deployment
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .containers[0];
        let args = container.args.as_ref().expect("args set");
        assert_eq!(
            args,
            &vec![
                "serve".to_string(),
                "proxy".to_string(),
                "--dedicated".to_string(),
                "--gateway-name=team-gw".to_string(),
                "--gateway-namespace=tenant-a".to_string(),
                "--log-format=json".to_string(),
            ]
        );
    }

    /// `--proxy-watch-namespaces` is rendered when the set is non-empty, in
    /// sorted order (BTreeSet iteration). The arg appears before
    /// `--log-format` so a human reading the spec sees scope before output
    /// format.
    #[test]
    fn container_args_carry_sorted_watch_namespaces() {
        let gw = make_gateway("tenant-a", "team-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams::default();
        let mut watch_ns = BTreeSet::new();
        watch_ns.insert("shared-services".to_string());
        watch_ns.insert("tenant-a".to_string());
        watch_ns.insert("certs".to_string());
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            watch_namespaces: &watch_ns,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
        });
        let container = &result
            .deployment
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .containers[0];
        let args = container.args.as_ref().expect("args set");
        // BTreeSet iterates lexicographically — certs, shared-services,
        // tenant-a.
        let expected_ns_arg = "--proxy-watch-namespaces=certs,shared-services,tenant-a";
        assert!(
            args.iter().any(|a| a == expected_ns_arg),
            "expected sorted --proxy-watch-namespaces arg; got: {args:?}"
        );
        let pos_ns = args
            .iter()
            .position(|a| a == expected_ns_arg)
            .expect("found");
        let pos_log = args
            .iter()
            .position(|a| a == "--log-format=json")
            .expect("found");
        assert!(
            pos_ns < pos_log,
            "namespace scoping arg should precede --log-format"
        );
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
            watch_namespaces: EMPTY_WATCH_NS,
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
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
}
