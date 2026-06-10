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
//! - Labels on every rendered resource:
//!   - `gateway.networking.k8s.io/gateway-name: <gateway-name>`
//!   - `app.kubernetes.io/name: coxswain`
//!   - `app.kubernetes.io/instance: <gateway-name>`
//!   - `app.kubernetes.io/managed-by: coxswain`
//!
//! ## Container args
//!
//! `serve proxy --dedicated --gateway-name=<name> --gateway-namespace=<ns>
//! --log-format=json`. The two RBAC opt-in flags
//! (`--allow-cluster-wide-route-read`, `--allow-cluster-wide-namespace-read`)
//! are *not* emitted yet: the CRD doesn't carry the matching fields in
//! v1alpha1. They land alongside the actual provisioning in Step 9 (#208),
//! together with the per-Gateway-proxy RBAC narrowing in Step 10 (#209).
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
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use std::collections::{BTreeMap, BTreeSet};

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

/// Render all three resources for a Gateway.
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
    let labels = standard_labels(inputs.gateway);

    RenderedSpecs {
        service_account: render_service_account(&name, &namespace, &labels),
        service: render_service(&name, &namespace, &labels, inputs.gateway, inputs.params),
        deployment: render_deployment(&name, &namespace, &labels, inputs),
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

fn render_service_account(
    name: &str,
    namespace: &str,
    labels: &BTreeMap<String, String>,
) -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn render_service(
    name: &str,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    gateway: &Gateway,
    params: &EffectiveParams,
) -> Service {
    let service_type = service_type_to_k8s_string(params.service_type.unwrap_or_default());
    let ports = service_ports(gateway);
    // The Service selects pods by the same labels the Deployment's pod
    // template carries. We use `app.kubernetes.io/instance` + `name` as the
    // selector — narrower than all four labels (which is a non-issue but
    // mirrors typical operator output).
    let mut selector = BTreeMap::new();
    selector.insert("app.kubernetes.io/name".to_string(), "coxswain".to_string());
    if let Some(instance) = labels.get("app.kubernetes.io/instance") {
        selector.insert(
            "app.kubernetes.io/instance".to_string(),
            instance.to_string(),
        );
    }

    Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
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
        let port = i32::from(listener.port);
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

fn render_deployment(
    name: &str,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    inputs: &RenderInputs<'_>,
) -> Deployment {
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

    let coxswain_container = Container {
        name: "coxswain".to_string(),
        image: Some(image),
        args: Some(vec![
            "serve".to_string(),
            "proxy".to_string(),
            "--dedicated".to_string(),
            format!("--gateway-name={gw_name}"),
            format!("--gateway-namespace={namespace}"),
            "--log-format=json".to_string(),
        ]),
        ports: Some(container_ports(inputs.gateway)),
        resources: inputs.params.resources.clone(),
        ..Default::default()
    };

    let base_pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(labels.clone()),
            ..Default::default()
        }),
        spec: Some(PodSpec {
            service_account_name: Some(name.to_string()),
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
    if let Some(instance) = labels.get("app.kubernetes.io/instance") {
        selector_labels.insert(
            "app.kubernetes.io/instance".to_string(),
            instance.to_string(),
        );
    }

    Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
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
        let port = i32::from(listener.port);
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
    use coxswain_reflector::gw_types::v::gateways::{GatewayListeners, GatewaySpec};
    use serde_json::json;

    fn make_gateway(namespace: &str, name: &str, listeners: Vec<(&str, u16, &str)>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
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
        });
        assert_eq!(result.deployment.spec.unwrap().replicas, Some(5));
        assert_eq!(
            result.service.spec.unwrap().type_.as_deref(),
            Some("ClusterIP")
        );
    }

    /// Container args carry the dedicated-mode invocation, gateway name +
    /// namespace, and JSON log format.
    #[test]
    fn container_args_carry_dedicated_invocation() {
        let gw = make_gateway("tenant-a", "team-gw", vec![("http", 80, "HTTP")]);
        let params = EffectiveParams::default();
        let result = render(&RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
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
}
