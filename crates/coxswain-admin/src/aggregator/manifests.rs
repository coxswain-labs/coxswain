//! `/api/v1/manifests/{kind}/{ns}/{name}` — raw Kubernetes manifest relay.

use http::{HeaderValue, Response, StatusCode, header};

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::Ingress;
use kube::Api;

use super::{OperatorAggregator, internal_error, json_response, not_found, service_unavailable};
use crate::gw_types;

impl OperatorAggregator {
    /// `GET /api/v1/manifests/{kind}/{namespace}/{name}` — raw Kubernetes
    /// manifest for the named resource, returned as JSON.
    ///
    /// `kind` ∈ `httproute` | `ingress` | `gateway` | `pod`.
    ///
    /// The response is the verbatim object returned by the Kubernetes API
    /// server, including `managedFields` and `status`. The operator UI
    /// converts it to YAML client-side for display in the manifest popup.
    ///
    /// # Errors
    ///
    /// Returns 400 for an unrecognised kind, 404 when the resource does not
    /// exist, 503 when the Kubernetes client cannot be initialised, and 500
    /// for other Kubernetes errors.
    pub(crate) async fn get_manifest(
        &self,
        kind: &str,
        namespace: &str,
        name: &str,
    ) -> Response<Vec<u8>> {
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/manifests");
                return service_unavailable("kubernetes client not available");
            }
        };

        match kind {
            "httproute" => {
                let api: Api<gw_types::HttpRoute> = Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(obj) => match serde_json::to_string(&obj) {
                        Ok(body) => json_response(body),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialise HTTPRoute manifest");
                            internal_error()
                        }
                    },
                    Err(kube::Error::Api(e)) if e.code == 404 => not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET HTTPRoute manifest failed");
                        internal_error()
                    }
                }
            }
            "gateway" => {
                let api: Api<gw_types::v::gateways::Gateway> =
                    Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(obj) => match serde_json::to_string(&obj) {
                        Ok(body) => json_response(body),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialise Gateway manifest");
                            internal_error()
                        }
                    },
                    Err(kube::Error::Api(e)) if e.code == 404 => not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET Gateway manifest failed");
                        internal_error()
                    }
                }
            }
            "ingress" => {
                let api: Api<Ingress> = Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(obj) => match serde_json::to_string(&obj) {
                        Ok(body) => json_response(body),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialise Ingress manifest");
                            internal_error()
                        }
                    },
                    Err(kube::Error::Api(e)) if e.code == 404 => not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET Ingress manifest failed");
                        internal_error()
                    }
                }
            }
            "pod" => {
                let api: Api<Pod> = Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(obj) => match serde_json::to_string(&obj) {
                        Ok(body) => json_response(body),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialise Pod manifest");
                            internal_error()
                        }
                    },
                    Err(kube::Error::Api(e)) if e.code == 404 => not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET Pod manifest failed");
                        internal_error()
                    }
                }
            }
            _ => {
                let body =
                    serde_json::json!({ "error": format!("unknown kind: {kind}") }).to_string();
                let mut r = Response::new(body.into_bytes());
                *r.status_mut() = StatusCode::BAD_REQUEST;
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                r
            }
        }
    }
}
