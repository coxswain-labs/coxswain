//! `CoxswainExternalAuth` CRD — external authorization (ext_authz) for Gateway API.
//!
//! Configures an external authorization check performed by the proxy before a
//! request reaches its upstream, following the [GEP-1494] `ExternalAuth` design
//! and the Envoy / Istio / kgateway `ext_authz` model. The auth service is named
//! by a **`backendRef`** (a `Service` + port), never a raw URL, and is reached
//! over one of two transports selected by `spec.protocol`:
//!
//! - `GRPC` — the Envoy `envoy.service.auth.v3.Authorization/Check` proto.
//! - `HTTP` — forward-auth: the original request headers are replayed to the
//!   service; a `2xx` allows, any other status denies.
//!
//! A `CoxswainExternalAuth` is **dual-surface**:
//!
//! - Referenced from an `HTTPRoute` rule via `filters[].extensionRef` (the
//!   [GEP-1494] Phase-1 route surface; same idiom as [`BasicAuth`](super::basic_auth)).
//! - Attached to a `Gateway` via `spec.targetRefs` (the GEP-713 Phase-2 policy
//!   surface; same idiom as [`ClientTrafficPolicy`](super::client_traffic_policy)).
//!
//! Precedence is **additive**: when both a Gateway-attached policy and a
//! route-level `extensionRef` apply to a request, the request must pass **both**
//! checks. A route cannot remove a Gateway-level auth mandate (GEP-713 override
//! posture — a platform-admin requirement is not weakenable from below).
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/coxswainexternalauths.yaml` and
//! `charts/coxswain/crds/coxswainexternalauths.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.
//!
//! [GEP-1494]: https://gateway-api.sigs.k8s.io/geps/gep-1494/

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// External-authorization configuration attachable to a `Gateway` (via
/// `targetRefs`) or referenceable from an `HTTPRoute` rule (via `extensionRef`).
///
/// The auth service is named by [`backend_ref`](Self::backend_ref) and spoken to
/// over [`protocol`](Self::protocol). When two policies target the same Gateway,
/// the older one (by `creationTimestamp`, ties broken by name) wins and the loser
/// receives `Accepted=False, reason=Conflicted` in its status.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "CoxswainExternalAuth",
    plural = "coxswainexternalauths",
    namespaced,
    status = "CoxswainExternalAuthStatus"
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CoxswainExternalAuthSpec {
    /// The external authorization service. Must speak [`protocol`](Self::protocol)
    /// on the referenced port. A cross-namespace `backendRef` requires a matching
    /// `ReferenceGrant`, exactly as a route `backendRef` does.
    pub backend_ref: ExternalAuthBackendRef,

    /// Transport the auth service speaks — `GRPC` (Envoy `ext_authz` proto) or
    /// `HTTP` (forward-auth).
    pub protocol: ExternalAuthProtocol,

    /// Maximum time to wait for the auth service to respond. Free-form GEP-2257
    /// duration string (e.g. `"250ms"`, `"2s"`). Absent or unparseable → `2s`
    /// (WARN + default at the reflector, never an apiserver rejection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    /// Behaviour when the auth service is unreachable, errors, or times out.
    /// `true` (the default) fails **closed** — the request is denied with `503`.
    /// `false` fails **open** — the request proceeds to the upstream unauthorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_closed: Option<bool>,

    /// Whether (and how much of) the request body to include in the auth check.
    /// When `None` no body is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_body: Option<ForwardBodyConfig>,

    /// Request header names forwarded to the auth service. When `None` or empty,
    /// the GEP-1494 default set is sent (`Authorization`, `Location`,
    /// `Proxy-Authenticate`, `Set-Cookie`, `WWW-Authenticate`) plus the pseudo
    /// headers required to build the check request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_headers: Option<Vec<String>>,

    /// Header names copied from the auth service's **allow** response onto the
    /// upstream request (Envoy `allowed_upstream_headers`). When `None` none are
    /// copied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_response_headers: Option<Vec<String>>,

    /// Gateways this policy attaches to. Each entry must reference a
    /// `gateway.networking.k8s.io/Gateway` in the same namespace. Present ⇒ the
    /// policy is a Gateway-level default applied to every HTTPRoute on the
    /// Gateway. Absent (empty) ⇒ the policy is only active when referenced from a
    /// route rule via `extensionRef`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_refs: Vec<ExternalAuthTargetRef>,
}

/// Transport a [`CoxswainExternalAuth`] service speaks.
///
/// Serialized verbatim as the Gateway API / GEP-1494 spec strings (`GRPC`,
/// `HTTP`) — never re-cased.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum ExternalAuthProtocol {
    /// Envoy `envoy.service.auth.v3.Authorization/Check` gRPC proto.
    Grpc,
    /// HTTP forward-auth: replay request headers, `2xx` allows.
    Http,
}

/// Reference to the `Service` backing the external authorization endpoint.
///
/// Mirrors the Gateway API `BackendObjectReference` shape without importing the
/// generated types, so we control the schema. Only a core `Service` is supported.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAuthBackendRef {
    /// API group of the backend. Defaults to `""` (the core group) for a `Service`.
    #[serde(default)]
    pub group: String,
    /// Kind of the backend. Defaults to `Service`; other kinds are rejected at
    /// resolve time.
    #[serde(default = "default_service_kind")]
    pub kind: String,
    /// Name of the auth `Service`.
    pub name: String,
    /// Namespace of the auth `Service`. Defaults to the policy's namespace; a
    /// different namespace requires a matching `ReferenceGrant`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Service port the auth backend listens on. A valid Kubernetes Service
    /// port is `1..=65535` (Gateway API `PortNumber`); `0` is rejected by the
    /// apiserver schema.
    #[schemars(range(min = 1, max = 65535))]
    pub port: u16,
}

/// Include (part of) the request body in the auth check.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForwardBodyConfig {
    /// Maximum number of body bytes to buffer and forward to the auth service.
    /// Capped at 65535 (GEP-1494) at resolve time; larger values are clamped
    /// with a WARN.
    pub max_size: u32,
}

/// A `Gateway` this policy targets (GEP-713 direct/inherited policy attachment).
///
/// Mirrors the Gateway API `LocalPolicyTargetReference` shape. Section-name
/// (per-listener) targeting is intentionally omitted — a policy applies to every
/// HTTPRoute on the Gateway.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAuthTargetRef {
    /// API group of the target. Must be `gateway.networking.k8s.io`.
    #[serde(default = "default_gateway_group")]
    pub group: String,
    /// Kind of the target. Must be `Gateway`.
    #[serde(default = "default_gateway_kind")]
    pub kind: String,
    /// Name of the target Gateway in the same namespace as this policy.
    pub name: String,
}

/// Default `kind` for [`ExternalAuthBackendRef`] — a core `Service`.
fn default_service_kind() -> String {
    "Service".to_owned()
}

/// Default `group` for [`ExternalAuthTargetRef`] — the Gateway API group.
fn default_gateway_group() -> String {
    "gateway.networking.k8s.io".to_owned()
}

/// Default `kind` for [`ExternalAuthTargetRef`] — a `Gateway`.
fn default_gateway_kind() -> String {
    "Gateway".to_owned()
}

/// Status written back to the `CoxswainExternalAuth` by the controller.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoxswainExternalAuthStatus {
    /// Per-ancestor (targeted `Gateway`) policy conditions. Empty for an
    /// `extensionRef`-only policy (route filter resolution is reflected on the
    /// route's own status instead).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<ExternalAuthAncestorStatus>,
}

/// Status of this policy with respect to one ancestor (a targeted `Gateway`).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAuthAncestorStatus {
    /// Reference to the `Gateway` this ancestor entry describes.
    pub ancestor_ref: ExternalAuthAncestorRef,
    /// The controller that wrote this entry.
    pub controller_name: String,
    /// Conditions for this ancestor (e.g. `Accepted`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition>,
}

/// Identifies the ancestor (targeted `Gateway`) an [`ExternalAuthAncestorStatus`]
/// entry corresponds to.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAuthAncestorRef {
    /// API group of the ancestor (`gateway.networking.k8s.io`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind of the ancestor (`Gateway`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Namespace of the ancestor Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Name of the ancestor Gateway.
    pub name: String,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/coxswainexternalauths.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/coxswainexternalauths.yaml");

    fn parse_cr(spec_fragment: &str) -> CoxswainExternalAuth {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: CoxswainExternalAuth\n\
             metadata:\n  name: t\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("parse failed: {e}\n--- yaml ---\n{yaml}"))
    }

    #[test]
    fn committed_manifest_crd_matches_generator() {
        let on_disk: CustomResourceDefinition = serde_yaml::from_str(MANIFEST_CRD_YAML)
            .unwrap_or_else(|e| panic!("committed CRD YAML must deserialize: {e}"));
        let generated = CoxswainExternalAuth::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/coxswainexternalauths.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- CoxswainExternalAuth \
             > deploy/manifests/crds/coxswainexternalauths.yaml \
             && cp deploy/manifests/crds/coxswainexternalauths.yaml \
             charts/coxswain/crds/coxswainexternalauths.yaml",
        );
    }

    #[test]
    fn chart_crd_is_byte_identical_to_manifest_crd() {
        assert_eq!(
            MANIFEST_CRD_YAML, CHART_CRD_YAML,
            "deploy/manifests/crds and charts/coxswain/crds CRDs diverged; \
             copy the manifest CRD over the chart CRD",
        );
    }

    #[test]
    fn minimal_grpc_spec_deserializes() {
        let cr = parse_cr(concat!(
            "protocol: GRPC\n",
            "backendRef:\n",
            "  name: authz\n",
            "  port: 9000",
        ));
        assert_eq!(cr.spec.protocol, ExternalAuthProtocol::Grpc);
        assert_eq!(cr.spec.backend_ref.name, "authz");
        assert_eq!(cr.spec.backend_ref.port, 9000);
        // Defaults.
        assert_eq!(cr.spec.backend_ref.kind, "Service");
        assert_eq!(cr.spec.backend_ref.group, "");
        assert!(cr.spec.backend_ref.namespace.is_none());
        assert!(cr.spec.timeout.is_none());
        assert!(cr.spec.fail_closed.is_none());
        assert!(cr.spec.target_refs.is_empty());
    }

    #[test]
    fn full_http_spec_round_trips() {
        let cr = parse_cr(concat!(
            "protocol: HTTP\n",
            "backendRef:\n",
            "  group: \"\"\n",
            "  kind: Service\n",
            "  name: oauth2-proxy\n",
            "  namespace: auth\n",
            "  port: 4180\n",
            "timeout: 250ms\n",
            "failClosed: false\n",
            "forwardBody:\n",
            "  maxSize: 4096\n",
            "allowedHeaders:\n",
            "- authorization\n",
            "- cookie\n",
            "allowedResponseHeaders:\n",
            "- x-auth-user",
        ));
        assert_eq!(cr.spec.protocol, ExternalAuthProtocol::Http);
        assert_eq!(cr.spec.backend_ref.namespace.as_deref(), Some("auth"));
        assert_eq!(cr.spec.backend_ref.port, 4180);
        assert_eq!(cr.spec.timeout.as_deref(), Some("250ms"));
        assert_eq!(cr.spec.fail_closed, Some(false));
        assert_eq!(
            cr.spec.forward_body.as_ref().map(|f| f.max_size),
            Some(4096)
        );
        assert_eq!(
            cr.spec.allowed_headers.as_deref(),
            Some(&["authorization".to_owned(), "cookie".to_owned()][..])
        );
        assert_eq!(
            cr.spec.allowed_response_headers.as_deref(),
            Some(&["x-auth-user".to_owned()][..])
        );
    }

    #[test]
    fn protocol_serializes_verbatim() {
        // The wire strings must stay the Gateway API / GEP-1494 spelling — a
        // stray `rename_all` change would silently break interop.
        assert_eq!(
            serde_yaml::to_string(&ExternalAuthProtocol::Grpc)
                .expect("serialize")
                .trim(),
            "GRPC"
        );
        assert_eq!(
            serde_yaml::to_string(&ExternalAuthProtocol::Http)
                .expect("serialize")
                .trim(),
            "HTTP"
        );
    }

    #[test]
    fn lowercase_protocol_is_rejected() {
        // The enum is not permissive: `grpc`/`http` (wrong case) must fail to
        // parse rather than silently coerce.
        let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                    kind: CoxswainExternalAuth\n\
                    metadata:\n  name: t\n\
                    spec:\n  protocol: grpc\n  backendRef:\n    name: a\n    port: 80\n";
        let parsed: Result<CoxswainExternalAuth, _> = serde_yaml::from_str(yaml);
        assert!(
            parsed.is_err(),
            "lower-cased protocol must be rejected, got {parsed:?}"
        );
    }

    #[test]
    fn gateway_target_ref_defaults() {
        let cr = parse_cr(concat!(
            "protocol: GRPC\n",
            "backendRef:\n",
            "  name: authz\n",
            "  port: 9000\n",
            "targetRefs:\n",
            "- name: my-gw",
        ));
        assert_eq!(cr.spec.target_refs.len(), 1);
        assert_eq!(cr.spec.target_refs[0].group, "gateway.networking.k8s.io");
        assert_eq!(cr.spec.target_refs[0].kind, "Gateway");
        assert_eq!(cr.spec.target_refs[0].name, "my-gw");
    }
}
