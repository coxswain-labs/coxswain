//! Coxswain-defined `CustomResourceDefinition` types and helpers.
//!
//! Each submodule owns one CRD: its spec, derived resource type, and any
//! helpers (default-value constructors, custom schemars callbacks) required by
//! the `kube::CustomResource` derive. The on-disk CRD YAML is generated from
//! these types by `examples/crdgen.rs` and pinned by snapshot tests.

use schemars::{Schema, SchemaGenerator};

/// Shared schemars callback that emits an opaque `x-kubernetes-preserve-unknown-fields`
/// object schema. Used by CRD fields typed as `serde_json::Value` escape hatches (e.g.
/// `podTemplate` overlays) so the CRD validator preserves arbitrary content the controller
/// merges and validates itself.
pub(crate) fn preserve_unknown_fields_schema(_: &mut SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true,
    }))
    .unwrap_or_else(|e| panic!("invariant: preserve-unknown-fields schema is a valid Schema: {e}"))
}

pub mod basic_auth;
pub mod client_traffic_policy;
pub mod compression;
pub mod coxswain_backend_policy;
pub mod coxswain_external_auth;
pub mod gateway_parameters;
pub mod ingress_parameters;
pub mod ip_access_control;
pub mod jwt_auth;
pub mod path_rewrite_regex;
pub mod rate_limit;
pub mod relay_policy;
pub mod request_size_limit;
pub mod retry_policy;

pub use basic_auth::{BasicAuth, BasicAuthSecretRef, BasicAuthSpec};
pub use client_traffic_policy::{
    ClientTrafficPolicy, ClientTrafficPolicySpec, ClientTrafficPolicyStatus, LocalPolicyTargetRef,
    PolicyAncestorRef, PolicyAncestorStatus, ProxyProtocolSpec,
};
pub use compression::{Compression, CompressionSpec};
pub use coxswain_backend_policy::{
    BackendPolicyAncestorRef, BackendPolicyAncestorStatus, BackendPolicyTargetRef, BackendTimeouts,
    CoxswainBackendPolicy, CoxswainBackendPolicySpec, CoxswainBackendPolicyStatus,
};
pub use coxswain_external_auth::{
    CoxswainExternalAuth, CoxswainExternalAuthSpec, CoxswainExternalAuthStatus,
    ExternalAuthAncestorRef, ExternalAuthAncestorStatus, ExternalAuthBackendRef,
    ExternalAuthProtocol, ExternalAuthTargetRef, ForwardBodyConfig,
};
pub use gateway_parameters::{
    AutoscalingParams, CoxswainGatewayParameters, CoxswainGatewayParametersSpec, ServiceType,
};
pub use ingress_parameters::{CoxswainIngressClassParameters, CoxswainIngressClassParametersSpec};
pub use ip_access_control::{IpAccessControl, IpAccessControlSpec};
pub use jwt_auth::{
    ClaimToHeader, InlineJwks, JwksSource, JwtAuth, JwtAuthSpec, JwtHeaderLocation, RemoteJwks,
};
pub use path_rewrite_regex::{PathRewriteRegex, PathRewriteRegexSpec};
pub use rate_limit::{RateLimit, RateLimitSpec};
pub use relay_policy::{CoxswainRelayPolicy, CoxswainRelayPolicySpec, RelayAutoscaling};
pub use request_size_limit::{RequestSizeLimit, RequestSizeLimitSpec};
// `RetryPolicy` is the CRD kind; its runtime counterpart is
// `routing::RetryPolicyConfig` (mirroring the `RateLimit` / `RateLimitConfig` split),
// so there is no short-name clash.
pub use retry_policy::{RetryPolicy, RetryPolicySpec};
