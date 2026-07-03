//! Coxswain-defined `CustomResourceDefinition` types and helpers.
//!
//! Each submodule owns one CRD: its spec, derived resource type, and any
//! helpers (default-value constructors, custom schemars callbacks) required by
//! the `kube::CustomResource` derive. The on-disk CRD YAML is generated from
//! these types by `examples/crdgen.rs` and pinned by snapshot tests.

pub mod basic_auth;
pub mod client_traffic_policy;
pub mod compression;
pub mod coxswain_backend_policy;
pub mod gateway_parameters;
pub mod ingress_parameters;
pub mod ip_access_control;
pub mod path_rewrite_regex;
pub mod rate_limit;
pub mod request_size_limit;

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
pub use gateway_parameters::{
    AutoscalingParams, CoxswainGatewayParameters, CoxswainGatewayParametersSpec, ServiceType,
};
pub use ingress_parameters::{CoxswainIngressClassParameters, CoxswainIngressClassParametersSpec};
pub use ip_access_control::{IpAccessControl, IpAccessControlSpec};
pub use path_rewrite_regex::{PathRewriteRegex, PathRewriteRegexSpec};
pub use rate_limit::{RateLimit, RateLimitSpec};
pub use request_size_limit::{RequestSizeLimit, RequestSizeLimitSpec};
