//! Coxswain-defined `CustomResourceDefinition` types and helpers.
//!
//! Each submodule owns one CRD: its spec, derived resource type, and any
//! helpers (default-value constructors, custom schemars callbacks) required by
//! the `kube::CustomResource` derive. The on-disk CRD YAML is generated from
//! these types by `examples/crdgen.rs` and pinned by snapshot tests.

pub mod client_traffic_policy;
pub mod gateway_parameters;
pub mod ingress_parameters;
pub mod path_rewrite_regex;
pub mod rate_limit;

pub use client_traffic_policy::{
    ClientTrafficPolicy, ClientTrafficPolicySpec, ClientTrafficPolicyStatus, LocalPolicyTargetRef,
    PolicyAncestorRef, PolicyAncestorStatus, ProxyProtocolSpec,
};
pub use gateway_parameters::{
    CoxswainGatewayParameters, CoxswainGatewayParametersSpec, ServiceType,
};
pub use ingress_parameters::{CoxswainIngressClassParameters, CoxswainIngressClassParametersSpec};
pub use path_rewrite_regex::{PathRewriteRegex, PathRewriteRegexSpec};
pub use rate_limit::{RateLimit, RateLimitSpec};
