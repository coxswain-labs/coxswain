//! Coxswain-defined `CustomResourceDefinition` types and helpers.
//!
//! Each submodule owns one CRD: its spec, derived resource type, and any
//! helpers (default-value constructors, custom schemars callbacks) required by
//! the `kube::CustomResource` derive. The on-disk CRD YAML is generated from
//! these types by `examples/crdgen.rs` and pinned by snapshot tests.

pub mod gateway_parameters;

pub use gateway_parameters::{
    CoxswainGatewayParameters, CoxswainGatewayParametersSpec, ServiceType,
};
