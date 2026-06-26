//! Re-exports Gateway API types from the active channel.
//!
//! Default (release): `gateway_api::apis::standard`
//! With `--features experimental`: `gateway_api::apis::experimental`
//!
//! Import as `use crate::gw_types::v::...` instead of hard-coding the channel
//! path. When adding a new alpha resource guarded by the experimental channel,
//! gate the call site with `#[cfg(feature = "experimental")]`.

#[cfg(not(feature = "experimental"))]
pub use gateway_api::apis::standard as v;

#[cfg(feature = "experimental")]
pub use gateway_api::apis::experimental as v;

// The fork (coxswain-labs/gateway-api-rs) already emits PascalCase type names
// (`GrpcRoute`, `HttpRoute`, `BackendTlsPolicy`, `TlsRoute`). These re-exports
// exist for a stable import path; the K8s API Kind strings ("GRPCRoute",
// "HTTPRoute", "BackendTLSPolicy", "TLSRoute") are kept verbatim only in
// literal strings.
pub use v::backendtlspolicies::BackendTlsPolicy;
pub use v::grpcroutes::GrpcRoute;
pub use v::httproutes::HttpRoute;
pub use v::tlsroutes::TlsRoute;
