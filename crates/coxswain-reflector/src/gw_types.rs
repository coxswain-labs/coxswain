//! Re-exports Gateway API types from the active channel.
//!
//! Default (release): `gateway_api_types::apis::standard`
//! With `--features experimental`: `gateway_api_types::apis::experimental`
//!
//! Import as `use crate::gw_types::v::...` instead of hard-coding the channel
//! path. When adding a new alpha resource guarded by the experimental channel,
//! gate the call site with `#[cfg(feature = "experimental")]`.

#[cfg(not(feature = "experimental"))]
pub use gateway_api_types::apis::standard as v;

#[cfg(feature = "experimental")]
pub use gateway_api_types::apis::experimental as v;

// gateway-api-types (like the fork it replaced, #510) emits PascalCase type
// names (`GrpcRoute`, `HttpRoute`, `BackendTlsPolicy`, `TlsRoute`). These
// re-exports exist for a stable import path; the K8s API Kind strings
// ("GRPCRoute", "HTTPRoute", "BackendTLSPolicy", "TLSRoute") are kept verbatim
// only in literal strings.
pub use v::backendtlspolicies::BackendTlsPolicy;
pub use v::grpcroutes::GrpcRoute;
pub use v::httproutes::HttpRoute;
// GEP-1713: ListenerSet is a standard-channel resource (no experimental gate). Re-exported
// for a stable import path alongside the route kinds; its listeners are merged into the
// parent Gateway's effective listener set during reconcile.
pub use v::listenersets::ListenerSet;
pub use v::tcproutes::TcpRoute;
pub use v::tlsroutes::TlsRoute;
pub use v::udproutes::UdpRoute;

/// Gateway API condition `type`/`reason` constants (#510), parsed straight
/// from upstream Go source by the repo-root `xtask` crate — not channel-scoped,
/// so re-exported unconditionally rather than through `v`. Import as
/// `crate::gw_types::constants::GatewayConditionType::Accepted`, etc.
pub use gateway_api_types::constants;
