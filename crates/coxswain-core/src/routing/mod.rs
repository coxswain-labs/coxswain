//! Compiled routing tables keyed by listener port, host pattern, and path rule.
//!
//! The per-rule machinery — backend groups, host routers, filter actions,
//! predicates — is shared between Ingress and Gateway-API traffic. The
//! top-level containers diverge by type only: [`IngressRoutingTable`] and
//! [`GatewayRoutingTable`] are distinct, mutually unaliasable types so a
//! proxy serving one cannot accidentally accept a snapshot from the other.

pub(crate) mod common;
mod gateway;
mod ingress;

#[cfg(test)]
mod tests;

pub use common::auth::{
    BasicCredential, ExtAuthConfig, ExtAuthTransport, HttpExtAuthConfig, IngressAuthConfig,
    PasswordHash,
};
pub use common::backend::{
    BackendGroup, BackendGroupSpec, HashSource, LoadBalance, Selected, SessionAffinity,
    affinity_hash, affinity_hash_parts, affinity_token,
};
pub use common::circuit_breaker::CircuitBreakerConfig;
pub use common::compression::CompressionConfig;
pub use common::entry::{
    ForwardedForConfig, RouteConflict, RouteEntry, RouteInfo, RouteKind, RouteTimeouts,
};
pub use common::filters::{
    CorsConfig, CorsOrigin, FilterAction, HeaderMod, HeaderModError, MirrorFraction, PathModifier,
};
pub use common::host_router::{
    HostRouter, HostRouterBuilder, RouteMatch, WildcardKind, compile_path_regex,
};
pub use common::path_normalize::NormalizeLevel;
pub use common::port::{HostPattern, PortRoutingTable, PortTableBuilder};
pub use common::predicate::{
    HeaderPredicate, MatchPredicates, QueryPredicate, RequestContext, ValueMatch,
};
pub use common::rate_limit::{RateLimitConfig, RateLimitKey};
pub use common::retry::{RetryOn, RetryPolicy};
pub use common::table::{RouteOutcome, RouterError, RoutingTable, RoutingTableBuilder};
pub use common::upstream_tls::{BackendProtocol, UpstreamCa, UpstreamTls, parse_app_protocol};

pub use gateway::{
    Gateway, GatewayRoutingTable, GatewayRoutingTableBuilder, SharedGatewayRoutingTable,
};
pub use ingress::{
    Ingress, IngressRoutingTable, IngressRoutingTableBuilder, SharedIngressRoutingTable,
};
