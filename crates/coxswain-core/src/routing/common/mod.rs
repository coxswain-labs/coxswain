//! Routing primitives shared between Ingress and Gateway-API tables.
//!
//! Both the Ingress and Gateway-API sibling modules build on the per-rule
//! machinery defined here (backend groups, host routers, predicates, filter
//! actions, route entries). The top-level container `RoutingTable<Kind>` is
//! also defined here and is given a distinct identity per spec via type
//! aliases in the sibling modules.

pub mod auth;
pub mod backend;
pub mod circuit_breaker;
pub mod compression;
pub mod entry;
pub mod filters;
pub mod host_router;
pub mod path_normalize;
pub mod port;
pub mod predicate;
pub mod rate_limit;
pub mod retry;
pub mod table;
pub mod upstream_tls;
