//! Gateway-API-flavored routing table types.
//!
//! `GatewayRoutingTable` is the immutable per-port host+path router built from
//! Kubernetes Gateway-API resources (`HTTPRoute`, `Gateway`, etc.). It is
//! structurally identical to its Ingress sibling — only the phantom type
//! marker differs — so the proxy that serves Gateway-API traffic can be
//! statically pinned to receive only this table.

use crate::routing::common::table::{RoutingTable, RoutingTableBuilder};
use crate::shared::Shared;

/// Phantom marker identifying Gateway-API-flavored routing tables.
///
/// Uninhabited; only ever appears as a type parameter, never as a value.
#[non_exhaustive]
pub enum Gateway {}

/// Compiled routing table built from Gateway-API resources.
pub type GatewayRoutingTable = RoutingTable<Gateway>;

/// Builder that compiles Gateway-API-sourced routes into a [`GatewayRoutingTable`].
pub type GatewayRoutingTableBuilder = RoutingTableBuilder<Gateway>;

/// Atomically-swappable handle to the active [`GatewayRoutingTable`].
pub type SharedGatewayRoutingTable = Shared<GatewayRoutingTable>;
