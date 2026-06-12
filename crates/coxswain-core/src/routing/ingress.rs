//! Ingress-flavored routing table types.
//!
//! `IngressRoutingTable` is the immutable per-port host+path router built from
//! Kubernetes `Ingress` resources. It is structurally identical to its
//! Gateway-API sibling — only the phantom type marker differs — so the proxy
//! that serves Ingress traffic can be statically pinned to receive only this
//! table.

use crate::routing::common::table::{RoutingTable, RoutingTableBuilder};
use crate::shared::Shared;

/// Phantom marker identifying Ingress-flavored routing tables.
///
/// Uninhabited; only ever appears as a type parameter, never as a value.
#[non_exhaustive]
pub enum Ingress {}

/// Compiled routing table built from `Ingress` resources.
pub type IngressRoutingTable = RoutingTable<Ingress>;

/// Builder that compiles `Ingress`-sourced routes into an [`IngressRoutingTable`].
pub type IngressRoutingTableBuilder = RoutingTableBuilder<Ingress>;

/// Atomically-swappable handle to the active [`IngressRoutingTable`].
pub type SharedIngressRoutingTable = Shared<IngressRoutingTable>;
