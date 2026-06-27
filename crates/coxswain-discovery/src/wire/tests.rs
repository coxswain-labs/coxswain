//! Cross-cutting wire mock and test helpers.

use super::*;
pub use crate::WireError;
pub use crate::proto::v1 as p;
pub use crate::subscription::Scope;
pub use std::sync::Arc;

pub use std::net::SocketAddr;
pub use std::num::NonZeroU32;

pub use coxswain_core::listener_status::{GatewayListenerStatus, ListenerInfo, ListenerTlsOutcome};
pub use coxswain_core::ownership::ObjectKey;
pub use coxswain_core::routing::{
    BackendGroup, CompressionConfig, FilterAction, GatewayRoutingTableBuilder,
    IngressRoutingTableBuilder, MatchPredicates, NormalizeLevel, PathModifier, RateLimitConfig,
    RateLimitKey, RequestContext, RouteEntry, RouteOutcome, RouteTimeouts, WildcardKind,
};
pub use coxswain_core::tls::{
    ClientCertConfig, ClientCertConfigState, ClientCertStoreBuilder, TlsCert, TlsStoreBuilder,
};
pub use prost::Message as _;
