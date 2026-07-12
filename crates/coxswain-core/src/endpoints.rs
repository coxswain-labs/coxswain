//! Canonical endpoint-resource model: `(namespace, service, port)`-keyed
//! resolved backend addresses.
//!
//! # Design decision (#511, settled)
//!
//! Backends can be modeled two ways: inlined in each route (endpoint churn
//! re-translates every route referencing the service) or normalized into a
//! separately-addressed, EDS-style resource keyed by `(namespace, service,
//! port)` (endpoint churn touches only that one resource). Coxswain settles
//! on the **EDS-style separation**, with this module as the canonical,
//! crate-shared model:
//!
//! - The reflector maintains an [`EndpointPool`] incrementally — one
//!   grouping/fingerprint pass per rebuild over the `EndpointSlice` store,
//!   re-resolving only `(namespace, service)` groups whose members changed
//!   (see `coxswain_reflector::endpoints`). `endpoints::resolve()` becomes an
//!   `O(1)` pool lookup instead of a full store rescan per backend reference.
//! - The **wire format is untouched by this decision** — #511 keeps
//!   `BackendGroup` inlining resolved addresses and `WIRE_VERSION` at 1, since
//!   no user-facing wire change is needed to realize the CPU win
//!   controller-side. **#383 is the source of truth for serializing this
//!   model onto the discovery wire** (a new DTO resource type, `BackendGroup`
//!   gaining an indirection handle) — this module is the shared type both
//!   sides settle on, so the controller-side cache and the eventual wire DTO
//!   agree by construction.

use crate::routing::BackendProtocol;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// Identifies one Kubernetes Service port as an endpoint-resolution unit.
///
/// `namespace`/`service` are `Arc<str>` so a hot rebuild loop can key a
/// [`EndpointPool`] without a fresh heap allocation per lookup once the
/// strings are interned by the caller (e.g. cloned from a route's own
/// `Arc<str>` fields). `port` mirrors the Gateway API / Ingress backend port
/// field width used elsewhere on the wire (`PortEntry`), not Kubernetes'
/// `i32` service-port representation — always in `1..=65535` by API-server
/// validation, so the narrower width loses no valid input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EndpointKey {
    /// Namespace of the referenced Service.
    pub namespace: Arc<str>,
    /// Name of the referenced Service.
    pub service: Arc<str>,
    /// Service port number (`spec.ports[].port`), not the pod-facing target port.
    pub port: u16,
}

impl EndpointKey {
    /// Builds a key from borrowed or owned string-like inputs.
    #[must_use]
    pub fn new(namespace: impl Into<Arc<str>>, service: impl Into<Arc<str>>, port: u16) -> Self {
        Self {
            namespace: namespace.into(),
            service: service.into(),
            port,
        }
    }
}

/// Resolved addresses and protocol metadata for a single backend service port.
///
/// The canonical value type of the endpoint-resource model (#511). Populated
/// by `coxswain_reflector::endpoints::resolve` from the `EndpointSlice` +
/// `Service` stores; read by every route builder via an [`EndpointPool`]
/// lookup instead of a direct store scan.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ResolvedEndpoints {
    /// Ready pod addresses backing the service port, at the pod-facing target port.
    pub addrs: Vec<SocketAddr>,
    /// Backend wire protocol, parsed from `Service.spec.ports[].appProtocol`.
    pub app_protocol: BackendProtocol,
    /// Whether the referenced Service exists in the cluster (present in the
    /// Service store). Lets callers separate "valid Service, zero ready
    /// endpoints" (Gateway API: SHOULD 503) from "no such Service" (MUST 500).
    pub service_exists: bool,
}

impl ResolvedEndpoints {
    /// Builds a resolved result from its three fields. `#[non_exhaustive]`
    /// blocks cross-crate struct-literal construction, so callers outside
    /// this module (route builders constructing a deliberately-empty result
    /// for a denied/invalid backendRef) go through this constructor instead.
    #[must_use]
    pub fn new(
        addrs: Vec<SocketAddr>,
        app_protocol: BackendProtocol,
        service_exists: bool,
    ) -> Self {
        Self {
            addrs,
            app_protocol,
            service_exists,
        }
    }

    /// A backend with no addresses and no resolved Service — the result for a
    /// zero-weight, non-Service-kind, or cross-namespace-denied backendRef.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            addrs: Vec::new(),
            app_protocol: BackendProtocol::default(),
            service_exists: false,
        }
    }
}

/// Endpoint-resolution pool: one resolved entry per referenced
/// `(namespace, service, port)`, maintained incrementally by the reflector
/// across rebuilds. `Arc`-wrapped values so route builders can hold a
/// resolved entry without cloning the address list.
pub type EndpointPool = HashMap<EndpointKey, Arc<ResolvedEndpoints>>;
