//! The unified status/provisioning work-queue key space (#574).
//!
//! One [`RateLimitingWorkqueue`] carries every object whose `*/status` (or, for
//! a dedicated Gateway, whose provisioned resources) the controller must
//! reconcile. The reflector's rebuild pass enqueues [`StatusKey`]s; a single
//! leader-gated worker in the controller drains them and dispatches by
//! [`StatusKind`]. This replaces the per-kind `kube::runtime::Controller`
//! work-queues and the lossy `Subscription` fan-out that fed them — one watch
//! fabric, one trigger, one worker.

use coxswain_core::ownership::ObjectKey;
use coxswain_core::workqueue::RateLimitingWorkqueue;

/// The resource kind a [`StatusKey`] refers to. Drives the worker's dispatch to
/// the matching `reconcile_*` handler and store reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusKind {
    /// `Gateway` — shared-pool status and, for dedicated-class Gateways, the
    /// provisioning/finalizer path.
    Gateway,
    /// `GatewayClass`.
    GatewayClass,
    /// `HTTPRoute`.
    HttpRoute,
    /// `GRPCRoute`.
    GrpcRoute,
    /// `TLSRoute`.
    TlsRoute,
    /// `TCPRoute`.
    TcpRoute,
    /// `UDPRoute`.
    UdpRoute,
    /// `Ingress`.
    Ingress,
    /// `IngressClass`.
    IngressClass,
    /// `BackendTLSPolicy`.
    BackendTlsPolicy,
    /// `XListenerSet` (GEP-1713).
    ListenerSet,
    /// `ClientTrafficPolicy` (#327).
    ClientTrafficPolicy,
    /// `CoxswainBackendPolicy` (#354).
    CoxswainBackendPolicy,
    /// `CoxswainExternalAuth` (#23).
    CoxswainExternalAuth,
}

/// A single unit of status/provisioning work: one object of one [`StatusKind`].
///
/// The worker resolves the live object from the matching reflector store at
/// dispatch time (never carrying a stale copy through the queue), so a key
/// whose object has since been deleted resolves to nothing and is dropped.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatusKey {
    /// Which resource kind — selects the dispatch handler and store.
    pub kind: StatusKind,
    /// Namespace/name of the object within that kind.
    pub object: ObjectKey,
}

impl StatusKey {
    /// Construct a key for one object of `kind`.
    #[must_use]
    pub fn new(kind: StatusKind, object: ObjectKey) -> Self {
        Self { kind, object }
    }
}

/// The controller's single status/provisioning work-queue. Producers (the
/// reflector's rebuild pass) hold clones; the controller worker is the sole
/// consumer.
pub type StatusWorkqueue = RateLimitingWorkqueue<StatusKey>;
