//! Provisioning operator for dedicated-mode Gateways.
//!
//! Step 9 of the architecture plan (#208): for each `Gateway` whose
//! `spec.infrastructure.parametersRef` (or whose `GatewayClass`'s
//! `spec.parametersRef`) resolves to a `CoxswainGatewayParameters` object,
//! render the desired `Deployment`, `Service`, and `ServiceAccount` and
//! server-side-apply them into the Gateway's namespace, owner-referenced to
//! the Gateway so deletion cascades.
//!
//! ## Architecture
//!
//! Built on `kube_runtime::controller::Controller` rather than the raw
//! `watcher` streams the existing status writer uses ([`crate::Controller`]).
//! The Controller pattern fits this module's "reconcile one Gateway at a time"
//! shape; the status writer's "rebuild the whole world on any event" shape
//! is structurally different and stays on raw streams. The two background
//! services coexist in the controller pod, each subscribed to their own
//! event streams.
//!
//! ## Status writing (Step 12, #211)
//!
//! For every dedicated-mode Gateway, the operator is the **sole writer** of
//! `Gateway.status`. One merge patch per reconcile carries
//! `Accepted`/`Programmed`/`status.addresses`, the per-listener stanza shared
//! with the shared-pool writer via [`crate::status_common`], and the
//! `gateway.coxswain-labs.dev/DedicatedProxyReady` cut-over signal consumed by
//! the shared-proxy reflector. The status writer in [`crate::controller`]
//! skips Gateways whose `parametersRef` (on the Gateway or its GatewayClass)
//! points at `gateway.coxswain-labs.dev/CoxswainGatewayParameters`, so the
//! two writers never patch the same Gateway. See [`status`] for the patch
//! builder.
//!
//! ## SSA contract
//!
//! - Every reconcile renders the desired specs and server-side-applies all
//!   three resources under field manager `"coxswain-controller"` with
//!   `force=true`. SSA is idempotent server-side; the same content costs one
//!   roundtrip with no write amplification.
//! - The rendered spec is hashed and compared against the previous hash. The
//!   YAML is re-logged at `INFO` only when it changes, at `DEBUG` otherwise.
//!   Per-Gateway hashes live in the kube-rs `Controller`'s reconcile
//!   `Context` and are GC'd when the Gateway is deleted.
//! - If `parametersRef` resolves to a missing object, the reconciler emits
//!   `Accepted=False, reason=InvalidParameters` (Gateway API spec) directly
//!   via [`status::patch_dedicated_gateway_status`] and re-queues.
//! - The reconcile is leader-gated: only the controller pod holding the
//!   leadership lease applies — non-leaders re-queue.

pub(crate) mod apply;
pub(crate) mod merge;
pub(crate) mod params;
pub(crate) mod reconciler;
pub(crate) mod render;
pub(crate) mod render_shared;
pub(crate) mod shared_alloc;
pub(crate) mod status;
pub(crate) mod vip;

pub use reconciler::{Operator, OperatorConfig};
