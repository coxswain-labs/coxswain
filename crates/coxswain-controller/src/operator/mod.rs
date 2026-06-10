//! Provisioning operator for dedicated-mode Gateways.
//!
//! Step 8 of the architecture plan: for each `Gateway` whose
//! `spec.infrastructure.parametersRef` (or whose `GatewayClass`'s
//! `spec.parametersRef`) resolves to a `CoxswainGatewayParameters` object,
//! render the desired `Deployment`, `Service`, and `ServiceAccount` specs
//! from the merged parameters and log them as YAML. **No cluster writes** —
//! Step 9 (#208) promotes this to server-side-apply.
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
//! ## Output (Step 8)
//!
//! - On first observation of a Gateway with a resolved `CoxswainGatewayParameters`,
//!   the rendered YAML is logged at `INFO`.
//! - On every subsequent reconcile, the rendered spec is hashed and compared
//!   against the previous hash; the YAML is re-logged at `INFO` only if it
//!   changed, otherwise at `DEBUG`. Per-Gateway hashes live in the kube-rs
//!   `Controller`'s reconcile `Context` and are GC'd when the Gateway is
//!   deleted.
//! - If `parametersRef` resolves to a missing object, the reconciler emits a
//!   `ResolvedRefs=False, reason=InvalidParameters` condition on the Gateway
//!   via the existing status writer's condition channel.
//! - The reconcile is leader-gated: only the controller pod holding the
//!   leadership lease renders + logs. This matches Step 9's behavior (apply
//!   must be leader-only) so promoting from log-only to apply requires zero
//!   gating churn.

pub(crate) mod merge;
pub(crate) mod params;
pub(crate) mod reconciler;
pub(crate) mod render;

pub use reconciler::{Operator, OperatorConfig};
