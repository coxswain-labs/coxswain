//! Provisioning operator for dedicated-mode Gateways.
//!
//! Step 9 of the architecture plan (#208): for each `Gateway` whose
//! `spec.infrastructure.parametersRef` (or whose `GatewayClass`'s
//! `spec.parametersRef`) resolves to a `CoxswainGatewayParameters` object,
//! render the desired `Deployment`, `Service`, and `ServiceAccount` and
//! server-side-apply them into the Gateway's namespace, owner-referenced to
//! the Gateway so deletion cascades.
//!
//! ## Architecture (#574 fold)
//!
//! The operator no longer runs its own `kube_runtime::controller::Controller` or
//! Kubernetes client. It reconciles off the single controller watch fabric: the
//! reflector exposes an [`crate::reconciler`-adjacent `OperatorStores`](coxswain_reflector::OperatorStores)
//! bundle, the [`crate::Controller`] builds the [`reconciler::ReconcileContext`]
//! from it and spawns the serialized [`vip::run_vip_reconciler`], and the unified
//! status worker's Gateway branch drives [`reconciler::reconcile_dedicated`] for
//! dedicated Gateways (it no-ops for shared ones, which the shared-pool status
//! writer owns). This removes the operator's duplicate Gateway / GatewayClass /
//! ListenerSet / Namespace / Service watches.
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
pub(crate) mod relay_autoscaler;
pub(crate) mod relay_params;
pub(crate) mod relay_reconcile;
pub(crate) mod render;
pub(crate) mod render_relay;
pub(crate) mod render_shared;
pub(crate) mod render_shared_proxy;
pub(crate) mod shared_alloc;
pub(crate) mod shared_install;
pub(crate) mod status;
pub(crate) mod vip;

pub use reconciler::{OperatorConfig, RelayConfig};
pub use render_shared_proxy::ProxyPoolConfig;
// #574 fold: the operator no longer runs as its own `BackgroundService`. The
// controller builds the reconcile context off the reflector's `OperatorStores`,
// the unified worker's dedicated branch calls `reconcile_dedicated`, and the
// controller spawns `run_vip_reconciler`.
pub(crate) use reconciler::{ReconcileContext, reconcile_dedicated};
pub(crate) use relay_reconcile::run_relay_reconciler;
pub(crate) use shared_install::run_shared_install_reconciler;
pub(crate) use vip::run_vip_reconciler;
