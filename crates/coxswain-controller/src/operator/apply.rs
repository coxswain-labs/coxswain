//! Server-side-apply of the rendered dedicated-proxy resources.
//!
//! ## Source-of-truth contract
//!
//! The controller is the **field-manager-authoritative** owner of every field
//! emitted by [`super::render::render`]. Users layer customisation through:
//!
//! - `Gateway.spec.infrastructure.{labels,annotations}` (GEP-1867)
//! - `CoxswainGatewayParameters.spec.podTemplate` (strategic-merge overlay)
//!
//! Direct edits on the generated `Deployment` / `Service` / `ServiceAccount` /
//! `HorizontalPodAutoscaler` / `PodDisruptionBudget` are **not** a supported
//! layering mechanism. Every reconcile re-asserts ownership via `force=true`,
//! so any direct edit will be overwritten on the next reconcile cycle.
//!
//! ## Field manager
//!
//! [`FIELD_MANAGER`] is `"coxswain-controller"`. The e2e suite asserts this
//! literal on `metadata.managedFields[].manager`; renaming it requires a
//! coordinated change to `provisioning.rs`.
//!
//! ## HPA / PDB lifecycle
//!
//! The HPA and PDB are **conditionally** provisioned: `RenderedSpecs.hpa` and
//! `.pdb` are `Some` only when the effective parameters call for them. When
//! `None`, `apply_rendered` deletes the named resource (via
//! `ignore_not_found`) so transitions between autoscaling-on and
//! autoscaling-off are handled on every reconcile without extra bookkeeping.

use super::reconciler::ignore_not_found;
use super::render::RenderedSpecs;
use super::render_relay::RenderedRelay;
use super::render_shared_proxy::RenderedSharedProxy;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::api::{DeleteParams, Patch, PatchParams};
use kube::{Api, Client};
use thiserror::Error;

/// SSA field manager used for every patch emitted by [`apply_rendered`].
///
/// The Step 9 acceptance criterion (#208) verifies this is exactly
/// `"coxswain-controller"` via `kubectl get deployment ... -o json | jq
/// '.metadata.managedFields[].manager'`. Do not rename without coordinating
/// the e2e assertion in `crates/coxswain-e2e/tests/provisioning.rs`.
pub(super) const FIELD_MANAGER: &str = "coxswain-controller";

/// Errors returned by [`apply_rendered`]. Each variant carries the underlying
/// [`kube::Error`] from the failing SSA call so callers can surface the
/// API-server message.
#[derive(Debug, Error)]
pub(super) enum ApplyError {
    /// SSA of the `ServiceAccount` failed.
    #[error("apply ServiceAccount: {0}")]
    ServiceAccount(#[source] kube::Error),
    /// SSA of the `Service` failed.
    #[error("apply Service: {0}")]
    Service(#[source] kube::Error),
    /// SSA of the `Deployment` failed.
    #[error("apply Deployment: {0}")]
    Deployment(#[source] kube::Error),
    /// SSA or deletion of the `HorizontalPodAutoscaler` failed.
    #[error("apply/delete HorizontalPodAutoscaler: {0}")]
    Hpa(#[source] kube::Error),
    /// SSA or deletion of the `PodDisruptionBudget` failed.
    #[error("apply/delete PodDisruptionBudget: {0}")]
    Pdb(#[source] kube::Error),
}

impl ApplyError {
    /// The underlying apiserver error, exposed for the bounded reason
    /// classification on `reconcile_errors_total{reason}` (#570).
    pub(super) fn kube_source(&self) -> &kube::Error {
        match self {
            Self::ServiceAccount(e)
            | Self::Service(e)
            | Self::Deployment(e)
            | Self::Hpa(e)
            | Self::Pdb(e) => e,
        }
    }
}

/// Server-side-apply the three rendered resources to the cluster.
///
/// Applies are sequenced ServiceAccount → Service → Deployment. The
/// ServiceAccount must exist before pods can mount its token (kubelet retries
/// transparently if it doesn't, but a strict order makes failure logs
/// attributable to a single resource). With `force=true`, every call
/// re-asserts field ownership — see the module-level source-of-truth
/// contract.
///
/// # Errors
///
/// Returns [`ApplyError::ServiceAccount`], [`ApplyError::Service`], or
/// [`ApplyError::Deployment`] if the apiserver rejects the corresponding
/// patch. On the first error, subsequent applies in the sequence are skipped
/// and the reconcile re-queues — the next reconcile retries from the
/// beginning.
///
/// # Panics
///
/// Panics if the rendered ServiceAccount, Service, or Deployment have no
/// `metadata.name` — a rendering invariant set by this crate's own render path,
/// so its absence indicates a controller bug.
pub(super) async fn apply_rendered(
    client: &Client,
    namespace: &str,
    rendered: &RenderedSpecs,
) -> Result<(), ApplyError> {
    let params = PatchParams::apply(FIELD_MANAGER).force();

    let sa_name = rendered
        .service_account
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered ServiceAccount has no name"));
    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    sa_api
        .patch(sa_name, &params, &Patch::Apply(&rendered.service_account))
        .await
        .map_err(ApplyError::ServiceAccount)?;

    let svc_name = rendered
        .service
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered Service has no name"));
    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    svc_api
        .patch(svc_name, &params, &Patch::Apply(&rendered.service))
        .await
        .map_err(ApplyError::Service)?;

    let deploy_name = rendered
        .deployment
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered Deployment has no name"));
    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    deploy_api
        .patch(deploy_name, &params, &Patch::Apply(&rendered.deployment))
        .await
        .map_err(ApplyError::Deployment)?;

    // HPA: apply when enabled, delete (idempotently) when disabled. This
    // handles the enabled→disabled transition without separate bookkeeping:
    // every reconcile either asserts the desired HPA or removes the stale one.
    let hpa_api: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), namespace);
    match rendered.hpa.as_ref() {
        Some(hpa) => {
            let hpa_name = hpa
                .metadata
                .name
                .as_deref()
                .unwrap_or_else(|| panic!("invariant: rendered HPA has no name"));
            hpa_api
                .patch(hpa_name, &params, &Patch::Apply(hpa))
                .await
                .map_err(ApplyError::Hpa)?;
        }
        None => {
            // When autoscaling is disabled, remove any previously-provisioned
            // HPA. The name follows the GEP-1762 pattern shared with the
            // Deployment, so we can derive it from the Deployment name.
            ignore_not_found(hpa_api.delete(deploy_name, &DeleteParams::default()).await)
                .map_err(ApplyError::Hpa)?;
        }
    }

    // PDB: same apply-or-delete pattern as HPA.
    let pdb_api: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), namespace);
    match rendered.pdb.as_ref() {
        Some(pdb) => {
            let pdb_name = pdb
                .metadata
                .name
                .as_deref()
                .unwrap_or_else(|| panic!("invariant: rendered PDB has no name"));
            pdb_api
                .patch(pdb_name, &params, &Patch::Apply(pdb))
                .await
                .map_err(ApplyError::Pdb)?;
        }
        None => {
            ignore_not_found(pdb_api.delete(deploy_name, &DeleteParams::default()).await)
                .map_err(ApplyError::Pdb)?;
        }
    }

    Ok(())
}

/// Server-side-apply a namespace relay's three rendered resources (#584).
///
/// Sequenced ServiceAccount → Service → Deployment under the same `force=true`
/// field-manager contract as [`apply_rendered`], so it is idempotent on an
/// unchanged relay and re-asserts image/args ownership on a controller upgrade.
/// No HPA/PDB — a relay's HA is its fixed replica floor, not autoscaling.
///
/// # Errors
///
/// Returns [`ApplyError::ServiceAccount`], [`ApplyError::Service`], or
/// [`ApplyError::Deployment`] if the apiserver rejects the corresponding patch.
///
/// # Panics
///
/// Panics if a rendered relay resource has no `metadata.name` — a rendering
/// invariant whose absence indicates a controller bug.
pub(super) async fn apply_relay(
    client: &Client,
    namespace: &str,
    rendered: &RenderedRelay,
) -> Result<(), ApplyError> {
    let params = PatchParams::apply(FIELD_MANAGER).force();

    let sa_name = rendered
        .service_account
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered relay ServiceAccount has no name"));
    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    sa_api
        .patch(sa_name, &params, &Patch::Apply(&rendered.service_account))
        .await
        .map_err(ApplyError::ServiceAccount)?;

    let svc_name = rendered
        .service
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered relay Service has no name"));
    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    svc_api
        .patch(svc_name, &params, &Patch::Apply(&rendered.service))
        .await
        .map_err(ApplyError::Service)?;

    let deploy_name = rendered
        .deployment
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered relay Deployment has no name"));
    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    deploy_api
        .patch(deploy_name, &params, &Patch::Apply(&rendered.deployment))
        .await
        .map_err(ApplyError::Deployment)?;

    // PDB: apply when the effective floor warrants one (≥2), delete otherwise — the same
    // apply-or-delete pattern `apply_rendered` uses for the dedicated proxy, so a policy
    // change that drops the floor below 2 reclaims a stale PDB without extra bookkeeping.
    // The relay's name is fixed (`RELAY_NAME`), so the delete target is `deploy_name`.
    let pdb_api: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), namespace);
    match rendered.pdb.as_ref() {
        Some(pdb) => {
            let pdb_name = pdb
                .metadata
                .name
                .as_deref()
                .unwrap_or_else(|| panic!("invariant: rendered relay PDB has no name"));
            pdb_api
                .patch(pdb_name, &params, &Patch::Apply(pdb))
                .await
                .map_err(ApplyError::Pdb)?;
        }
        None => {
            ignore_not_found(pdb_api.delete(deploy_name, &DeleteParams::default()).await)
                .map_err(ApplyError::Pdb)?;
        }
    }

    Ok(())
}

/// Server-side-apply the controller-owned shared proxy pool's rendered objects
/// (#604).
///
/// Sequenced ServiceAccount → internal Service → Deployment under the same
/// `force=true` field-manager contract as [`apply_rendered`], then HPA and PDB
/// apply-or-delete via [`ignore_not_found`] so autoscaling/PDB on↔off transitions
/// reconcile with no extra bookkeeping. Idempotent on an unchanged pool: a second
/// `helm upgrade` never touches these objects (they left the chart), so the
/// controller re-asserts ownership without a field-manager fight. The external
/// Ingress LoadBalancer Service is **not** applied here — it stays Helm-owned.
///
/// # Errors
///
/// Returns the matching [`ApplyError`] variant if the apiserver rejects the SA,
/// internal Service, Deployment, HPA, or PDB call. On the first error the
/// remaining applies are skipped and the next install-reconcile pass retries.
///
/// # Panics
///
/// Panics if a rendered shared-proxy resource has no `metadata.name` — a
/// rendering invariant whose absence indicates a controller bug.
pub(super) async fn apply_shared_proxy(
    client: &Client,
    namespace: &str,
    rendered: &RenderedSharedProxy,
) -> Result<(), ApplyError> {
    let params = PatchParams::apply(FIELD_MANAGER).force();

    let sa_name = rendered
        .service_account
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered shared-proxy ServiceAccount has no name"));
    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    sa_api
        .patch(sa_name, &params, &Patch::Apply(&rendered.service_account))
        .await
        .map_err(ApplyError::ServiceAccount)?;

    let svc_name = rendered
        .internal_service
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered shared-proxy internal Service has no name"));
    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    svc_api
        .patch(svc_name, &params, &Patch::Apply(&rendered.internal_service))
        .await
        .map_err(ApplyError::Service)?;

    let deploy_name = rendered
        .deployment
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered shared-proxy Deployment has no name"));
    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    deploy_api
        .patch(deploy_name, &params, &Patch::Apply(&rendered.deployment))
        .await
        .map_err(ApplyError::Deployment)?;

    // HPA: apply-or-delete on the shared Deployment name, so an autoscaling
    // on↔off flip reclaims the stale HPA without extra bookkeeping.
    let hpa_api: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), namespace);
    match rendered.hpa.as_ref() {
        Some(hpa) => {
            let hpa_name = hpa
                .metadata
                .name
                .as_deref()
                .unwrap_or_else(|| panic!("invariant: rendered shared-proxy HPA has no name"));
            hpa_api
                .patch(hpa_name, &params, &Patch::Apply(hpa))
                .await
                .map_err(ApplyError::Hpa)?;
        }
        None => {
            ignore_not_found(hpa_api.delete(deploy_name, &DeleteParams::default()).await)
                .map_err(ApplyError::Hpa)?;
        }
    }

    // PDB: same apply-or-delete pattern.
    let pdb_api: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), namespace);
    match rendered.pdb.as_ref() {
        Some(pdb) => {
            let pdb_name = pdb
                .metadata
                .name
                .as_deref()
                .unwrap_or_else(|| panic!("invariant: rendered shared-proxy PDB has no name"));
            pdb_api
                .patch(pdb_name, &params, &Patch::Apply(pdb))
                .await
                .map_err(ApplyError::Pdb)?;
        }
        None => {
            ignore_not_found(pdb_api.delete(deploy_name, &DeleteParams::default()).await)
                .map_err(ApplyError::Pdb)?;
        }
    }

    Ok(())
}

/// Delete every controller-owned shared proxy pool object by name (#604), so
/// disabling the pool (`proxy.shared.enabled=false`) or clearing its selector
/// reclaims it instead of orphaning it. Idempotent: each delete is 404-tolerant,
/// so a never-provisioned install (or a repeated pass) is a harmless no-op. The
/// retained Ingress LoadBalancer Service is Helm-owned and left untouched.
///
/// # Errors
///
/// Returns the matching [`ApplyError`] variant if a delete fails for a reason
/// other than 404 Not Found.
pub(super) async fn delete_shared_proxy(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<(), ApplyError> {
    let dp = DeleteParams::default();
    let internal = format!("{name}-internal");

    let hpa_api: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), namespace);
    ignore_not_found(hpa_api.delete(name, &dp).await).map_err(ApplyError::Hpa)?;

    let pdb_api: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), namespace);
    ignore_not_found(pdb_api.delete(name, &dp).await).map_err(ApplyError::Pdb)?;

    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    ignore_not_found(deploy_api.delete(name, &dp).await).map_err(ApplyError::Deployment)?;

    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    ignore_not_found(svc_api.delete(&internal, &dp).await).map_err(ApplyError::Service)?;

    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    ignore_not_found(sa_api.delete(name, &dp).await).map_err(ApplyError::ServiceAccount)?;

    Ok(())
}

/// Server-side-apply a single shared-mode per-Gateway VIP Service (#472).
///
/// Idempotent under the same `force=true` field-manager contract as
/// [`apply_rendered`]: an unchanged Service is a no-op, so this can run on
/// every shared-Gateway reconcile without churning `resourceVersion`.
///
/// # Errors
///
/// Returns [`ApplyError::Service`] if the apiserver rejects the patch.
///
/// # Panics
///
/// Panics if `service` has no `metadata.name` — a rendering invariant whose
/// absence indicates a controller bug.
pub(super) async fn apply_shared_vip_service(
    client: &Client,
    namespace: &str,
    service: &Service,
) -> Result<(), ApplyError> {
    let name = service
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered shared VIP Service has no name"));
    let params = PatchParams::apply(FIELD_MANAGER).force();
    let api: Api<Service> = Api::namespaced(client.clone(), namespace);
    api.patch(name, &params, &Patch::Apply(service))
        .await
        .map_err(ApplyError::Service)?;
    Ok(())
}

/// Server-side-apply the per-Gateway shared-mode identity `ServiceAccount`
/// (#482, GEP-1867) into the Gateway's own namespace.
///
/// Same `force=true` field-manager contract as [`apply_rendered`]: idempotent on
/// an unchanged SA, and force-apply prunes any infra label/annotation the
/// operator removes from `spec.infrastructure` — so add/update/remove all
/// reconcile through the next apply with no extra bookkeeping.
///
/// # Errors
///
/// Returns [`ApplyError::ServiceAccount`] if the apiserver rejects the patch.
///
/// # Panics
///
/// Panics if `sa` has no `metadata.name` — a rendering invariant whose absence
/// indicates a controller bug.
pub(super) async fn apply_shared_gateway_service_account(
    client: &Client,
    namespace: &str,
    sa: &ServiceAccount,
) -> Result<(), ApplyError> {
    let name = sa.metadata.name.as_deref().unwrap_or_else(|| {
        panic!("invariant: rendered shared identity ServiceAccount has no name")
    });
    let params = PatchParams::apply(FIELD_MANAGER).force();
    let api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    api.patch(name, &params, &Patch::Apply(sa))
        .await
        .map_err(ApplyError::ServiceAccount)?;
    Ok(())
}
