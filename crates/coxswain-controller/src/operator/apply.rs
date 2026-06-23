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
//! Direct edits on the generated `Deployment` / `Service` / `ServiceAccount`
//! are **not** a supported layering mechanism. Every reconcile re-asserts
//! ownership via `force=true`, so any direct edit will be overwritten on the
//! next reconcile cycle. The two CR-level escape hatches above are
//! intentionally the only way to customise the generated resources — this
//! keeps the desired-state graph closed under the controller's view.
//!
//! ## Field manager
//!
//! [`FIELD_MANAGER`] is `"coxswain-controller"`. The e2e suite asserts this
//! literal on `metadata.managedFields[].manager`; renaming it requires a
//! coordinated change to `provisioning_rbac.rs`.

use super::render::RenderedSpecs;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use thiserror::Error;

/// SSA field manager used for every patch emitted by [`apply_rendered`].
///
/// The Step 9 acceptance criterion (#208) verifies this is exactly
/// `"coxswain-controller"` via `kubectl get deployment ... -o json | jq
/// '.metadata.managedFields[].manager'`. Do not rename without coordinating
/// the e2e assertion in `crates/coxswain-e2e/tests/provisioning_rbac.rs`.
pub(super) const FIELD_MANAGER: &str = "coxswain-controller";

/// Errors returned by [`apply_rendered`]. Each variant carries the underlying
/// [`kube::Error`] from the failing SSA call so callers can surface the
/// API-server message.
#[non_exhaustive]
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
/// Panics if the Gateway has no `metadata.namespace`, or if the rendered
/// ServiceAccount, Service, or Deployment have no `metadata.name`. All are
/// apiserver invariants or rendering invariants; their absence indicates a
/// controller bug.
pub(super) async fn apply_rendered(
    client: &Client,
    gateway: &Gateway,
    rendered: &RenderedSpecs,
) -> Result<(), ApplyError> {
    let namespace = gateway.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });

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

    Ok(())
}
