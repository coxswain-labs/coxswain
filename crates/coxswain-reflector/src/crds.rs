//! Gateway API CRD-presence probe.
//!
//! Run once at startup to decide whether to spawn Gateway API reflectors. If
//! the CRDs are absent (`404` from the API server), the caller logs the
//! Ingress-only warning and skips `Gateway`, `GatewayClass`, `HTTPRoute`,
//! `ReferenceGrant`, and `BackendTLSPolicy` watches. Any other error (network
//! blip, transient API server failure) is treated as "assume present" so a
//! single bad reply cannot silently disable Gateway API.
//!
//! Detection is one-shot: installing the CRDs after a Coxswain pod is already
//! running requires a pod restart to pick them up.

use crate::gw_types::v::gatewayclasses::GatewayClass;
use kube::{Api, Client};

/// Probe the cluster for Gateway API CRDs. Returns `false` only when the API
/// server explicitly returns `404` for a `GatewayClass` list call; any other
/// outcome (success, network error, permission denied) returns `true`.
///
/// `GatewayClass` is the probe target because it is cluster-scoped (no
/// namespace plumbing required) and part of the GA channel — both pods already
/// hold `get/list/watch` on it via their RBAC.
///
/// # Errors
///
/// None — every error path is mapped to "assume present" and logged at warn
/// level. Callers do not need to handle failure.
#[must_use]
pub async fn gateway_api_crds_present(client: &Client) -> bool {
    let api = Api::<GatewayClass>::all(client.clone());
    let params = kube::api::ListParams::default().limit(1);
    match api.list(&params).await {
        Ok(_) => true,
        Err(kube::Error::Api(status)) if classify_absent(&status) => {
            tracing::warn!(
                "Gateway API CRDs not found; running in Ingress-only mode — \
                 restart after installing the CRDs to enable Gateway API"
            );
            false
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Gateway API CRD-presence probe failed; assuming CRDs are present"
            );
            true
        }
    }
}

/// Returns `true` when the API error is a `404 NotFound` — the canonical
/// shape returned by the API server when the CRD's resource is unknown.
fn classify_absent(status: &kube::core::Status) -> bool {
    status.code == 404
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::Status;

    /// Builds the canonical "CRD not found" status that the API server
    /// returns when the requested CRD is not installed.
    fn crd_not_found_status() -> Status {
        Status {
            code: 404,
            message: "the server could not find the requested resource".to_string(),
            reason: "NotFound".to_string(),
            ..Status::default()
        }
    }

    /// Builds a non-404 status used to verify the "assume present" fallback.
    fn forbidden_status() -> Status {
        Status {
            code: 403,
            message: "forbidden".to_string(),
            reason: "Forbidden".to_string(),
            ..Status::default()
        }
    }

    #[test]
    fn classify_404_as_absent() {
        let status = crd_not_found_status();
        assert!(
            classify_absent(&status),
            "404 must be classified as absent so reflectors are skipped"
        );
    }

    #[test]
    fn classify_non_404_as_present() {
        let status = forbidden_status();
        assert!(
            !classify_absent(&status),
            "non-404 must NOT be classified as absent — a permission error \
             should not silently disable Gateway API"
        );
    }
}
