//! Naming helpers shared across operator provisioning and discovery scope binding.
//!
//! Centralises name-formula logic so provisioned Kubernetes resources and the
//! discovery layer always agree on what to call a Gateway's dedicated proxy
//! objects.  A drift between the two would cause the scope-binding check to
//! reject every real dedicated proxy.

// ── GEP-1762 resource name ────────────────────────────────────────────────────

/// Compute the GEP-1762 resource name for a Gateway's dedicated proxy objects.
///
/// GEP-1762 names the Deployment, Service, and ServiceAccount the controller
/// provisions for a dedicated proxy as `<GATEWAY-NAME>-<GATEWAYCLASS-NAME>`.
/// This is the single source of truth shared by:
///
/// - `coxswain_controller::operator::render`, which provisions the
///   Deployment/Service/ServiceAccount under this name.
/// - [`crate::dedicated_registry::DedicatedRoutingSnapshot`], which
///   records it as the `expected_proxy_sa` field so the discovery server can
///   reconstruct the dedicated proxy's ServiceAccount — and thus its SVID
///   identity — without accessing the Kubernetes API.
///
/// Both consumers call this function; changing the formula here changes both
/// in sync.
#[must_use]
pub fn gep1762_resource_name(gateway_name: &str, class_name: &str) -> String {
    format!("{gateway_name}-{class_name}")
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gep1762_resource_name_concatenates_with_dash() {
        assert_eq!(
            gep1762_resource_name("my-gateway", "coxswain"),
            "my-gateway-coxswain",
        );
    }

    #[test]
    fn gep1762_resource_name_gateway_with_class_variants() {
        // Verify a few realistic names produce the expected format.
        assert_eq!(
            gep1762_resource_name("public", "coxswain"),
            "public-coxswain",
        );
        assert_eq!(
            gep1762_resource_name("tenant-a", "coxswain"),
            "tenant-a-coxswain",
        );
    }
}
