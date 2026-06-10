//! YAML fixture paths for the Step 9 (#208) dedicated-mode provisioning e2e.

macro_rules! fixture {
    ($path:literal) => {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/dedicated_proxy/",
            $path
        )
    };
}

/// `CoxswainGatewayParameters` + dedicated-mode `Gateway` referencing it.
pub const DEDICATED_GATEWAY: &str = fixture!("dedicated_gateway.yaml");

/// Same dedicated-mode `Gateway` + an `HTTPRoute` attached to it backing a
/// same-namespace Service. Used by the #209 e2e to verify per-namespace
/// `RoleBinding` reconciliation.
pub const DEDICATED_GATEWAY_WITH_ROUTE: &str = fixture!("dedicated_gateway_with_route.yaml");
