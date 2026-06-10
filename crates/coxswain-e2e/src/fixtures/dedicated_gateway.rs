//! YAML fixture paths for the Step 9 (#208) dedicated-mode provisioning e2e.

macro_rules! fixture {
    ($path:literal) => {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/dedicated_gateway/",
            $path
        )
    };
}

/// `CoxswainGatewayParameters` + dedicated-mode `Gateway` referencing it.
pub const DEDICATED_GATEWAY: &str = fixture!("dedicated_gateway.yaml");
