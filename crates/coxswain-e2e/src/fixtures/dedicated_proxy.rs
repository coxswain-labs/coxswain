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

/// Dedicated-mode `Gateway` with `serviceType: ClusterIP` (#211 Scenario A).
/// Pins the proxy `image` to `registry.k8s.io/pause:3.10` so the Pod becomes
/// Ready instantly — this test gates `Programmed=True` on Pod readiness but
/// only exercises the operator's status writer, not the proxy data plane.
pub const DEDICATED_GATEWAY_CLUSTERIP: &str = fixture!("dedicated_gateway_clusterip.yaml");

/// Dedicated-mode `Gateway` with `serviceType: LoadBalancer` (#211 Scenario
/// B). Used to verify the operator's address resolution from
/// `Service.status.loadBalancer.ingress` and the `Programmed` transition
/// from `AddressNotAssigned` → `True` once the harness injects a synthetic
/// LB ingress. Same pause-image stub as `DEDICATED_GATEWAY_CLUSTERIP`.
pub const DEDICATED_GATEWAY_LOADBALANCER: &str = fixture!("dedicated_gateway_loadbalancer.yaml");

/// Dedicated-mode `Gateway` whose `parametersRef` targets a missing
/// `CoxswainGatewayParameters` object (#211 Scenario C). Used to verify the
/// operator writes `Accepted=False, reason=InvalidParameters` directly.
pub const DEDICATED_GATEWAY_INVALID_PARAMS: &str =
    fixture!("dedicated_gateway_invalid_params.yaml");
