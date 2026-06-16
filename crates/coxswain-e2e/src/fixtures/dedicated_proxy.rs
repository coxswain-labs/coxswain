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

/// Dedicated-mode `Gateway` whose `CoxswainGatewayParameters` sets every spec
/// knob at once (`replicas`, `image`, `resources`, `serviceType: NodePort`,
/// `podTemplate`). Used by the #333 per-field coverage test to assert each one
/// lands on the rendered Deployment/Service.
pub const DEDICATED_GATEWAY_FIELDS: &str = fixture!("dedicated_gateway_fields.yaml");

/// Dedicated-mode `Gateway` with `allowedRoutes.namespaces.from: All` on its
/// listener (#229). Used to verify that the controller auto-provisions a
/// `ClusterRoleBinding` for the proxy SA and renders
/// `--allow-cluster-wide-route-read` into the Deployment args.
pub const DEDICATED_GATEWAY_FROM_ALL: &str = fixture!("dedicated_gateway_from_all.yaml");

// -----------------------------------------------------------------------------
// Step 13 (#212) — full-lifecycle suite fixtures. Listener ports use the
// harness-substituted `GATEWAY_HTTP_PORT`, and the dedicated pod's image is
// pinned to `registry.k8s.io/pause:3.10` so the Pod becomes Ready without a
// coxswain image build.
// -----------------------------------------------------------------------------

/// Dedicated-mode Gateway + `CoxswainGatewayParameters` (no HTTPRoute). Used
/// by the provisioning, status, GC, and restart-idempotency lifecycle tests.
pub const PROVISIONING: &str = fixture!("provisioning.yaml");

/// Dedicated-mode Gateway + `CoxswainGatewayParameters` + same-namespace
/// HTTPRoute targeting `echo-a` from `backends/echo.yaml`. Used by the traffic
/// and dedicated→shared migration lifecycle tests.
pub const TRAFFIC: &str = fixture!("traffic.yaml");

/// Dedicated-mode Gateway + HTTPRoute targeting a backend Service in TENANTNS.
/// Pair with [`CROSS_NAMESPACE_TENANT`]; the route only resolves while the
/// matching `ReferenceGrant` is present.
pub const CROSS_NAMESPACE_ROUTE: &str = fixture!("cross_namespace_route.yaml");

/// Tenant-namespace counterpart of [`CROSS_NAMESPACE_ROUTE`]: backend `echo-d`
/// plus the `ReferenceGrant` permitting an HTTPRoute in TESTNS to target
/// Services here.
pub const CROSS_NAMESPACE_TENANT: &str = fixture!("cross_namespace_tenant.yaml");

/// Shared-mode starting point for the shared→dedicated migration test: Gateway
/// without `infrastructure.parametersRef`, HTTPRoute attached. The
/// `dedicated-params` object is bundled so the test can patch the parametersRef
/// in without a second apply.
pub const MODE_MIGRATION_SHARED: &str = fixture!("mode_migration_shared.yaml");

/// Dedicated-mode starting point for the dedicated→shared migration test:
/// Gateway with `infrastructure.parametersRef` set, HTTPRoute attached.
pub const MODE_MIGRATION_DEDICATED: &str = fixture!("mode_migration_dedicated.yaml");
