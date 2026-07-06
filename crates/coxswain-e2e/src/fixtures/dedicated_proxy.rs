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
/// Runs the real coxswain image (no `image` override): `Programmed=True`
/// requires the dedicated proxy to report its listener ports bound over
/// discovery (#531), so a stub container would never converge.
pub const DEDICATED_GATEWAY_CLUSTERIP: &str = fixture!("dedicated_gateway_clusterip.yaml");

/// Dedicated-mode `Gateway` with `serviceType: LoadBalancer` (#211 Scenario
/// B). Used to verify the operator's address resolution from
/// `Service.status.loadBalancer.ingress` and the `Programmed` transition
/// from `AddressNotAssigned` → `True` once the harness injects a synthetic
/// LB ingress. Runs the real coxswain image, like
/// [`DEDICATED_GATEWAY_CLUSTERIP`].
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
// harness-substituted `GATEWAY_HTTP_PORT`; the dedicated pod runs the real
// coxswain image so the #531 bound-port Programmed gate can converge.
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

// ── GEP-1867 infrastructure propagation, shared mode (#482) ──────────────────

/// Shared-mode Gateway (no `parametersRef`) declaring `infrastructure.labels`
/// (incl. a reserved-key override that must be dropped, and a benign `kept`
/// label) and `infrastructure.annotations`. Drives the per-Gateway identity
/// ServiceAccount the controller provisions in the Gateway's namespace.
pub const SHARED_GATEWAY_INFRA: &str = fixture!("shared_gateway_infra.yaml");

// ── CRD openAPIV3Schema rejection (#335) ─────────────────────────────────────

/// `CoxswainGatewayParameters` with `serviceType: FooBar` — rejected by the
/// coxswain-owned CRD schema (`FooBar` is not in the enum
/// `{LoadBalancer, NodePort, ClusterIP}`).
pub const REJECT_GATEWAY_PARAMS_INVALID_SERVICE_TYPE: &str =
    fixture!("reject_gateway_params_invalid_service_type.yaml");

// ── Autoscaling (#497) ───────────────────────────────────────────────────────

/// Dedicated-mode `Gateway` with `autoscaling.enabled: true`, `minReplicas: 2`,
/// `maxReplicas: 5`, `targetCPUUtilizationPercentage: 70`. Used to verify the
/// controller provisions an `HPA` and `PDB` alongside the Deployment, and that
/// the Deployment has no static `spec.replicas` (HPA owns the count).
pub const DEDICATED_GATEWAY_AUTOSCALING: &str = fixture!("dedicated_gateway_autoscaling.yaml");
