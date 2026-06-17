#![allow(missing_docs)]
//! Routing data-plane: how requests reach a backend.
//!
//! Plane: **data-plane**. Execution: **parallel** — every test owns a fresh
//! namespace and asserts only traffic served through that partition.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. "Traffic flows to backend X" is data-plane even if it provisions
//! first. Ingress vs Gateway API is a sub-grouping *within* this file (the
//! `ingress_`/`gateway_` prefix disambiguates behaviors tested for both APIs);
//! it is no longer a top-level split.
//!
//! Covers: path/host/header/method/query matching, weighted split, named-port,
//! default-backend, default IngressClass, wildcard hosts, cross-namespace +
//! ReferenceGrant, endpoint serving-state exclusion, parent-ref port scoping,
//! HTTPRoute filters, request/backend timeouts, and the rewrite-target
//! annotation. TLS lives in `tls.rs`; traffic-policy knobs in `traffic_policy.rs`.

use coxswain_e2e::{
    ControllerOptions, ControllerProcess, FixtureVars, Harness, HttpClient, IngressClassGuard,
    NamespaceGuard, bootstrap,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::{http, wait},
};
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use kube::api::{DeleteParams, PostParams};
use reqwest::Method;
use std::collections::BTreeMap;
use std::time::Duration;

mod common;

/// Tests both the per-Ingress spec.defaultBackend and the controller-wide
/// --ingress-default-backend flag. Backends are deployed before the controller
/// starts so that echo-c is already ready on the first routing-table rebuild.
#[tokio::test]
async fn default_backend_serves_unmatched_requests() -> anyhow::Result<()> {
    // Bootstrap cluster connection and create the namespace before starting the
    // controller, so the default-backend endpoints are ready on first sync.
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "ing-default").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Start the controller with the controller-wide default pointing at echo-c.
    let controller = ControllerProcess::start_with_options(ControllerOptions {
        ingress_default_backend: Some(format!("{}/echo-c:3000", ns.name)),
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;
    let http = HttpClient::new(controller.proxy_addr)?;

    // Apply the fixture: rule /api → echo-a, spec.defaultBackend → echo-b.
    fixtures::apply_fixture(ingress::DEFAULT_BACKEND, FixtureVars::new(&ns.name)).await?;

    let host = format!("app.{}.local", ns.name);
    let unknown_host = format!("unknown.{}.local", ns.name);

    // Wait until the explicit rule is live with the correct backend.
    // Use wait_for_backend (not wait_for_route) because the controller-wide catchall
    // may serve echo-c for this host before the Ingress-specific route is reconciled.
    wait::wait_for_backend(&http, &host, "/api", "echo-a", Duration::from_secs(60)).await?;

    // Per-Ingress defaultBackend catches path-miss on the rule's host.
    let resp = http.get(&host, "/other").await?;
    resp.assert_backend("echo-b");

    // Per-Ingress defaultBackend wins over controller-wide for unmatched hosts too.
    let resp = http.get(&unknown_host, "/anything").await?;
    resp.assert_backend("echo-b");

    Ok(())
}

/// Tests a rules-less Ingress (only spec.defaultBackend, no spec.rules).
/// The defaultBackend should serve all traffic regardless of host or path.
#[tokio::test]
async fn default_backend_alone_serves_all_hosts() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-default-only").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::DEFAULT_BACKEND_ONLY, FixtureVars::new(&ns.name)).await?;

    // Wait for the defaultBackend to be live, probing an arbitrary host+path.
    let resp =
        wait::wait_for_route(&h.http, "random.example", "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-b");

    // Any host and any path should hit echo-b.
    let resp = h.http.get("other.io", "/api/v1").await?;
    resp.assert_backend("echo-b");

    Ok(())
}

#[tokio::test]
async fn ingress_path_match_routes_to_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-path").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);

    let resp = wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // /b shares the same ingress as /a, so a short deadline is enough; use
    // wait_for_route rather than a bare get() to tolerate transient timeouts.
    let resp = wait::wait_for_route(&h.http, &host, "/b", Duration::from_secs(15)).await?;
    resp.assert_backend("echo-b");

    Ok(())
}

/// Deleting the Ingress object stops the data plane serving its route: apply →
/// serves echo-a → delete the Ingress → the path 404s. Asserts the teardown
/// negative (rubric #5) that the Ingress API otherwise lacks — withdrawal of a
/// route object, not just a backend, must take the route out of the table.
#[tokio::test]
async fn ingress_deleted_route_stops_serving() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-delete-stops").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    // Baseline: the route serves echo-a while the Ingress exists.
    wait::wait_for_backend(&h.http, &host, "/a", "echo-a", Duration::from_secs(60)).await?;

    // Delete the Ingress object.
    let ingresses: Api<Ingress> = Api::namespaced(h.client.clone(), &ns.name);
    ingresses
        .delete("echo-ingress", &DeleteParams::default())
        .await?;

    // The route is withdrawn from the routing table → the path 404s.
    wait::wait_for_route_status(&h.http, &host, "/a", 404, Duration::from_secs(30)).await?;

    Ok(())
}

/// Gateway-API counterpart to [`ingress_deleted_route_stops_serving`]: deleting
/// the HTTPRoute (leaving the Gateway in place) stops the listener serving its
/// route → the path 404s.
#[tokio::test]
async fn gateway_deleted_route_stops_serving() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-delete-stops").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    // Baseline: the route serves echo-a while the HTTPRoute exists.
    wait::wait_for_backend(
        &h.gateway_http,
        &host,
        "/a",
        "echo-a",
        Duration::from_secs(60),
    )
    .await?;

    // Delete the HTTPRoute object — leave the Gateway in place.
    let routes: Api<HTTPRoute> = Api::namespaced(h.client.clone(), &ns.name);
    routes
        .delete("echo-route", &DeleteParams::default())
        .await?;

    // With no attached route the Gateway listener 404s for the host.
    wait::wait_for_route_status(&h.gateway_http, &host, "/a", 404, Duration::from_secs(30)).await?;

    Ok(())
}

/// Verifies wildcard Ingress (`*.wildcard.{ns}.local`) routing behavior.
///
/// The Kubernetes Ingress spec requires `*.example.com` to match exactly one DNS label,
/// so `api.wildcard.{ns}.local` (single-label) is served but
/// `nested.api.wildcard.{ns}.local` (multi-label) must return 404.
#[tokio::test]
async fn ingress_wildcard_host_matches_single_label_only() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-wildcard").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::WILDCARD_HOST,
        FixtureVars::new(&ns.name).with("TESTNS", &ns.name),
    )
    .await?;

    // Single-label subdomain must match per both Ingress spec and Gateway API spec.
    let host = format!("api.wildcard.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-c");

    // Multi-label subdomain must NOT match — Ingress spec restricts `*` to one label.
    let nested = format!("nested.api.wildcard.{}.local", ns.name);
    let status = h.http.get_status(&nested, "/").await?;
    assert_eq!(
        status, 404,
        "Ingress wildcard must not match multi-label subdomains"
    );

    Ok(())
}

/// Verifies that an Ingress backend with a named service port (`port.name: http`)
/// is resolved correctly and routes traffic to the expected backend.
/// Also covers `pathType: Exact` end-to-end (previously untested at this level).
#[tokio::test]
async fn named_port_backend_resolves_to_target_port() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-named-port").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("named.{}.local", ns.name);
    fixtures::apply_fixture(
        ingress::NAMED_PORT,
        FixtureVars::new(&ns.name).with("INGRESS_HOST", &host),
    )
    .await?;

    let resp = wait::wait_for_route(&h.http, &host, "/named", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // Exact pathType: a longer path must not match.
    let status = h.http.get_status(&host, "/named/extra").await?;
    assert_eq!(status, 404, "Exact path should not match /named/extra");

    Ok(())
}

/// Verifies that an Ingress with no ingressClassName and no legacy annotation
/// is reconciled and routes traffic when the controller owns the cluster-default
/// IngressClass (annotated `ingressclass.kubernetes.io/is-default-class: "true"`).
#[tokio::test]
async fn default_ingress_class_claims_unannotated_ingress() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-default-class").await?;

    // Create a uniquely-named default IngressClass scoped to this test run.
    // The guard deletes it on drop so the cluster-scoped resource doesn't leak.
    let ic_name = format!("coxswain-default-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&h.client, &ic_name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::DEFAULT_CLASS, FixtureVars::new(&ns.name)).await?;

    let host = format!("default-ingress.{}.local", ns.name);
    // Use wait_for_backend rather than wait_for_route: a leftover catchall entry
    // from a concurrent test could serve a 200 before this route is reconciled.
    wait::wait_for_backend(&h.http, &host, "/", "echo-a", Duration::from_secs(60)).await?;

    Ok(())
}

/// Verifies the `ingress.coxswain-labs.dev/rewrite-target` annotation:
/// the echo backend must see the annotation value (`/v2`) as its request path,
/// not the original client-side path (`/api`).
///
/// This confirms the `PathModifier::ReplaceFullPath` filter action wired in
/// by the annotation parser is applied on the upstream request.
#[tokio::test]
async fn annotation_rewrite_target_rewrites_upstream_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-rewrite").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_REWRITE_TARGET,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("rewrite.{}.local", ns.name);

    // Wait until the route is live. The echo response path after rewrite must
    // be "/v2", not "/api" (which the client sends).
    let resp = wait::wait_for_route(&h.http, &host, "/api", Duration::from_secs(60)).await?;
    assert_eq!(
        resp.path.as_deref(),
        Some("/v2"),
        "upstream must see the rewrite-target path /v2, not the original /api"
    );

    Ok(())
}

/// `use-regex` (#265): a `pathType: ImplementationSpecific` path is matched as a
/// regular expression. `/digits/[0-9]+` serves echo-a for a digit tail and 404s for a
/// non-digit tail — proving the value is a regex, not a literal prefix.
#[tokio::test]
async fn ingress_use_regex_matches_implementation_specific_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-regex-match").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::USE_REGEX, FixtureVars::new(&ns.name)).await?;

    let host = format!("regex-match.{}.local", ns.name);

    // Happy: a digit tail matches the regex and reaches echo-a.
    let resp = wait::wait_for_backend(
        &h.http,
        &host,
        "/digits/42",
        "echo-a",
        Duration::from_secs(60),
    )
    .await?;
    resp.assert_backend("echo-a");

    // Sad: a non-digit tail does not match the regex (and no other route claims it).
    wait::wait_for_route_status(&h.http, &host, "/digits/abc", 404, Duration::from_secs(30))
        .await?;

    Ok(())
}

/// `use-regex` is armed per-path by `pathType`, not host-wide (unlike nginx): a sibling
/// `pathType: Prefix` path on the same `use-regex` Ingress still matches as a prefix.
#[tokio::test]
async fn ingress_use_regex_leaves_sibling_prefix_path_unaffected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-regex-mixed").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::USE_REGEX, FixtureVars::new(&ns.name)).await?;

    let host = format!("regex-match.{}.local", ns.name);

    // The /plain Prefix path is untouched by use-regex and still routes to echo-b,
    // including sub-paths (prefix semantics).
    let resp =
        wait::wait_for_backend(&h.http, &host, "/plain", "echo-b", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-b");
    let resp = wait::wait_for_backend(
        &h.http,
        &host,
        "/plain/sub",
        "echo-b",
        Duration::from_secs(15),
    )
    .await?;
    resp.assert_backend("echo-b");

    Ok(())
}

/// `use-regex` + `rewrite-target` (#265): capture groups from the regex path are
/// substituted into the rewritten upstream path. `^/svc/(.*)` + `/$1` rewrites
/// `/svc/users/42` to `/users/42` as seen by the backend.
#[tokio::test]
async fn ingress_use_regex_rewrite_target_substitutes_capture_group() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-regex-rewrite").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::USE_REGEX, FixtureVars::new(&ns.name)).await?;

    let host = format!("regex-rewrite.{}.local", ns.name);

    let resp = wait::wait_for_backend(
        &h.http,
        &host,
        "/svc/users/42",
        "echo-a",
        Duration::from_secs(60),
    )
    .await?;
    resp.assert_backend("echo-a");
    assert_eq!(
        resp.path.as_deref(),
        Some("/users/42"),
        "capture group $1 must be substituted into the upstream path"
    );

    Ok(())
}

/// `use-regex` invalid pattern (#265): an uncompilable regex path is skipped with a
/// WARN, but a sibling valid regex path on the same Ingress still serves — the bad
/// pattern never fails the whole Ingress (or the routing table).
#[tokio::test]
async fn ingress_use_regex_invalid_pattern_skips_only_that_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-regex-invalid").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::USE_REGEX, FixtureVars::new(&ns.name)).await?;

    let host = format!("regex-invalid.{}.local", ns.name);

    // The valid sibling path serves despite the invalid one being present.
    let resp = wait::wait_for_backend(&h.http, &host, "/ok/foo", "echo-a", Duration::from_secs(60))
        .await?;
    resp.assert_backend("echo-a");

    // The invalid path installed no route, so it 404s.
    wait::wait_for_route_status(
        &h.http,
        &host,
        "/bad/anything",
        404,
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

/// `use-regex` opt-in off (#265): without the annotation, an `ImplementationSpecific`
/// path stays a literal Prefix — regex metacharacters are not interpreted, so
/// `/lit/[0-9]+` does not match the request `/lit/42`.
#[tokio::test]
async fn ingress_without_use_regex_treats_implementation_specific_literally() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-regex-off").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::USE_REGEX, FixtureVars::new(&ns.name)).await?;

    let host = format!("regex-off.{}.local", ns.name);

    // Establish that the data plane has the fixture's routes live, then assert the
    // negative: the literal-prefix path `/lit/[0-9]+` does not match `/lit/42`.
    let match_host = format!("regex-match.{}.local", ns.name);
    wait::wait_for_backend(
        &h.http,
        &match_host,
        "/digits/1",
        "echo-a",
        Duration::from_secs(60),
    )
    .await?;
    wait::wait_for_route_status(&h.http, &host, "/lit/42", 404, Duration::from_secs(30)).await?;

    Ok(())
}

/// Verifies per-class annotation defaults resolved from `IngressClass.spec.parameters`
/// (#190): a `CoxswainIngressClassParameters` CR sets a default `rewrite-target`,
/// and an Ingress claiming that class inherits it while a second Ingress overrides
/// it per-key. The echo backend's reflected upstream path is the deterministic
/// proof of which value won — exercising the full resolve → merge → reflector →
/// RBAC path on live traffic. (Per-key precedence is also unit-covered in
/// `coxswain-reflector::ingress::reconcile`.)
#[tokio::test]
async fn ingress_class_parameters_default_annotation_applies_and_is_overridable()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-class-params").await?;

    // The IngressClass is cluster-scoped and uniquely named; the guard deletes it
    // on drop so the resource doesn't leak. The name matches the fixture's
    // `coxswain-clsdefault-${TESTNS}`.
    let ic_name = format!("coxswain-clsdefault-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&h.client, &ic_name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::CLASS_DEFAULT_REWRITE, FixtureVars::new(&ns.name)).await?;

    // Inherited: the Ingress sets no rewrite of its own, so the class default
    // (/from-class) must reach the upstream.
    let inherit_host = format!("clsdefault-inherit.{}.local", ns.name);
    let resp =
        wait::wait_for_route(&h.http, &inherit_host, "/api", Duration::from_secs(60)).await?;
    assert_eq!(
        resp.path.as_deref(),
        Some("/from-class"),
        "an Ingress with no own rewrite-target must inherit the class default"
    );

    // Overridden: the Ingress's own rewrite-target wins per-key.
    let override_host = format!("clsdefault-override.{}.local", ns.name);
    let resp =
        wait::wait_for_route(&h.http, &override_host, "/api", Duration::from_secs(60)).await?;
    assert_eq!(
        resp.path.as_deref(),
        Some("/from-ingress"),
        "a per-Ingress rewrite-target must override the class default"
    );

    Ok(())
}

/// Unhappy-path companion to the class-defaults test (#190): an IngressClass whose
/// `spec.parameters` points at a missing `CoxswainIngressClassParameters`. The
/// reference dangles, so coxswain WARNs and degrades gracefully — the Ingress is
/// never rejected, still routes to its backend, and no class default is applied,
/// so the upstream sees the original request path.
#[tokio::test]
async fn ingress_class_parameters_dangling_ref_degrades_gracefully() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-class-dangling").await?;

    let ic_name = format!("coxswain-clsdangling-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&h.client, &ic_name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::CLASS_DEFAULT_DANGLING, FixtureVars::new(&ns.name)).await?;

    let host = format!("dangling.{}.local", ns.name);
    // The route still serves despite the broken ref, and — because no class
    // default was applied — the upstream sees the original path, not a rewrite.
    let resp = wait::wait_for_route(&h.http, &host, "/api", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");
    assert_eq!(
        resp.path.as_deref(),
        Some("/api"),
        "a dangling parametersRef must not apply any class default — original path preserved"
    );

    Ok(())
}

#[tokio::test]
async fn gateway_path_match_routes_to_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-path").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);

    // Wait for the route to become live before asserting individual paths.
    let resp = wait::wait_for_route(&h.gateway_http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let resp = h.gateway_http.get(&host, "/b").await?;
    resp.assert_backend("echo-b");

    // Catch-all rule routes to echo-a.
    let resp = h.gateway_http.get(&host, "/").await?;
    resp.assert_backend("echo-a");

    Ok(())
}

#[tokio::test]
async fn host_pool_round_robins_across_backends() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-pool").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::HOST_POOL, FixtureVars::new(&ns.name)).await?;

    let host = format!("pool.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // Round-robin across echo-a and echo-b — collect enough responses to see both.
    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..20 {
        let resp = h.gateway_http.get(&host, "/").await?;
        let pod = resp.pod.as_deref().unwrap_or("");
        if pod.starts_with("echo-a-") {
            saw_a = true;
        }
        if pod.starts_with("echo-b-") {
            saw_b = true;
        }
        if saw_a && saw_b {
            break;
        }
    }
    assert!(saw_a, "never saw echo-a in round-robin pool");
    assert!(saw_b, "never saw echo-b in round-robin pool");

    Ok(())
}

#[tokio::test]
async fn gateway_wildcard_host_matches_multi_label_subdomains() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-wildcard").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::WILDCARD_HOST, FixtureVars::new(&ns.name)).await?;

    // Any subdomain of *.wildcard.TESTNS.local should reach echo-c.
    let host = format!("foo.wildcard.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-c");

    let host2 = format!("bar.wildcard.{}.local", ns.name);
    let resp2 = h.gateway_http.get(&host2, "/").await?;
    resp2.assert_backend("echo-c");

    // Gateway API spec: `*` matches any number of subdomain labels, so multi-label
    // subdomains must also reach echo-c.
    let multi = format!("a.b.foo.wildcard.{}.local", ns.name);
    let resp3 = h.gateway_http.get(&multi, "/").await?;
    resp3.assert_backend("echo-c");

    Ok(())
}

#[tokio::test]
async fn cross_namespace_grant_allows_backend_routing() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-xns-tenant").await?;

    // Deploy the backend + ReferenceGrant into the tenant namespace.
    fixtures::apply_fixture(
        gwa::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    // Deploy the Gateway + HTTPRoute into the primary namespace.
    fixtures::apply_fixture(
        gwa::CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let host = format!("cross-ns.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-d");

    Ok(())
}

#[tokio::test]
async fn cross_namespace_without_grant_blocks_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-xns-deny").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-xns-deny-tenant").await?;

    // Deploy tenant backend WITHOUT a ReferenceGrant.
    // Apply only the Deployment + Service from the tenant fixture
    // by stripping the ReferenceGrant via a second apply after deletion.
    fixtures::apply_fixture(
        gwa::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    // Delete the ReferenceGrant that was just applied.
    tokio::process::Command::new("kubectl")
        .args([
            "delete",
            "referencegrant",
            &format!("allow-httproute-from-{}", ns.name),
            "-n",
            &tenant.name,
            "--ignore-not-found",
        ])
        .status()
        .await?;

    fixtures::apply_fixture(
        gwa::CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let host = format!("cross-ns.{}.local", ns.name);

    // Without the grant the backend cannot be resolved so an error-sentinel
    // route is installed, returning 500. Poll until the route is live —
    // a fixed sleep raced HotReloader's restart cycle on slow runs.
    wait::wait_for_route_status(&h.gateway_http, &host, "/", 500, Duration::from_secs(60)).await?;

    Ok(())
}

#[tokio::test]
async fn header_match_routes_only_matching_requests() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::HEADER_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // Exact header match → echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/hdr", &[("X-Tenant", "a")])
        .await?;
    assert_eq!(status, 200, "expected 200 for exact header match");
    body.unwrap().assert_backend("echo-a");

    // Regex header match → echo-b
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/hdr", &[("X-Tenant", "beta")])
        .await?;
    assert_eq!(status, 200, "expected 200 for regex header match");
    body.unwrap().assert_backend("echo-b");

    // No matching header → no route
    let (status, _) = h
        .gateway_http
        .request(Method::GET, &host, "/hdr", &[])
        .await?;
    assert_eq!(
        status, 404,
        "expected 404 (no matching route) when header predicate not satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn method_match_routes_by_method() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-method").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::METHOD_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // GET → echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/method", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for GET");
    body.unwrap().assert_backend("echo-a");

    // POST → echo-b
    let (status, body) = h
        .gateway_http
        .request(Method::POST, &host, "/method", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for POST");
    body.unwrap().assert_backend("echo-b");

    Ok(())
}

#[tokio::test]
async fn query_param_match_routes_only_matching_requests() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-query").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::QUERY_PARAM_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // Exact query param match → echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/query?version=v1", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for exact query param match");
    body.unwrap().assert_backend("echo-a");

    // Regex query param match → echo-b
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/query?version=v2.5", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for regex query param match");
    body.unwrap().assert_backend("echo-b");

    // No matching query param → no route
    let (status, _) = h
        .gateway_http
        .request(Method::GET, &host, "/query", &[])
        .await?;
    assert_eq!(
        status, 404,
        "expected 404 (no matching route) when query predicate not satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn combined_match_applies_and_or_semantics() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-combined").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::COMBINED_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // AND semantics: GET + X-Env: prod → echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/combined", &[("X-Env", "prod")])
        .await?;
    assert_eq!(status, 200, "expected 200 for GET + X-Env: prod");
    body.unwrap().assert_backend("echo-a");

    // OR semantics: second match (POST + X-Env: staging) also routes to echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::POST, &host, "/combined", &[("X-Env", "staging")])
        .await?;
    assert_eq!(status, 200, "expected 200 for POST + X-Env: staging");
    body.unwrap().assert_backend("echo-a");

    // AND semantics failure: correct method, wrong header value → no match
    let (status, _) = h
        .gateway_http
        .request(Method::GET, &host, "/combined", &[("X-Env", "dev")])
        .await?;
    assert_eq!(
        status, 404,
        "expected 404 (no matching route) when AND predicates not fully satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn request_header_modifier_injects_request_header() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-req-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(
        &h.gateway_http,
        &host,
        "/filter/probe",
        Duration::from_secs(60),
    )
    .await?;

    // The echo backend reflects request headers in the response body JSON;
    // echo-basic returns headers as Title-Case keys with JSON array values.
    let resp = h.gateway_http.get(&host, "/filter/req-header").await?;
    let injected = resp
        .headers
        .get("X-Test-Set")
        .and_then(|v| v[0].as_str())
        .unwrap_or("");
    assert_eq!(
        injected, "injected",
        "RequestHeaderModifier: expected X-Test-Set=injected in echo body, got {injected:?}"
    );

    Ok(())
}

#[tokio::test]
async fn response_header_modifier_sets_response_header() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-resp-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(
        &h.gateway_http,
        &host,
        "/filter/probe",
        Duration::from_secs(60),
    )
    .await?;

    let (status, resp_headers, _) = h
        .gateway_http
        .get_full(&host, "/filter/resp-header")
        .await?;
    assert_eq!(status, 200, "ResponseHeaderModifier: expected 200");
    let hdr_val = resp_headers
        .get("x-test-response")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        hdr_val, "coxswain",
        "ResponseHeaderModifier: expected X-Test-Response=coxswain in response headers"
    );

    Ok(())
}

#[tokio::test]
async fn request_redirect_returns_302_to_target() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-redirect").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(
        &h.gateway_http,
        &host,
        "/filter/probe",
        Duration::from_secs(60),
    )
    .await?;

    // The default reqwest client follows redirects; disable that to observe the 302.
    let url = format!("http://{}{}", h.gateway_http.proxy_addr, "/filter/redirect");
    let redirect_resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?
        .get(&url)
        .header("Host", &host)
        .send()
        .await?;
    assert_eq!(
        redirect_resp.status().as_u16(),
        302,
        "RequestRedirect: expected 302"
    );
    let location = redirect_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.ends_with("/filter/redirected"),
        "RequestRedirect: expected Location ending in /filter/redirected, got {location:?}"
    );

    Ok(())
}

#[tokio::test]
async fn url_rewrite_replaces_request_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-rewrite").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(
        &h.gateway_http,
        &host,
        "/filter/probe",
        Duration::from_secs(60),
    )
    .await?;

    // The echo backend returns the path it received; expect the rewritten path.
    let resp = h.gateway_http.get(&host, "/filter/old/resource").await?;
    let echo_path = resp.path.as_deref().unwrap_or("");
    assert_eq!(
        echo_path, "/filter/new/resource",
        "URLRewrite: expected rewritten path /filter/new/resource, got {echo_path:?}"
    );

    Ok(())
}

#[tokio::test]
async fn timeouts_request_returns_504() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-timeouts-req").await?;

    fixtures::apply_fixture(backends::SLOW_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["slow-echo"]).await?;
    fixtures::apply_fixture(gwa::TIMEOUTS, FixtureVars::new(&ns.name)).await?;

    let host = format!("timeout.{}.local", ns.name);

    // Wait until the route is programmed. /request-timeout always returns 504 so we
    // can't use it as a readiness probe; use /backend-timeout (also 504) instead.
    wait::wait_for_route_status(
        &h.gateway_http,
        &host,
        "/backend-timeout",
        504,
        Duration::from_secs(60),
    )
    .await?;

    let status = h.gateway_http.get_status(&host, "/request-timeout").await?;
    assert_eq!(
        status, 504,
        "expected 504 from request timeout, got {status}"
    );

    Ok(())
}

#[tokio::test]
async fn timeouts_backend_request_returns_504() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-timeouts-be").await?;

    fixtures::apply_fixture(backends::SLOW_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["slow-echo"]).await?;
    fixtures::apply_fixture(gwa::TIMEOUTS, FixtureVars::new(&ns.name)).await?;

    let host = format!("timeout.{}.local", ns.name);

    // Wait until the route is registered. Both rules time out so we cannot use
    // wait_for_route; instead we poll until the 504 appears.
    wait::wait_for_route_status(
        &h.gateway_http,
        &host,
        "/backend-timeout",
        504,
        Duration::from_secs(60),
    )
    .await?;

    let status = h.gateway_http.get_status(&host, "/backend-timeout").await?;
    assert_eq!(
        status, 504,
        "expected 504 from backend request timeout, got {status}"
    );

    Ok(())
}

#[tokio::test]
async fn weighted_split_distributes_by_weight() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-weighted").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::WEIGHTED_SPLIT, FixtureVars::new(&ns.name)).await?;

    let host = format!("weighted.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // /zero: echo-a has weight 0 → all traffic must go to echo-b.
    let counts = http::count_backends(&h.gateway_http, &host, "/zero", 40).await?;
    assert_eq!(
        counts.get("echo-a").copied().unwrap_or(0),
        0,
        "/zero: weight-0 backend echo-a received traffic: {counts:?}"
    );
    assert!(
        counts.get("echo-b").copied().unwrap_or(0) > 0,
        "/zero: echo-b should receive all traffic: {counts:?}"
    );

    // /skewed: echo-a weight 4, echo-b weight 1 → ~80% to echo-a.
    // Send 200 requests; allow ±10pp tolerance to stay robust under scheduling noise.
    let n = 200usize;
    let counts = http::count_backends(&h.gateway_http, &host, "/skewed", n).await?;
    let a = counts.get("echo-a").copied().unwrap_or(0);
    let ratio = a as f64 / n as f64;
    assert!(
        (0.70..=0.90).contains(&ratio),
        "/skewed: echo-a ratio {ratio:.2} out of expected 0.70–0.90 (counts: {counts:?})"
    );

    Ok(())
}

#[tokio::test]
async fn endpoint_serving_false_is_excluded() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-serving").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Inject an orphan EndpointSlice for echo-a whose single endpoint has
    // serving:false/ready:true — the race window during rolling deploys.
    // The unroutable RFC 5737 TEST-NET-1 address (192.0.2.1) is used so that
    // any accidental selection causes an immediate connection error rather than
    // silently hanging. The non-standard managed-by label prevents the cluster's
    // endpointslice-controller from reconciling this slice away.
    let slice_api: Api<EndpointSlice> = Api::namespaced(h.client.clone(), &ns.name);
    let orphan = EndpointSlice {
        metadata: ObjectMeta {
            name: Some("echo-a-drain-test".to_string()),
            namespace: Some(ns.name.clone()),
            labels: Some({
                let mut m = BTreeMap::new();
                m.insert(
                    "kubernetes.io/service-name".to_string(),
                    "echo-a".to_string(),
                );
                m.insert(
                    "endpointslice.kubernetes.io/managed-by".to_string(),
                    "e2e-test".to_string(),
                );
                m
            }),
            ..Default::default()
        },
        address_type: "IPv4".to_string(),
        endpoints: vec![Endpoint {
            addresses: vec!["192.0.2.1".to_string()],
            conditions: Some(EndpointConditions {
                serving: Some(false),
                ready: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }],
        ports: None,
    };
    slice_api.create(&PostParams::default(), &orphan).await?;

    fixtures::apply_fixture(gwa::SERVING_DRAIN, FixtureVars::new(&ns.name)).await?;
    let host = format!("serving.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;

    // All 30 requests must reach echo-a. If the serving:false endpoint were
    // selected, ~50% of requests would fail with a connection error to 192.0.2.1,
    // causing count_backends to return Err and the test to fail.
    let counts = http::count_backends(&h.gateway_http, &host, "/", 30).await?;
    assert_eq!(
        counts.get("echo-a").copied().unwrap_or(0),
        30,
        "not all requests hit echo-a: {counts:?}"
    );

    Ok(())
}

// Verifies SupportHTTPRouteParentRefPort (#82, #98):
// A route pinned to a listener port attaches only to that port; a route with no
// port filter attaches to all listeners; routing-table isolation is verified via
// the admin /api/v1/routes endpoint.
#[tokio::test]
async fn parent_ref_port_match_binds_only_pinned_listener() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-port").await?;

    // Any unused high port that coxswain is definitely NOT listening on.
    let wrong_port = "19999";

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        gwa::PARENT_REF_PORT,
        FixtureVars::new(&ns.name).with("WRONG_PORT", wrong_port),
    )
    .await?;

    // route-pinned (parentRef.port=HTTP_PORT) must attach only to the HTTP listener.
    let pinned_host = format!("pinned.{}.local", ns.name);
    let resp = wait::wait_for_route(
        &h.gateway_http,
        &pinned_host,
        "/probe",
        Duration::from_secs(60),
    )
    .await?;
    resp.assert_backend("echo-a");

    // route-unpinned (no parentRef.port) must attach to BOTH listeners.
    let both_host = format!("both.{}.local", ns.name);
    let resp = wait::wait_for_route(
        &h.gateway_http,
        &both_host,
        "/probe",
        Duration::from_secs(30),
    )
    .await?;
    resp.assert_backend("echo-a");

    // route-wrong-port (parentRef.port=WRONG_PORT) must NOT be routable on HTTP_PORT:
    // the route is scoped to the alt listener, which coxswain doesn't bind.
    let wrong_host = format!("wrong.{}.local", ns.name);
    let status = h.gateway_http.get_status(&wrong_host, "/").await?;
    assert_eq!(
        status, 404,
        "route-wrong-port must not be routable on HTTP_PORT (no attached route → 404)"
    );

    // Verify routing-table isolation via admin /api/v1/routes.
    // Once pinned.* and both.* are live the table is fully settled.
    //
    // Since the IngressProxy/GatewayProxy split (#201), `/api/v1/routes` reports
    // the two tables under separate keys; this test only inspects Gateway-API routes.
    let routes: serde_json::Value = reqwest::get(h.admin_url("/api/v1/routes"))
        .await?
        .json()
        .await?;
    let hosts = routes["gateway"]["hosts"]
        .as_array()
        .expect("gateway.hosts array");

    let http_port = u64::from(h.controller.gateway_http_addr.port());
    let wrong_port_u64: u64 = wrong_port.parse().unwrap();

    let ports_for = |host: &str| -> std::collections::BTreeSet<u64> {
        hosts
            .iter()
            .filter(|e| e["host"].as_str() == Some(host))
            .filter_map(|e| e["port"].as_u64())
            .collect()
    };

    // pinned.* appears under http_port only.
    assert_eq!(
        ports_for(&pinned_host),
        [http_port].into(),
        "pinned.* must appear only under HTTP_PORT in the routing table"
    );
    // wrong.* appears under wrong_port only (installed by controller; proxy doesn't bind that port).
    assert_eq!(
        ports_for(&wrong_host),
        [wrong_port_u64].into(),
        "wrong.* must appear only under WRONG_PORT in the routing table"
    );
    // both.* appears under both ports (no port filter → all listeners).
    let both_ports = ports_for(&both_host);
    assert!(
        both_ports.contains(&http_port) && both_ports.contains(&wrong_port_u64),
        "both.* must appear under both HTTP_PORT and WRONG_PORT, got {both_ports:?}"
    );

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/request-header-{set,add,remove}` annotations
/// are applied on the upstream request before the backend receives it:
/// - The SET header is overwritten to the annotation value.
/// - The ADD header is appended.
/// - The REMOVE header sent by the client is stripped before forwarding.
#[tokio::test]
async fn ingress_request_header_modifier_sets_adds_and_removes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-req-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_REQUEST_HEADERS,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("req-headers.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Send a request with X-Remove-Me present; the proxy must strip it before forwarding.
    let (_, body) = h
        .http
        .request(
            Method::GET,
            &host,
            "/",
            &[("X-Remove-Me", "should-be-stripped")],
        )
        .await?;
    let resp = body.expect("expected 200 echo body from echo-a");
    resp.assert_backend("echo-a");

    // SET: echo body must reflect the annotation value for X-Custom-Set.
    let set_val = resp
        .headers
        .get("X-Custom-Set")
        .and_then(|v| v[0].as_str())
        .unwrap_or("");
    assert_eq!(
        set_val, "coxswain",
        "request-header-set: expected X-Custom-Set=coxswain, got {set_val:?}"
    );

    // ADD: echo body must contain X-Custom-Add (added by the proxy).
    let add_val = resp
        .headers
        .get("X-Custom-Add")
        .and_then(|v| v[0].as_str())
        .unwrap_or("");
    assert_eq!(
        add_val, "appended",
        "request-header-add: expected X-Custom-Add=appended, got {add_val:?}"
    );

    // REMOVE: X-Remove-Me must not be present in the upstream request.
    assert!(
        !resp.headers.contains_key("X-Remove-Me"),
        "request-header-remove: X-Remove-Me must be absent from upstream request, \
         but was still present in echo body"
    );

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/response-header-{set,add,remove}` annotations
/// are applied on the downstream response before the client receives it:
/// - The SET header is present in the response with the annotation value.
/// - The ADD header is appended to the response.
/// - A header that was SET and then also REMOVEd is absent from the final response.
#[tokio::test]
async fn ingress_response_header_modifier_sets_adds_and_removes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-resp-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_RESPONSE_HEADERS,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("resp-headers.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, _) = h.http.get_full(&host, "/").await?;
    assert_eq!(status, 200, "response-header modifier: expected 200");

    // SET: X-Response-Tag must be present with the annotation value.
    let tag_val = resp_headers
        .get("x-response-tag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        tag_val, "coxswain",
        "response-header-set: expected X-Response-Tag=coxswain, got {tag_val:?}"
    );

    // ADD: X-Response-Extra must be present (added by the proxy).
    let extra_val = resp_headers
        .get("x-response-extra")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        extra_val, "added",
        "response-header-add: expected X-Response-Extra=added, got {extra_val:?}"
    );

    // REMOVE: X-Will-Be-Gone was SET then REMOVED in the same modifier; apply order is
    // set → add → remove, so it must be absent from the final response.
    assert!(
        resp_headers.get("x-will-be-gone").is_none(),
        "response-header-remove: X-Will-Be-Gone must be absent (set then removed), \
         but was present in the response"
    );

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/redirect-{scheme,hostname,port,path,status-code}`
/// annotations cause the proxy to issue a redirect with the configured status and Location.
/// No backend is hit — the redirect fires at the proxy layer.
#[tokio::test]
async fn ingress_request_redirect_returns_configured_status_and_location() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-redirect").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_REDIRECT, FixtureVars::new(&ns.name)).await?;

    let host = format!("redirect.{}.local", ns.name);
    let redirect_host = format!("new.{}.local", ns.name);

    // Wait until the 301 redirect is live (the route returns 301, not 2xx).
    let location =
        wait::wait_for_route_redirect(h.http.proxy_addr, &host, "/", 301, Duration::from_secs(60))
            .await?;

    // Location must point to https://new.TESTNS.local:8443/v2 (all five redirect-* fields).
    assert_eq!(
        location,
        format!("https://{redirect_host}:8443/v2"),
        "redirect-* annotations: expected Location https://{redirect_host}:8443/v2, \
         got {location:?}"
    );

    Ok(())
}

/// Verifies that an invalid `request-header-set` annotation (space in header name) is
/// silently dropped: the route still serves 200 from the expected backend, and the
/// independent `response-header-set` sibling modifier is still applied.
#[tokio::test]
async fn ingress_invalid_filter_annotation_is_skipped_and_route_still_serves() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-bad-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_INVALID_HEADER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("invalid-header.{}.local", ns.name);

    // Route must still serve despite the bad annotation; wait for it to become live.
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // The valid response-header-set sibling must still be applied.
    let (status, resp_headers, _) = h.http.get_full(&host, "/").await?;
    assert_eq!(
        status, 200,
        "bad annotation: expected route to still serve 200"
    );
    let survived = resp_headers
        .get("x-survived")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        survived, "yes",
        "bad annotation: expected valid sibling X-Survived=yes in response, got {survived:?}"
    );

    Ok(())
}
