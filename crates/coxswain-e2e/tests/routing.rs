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
//! HTTPRoute filters, request/backend timeouts, rewrite-target annotation, and
//! downstream HTTP/2 (h2c prior-knowledge and h1 backward compatibility).
//! TLS lives in `tls.rs`; traffic-policy knobs in `traffic_policy.rs`.

use anyhow::Context as _;
use coxswain_e2e::{
    ControllerOptions, ControllerProcess, FixtureVars, Harness, HttpClient, IngressClassGuard,
    NamespaceGuard, bootstrap,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::{http, wait},
};
use gateway_api_types::apis::standard::httproutes::HttpRoute;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use kube::api::{DeleteParams, PostParams};
use reqwest::Method;
use reqwest::Version;
use std::collections::BTreeMap;
use std::time::Duration;

mod common;
use common::grpc_echo as grpcecho;

/// Tests both the per-Ingress spec.defaultBackend and the controller-wide
/// --ingress-default-backend flag. Backends are deployed before the controller
/// starts so that echo-c is already ready on the first routing-table rebuild.
#[tokio::test]
async fn default_backend_serves_unmatched_requests() -> anyhow::Result<()> {
    // Bootstrap cluster connection and create the namespace before starting the
    // controller, so the default-backend endpoints are ready on first sync.
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "rt-ing-default").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-default-only").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-path").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-delete-stops").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-delete-stops").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    // Baseline: the route serves echo-a while the HTTPRoute exists.
    wait::wait_for_backend(&gw, &host, "/a", "echo-a", Duration::from_secs(60)).await?;

    // Delete the HTTPRoute object — leave the Gateway in place.
    let routes: Api<HttpRoute> = Api::namespaced(h.client.clone(), &ns.name);
    routes
        .delete("echo-route", &DeleteParams::default())
        .await?;

    // With no attached route the Gateway listener 404s for the host.
    wait::wait_for_route_status(&gw, &host, "/a", 404, Duration::from_secs(30)).await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-wildcard").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-named-port").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-default-class").await?;

    // Create a uniquely-named default IngressClass scoped to this test run.
    // The guard deletes it on drop so the cluster-scoped resource doesn't leak.
    let ic_name = format!("coxswain-default-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&ic_name);

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-rewrite").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-regex-match").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-regex-mixed").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-regex-rewrite").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-regex-invalid").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-regex-off").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-class-params").await?;

    // The IngressClass is cluster-scoped and uniquely named; the guard deletes it
    // on drop so the resource doesn't leak. The name matches the fixture's
    // `coxswain-clsdefault-${TESTNS}`.
    let ic_name = format!("coxswain-clsdefault-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&ic_name);

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-class-dangling").await?;

    let ic_name = format!("coxswain-clsdangling-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&ic_name);

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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-path").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    // Wait for the route to become live before asserting individual paths.
    let resp = wait::wait_for_route(&gw, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let resp = gw.get(&host, "/b").await?;
    resp.assert_backend("echo-b");

    // Catch-all rule routes to echo-a.
    let resp = gw.get(&host, "/").await?;
    resp.assert_backend("echo-a");

    Ok(())
}

#[tokio::test]
async fn host_pool_round_robins_across_backends() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-pool").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::HOST_POOL, FixtureVars::new(&ns.name)).await?;

    let host = format!("pool.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // Round-robin across echo-a and echo-b — collect enough responses to see both.
    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..20 {
        let resp = gw.get(&host, "/").await?;
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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-wildcard").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::WILDCARD_HOST, FixtureVars::new(&ns.name)).await?;

    // Any subdomain of *.wildcard.TESTNS.local should reach echo-c.
    let host = format!("foo.wildcard.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-c");

    let host2 = format!("bar.wildcard.{}.local", ns.name);
    let resp2 = gw.get(&host2, "/").await?;
    resp2.assert_backend("echo-c");

    // Gateway API spec: `*` matches any number of subdomain labels, so multi-label
    // subdomains must also reach echo-c.
    let multi = format!("a.b.foo.wildcard.{}.local", ns.name);
    let resp3 = gw.get(&multi, "/").await?;
    resp3.assert_backend("echo-c");

    Ok(())
}

#[tokio::test]
async fn cross_namespace_grant_allows_backend_routing() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "rt-gw-xns-tenant").await?;

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
    let gw = h.gateway_http(&ns.name).await?;
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-d");

    Ok(())
}

#[tokio::test]
async fn cross_namespace_without_grant_blocks_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-xns-deny").await?;
    let tenant = NamespaceGuard::create(&h.client, "rt-gw-xns-deny-tenant").await?;

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
    let gw = h.gateway_http(&ns.name).await?;

    // Without the grant the backend cannot be resolved so an error-sentinel
    // route is installed, returning 500. Poll until the route is live —
    // a fixed sleep raced HotReloader's restart cycle on slow runs.
    wait::wait_for_route_status(&gw, &host, "/", 500, Duration::from_secs(60)).await?;

    Ok(())
}

#[tokio::test]
async fn header_match_routes_only_matching_requests() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::HEADER_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // Exact header match → echo-a
    let (status, body) = gw
        .request(Method::GET, &host, "/hdr", &[("X-Tenant", "a")])
        .await?;
    assert_eq!(status, 200, "expected 200 for exact header match");
    body.unwrap().assert_backend("echo-a");

    // Regex header match → echo-b
    let (status, body) = gw
        .request(Method::GET, &host, "/hdr", &[("X-Tenant", "beta")])
        .await?;
    assert_eq!(status, 200, "expected 200 for regex header match");
    body.unwrap().assert_backend("echo-b");

    // No matching header → no route
    let (status, _) = gw.request(Method::GET, &host, "/hdr", &[]).await?;
    assert_eq!(
        status, 404,
        "expected 404 (no matching route) when header predicate not satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn method_match_routes_by_method() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-method").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::METHOD_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // GET → echo-a
    let (status, body) = gw.request(Method::GET, &host, "/method", &[]).await?;
    assert_eq!(status, 200, "expected 200 for GET");
    body.unwrap().assert_backend("echo-a");

    // POST → echo-b
    let (status, body) = gw.request(Method::POST, &host, "/method", &[]).await?;
    assert_eq!(status, 200, "expected 200 for POST");
    body.unwrap().assert_backend("echo-b");

    Ok(())
}

#[tokio::test]
async fn query_param_match_routes_only_matching_requests() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-query").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::QUERY_PARAM_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // Exact query param match → echo-a
    let (status, body) = gw
        .request(Method::GET, &host, "/query?version=v1", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for exact query param match");
    body.unwrap().assert_backend("echo-a");

    // Regex query param match → echo-b
    let (status, body) = gw
        .request(Method::GET, &host, "/query?version=v2.5", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for regex query param match");
    body.unwrap().assert_backend("echo-b");

    // No matching query param → no route
    let (status, _) = gw.request(Method::GET, &host, "/query", &[]).await?;
    assert_eq!(
        status, 404,
        "expected 404 (no matching route) when query predicate not satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn combined_match_applies_and_or_semantics() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-combined").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::COMBINED_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // AND semantics: GET + X-Env: prod → echo-a
    let (status, body) = gw
        .request(Method::GET, &host, "/combined", &[("X-Env", "prod")])
        .await?;
    assert_eq!(status, 200, "expected 200 for GET + X-Env: prod");
    body.unwrap().assert_backend("echo-a");

    // OR semantics: second match (POST + X-Env: staging) also routes to echo-a
    let (status, body) = gw
        .request(Method::POST, &host, "/combined", &[("X-Env", "staging")])
        .await?;
    assert_eq!(status, 200, "expected 200 for POST + X-Env: staging");
    body.unwrap().assert_backend("echo-a");

    // AND semantics failure: correct method, wrong header value → no match
    let (status, _) = gw
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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-req-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/filter/probe", Duration::from_secs(60)).await?;

    // The echo backend reflects request headers in the response body JSON;
    // echo-basic returns headers as Title-Case keys with JSON array values.
    let resp = gw.get(&host, "/filter/req-header").await?;
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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-resp-hdr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/filter/probe", Duration::from_secs(60)).await?;

    let (status, resp_headers, _) = gw.get_full(&host, "/filter/resp-header").await?;
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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-redirect").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/filter/probe", Duration::from_secs(60)).await?;

    // The default reqwest client follows redirects; disable that to observe the 302.
    let url = format!("http://{}{}", gw.proxy_addr, "/filter/redirect");
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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-rewrite").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/filter/probe", Duration::from_secs(60)).await?;

    // The echo backend returns the path it received; expect the rewritten path.
    let resp = gw.get(&host, "/filter/old/resource").await?;
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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-timeouts-req").await?;

    fixtures::apply_fixture(backends::SLOW_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["slow-echo"]).await?;
    fixtures::apply_fixture(gwa::TIMEOUTS, FixtureVars::new(&ns.name)).await?;

    let host = format!("timeout.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    // Wait until the route is programmed. /request-timeout always returns 504 so we
    // can't use it as a readiness probe; use /backend-timeout (also 504) instead.
    wait::wait_for_route_status(&gw, &host, "/backend-timeout", 504, Duration::from_secs(60))
        .await?;

    let status = gw.get_status(&host, "/request-timeout").await?;
    assert_eq!(
        status, 504,
        "expected 504 from request timeout, got {status}"
    );

    Ok(())
}

#[tokio::test]
async fn timeouts_backend_request_returns_504() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-timeouts-be").await?;

    fixtures::apply_fixture(backends::SLOW_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["slow-echo"]).await?;
    fixtures::apply_fixture(gwa::TIMEOUTS, FixtureVars::new(&ns.name)).await?;

    let host = format!("timeout.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    // Wait until the route is registered. Both rules time out so we cannot use
    // wait_for_route; instead we poll until the 504 appears.
    wait::wait_for_route_status(&gw, &host, "/backend-timeout", 504, Duration::from_secs(60))
        .await?;

    let status = gw.get_status(&host, "/backend-timeout").await?;
    assert_eq!(
        status, 504,
        "expected 504 from backend request timeout, got {status}"
    );

    Ok(())
}

#[tokio::test]
async fn weighted_split_distributes_by_weight() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-weighted").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::WEIGHTED_SPLIT, FixtureVars::new(&ns.name)).await?;

    let host = format!("weighted.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // /zero: echo-a has weight 0 → all traffic must go to echo-b.
    let counts = http::count_backends(&gw, &host, "/zero", 40).await?;
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
    let counts = http::count_backends(&gw, &host, "/skewed", n).await?;
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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-serving").await?;

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
        endpoints: Some(vec![Endpoint {
            addresses: vec!["192.0.2.1".to_string()],
            conditions: Some(EndpointConditions {
                serving: Some(false),
                ready: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        ports: None,
    };
    slice_api.create(&PostParams::default(), &orphan).await?;

    fixtures::apply_fixture(gwa::SERVING_DRAIN, FixtureVars::new(&ns.name)).await?;
    let host = format!("serving.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;

    // All 30 requests must reach echo-a. If the serving:false endpoint were
    // selected, ~50% of requests would fail with a connection error to 192.0.2.1,
    // causing count_backends to return Err and the test to fail.
    let counts = http::count_backends(&gw, &host, "/", 30).await?;
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
    let ns = NamespaceGuard::create(&h.client, "rt-gw-port").await?;

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
    let gw = h.gateway_http(&ns.name).await?;
    let resp = wait::wait_for_route(&gw, &pinned_host, "/probe", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // route-unpinned (no parentRef.port) must attach to BOTH listeners.
    let both_host = format!("both.{}.local", ns.name);
    let resp = wait::wait_for_route(&gw, &both_host, "/probe", Duration::from_secs(30)).await?;
    resp.assert_backend("echo-a");

    // route-wrong-port (parentRef.port=WRONG_PORT) must NOT be routable on HTTP_PORT:
    // the route is scoped to the alt listener, which coxswain doesn't bind.
    let wrong_host = format!("wrong.{}.local", ns.name);
    let status = gw.get_status(&wrong_host, "/").await?;
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

    let ports_for = |host: &str| -> std::collections::BTreeSet<u64> {
        hosts
            .iter()
            .filter(|e| e["host"].as_str() == Some(host))
            .filter_map(|e| e["port"].as_u64())
            .collect()
    };

    // The routing table is keyed by the per-Gateway internal target port (#472),
    // not the advertised listener port — each of the two listeners (HTTP_PORT and
    // WRONG_PORT) maps to a distinct internal port. Assert the parentRef.port
    // isolation PROPERTY structurally rather than by literal port number:
    //   - a pinned route attaches to exactly one listener,
    //   - the two pinned routes attach to *different* listeners,
    //   - the unpinned route spans both.
    let pinned_ports = ports_for(&pinned_host);
    let wrong_ports = ports_for(&wrong_host);
    let both_ports = ports_for(&both_host);

    assert_eq!(
        pinned_ports.len(),
        1,
        "pinned.* must attach to exactly one listener, got {pinned_ports:?}"
    );
    assert_eq!(
        wrong_ports.len(),
        1,
        "wrong.* must attach to exactly one listener, got {wrong_ports:?}"
    );
    assert_ne!(
        pinned_ports, wrong_ports,
        "pinned.* and wrong.* are pinned to different listeners, so must occupy \
         distinct internal ports (got pinned={pinned_ports:?}, wrong={wrong_ports:?})"
    );
    assert_eq!(
        both_ports,
        &pinned_ports | &wrong_ports,
        "both.* (no parentRef.port) must span both listeners' internal ports; \
         got both={both_ports:?}, pinned={pinned_ports:?}, wrong={wrong_ports:?}"
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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-req-hdr").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-resp-hdr").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-redirect").await?;

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
    let ns = NamespaceGuard::create(&h.client, "rt-ing-bad-hdr").await?;

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

/// Verifies `urlRewrite.hostname` correctly rewrites the `Host` header sent to the upstream backend.
#[tokio::test]
async fn url_rewrite_replaces_request_host() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-host-rewrite").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::HOST_REWRITE, FixtureVars::new(&ns.name)).await?;

    let host = format!("rewrite.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    let resp = wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let resp = gw.get(&host, "/test").await?;
    resp.assert_backend("echo-a");

    let echo_host = resp.host.as_deref().expect("missing or invalid host echo");

    let expected_host = format!("new-host.{}.local", ns.name);
    assert_eq!(
        echo_host, expected_host,
        "URLRewrite: expected rewritten host {expected_host:?}, got {echo_host:?}"
    );

    Ok(())
}

/// Verifies `RequestRedirect` correctly emits 303, 307, and 308 status codes.
#[tokio::test]
async fn request_redirect_returns_various_status_codes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-redirect-status").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::REDIRECT_STATUS_CODES, FixtureVars::new(&ns.name)).await?;

    let host = format!("redirect.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    let _ = wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // HTTP 303
    let req = reqwest::Request::new(
        Method::GET,
        format!("http://{}:{}/303", gw.proxy_addr.ip(), gw.proxy_addr.port())
            .parse()
            .unwrap(),
    );
    let mut req = req;
    req.headers_mut().insert("Host", host.parse().unwrap());

    // Create a client that doesn't follow redirects.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let resp = client.execute(req).await?;
    assert_eq!(resp.status().as_u16(), 303);

    // HTTP 307
    let req = reqwest::Request::new(
        Method::GET,
        format!("http://{}:{}/307", gw.proxy_addr.ip(), gw.proxy_addr.port())
            .parse()
            .unwrap(),
    );
    let mut req = req;
    req.headers_mut().insert("Host", host.parse().unwrap());
    let resp = client.execute(req).await?;
    assert_eq!(resp.status().as_u16(), 307);

    // HTTP 308
    let req = reqwest::Request::new(
        Method::GET,
        format!("http://{}:{}/308", gw.proxy_addr.ip(), gw.proxy_addr.port())
            .parse()
            .unwrap(),
    );
    let mut req = req;
    req.headers_mut().insert("Host", host.parse().unwrap());
    let resp = client.execute(req).await?;
    assert_eq!(resp.status().as_u16(), 308);

    Ok(())
}

// ── path-normalize (#280) ─────────────────────────────────────────────────────

/// `path-normalize` default `base`: a `%2E%2E`-encoded dot-dot segment is
/// decoded (unreserved-char decode step) and then removed by dot-segment
/// removal, so a request for `/api/%2E%2E/v1` routes to the `/v1` prefix and
/// the upstream sees `/v1`.
///
/// Uses a percent-encoded path to bypass client-side URL normalization —
/// `reqwest` resolves literal `..` segments before sending, but preserves
/// `%2E%2E` as-is. This lets the proxy be the sole normalizer.
#[tokio::test]
async fn encoded_dot_segment_resolved_at_base_by_default() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "pn-base-happy").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_PATH_NORMALIZE_DEFAULT,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("pn-default.{}.local", ns.name);
    // Prime the route (waits until /v1 is reachable).
    wait::wait_for_route(&h.http, &host, "/v1", Duration::from_secs(60)).await?;

    // Now request /api/%2E%2E/v1 — the proxy must normalise to /v1 and forward it.
    let resp = h.http.get(&host, "/api/%2E%2E/v1").await?;
    assert_eq!(
        resp.path.as_deref(),
        Some("/v1"),
        "upstream must see the dot-segment-resolved path /v1, not the original /api/%2E%2E/v1"
    );

    Ok(())
}

/// `path-normalize` default `base`: the encoded slash `%2F` is NOT decoded at
/// the `base` level (only `decode-and-merge-slashes` decodes it). A request
/// for `/api%2Fv1` therefore does not match the `/api/v1` prefix route and the
/// proxy returns 404 — proving the security guard against path-traversal via
/// encoded slashes is active by default.
#[tokio::test]
async fn encoded_slash_not_decoded_at_base() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "pn-enc-slash").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_PATH_NORMALIZE_DEFAULT,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("pn-default.{}.local", ns.name);
    // Prime with a clean path to ensure the route table is live.
    wait::wait_for_route(&h.http, &host, "/api/v1", Duration::from_secs(60)).await?;

    // /api%2Fv1 must NOT match /api/v1 (no slash between segments at the routing layer).
    let status = h.http.get_status(&host, "/api%2Fv1").await?;
    assert_eq!(
        status, 404,
        "encoded %2F must not be decoded at base level — /api%2Fv1 must not match /api/v1"
    );

    Ok(())
}

/// `path-normalize: merge-slashes` collapses consecutive slashes before
/// routing, so `/api//v1` matches the `/api/v1` prefix route and the upstream
/// sees the normalised `/api/v1`.
#[tokio::test]
async fn double_slash_collapsed_when_merge_slashes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "pn-merge-happy").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_PATH_NORMALIZE_MERGE_SLASHES,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("pn-merge.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/api/v1", Duration::from_secs(60)).await?;

    // /api//v1 → collapsed to /api/v1 → matches → upstream sees /api/v1.
    let resp = h.http.get(&host, "/api//v1").await?;
    assert_eq!(
        resp.path.as_deref(),
        Some("/api/v1"),
        "upstream must see the slash-merged path /api/v1, not the original /api//v1"
    );

    Ok(())
}

/// Default `base` normalization does NOT merge consecutive slashes.  A request
/// for `/api//v1` does not match the `/api/v1` prefix route and returns 404 —
/// proving that slash merging is opt-in via `merge-slashes`.
#[tokio::test]
async fn double_slash_not_collapsed_at_base() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "pn-merge-sad").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_PATH_NORMALIZE_DEFAULT,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("pn-default.{}.local", ns.name);
    // Prime with the exact clean path — proves the routing table is live.
    wait::wait_for_route(&h.http, &host, "/api/v1", Duration::from_secs(60)).await?;

    // /api//v1 should NOT match /api/v1 at base (no slash merging).
    let status = h.http.get_status(&host, "/api//v1").await?;
    assert_eq!(
        status, 404,
        "consecutive slashes must not be merged at base level — /api//v1 must not match /api/v1"
    );

    Ok(())
}

/// `path-normalize: none` is dropped in #483: it no longer disables
/// normalization but falls back to the secure `base` floor.  Send `/v1/%7E`
/// (tilde percent-encoded); under `base` the proxy decodes `%7E` → `~` before
/// forwarding.  Asserting `resp.path == "/v1/~"` proves end-to-end that the
/// insecure passthrough is gone and `base` normalization is applied instead —
/// had `none` still disabled normalization, the upstream would see `/v1/%7E`.
#[tokio::test]
async fn path_normalize_none_falls_back_to_base() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "pn-none-fallback").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_PATH_NORMALIZE_NONE_FALLS_BACK,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("pn-none.{}.local", ns.name);
    // Prime the route table with the clean path.
    wait::wait_for_route(&h.http, &host, "/v1", Duration::from_secs(60)).await?;

    // /v1/%7E matches the /v1 prefix (rest = %7E); `none` falls back to `base`,
    // which decodes the unreserved %7E → ~ before forwarding upstream.
    let resp = h.http.get(&host, "/v1/%7E").await?;
    assert_eq!(
        resp.path.as_deref(),
        Some("/v1/~"),
        "path-normalize: none must fall back to base — %7E is decoded to ~, \
         not forwarded verbatim"
    );

    Ok(())
}

/// Gateway API `HTTPRoute`s default to `base` normalization (no per-route
/// annotation; the default is infrastructure-level, mirroring Istio).  A
/// request for `/api/%2E%2E/v1` reaches the `/v1` prefix route and the
/// upstream sees the normalised `/v1`.
#[tokio::test]
async fn gateway_route_encoded_dot_segment_resolved_by_default() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "pn-gw-base").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_NORMALIZE_DEFAULT, FixtureVars::new(&ns.name)).await?;

    let host = format!("pn-gw.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    // Wait for the probe path to confirm the Gateway + HTTPRoute are live.
    wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // Send /api/%2E%2E/v1 — proxy must normalise and route to /v1.
    let resp = gw.get(&host, "/api/%2E%2E/v1").await?;
    assert_eq!(
        resp.path.as_deref(),
        Some("/v1"),
        "Gateway HTTPRoute: upstream must see /v1 after dot-segment removal from /api/%2E%2E/v1"
    );

    Ok(())
}

/// Verifies downstream HTTP/2 cleartext (h2c, prior-knowledge) support (#32).
///
/// A client that sends the h2c connection preface on a plain-TCP listener must
/// have its request routed to the backend and receive an HTTP/2 response.  The
/// detection is non-destructive: HTTP/1.1 clients on the same listener are
/// unaffected (verified by [`h1_client_unaffected_when_h2c_active`]).
#[tokio::test]
async fn h2c_prior_knowledge_request_reaches_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-h2c-dk").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    // Wait for the route to be live before issuing the h2c request.
    wait::wait_for_route(&gw, &host, "/probe", Duration::from_secs(60)).await?;

    // Build a client that sends h2c prior-knowledge (PRI * HTTP/2.0... preface).
    let gw_addr = gw.proxy_addr;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(5))
        .resolve(&host, gw_addr)
        .build()?;
    let url = format!("http://{}:{}/a", host, gw_addr.port());
    let resp = client.get(&url).send().await?;

    assert_eq!(resp.status().as_u16(), 200, "h2c request must return 200");
    assert_eq!(
        resp.version(),
        Version::HTTP_2,
        "proxy must negotiate HTTP/2 for a client using h2c prior-knowledge"
    );
    let body = resp
        .json::<http::EchoResponse>()
        .await
        .context("parse echo response")?;
    body.assert_backend("echo-a");

    Ok(())
}

/// Verifies that HTTP/1.1 clients reach the backend normally on a listener that
/// also accepts h2c prior-knowledge (#32 backward compatibility).
///
/// h2c detection is a non-destructive peek — an HTTP/1.1 request does not start
/// with the h2c connection preface, so the proxy falls through to HTTP/1.1
/// handling without any disruption.
#[tokio::test]
async fn h1_client_unaffected_when_h2c_active() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-h1-h2c").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    // Standard HTTP/1.1 client — same path as all other routing tests.
    let resp = wait::wait_for_route(&gw, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// A GRPCRoute with an exact service+method match forwards the call to the
/// correct backend and returns a successful gRPC response (`grpc-status: 0`).
///
/// Verifies that:
/// - the proxy understands `GRPCRoute` and translates `method.type=Exact` to a
///   path match on `/{service}/{method}`;
/// - trailers (`grpc-status`) are forwarded transparently (Pingora h2 path);
/// - the pod identity in the response confirms which backend served the call.
#[tokio::test]
async fn grpc_route_forwards_to_matched_service_method() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-grpc-exact-method").await?;

    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_ROUTE_EXACT_METHOD, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_grpcroute_programmed(
        &h.client,
        "grpc-echo-route",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    let host = format!("grpc-echo.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;
    let origin: tonic::transport::Uri = format!("http://{}:{}", host, gw_addr.port()).parse()?;
    let endpoint =
        tonic::transport::Endpoint::from_shared(format!("http://{gw_addr}"))?.origin(origin);

    // Poll until the data plane picks up the new route and the gRPC call succeeds.
    let inner = wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo call via {host} to succeed") },
        || async {
            let channel = endpoint.clone().connect().await.ok()?;
            let mut client = tonic::client::Grpc::new(channel);
            client.ready().await.ok()?;
            let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo"
                .parse::<tonic::codegen::http::uri::PathAndQuery>()
                .ok()?;
            let codec =
                tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
            client
                .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
                .await
                .ok()
                .map(tonic::Response::into_inner)
        },
    )
    .await?;

    let pod = inner
        .assertions
        .and_then(|a| a.context)
        .map(|c| c.pod)
        .unwrap_or_default();
    assert!(
        pod.starts_with("grpc-echo-"),
        "response must come from grpc-echo-* pod, got {pod:?}"
    );

    Ok(())
}

/// A gRPC call to a method not covered by any GRPCRoute rule is not forwarded
/// to the backend — the proxy returns an error response.
///
/// The GRPCRoute only matches `GrpcEcho/Echo`; a call to `GrpcEcho/EchoTwo`
/// has no matching rule and must fail (the proxy returns a non-OK HTTP or gRPC
/// status). Validates the GRPCRoute's match semantics: only the declared
/// methods are admitted.
#[tokio::test]
async fn grpc_route_unmatched_method_is_not_served() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-grpc-unmatched").await?;

    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_ROUTE_EXACT_METHOD, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_grpcroute_programmed(
        &h.client,
        "grpc-echo-route",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    let host = format!("grpc-echo.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;
    let origin: tonic::transport::Uri = format!("http://{}:{}", host, gw_addr.port()).parse()?;
    let endpoint =
        tonic::transport::Endpoint::from_shared(format!("http://{gw_addr}"))?.origin(origin);

    // First confirm the happy path is live so we know the data plane is ready.
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo warm-up via {host} to succeed") },
        || async {
            let channel = endpoint.clone().connect().await.ok()?;
            let mut client = tonic::client::Grpc::new(channel);
            client.ready().await.ok()?;
            let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo"
                .parse::<tonic::codegen::http::uri::PathAndQuery>()
                .ok()?;
            let codec =
                tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
            client
                .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
                .await
                .ok()
                .map(|_| ())
        },
    )
    .await?;

    // Now call EchoTwo — not matched by any rule → must fail.
    let channel = endpoint.connect().await.context("connect to gateway")?;
    let mut client = tonic::client::Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|e| anyhow::anyhow!("gRPC channel not ready: {e}"))?;
    let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/EchoTwo"
        .parse::<tonic::codegen::http::uri::PathAndQuery>()?;
    let codec = tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
    let result = client
        .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
        .await;

    assert!(
        result.is_err(),
        "call to unmatched GrpcEcho/EchoTwo must fail, but got a successful response"
    );

    Ok(())
}

// ── GRPCRouteNamedRouteRule — GEP-995 (#504) ─────────────────────────────────

/// A `GRPCRoute` rule carrying `.name` still routes correctly, and the name
/// replaces the positional rule index as the proxy's `route` metric label —
/// the reorder-stable identifier the field exists to provide. The sibling
/// unnamed rule is unaffected: it keeps its positional-index label.
#[tokio::test]
async fn grpc_route_with_named_rule_routes_by_method() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-grpc-named-rule").await?;

    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_ROUTE_NAMED_RULE, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_grpcroute_programmed(
        &h.client,
        "grpc-named-rule-route",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    let host = format!("grpc-named-rule.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;
    let origin: tonic::transport::Uri = format!("http://{}:{}", host, gw_addr.port()).parse()?;
    let endpoint =
        tonic::transport::Endpoint::from_shared(format!("http://{gw_addr}"))?.origin(origin);

    // Poll until the data plane picks up the new route and the named rule's
    // method (Echo) succeeds.
    let inner = wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo call via {host} (named rule) to succeed") },
        || async {
            let channel = endpoint.clone().connect().await.ok()?;
            let mut client = tonic::client::Grpc::new(channel);
            client.ready().await.ok()?;
            let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo"
                .parse::<tonic::codegen::http::uri::PathAndQuery>()
                .ok()?;
            let codec =
                tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
            client
                .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
                .await
                .ok()
                .map(tonic::Response::into_inner)
        },
    )
    .await?;
    let pod = inner
        .assertions
        .and_then(|a| a.context)
        .map(|c| c.pod)
        .unwrap_or_default();
    assert!(
        pod.starts_with("grpc-echo-"),
        "named-rule call must be served by grpc-echo-* pod, got {pod:?}"
    );

    // The sibling unnamed rule (EchoTwo) must still route — naming rule 0
    // must not perturb rule 1's matching.
    let channel = endpoint.connect().await.context("connect to gateway")?;
    let mut client = tonic::client::Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|e| anyhow::anyhow!("gRPC channel not ready: {e}"))?;
    let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/EchoTwo"
        .parse::<tonic::codegen::http::uri::PathAndQuery>()?;
    let codec = tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
    let response = client
        .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
        .await
        .map_err(|e| anyhow::anyhow!("unnamed-rule EchoTwo call failed: {e}"))?
        .into_inner();
    let pod = response
        .assertions
        .and_then(|a| a.context)
        .map(|c| c.pod)
        .unwrap_or_default();
    assert!(
        pod.starts_with("grpc-echo-"),
        "unnamed-rule call must be served by grpc-echo-* pod, got {pod:?}"
    );

    // The named rule's metric label uses the name; the unnamed rule (index 1)
    // still uses its positional index.
    let metrics = reqwest::get(h.admin_url("/metrics")).await?.text().await?;
    let named_label = format!(
        "route=\"grpcroute/{}/grpc-named-rule-route:named-rule\"",
        ns.name
    );
    assert!(
        metrics.lines().any(|l| l.contains(&named_label)),
        "requests_total must carry a route label using the rule name `{named_label}`, metrics:\n{metrics}"
    );
    let indexed_label = format!("route=\"grpcroute/{}/grpc-named-rule-route:1\"", ns.name);
    assert!(
        metrics.lines().any(|l| l.contains(&indexed_label)),
        "the unnamed sibling rule must keep its positional-index label `{indexed_label}`, metrics:\n{metrics}"
    );

    Ok(())
}

/// A gRPC call to a method matched by neither rule of a named-rule
/// `GRPCRoute` is not served — naming one rule must not widen matching for
/// the route as a whole.
#[tokio::test]
async fn grpc_route_named_rule_unmatched_method_is_not_served() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-grpc-named-rule-unmatched").await?;

    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_ROUTE_NAMED_RULE, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_grpcroute_programmed(
        &h.client,
        "grpc-named-rule-route",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    let host = format!("grpc-named-rule.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;
    let origin: tonic::transport::Uri = format!("http://{}:{}", host, gw_addr.port()).parse()?;
    let endpoint =
        tonic::transport::Endpoint::from_shared(format!("http://{gw_addr}"))?.origin(origin);

    // First confirm the happy path is live so we know the data plane is ready.
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo warm-up via {host} to succeed") },
        || async {
            let channel = endpoint.clone().connect().await.ok()?;
            let mut client = tonic::client::Grpc::new(channel);
            client.ready().await.ok()?;
            let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo"
                .parse::<tonic::codegen::http::uri::PathAndQuery>()
                .ok()?;
            let codec =
                tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
            client
                .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
                .await
                .ok()
                .map(|_| ())
        },
    )
    .await?;

    // EchoThree is matched by neither rule → must fail.
    let channel = endpoint.connect().await.context("connect to gateway")?;
    let mut client = tonic::client::Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|e| anyhow::anyhow!("gRPC channel not ready: {e}"))?;
    let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/EchoThree"
        .parse::<tonic::codegen::http::uri::PathAndQuery>()?;
    let codec = tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
    let result = client
        .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
        .await;

    assert!(
        result.is_err(),
        "call to unmatched GrpcEcho/EchoThree must fail, but got a successful response"
    );

    Ok(())
}

// ── CORS filter — GEP-1767 (#41) ─────────────────────────────────────────────

/// Preflight `OPTIONS` from an allowed origin returns 204 with
/// `Access-Control-Allow-Origin` echoing the concrete request origin and
/// `Access-Control-Allow-Methods` listing the configured methods. The backend
/// is never contacted (no echo body in the response).
#[tokio::test]
async fn cors_preflight_returns_204_with_allow_headers() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-cors-preflight").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::CORS, FixtureVars::new(&ns.name)).await?;

    let host = format!("cors.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/cors/probe", Duration::from_secs(60)).await?;

    let url = format!(
        "http://{}:{}/cors/preflight",
        gw.proxy_addr.ip(),
        gw.proxy_addr.port()
    );
    let resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?
        .request(Method::OPTIONS, &url)
        .header("Host", &host)
        .header("Origin", "https://allowed.example")
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await?;

    assert_eq!(
        resp.status().as_u16(),
        204,
        "CORS preflight from allowed origin must return 204"
    );
    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        acao, "https://allowed.example",
        "CORS preflight: Access-Control-Allow-Origin must echo the request origin, got {acao:?}"
    );
    let acam = resp
        .headers()
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        acam.contains("POST"),
        "CORS preflight: Access-Control-Allow-Methods must include POST, got {acam:?}"
    );

    Ok(())
}

/// A preflight `OPTIONS` from an origin not in the allow-list: the proxy must
/// NOT return any `Access-Control-Allow-Origin` header (the browser then blocks
/// the cross-origin request).
#[tokio::test]
async fn cors_disallowed_origin_omits_allow_origin_header() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-cors-sad").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::CORS, FixtureVars::new(&ns.name)).await?;

    let host = format!("cors.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/cors/probe", Duration::from_secs(60)).await?;

    let url = format!(
        "http://{}:{}/cors/actual",
        gw.proxy_addr.ip(),
        gw.proxy_addr.port()
    );
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?
        .get(&url)
        .header("Host", &host)
        .header("Origin", "https://evil.example")
        .send()
        .await?;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "CORS: disallowed origin must not block the request itself"
    );
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "CORS: response for a disallowed origin must carry no Access-Control-Allow-Origin header"
    );

    Ok(())
}

/// An actual (non-preflight) GET from an allowed origin: the proxy must forward
/// the request to the backend AND inject `Access-Control-Allow-Origin` echoing
/// the request origin into the response.
#[tokio::test]
async fn cors_actual_request_injects_allow_origin_header() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-cors-actual").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::CORS, FixtureVars::new(&ns.name)).await?;

    let host = format!("cors.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/cors/probe", Duration::from_secs(60)).await?;

    let (status, resp_headers, body) = gw
        .get_full_with_headers(
            &host,
            "/cors/actual",
            &[("Origin", "https://allowed.example")],
        )
        .await?;

    assert_eq!(
        status, 200,
        "CORS actual request from allowed origin must reach the backend (200)"
    );
    assert!(
        body.is_some(),
        "CORS actual request: expected echo response body from backend"
    );
    let acao = resp_headers
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        acao, "https://allowed.example",
        "CORS actual request: Access-Control-Allow-Origin must echo the request origin, got {acao:?}"
    );

    Ok(())
}

// ── RequestMirror tests (#261) ────────────────────────────────────────────────

/// Sum `coxswain_proxy_mirror_requests_total{…}` counter values for routes in
/// namespace `route_ns`, from a raw Prometheus metrics body. Returns `0.0` when no
/// matching series exists (not yet incremented).
///
/// The `route` label is `httproute/{ns}/{name}:{rule}` (see the reflector's
/// `metric_route_id`). The shared proxy serves every concurrent test, so scoping
/// to the caller's (unique) namespace is what keeps one mirror test's dispatches
/// from polluting another's before/after delta — the proxy counter is global.
fn mirror_dispatch_count(metrics_body: &str, route_ns: &str) -> f64 {
    let ns_marker = format!("/{route_ns}/");
    metrics_body
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let rest = l.strip_prefix("coxswain_proxy_mirror_requests_total{")?;
            let (labels, value) = rest.split_once('}')?;
            if !labels.contains(&ns_marker) {
                return None;
            }
            value.trim().parse::<f64>().ok()
        })
        .sum()
}

async fn fetch_proxy_metrics(
    client: &reqwest::Client,
    metrics_url: &str,
    route_ns: &str,
) -> anyhow::Result<f64> {
    let body = client
        .get(metrics_url)
        .send()
        .await
        .context("fetch /metrics")?
        .text()
        .await
        .context("read /metrics body")?;
    Ok(mirror_dispatch_count(&body, route_ns))
}

#[tokio::test]
async fn mirrored_request_reaches_shadow_while_client_sees_primary() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-mirror-single").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::MIRROR, FixtureVars::new(&ns.name)).await?;

    let host = format!("mirror.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/mirror/probe", Duration::from_secs(60)).await?;

    let metrics_url = h.admin_url("/metrics");
    let metrics_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build metrics client")?;

    let before = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;

    // Send a request through the mirrored rule.
    let (status, body) = gw
        .request(Method::GET, &host, "/mirror/single", &[])
        .await?;
    assert_eq!(status, 200, "primary backend must return 200");
    body.unwrap().assert_backend("echo-a");

    // Poll until the mirror counter increments — the fire-and-forget task is
    // asynchronous so it may not have run yet at the time of the assert.
    wait::poll_until(
        Duration::from_secs(15),
        Duration::from_millis(250),
        || async {
            "mirror_requests_total to increment after mirrored GET /mirror/single".to_string()
        },
        || async {
            let count = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name)
                .await
                .unwrap_or(0.0);
            (count > before).then_some(())
        },
    )
    .await?;

    // Negative: a sibling route without a mirror filter must not bump the counter.
    // The counter is bumped synchronously before spawn, so a simple before/after
    // check across the request is sufficient.
    let before2 = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;
    let (status2, body2) = gw.request(Method::GET, &host, "/mirror/probe", &[]).await?;
    assert_eq!(status2, 200, "probe route must return 200");
    body2.unwrap().assert_backend("echo-a");
    let after2 = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;
    assert_eq!(
        before2, after2,
        "non-mirrored route must not increment mirror_requests_total"
    );

    Ok(())
}

#[tokio::test]
async fn percent_zero_mirror_never_dispatches() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-mirror-pct0").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::MIRROR, FixtureVars::new(&ns.name)).await?;

    let host = format!("mirror.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/mirror/probe", Duration::from_secs(60)).await?;

    let metrics_url = h.admin_url("/metrics");
    let metrics_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build metrics client")?;

    let before = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;

    // Send several requests through the percent=0 rule.
    for _ in 0..5u8 {
        let (status, _) = gw
            .request(Method::GET, &host, "/mirror/percent-zero", &[])
            .await?;
        assert_eq!(
            status, 200,
            "percent-zero route must still serve primary 200"
        );
    }

    // Counter is bumped synchronously before spawn, so checking right after the
    // requests return is deterministic.
    let after = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;
    assert_eq!(
        before, after,
        "percent=0 mirror must never increment mirror_requests_total"
    );

    Ok(())
}

#[tokio::test]
async fn multiple_mirrors_each_receive_a_copy() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-mirror-multi").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::MIRROR_MULTIPLE, FixtureVars::new(&ns.name)).await?;

    let host = format!("mirror-multi.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/mirror-multi/probe", Duration::from_secs(60)).await?;

    let metrics_url = h.admin_url("/metrics");
    let metrics_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build metrics client")?;

    let before = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;

    // Send a request through the two-mirror rule.
    let (status, body) = gw
        .request(Method::GET, &host, "/mirror-multi/both", &[])
        .await?;
    assert_eq!(status, 200, "primary backend must return 200");
    body.unwrap().assert_backend("echo-a");

    // Poll until the counter has incremented by at least 2 (one per mirror).
    wait::poll_until(
        Duration::from_secs(15),
        Duration::from_millis(250),
        || async {
            "mirror_requests_total to reach before+2 after two-mirror GET /mirror-multi/both"
                .to_string()
        },
        || async {
            let count = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name)
                .await
                .unwrap_or(0.0);
            (count >= before + 2.0).then_some(())
        },
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn cross_namespace_mirror_requires_reference_grant() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-mirror-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "rt-mirror-xns-tenant").await?;

    // Deploy echo-a in the primary namespace.
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Deploy echo-d + ReferenceGrant in the tenant namespace.
    fixtures::apply_fixture(
        gwa::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    // Apply the mirror route (cross-namespace mirror → echo-d in tenant ns).
    fixtures::apply_fixture(
        gwa::MIRROR_XNS,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let host = format!("mirror-xns.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route(&gw, &host, "/mirror-xns/probe", Duration::from_secs(60)).await?;

    let metrics_url = h.admin_url("/metrics");
    let metrics_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build metrics client")?;

    let before = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;

    // With the grant in place: mirror must fire.
    let (status, body) = gw
        .request(Method::GET, &host, "/mirror-xns/path", &[])
        .await?;
    assert_eq!(status, 200, "primary must return 200");
    body.unwrap().assert_backend("echo-a");

    wait::poll_until(
        Duration::from_secs(15),
        Duration::from_millis(250),
        || async { "mirror_requests_total to increment after cross-ns GET".to_string() },
        || async {
            let count = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name)
                .await
                .unwrap_or(0.0);
            (count > before).then_some(())
        },
    )
    .await?;

    // Sad path: delete the ReferenceGrant → mirror must stop dispatching.
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
        .await
        .context("delete ReferenceGrant")?;

    // The controller reconciles the grant deletion and pushes a new snapshot, but
    // the proxy applies it asynchronously over discovery — waiting on the
    // *controller* (it has reconciled-since-startup from the moment it came up)
    // races that push. The mirror counter bumps SYNCHRONOUSLY with the primary
    // request (see `spawn_mirror_dispatch`), so poll by driving requests until one
    // leaves the counter unchanged: that request was served by the post-removal
    // snapshot, where the denied cross-ns mirror backend is gone.
    wait::poll_until(
        Duration::from_secs(30),
        Duration::from_millis(250),
        || async { "cross-ns mirror to stop firing after ReferenceGrant removal".to_string() },
        || async {
            let before = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name)
                .await
                .ok()?;
            let (status, _) = gw
                .request(Method::GET, &host, "/mirror-xns/path", &[])
                .await
                .ok()?;
            if status != 200 {
                return None;
            }
            let after = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name)
                .await
                .ok()?;
            // Synchronous counter: equal ⇒ the mirror did not fire ⇒ snapshot applied.
            (after == before).then_some(())
        },
    )
    .await?;

    // Snapshot is live and the state is monotonic, so these are now deterministic:
    // the primary still serves echo-a and the denied mirror stays off.
    let before_denied = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;
    let (status2, body2) = gw
        .request(Method::GET, &host, "/mirror-xns/path", &[])
        .await?;
    assert_eq!(
        status2, 200,
        "primary must still return 200 after grant removal"
    );
    body2.unwrap().assert_backend("echo-a");

    let after_denied = fetch_proxy_metrics(&metrics_client, &metrics_url, &ns.name).await?;
    assert_eq!(
        before_denied, after_denied,
        "mirror to denied cross-ns backend must not fire after ReferenceGrant is removed"
    );

    Ok(())
}

/// GEP-1713: an HTTPRoute attaches to a ListenerSet listener on a NEW port the
/// parent Gateway does not itself serve. Proves the full path: the parent opts
/// in (`allowedListeners`), the merge attaches the ListenerSet, the operator
/// provisions the new port on the per-Gateway VIP (G3), and traffic routes.
#[tokio::test]
async fn gateway_listenerset_routes_to_backend_on_new_port() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-gw-ls").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::LISTENERSET_BASIC, FixtureVars::new(&ns.name)).await?;

    // The ListenerSet listener is on port 8001 — a port the Gateway itself does
    // not serve. Resolve the per-Gateway VIP on that port (G3 must expose it).
    const LS_PORT: u16 = 8001;
    let addr = wait::wait_for_gateway_address(
        &h.client,
        "coxswain-test",
        &ns.name,
        LS_PORT,
        Duration::from_secs(120),
    )
    .await?;
    let gw = HttpClient::new(addr)?;

    let host = format!("ls.{}.local", ns.name);
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// Gateway API `HTTPRouteNoBackendRefs` (#517): a rule with omitted or empty
/// `backendRefs` must route with a distinct **500**, not fall through to a 404.
///   - happy: the sibling rule WITH real backendRefs routes to the backend (200);
///   - sad: rules with `backendRefs: []` and with the field omitted both return 500.
#[tokio::test]
async fn route_returns_500_when_rule_has_no_backend_refs() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rt-no-backends").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::HTTPROUTE_NO_BACKEND_REFS, FixtureVars::new(&ns.name)).await?;

    let addr = h.gateway_http_addr(&ns.name).await?;
    let gw = HttpClient::new(addr)?;
    let host = format!("no-backends.{}.local", ns.name);

    // Happy: the rule with real backendRefs routes to the backend. This also
    // confirms the HTTPRoute is fully reconciled before the 500 assertions below.
    let resp = wait::wait_for_route(&gw, &host, "/forward", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // Sad: both no-backend rules return a distinct 500 (not a 404). A 404 here
    // would mean the rule was skipped rather than installed as an error route.
    assert_eq!(
        gw.get_status(&host, "/empty").await?,
        500,
        "a rule with empty backendRefs must return 500, not 404"
    );
    assert_eq!(
        gw.get_status(&host, "/omitted").await?,
        500,
        "a rule with omitted backendRefs must return 500, not 404"
    );

    Ok(())
}
