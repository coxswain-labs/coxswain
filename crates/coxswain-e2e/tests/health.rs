#![allow(missing_docs)]
//! Regression tests for the per-subsystem readiness model (issue #158).
//!
//! - `readyz_starts_not_ready_then_transitions_to_ready` proves the gate is not
//!   stuck open at startup: at least one probe before the first rebuild observes
//!   503 (or connection-refused), and the gate eventually flips to 200.
//! - `status_exposes_per_subsystem_checks` proves the `/status` shape matches the
//!   documented contract: every registered controller check plus the proxy's
//!   `routing_table_loaded` are present and `ready` after the harness's
//!   `wait_for_ready` returns.

use coxswain_e2e::{ControllerProcess, Harness, bootstrap};
use std::time::Duration;

mod common;

/// Controller-subsystem checks asserted in `/status.subsystems.controller.checks`.
///
/// Order is irrelevant but the set must match what `main.rs` registers — keep in
/// lockstep with the `controller_handle` registration call.
const CONTROLLER_CHECKS: &[&str] = &[
    "httproute",
    "ingress",
    "ingress_class",
    "gateway",
    "gateway_class",
    "endpoint_slice",
    "reference_grant",
    "secret",
    "service",
    "backend_tls_policy",
    "config_map",
    "routing_table_built",
];

#[tokio::test]
async fn readyz_starts_not_ready_then_transitions_to_ready() -> anyhow::Result<()> {
    common::init_tracing();
    bootstrap().await?;

    let controller = ControllerProcess::start().await?;
    let url = format!("http://{}/readyz", controller.health_addr);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;

    // Probe at high frequency from the moment the subprocess is spawned. We
    // expect at least one not-ready response (HTTP 503, or connection-refused
    // before the health server has bound its port) before the eventual 200.
    let mut saw_not_ready = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() > deadline {
            anyhow::bail!("readyz never returned 200 within 30s");
        }
        match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => break,
            Ok(r) => {
                tracing::debug!(status = %r.status(), "readyz not yet ready");
                saw_not_ready = true;
            }
            Err(e) => {
                tracing::debug!(error = %e, "readyz probe error (likely pre-bind)");
                saw_not_ready = true;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        saw_not_ready,
        "readyz returned 200 on the first probe; either the gate is broken or the test lost the race"
    );
    Ok(())
}

#[tokio::test]
async fn status_exposes_per_subsystem_checks() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;

    let status: serde_json::Value = reqwest::get(h.admin_url("/status")).await?.json().await?;

    // Top-level alias retained for back-compat with pre-refactor dashboards.
    assert_eq!(
        status["synced"],
        serde_json::Value::Bool(true),
        "/status.synced must be true after harness wait_for_ready",
    );

    let subsystems = status["subsystems"]
        .as_object()
        .expect("/status.subsystems must be an object");
    assert!(
        subsystems.contains_key("controller"),
        "/status.subsystems must contain 'controller'",
    );
    assert!(
        subsystems.contains_key("proxy"),
        "/status.subsystems must contain 'proxy'",
    );

    let controller = &subsystems["controller"];
    assert_eq!(
        controller["state"]["state"], "ready",
        "controller subsystem aggregate must be ready"
    );
    let controller_checks = controller["checks"]
        .as_object()
        .expect("controller.checks must be an object");
    for expected in CONTROLLER_CHECKS {
        let entry = controller_checks
            .get(*expected)
            .unwrap_or_else(|| panic!("controller.checks must contain '{expected}'"));
        assert_eq!(
            entry["state"], "ready",
            "controller.checks.{expected} must be ready after sync"
        );
    }

    let proxy = &subsystems["proxy"];
    assert_eq!(
        proxy["state"]["state"], "ready",
        "proxy subsystem aggregate must be ready"
    );
    let proxy_checks = proxy["checks"]
        .as_object()
        .expect("proxy.checks must be an object");
    assert_eq!(
        proxy_checks["routing_table_loaded"]["state"], "ready",
        "proxy.routing_table_loaded must be ready after first rebuild"
    );

    Ok(())
}
