//! Unit tests for the `coxswain-core::health` module.

#![allow(missing_docs)]

use crate::health::{CheckState, HealthRegistry};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

fn degraded(reason: &str) -> CheckState {
    CheckState::Degraded {
        reason: Arc::from(reason),
    }
}

fn failed(reason: &str) -> CheckState {
    CheckState::Failed {
        reason: Arc::from(reason),
    }
}

#[test]
fn severity_order_is_failed_degraded_pending_ready() {
    assert_eq!(CheckState::Ready.severity(), 0);
    assert_eq!(CheckState::Pending.severity(), 1);
    assert_eq!(degraded("x").severity(), 2);
    assert_eq!(failed("x").severity(), 3);
}

#[test]
fn check_is_ready_only_for_ready_and_degraded() {
    assert!(CheckState::Ready.is_ready());
    assert!(degraded("warming up").is_ready());
    assert!(!CheckState::Pending.is_ready());
    assert!(!failed("blown").is_ready());
}

#[test]
fn fresh_subsystem_aggregate_is_pending_until_every_check_reports() {
    let reg = HealthRegistry::new();
    let sub = reg.register("controller", &["httproute", "ingress"]);

    assert!(!reg.is_ready(), "fresh registry must not be ready");
    assert!(!reg.is_subsystem_ready("controller"));

    sub.ready("httproute");
    assert!(!reg.is_ready(), "still Pending on the ingress check");

    sub.ready("ingress");
    assert!(reg.is_ready(), "all checks Ready → registry ready");
    assert!(reg.is_subsystem_ready("controller"));
}

#[test]
fn empty_subsystem_is_immediately_ready() {
    let reg = HealthRegistry::new();
    let _empty = reg.register("proxy", &[]);
    assert!(reg.is_ready());
    assert!(reg.is_subsystem_ready("proxy"));
}

#[test]
fn empty_registry_is_ready() {
    let reg = HealthRegistry::new();
    assert!(reg.is_ready());
}

#[test]
fn unknown_subsystem_is_not_ready() {
    let reg = HealthRegistry::new();
    assert!(
        !reg.is_subsystem_ready("missing"),
        "unknown subsystem must fail closed",
    );
}

#[test]
fn degraded_keeps_readyz_at_ready_but_pending_and_failed_do_not() {
    let reg = HealthRegistry::new();
    let sub = reg.register("controller", &["a", "b"]);
    sub.ready("a");
    sub.degraded("b", "warming up");
    assert!(reg.is_ready(), "Degraded must not flip /readyz to 503");

    sub.set("b", CheckState::Pending);
    assert!(!reg.is_ready(), "Pending must flip /readyz to 503");

    sub.failed("b", "blown");
    assert!(!reg.is_ready(), "Failed must flip /readyz to 503");
}

#[test]
fn registry_is_ready_only_if_every_subsystem_is_ready() {
    let reg = HealthRegistry::new();
    let controller = reg.register("controller", &["a"]);
    let proxy = reg.register("proxy", &["b"]);

    controller.ready("a");
    assert!(!reg.is_ready(), "proxy still Pending");

    proxy.ready("b");
    assert!(reg.is_ready(), "both subsystems Ready");

    controller.failed("a", "boom");
    assert!(!reg.is_ready(), "one Failed propagates to registry");
}

#[test]
fn snapshot_picks_highest_severity_as_aggregate_with_reason() {
    let reg = HealthRegistry::new();
    let sub = reg.register("controller", &["a", "b", "c"]);
    sub.ready("a");
    sub.degraded("b", "warming up");
    sub.failed("c", "cert expired");

    let snap = reg.snapshot();
    let controller = snap
        .subsystems
        .get("controller")
        .expect("controller subsystem must be present");

    // Aggregate state is the highest-severity check, including its reason.
    match &controller.state {
        CheckState::Failed { reason } => assert_eq!(reason.as_ref(), "cert expired"),
        other => panic!("expected Failed aggregate, got {other:?}"),
    }
    assert_eq!(controller.checks.len(), 3);
}

#[test]
fn snapshot_iteration_order_is_stable_btreemap() {
    let reg = HealthRegistry::new();
    let _z = reg.register("zeta", &["c", "a", "b"]);
    let _a = reg.register("alpha", &["b", "a"]);

    let snap = reg.snapshot();
    let subsys: Vec<&str> = snap.subsystems.keys().map(|k| k.as_ref()).collect();
    assert_eq!(subsys, vec!["alpha", "zeta"]);

    let alpha_checks: Vec<&str> = snap.subsystems["alpha"]
        .checks
        .keys()
        .map(|k| k.as_ref())
        .collect();
    assert_eq!(alpha_checks, vec!["a", "b"]);
}

#[test]
fn set_under_concurrent_writers_converges_to_highest_severity() {
    let reg = HealthRegistry::new();
    let sub = reg.register("controller", &["a", "b", "c", "d"]);

    let started = Arc::new(AtomicUsize::new(0));
    let writers: Vec<_> = ["a", "b", "c", "d"]
        .into_iter()
        .map(|name| {
            let h = sub.clone();
            let started = Arc::clone(&started);
            thread::spawn(move || {
                started.fetch_add(1, Ordering::Relaxed);
                for _ in 0..200 {
                    h.ready(name);
                    h.degraded(name, "warming");
                }
                h.failed(name, "final");
            })
        })
        .collect();
    for w in writers {
        w.join().expect("writer thread panicked");
    }

    let snap = reg.snapshot();
    let controller = &snap.subsystems["controller"];
    assert!(matches!(controller.state, CheckState::Failed { .. }));
    for state in controller.checks.values() {
        assert!(matches!(state, CheckState::Failed { .. }));
    }
    assert!(!reg.is_ready());
}

#[test]
#[should_panic(expected = "not registered")]
fn set_on_unregistered_check_panics() {
    let reg = HealthRegistry::new();
    let sub = reg.register("controller", &["only_this_one"]);
    sub.ready("typo");
}

#[test]
#[should_panic(expected = "already registered")]
fn duplicate_subsystem_registration_panics() {
    let reg = HealthRegistry::new();
    let _a = reg.register("controller", &["a"]);
    let _b = reg.register("controller", &["b"]);
}

#[test]
fn check_state_serialize_shape_is_stable() {
    let ready = serde_json::to_value(CheckState::Ready).unwrap();
    assert_eq!(ready, serde_json::json!({ "state": "ready" }));

    let pending = serde_json::to_value(CheckState::Pending).unwrap();
    assert_eq!(pending, serde_json::json!({ "state": "pending" }));

    let degraded = serde_json::to_value(degraded("warming up")).unwrap();
    assert_eq!(
        degraded,
        serde_json::json!({ "state": "degraded", "reason": "warming up" })
    );

    let failed = serde_json::to_value(failed("blown")).unwrap();
    assert_eq!(
        failed,
        serde_json::json!({ "state": "failed", "reason": "blown" })
    );
}

#[test]
fn snapshot_serializes_to_documented_status_shape() {
    let reg = HealthRegistry::new();
    let controller = reg.register("controller", &["httproute", "ingress"]);
    let proxy = reg.register("proxy", &["routing_table_loaded"]);
    controller.ready("httproute");
    controller.ready("ingress");
    proxy.ready("routing_table_loaded");

    let snap = reg.snapshot();
    let json = serde_json::to_value(&snap).unwrap();
    let expected = serde_json::json!({
        "subsystems": {
            "controller": {
                "state":  { "state": "ready" },
                "checks": {
                    "httproute": { "state": "ready" },
                    "ingress":   { "state": "ready" },
                },
            },
            "proxy": {
                "state":  { "state": "ready" },
                "checks": {
                    "routing_table_loaded": { "state": "ready" },
                },
            },
        }
    });
    assert_eq!(json, expected);
}
