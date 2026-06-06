use crate::reference_grants::*;
use std::collections::HashSet;

fn grants(entries: &[(&str, &str, Option<&str>)]) -> HashSet<ReferenceGrantKey> {
    entries
        .iter()
        .map(|(f, t, n)| match n {
            Some(name) => ReferenceGrantKey::specific(*f, *t, *name),
            None => ReferenceGrantKey::wildcard(*f, *t),
        })
        .collect()
}

#[test]
fn wildcard_grant_permits_any_service() {
    let g = grants(&[("apps", "billing", None)]);
    assert!(backend_ref_allowed("apps", "billing", "payments", &g));
    assert!(backend_ref_allowed("apps", "billing", "other-svc", &g));
}

#[test]
fn specific_grant_permits_named_service() {
    let g = grants(&[("apps", "billing", Some("payments"))]);
    assert!(backend_ref_allowed("apps", "billing", "payments", &g));
}

#[test]
fn specific_grant_denies_different_service() {
    let g = grants(&[("apps", "billing", Some("payments"))]);
    assert!(!backend_ref_allowed("apps", "billing", "other-svc", &g));
}

#[test]
fn denied_when_from_ns_mismatch() {
    let g = grants(&[("apps", "billing", None)]);
    assert!(!backend_ref_allowed("other", "billing", "payments", &g));
}

#[test]
fn denied_when_to_ns_mismatch() {
    let g = grants(&[("apps", "billing", None)]);
    assert!(!backend_ref_allowed("apps", "other", "payments", &g));
}

#[test]
fn denied_on_empty_grants() {
    assert!(!backend_ref_allowed(
        "apps",
        "billing",
        "payments",
        &HashSet::new()
    ));
}

#[test]
fn wildcard_and_specific_coexist() {
    let g = grants(&[
        ("apps", "billing", None),
        ("apps", "billing", Some("payments")),
    ]);
    assert!(backend_ref_allowed("apps", "billing", "payments", &g));
    assert!(backend_ref_allowed("apps", "billing", "anything", &g));
}
