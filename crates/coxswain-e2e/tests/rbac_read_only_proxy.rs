//! Structural verification that the shared-proxy ServiceAccount has zero
//! write verbs.
//!
//! This is the load-bearing invariant of v0.2's controller/proxy split: a
//! compromised proxy must not be able to write to Kubernetes. The chart
//! enforces it by not granting any write rules in `shared-proxy-rbac.yaml`;
//! this test enforces it by asking the API server.
//!
//! Mechanism: parse `kubectl auth can-i --list --as=<sa>` and assert that
//! every verb in the right-hand column belongs to `{get, list, watch}`. The
//! check is structural — it doesn't depend on which resources show up, only
//! on which verbs are bound. Adding a `create` / `patch` / `update` /
//! `delete` / `deletecollection` rule to the proxy ClusterRole, even on an
//! unrelated resource, regresses the invariant.
//!
//! Two baseline-grant carve-outs:
//! - `selfsubjectaccessreviews` / `selfsubjectrulesreviews` (api group
//!   `authorization.k8s.io`) — every authenticated user holds `create` on
//!   these via the cluster-default `system:basic-user` ClusterRoleBinding;
//!   that's not the proxy's RBAC, it's Kubernetes plumbing.
//! - Non-resource URLs (`/healthz`, `/version`, `/.well-known/*`) — same
//!   reason, `system:public-info-viewer` grants `get` on these to every
//!   authenticated user.
//!
//! The test skips when no cluster is reachable (kubectl unavailable, no
//! kubeconfig context) so it remains runnable locally without infrastructure.
//! In CI it runs against the same cluster the rest of the e2e suite targets.

#![allow(missing_docs)]

use std::collections::HashSet;
use std::process::Command;

/// The ServiceAccount under audit. Matches the name rendered by both the
/// raw manifests in `deploy/manifests/shared-proxy-rbac.yaml` and the Helm
/// chart's default release-name convention (`<release>-coxswain-shared-proxy`).
const PROXY_SA_CANDIDATES: &[&str] = &[
    "coxswain-shared-proxy",
    "release-name-coxswain-shared-proxy",
];

/// Verbs the proxy is allowed to hold. Anything outside this set is a
/// regression of the read-only-proxy invariant.
const ALLOWED_VERBS: &[&str] = &["get", "list", "watch"];

/// Resource prefixes whose verbs come from baseline cluster grants
/// (`system:basic-user`, `system:public-info-viewer`), not from the
/// `coxswain-shared-proxy` ClusterRole. Excluded from the audit so the test
/// fails only on real regressions.
///
/// Every `selfsubject*` resource (under both `authorization.k8s.io` and
/// `authentication.k8s.io`) grants `create` to every authenticated principal
/// via cluster-default bindings; that's K8s plumbing, not coxswain.
const BASELINE_RESOURCE_PREFIXES: &[&str] = &["selfsubject"];

#[test]
fn shared_proxy_sa_has_only_read_verbs() {
    let Some(output) = try_auth_can_i_list() else {
        eprintln!(
            "rbac_read_only_proxy: no reachable cluster — skipping. Run against a cluster \
             with coxswain installed (helm or manifests) to enforce the invariant."
        );
        return;
    };

    let rows = parse_auth_can_i(&output);
    assert!(
        !rows.is_empty(),
        "auth can-i --list returned no rows — is the ServiceAccount actually bound? \
         Output was:\n{output}"
    );

    let allowed: HashSet<&str> = ALLOWED_VERBS.iter().copied().collect();
    let mut violations: Vec<String> = Vec::new();

    for row in &rows {
        if is_baseline_grant(row) {
            continue;
        }
        for verb in &row.verbs {
            if !allowed.contains(verb.as_str()) {
                violations.push(format!("resource={}, verb={}", row.resource, verb));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "shared-proxy ServiceAccount has write verbs — read-only invariant regressed!\n\
         {}\n\
         full kubectl output:\n{output}",
        violations.join("\n")
    );
}

/// Try each candidate SA name; return the first kubectl output that succeeded.
/// Returns `None` when no cluster is reachable or no candidate SA exists.
fn try_auth_can_i_list() -> Option<String> {
    let namespace =
        std::env::var("COXSWAIN_E2E_NAMESPACE").unwrap_or_else(|_| "coxswain-system".to_string());

    for sa in PROXY_SA_CANDIDATES {
        let principal = format!("system:serviceaccount:{namespace}:{sa}");
        let output = Command::new("kubectl")
            .args(["auth", "can-i", "--list", "--as", &principal])
            .output()
            .ok()?;
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("rbac_read_only_proxy: candidate `{sa}` failed: {stderr}");
    }
    None
}

/// One parsed row of `kubectl auth can-i --list` output.
#[derive(Debug, Default)]
struct AuthRow {
    /// Resource cell (first column). Empty when the row is a non-resource URL.
    resource: String,
    /// Verbs from the rightmost bracketed segment.
    verbs: Vec<String>,
    /// True when the row's non-resource URL column is non-empty.
    is_non_resource_url: bool,
}

/// Parse the kubectl table into [`AuthRow`]s. The output is column-aligned
/// whitespace; columns are: Resources, Non-Resource URLs, Resource Names,
/// Verbs. We split on whitespace runs, then re-assemble: the last bracketed
/// segment is verbs; segments preceding it are the first three columns.
fn parse_auth_can_i(output: &str) -> Vec<AuthRow> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Resources") {
            continue;
        }
        let Some(open) = trimmed.rfind('[') else {
            continue;
        };
        let Some(close) = trimmed.rfind(']') else {
            continue;
        };
        if close <= open {
            continue;
        }

        // Verbs.
        let mut verbs = Vec::new();
        for verb in trimmed[open + 1..close].split(|c: char| c.is_whitespace() || c == ',') {
            let v = verb.trim();
            if !v.is_empty() {
                verbs.push(v.to_string());
            }
        }

        // Everything before the verbs bracket is the first three columns.
        let prefix = trimmed[..open].trim_end();
        let first_col = prefix.split_whitespace().next().unwrap_or("").to_string();

        let is_non_resource_url = first_col.starts_with('[') || first_col.is_empty();

        rows.push(AuthRow {
            resource: if is_non_resource_url {
                String::new()
            } else {
                first_col
            },
            verbs,
            is_non_resource_url,
        });
    }
    rows
}

fn is_baseline_grant(row: &AuthRow) -> bool {
    if row.is_non_resource_url {
        return true;
    }
    BASELINE_RESOURCE_PREFIXES
        .iter()
        .any(|p| row.resource == *p || row.resource.starts_with(p))
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    const SAMPLE_READ_ONLY: &str = "\
Resources                          Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []   []   [create]
selfsubjectrulesreviews.authorization.k8s.io    []   []   [create]
services                                        []   []   [get list watch]
secrets                                         []   []   [get,list,watch]
gateways.gateway.networking.k8s.io              []   []   [get list watch]
                                                [/.well-known/openid-configuration]   []   [get]
                                                [/.well-known/openid/v1/jwks]         []   [get]
";

    const SAMPLE_HAS_WRITE: &str = "\
Resources                          Non-Resource URLs   Resource Names   Verbs
services                                        []   []   [get list watch]
gateways/status.gateway.networking.k8s.io       []   []   [patch update]
";

    #[test]
    fn read_only_sample_passes_audit() {
        let rows = parse_auth_can_i(SAMPLE_READ_ONLY);
        let allowed: HashSet<&str> = ALLOWED_VERBS.iter().copied().collect();
        for row in &rows {
            if is_baseline_grant(row) {
                continue;
            }
            for verb in &row.verbs {
                assert!(
                    allowed.contains(verb.as_str()),
                    "real read-only sample should not yield disallowed verbs; got {verb} on {}",
                    row.resource
                );
            }
        }
    }

    #[test]
    fn write_sample_yields_violation() {
        let rows = parse_auth_can_i(SAMPLE_HAS_WRITE);
        let allowed: HashSet<&str> = ALLOWED_VERBS.iter().copied().collect();
        let mut violations = 0;
        for row in &rows {
            if is_baseline_grant(row) {
                continue;
            }
            for verb in &row.verbs {
                if !allowed.contains(verb.as_str()) {
                    violations += 1;
                }
            }
        }
        assert!(
            violations >= 2,
            "write sample must produce at least two violations (patch + update); got {violations}"
        );
    }

    #[test]
    fn parse_ignores_header() {
        let rows = parse_auth_can_i("Resources Non-Resource URLs Resource Names Verbs\n");
        assert!(rows.is_empty(), "header line must not produce rows");
    }

    #[test]
    fn parse_handles_empty_output() {
        let rows = parse_auth_can_i("");
        assert!(rows.is_empty());
    }
}
