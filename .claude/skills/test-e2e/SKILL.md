---
name: test-e2e
description: Reset the local Kubernetes cluster and run one or more of the coxswain e2e suites (ingress, gateway_api, dedicated_proxy, proxy_hot_reconfig, observability, conformance). Use when the user wants to validate a change against a live cluster — for example "test e2e", "run e2e", "run conformance", or "run the full e2e suite". Asks which suites to run; auto-detects the local cluster type (caches the reset command in memory after first use); reports a clean summary; offers to debug on failure.
---

Run one or more of the project's e2e suites against a freshly-reset local Kubernetes cluster. Follow these steps in order.

## 1 — Ask the user which suites to run

Use `AskUserQuestion` with `multiSelect: true` and these options (omit "Other"; the harness manages it):

- **ingress** — Cargo e2e suite. Harness builds the Docker image, installs via Helm, runs tests in-cluster. `cargo test -p coxswain-e2e --test ingress -- --test-threads=1`
- **gateway_api** — Cargo e2e suite. Same shape as ingress; also covers health endpoint checks. `cargo test -p coxswain-e2e --test gateway_api -- --test-threads=1`
- **dedicated_proxy** — Cargo e2e suite covering dedicated-mode provisioning + per-namespace RBAC. Dedicated-proxy Services use NodePort; tests connect via node IP. `cargo test -p coxswain-e2e --test dedicated_proxy -- --test-threads=1`
- **proxy_hot_reconfig** — Cargo load-test suite: zero-drop listener add/remove; crash-loop shared-pool fallback. `cargo test -p coxswain-e2e --test proxy_hot_reconfig -- --test-threads=1`
- **observability** — Cargo e2e suite covering readiness/status (formerly `health.rs`), the `coxswain_proxy_*` / `coxswain_controller_*` Prometheus surface, and the access-log contract (field set, path-mode behaviour, disabled mode). `cargo test -p coxswain-e2e --test observability -- --test-threads=1`
- **conformance** — Gateway API Go conformance suite. The Cargo harness bootstrap handles image build + Helm install + LB-IP discovery; `go test` runs against the deployed cluster. Takes ~2 minutes.

Cap the question at one phrase: "Which e2e suites to run?". Header: "E2E suites".

If the user picks multiple, run them in the order listed above. Stop after the first failing suite unless the user opted to continue.

## 2 — Determine the cluster reset command

Reset the cluster **before every suite**, even when running multiple suites back-to-back. Resetting between suites guarantees each one starts from an identical clean baseline — no leftover Gateways, no leftover RBAC, no terminating namespaces racing with the harness's bootstrap. The reset is the expensive part (~30s); paying it per suite is cheap compared to chasing a flaky cross-suite interaction.

Check `MEMORY.md` for an entry named `project_local_cluster_reset` (or similar — search the index for "cluster reset" / "reset"). If present, read it and use its `reset` command verbatim.

If absent, **detect the cluster type** from `kubectl config current-context`:

- `orbstack` → OrbStack — reset: `orb delete -f k8s && orb start k8s`
- starts with `kind-` → kind — reset: `kind delete cluster --name <name> && kind create cluster --name <name>` (extract name from context after `kind-`)
- `minikube` → minikube — reset: `minikube delete && minikube start`
- starts with `k3d-` → k3d — reset: `k3d cluster delete <name> && k3d cluster create <name>`
- `docker-desktop` → Docker Desktop — ask the user how they want to reset (kubectl-namespace-purge is usually enough); no canonical CLI reset.
- anything else → ask the user: "I see context `<X>`. What command resets this cluster?"

Once you know the reset command, **save it to memory** under `memory/project_local_cluster_<type>.md` (e.g. `project_local_cluster_kind.md`) — matches the existing `project_local_cluster_orb.md` convention. Frontmatter: `type: project`. Body: cluster type, reset command, any notes (e.g. apiserver-ready timeout). Add a one-line entry to `MEMORY.md`'s index so the next invocation finds it on the index scan. Don't create a duplicate if a memory for this cluster type already exists — update the existing one instead.

For each reset: briefly tell the user one line ("Resetting <type> cluster with `<command>`"), then run with a generous timeout (`120000` ms / 2 min). Verify with `kubectl get nodes` afterwards; if the node isn't `Ready` within 60s, stop and report. Do this once at the start, and **again before every subsequent suite** in the user's selection.

## 3 — Bootstrap

**All Cargo suites** (ingress, gateway_api, dedicated_proxy, proxy_hot_reconfig, observability) bootstrap the cluster themselves via `coxswain-e2e`'s harness — no manual cluster setup. The bootstrap:
1. Detects cluster type (OrbStack vs kind).
2. Builds `coxswain:e2e` via `Dockerfile.e2e` — a 2-line COPY-only image wrapping the already-compiled binary (~5 s). The full production Dockerfile is NOT used locally.
3. For kind: `kind load docker-image` + starts cloud-provider-kind if not running.
4. Installs Gateway API CRDs, cert-manager, coxswain CRDs, and the Helm chart.

**Before running any Cargo suite, build the binary once:**
```bash
cargo build --release --bin coxswain
```
The bootstrap fails fast with a clear error if `target/release/coxswain` is absent. Re-run only when source changes — the Docker image rebuild (~5 s) and cluster state are separate.

**Conformance**: also handled automatically by the Cargo bootstrap infrastructure when you run the Go test. No manual Helm install or coxswain startup needed.

## 4 — Run each chosen suite

**ingress / gateway_api / dedicated_proxy / proxy_hot_reconfig**:

```bash
cargo test -p coxswain-e2e --test <suite> -- --test-threads=1
```

No `cargo build` prerequisite. Set `COXSWAIN_E2E_SKIP_BUILD=1` only if you know the `coxswain:e2e` image is already up to date in the local Docker daemon and you want to skip the build step.

Capture stdout+stderr to a tmpfile so a failure can be inspected without re-running. Set the Bash timeout to 600000 ms (10 min) — enough for ingress (~4 min), gateway_api (~6 min), dedicated_proxy (~3 min), proxy_hot_reconfig (~2 min) on a fresh cluster.

**conformance**:

```bash
cd conformance && go test -v -timeout 60m -run TestConformance -args \
  --organization=coxswain-labs --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version="$(git describe --tags --always)" \
  --report-output=reports/local-report.yaml
```

Timeout 3600000 ms (1 h) on the Bash call (go's `-timeout` is the inner ceiling). After the run, summarize by reading `conformance/reports/local-report.yaml` — call out `core.{Passed,Failed,Skipped}` and `extended.{Passed,Failed,Skipped}` per-profile.

There is no coxswain host process to stop after conformance — it runs in-cluster.

## 5 — Report results

One concise summary per suite. For Cargo suites: pass/fail counts (`grep -E "test result"`). For conformance: the per-profile table from the report file. Don't dump the full log unless the user asks.

If everything passes: end with one line ("All suites green").

## 6 — On failure, offer to debug

If any suite has at least one failing test, use `AskUserQuestion` (single-select) with:

- **Debug and fix** — investigate the failure, propose a fix, and apply it (recommended if the user is around to review).
- **Show details only** — print the failing tests' relevant log excerpts; don't change anything.
- **Stop here** — leave the working tree as-is.

If the user picks "Debug and fix", treat it as a normal bug-investigation flow: read the failing test, the production code paths it exercises, recent commits that might have introduced the regression, and propose a minimal fix. Don't push or commit without explicit user approval.

## Misc

- **Reset the cluster between every suite** (see step 2 — this is non-negotiable; deterministic baselines outweigh the ~30s per-reset cost).
- There is no host coxswain process to kill between suites — the in-cluster Helm release persists and is reused across tests within a suite. Between suites the cluster is reset anyway.
- If `kubectl get nodes` shows the cluster missing CRDs after a reset (suggesting `orb start k8s` returned before the apiserver was fully ready), poll for them up to 60 s before failing.
- On kind with local development: if LoadBalancer Services don't get IPs, ensure `cloud-provider-kind` is running: `go install sigs.k8s.io/cloud-provider-kind@latest && sudo cloud-provider-kind &`
- Hardware-key signing is irrelevant to e2e — don't try to commit anything from this skill.
