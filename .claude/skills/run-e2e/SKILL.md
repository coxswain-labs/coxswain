---
name: run-e2e
description: Reset the local Kubernetes cluster and run one or more of the coxswain by-plane e2e suites (routing, tls, traffic_policy, status_conditions, provisioning_rbac, resilience, observability, conformance) against it. Use when the user wants to validate a change against a live cluster — for example "run e2e", "test e2e", "run conformance", or "run the full e2e suite". Asks which suites to run; auto-detects the local cluster type (caches the reset command in memory after first use); reports a clean summary; offers to debug on failure.
---

Run one or more of the project's e2e suites against a freshly-reset local Kubernetes cluster. Follow these steps in order.

## 1 — Ask the user which suites to run

Use `AskUserQuestion` with `multiSelect: true` and these options (omit "Other"; the harness manages it):

Suites are organized by **behavior plane** (see each `tests/*.rs` header). `security.rs` carries no tests yet, so it is not offered.

- **routing** — data-plane: path/host/header/method/query/weighted matching, wildcard, named-port, default-backend, cross-namespace, timeouts, endpoint-serving exclusion, parent-ref port (Ingress + Gateway API). `cargo test -p coxswain-e2e --test routing -- --test-threads=1`
- **tls** — data-plane: SNI termination, cert rotation/fallback, cert-manager, BackendTLSPolicy, PROXY protocol, h2c, WebSocket (Ingress + Gateway API). `cargo test -p coxswain-e2e --test tls -- --test-threads=1`
- **traffic_policy** — data-plane: per-route/backend knobs (currently the connect-retry annotation; v0.3 knobs land here). `cargo test -p coxswain-e2e --test traffic_policy -- --test-threads=1`
- **status_conditions** — control-plane: Ingress LB status, Gateway Accepted/Programmed/observedGeneration, GatewayClass features, dedicated-mode (#211) status writer. `cargo test -p coxswain-e2e --test status_conditions -- --test-threads=1`
- **provisioning_rbac** — control-plane: dedicated-proxy provisioning + GC, per-namespace + cluster-wide RBAC, ReferenceGrant, dedicated traffic, and the read-only-proxy SA audit. `cargo test -p coxswain-e2e --test provisioning_rbac -- --test-threads=1`
- **resilience** — control-plane (serial): in-flight listener add/remove under load, crash-loop shared-pool fallback, controller-restart idempotency, mode migration. `cargo test -p coxswain-e2e --test resilience -- --test-threads=1`
- **observability** — cross-cutting: readiness/status (formerly `health.rs`), the `coxswain_proxy_*` / `coxswain_controller_*` Prometheus surface, the access-log contract, the problems aggregate, and the routing admin endpoints. `cargo test -p coxswain-e2e --test observability -- --test-threads=1`
- **conformance** — Gateway API Go conformance suite. Unlike the Cargo suites, conformance is NOT auto-bootstrapped — it needs the production multi-stage `Dockerfile` and conformance-specific Helm overrides. Use `scripts/setup-conformance.sh` to prepare the cluster, then `go test` runs against the deployed cluster. Setup is ~3–5 min on macOS (BoringSSL build); the test itself is ~2 min.

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

**All Cargo suites** (routing, tls, traffic_policy, status_conditions, provisioning_rbac, resilience, observability) bootstrap the cluster themselves via `coxswain-e2e`'s harness — no manual cluster setup. The bootstrap:
1. Detects cluster type (OrbStack vs kind).
2. Builds the `coxswain:e2e` Docker image. **On Linux CI runners**: `Dockerfile.e2e` — a 2-line COPY-only image wrapping the already-compiled binary (~5 s). **On macOS (or any non-Linux host)**: the production multi-stage `Dockerfile`, because the host produces Mach-O binaries that won't run in Linux containers. First macOS build is ~5–10 min for BoringSSL; cached afterwards. The harness picks the right Dockerfile at compile time via `cfg!(target_os = "linux")`.
3. For kind: `kind load docker-image` + starts cloud-provider-kind if not running.
4. Installs Gateway API CRDs, cert-manager, coxswain CRDs, and the Helm chart.

**Before running any Cargo suite, build the binary once:**
```bash
cargo build --release --bin coxswain
```
The bootstrap fails fast with a clear error if `target/release/coxswain` is absent. Re-run only when source changes.

**Conformance is NOT auto-bootstrapped.** Its setup differs from the Cargo suites (Ingress entry points off, gateway Service pre-declares ports 80/443/8080/8090/8443, controller status-address set to the LB IP). Use `scripts/setup-conformance.sh` — it wraps the documented procedure and takes a `--reset` flag for cluster-agnostic operation. See step 4.

## 4 — Run each chosen suite

**routing / tls / traffic_policy / status_conditions / provisioning_rbac / resilience / observability**:

```bash
cargo test -p coxswain-e2e --test <suite> -- --test-threads=1
```

No `cargo build` prerequisite. Set `COXSWAIN_E2E_SKIP_BUILD=1` only if you know the `coxswain:e2e` image is already up to date in the local Docker daemon and you want to skip the build step.

Capture stdout+stderr to a tmpfile so a failure can be inspected without re-running. Set the Bash timeout to 600000 ms (10 min) — Cargo suites typically run in 2–7 min each on a fresh cluster, so 10 min is generous headroom.

**conformance**:

```bash
bash scripts/setup-conformance.sh --reset '<your cluster reset command>'

cd conformance && go test -v -timeout 60m -run TestConformance -args \
  --organization=coxswain-labs --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version="$(git describe --tags --always)" \
  --report-output=reports/local-report.yaml
```

`scripts/setup-conformance.sh` does what the Cargo harness does NOT do for conformance: production multi-stage `Dockerfile` build (the conformance claim must validate the artifact GHCR publishes, never `Dockerfile.e2e`), Gateway API CRDs install, Helm install with the conformance overrides, LB IP discovery, and the status-address upgrade. Pass the reset command verbatim — the same one cached in memory from step 2. Pass `SKIP_RESET=1` to skip the reset entirely when iterating against an already-clean cluster.

Timeout 3600000 ms (1 h) on the Bash call for `go test` (go's `-timeout` is the inner ceiling). After the run, summarize by reading `conformance/reports/local-report.yaml` — call out `core.{Passed,Failed,Skipped}` and `extended.{Passed,Failed,Skipped}` per-profile.

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
- If `kubectl get nodes` shows the cluster not Ready after a reset (the apiserver returned before it was fully responsive), poll for it up to 60 s before failing.
- On kind with local development: if LoadBalancer Services don't get IPs, ensure `cloud-provider-kind` is running: `go install sigs.k8s.io/cloud-provider-kind@latest && sudo cloud-provider-kind &`
- Hardware-key signing is irrelevant to e2e — don't try to commit anything from this skill.
