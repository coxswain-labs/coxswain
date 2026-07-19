# Gateway API Conformance

Coxswain is tested against the official [Gateway API conformance suite](https://gateway-api.sigs.k8s.io/concepts/conformance/) on every release. This page explains what is claimed, how to run the suite locally, and how to interpret the report.

## Claimed profiles and features

Coxswain claims up to five conformance profiles. Which ones are claimed depends
on the **installed Gateway API CRDs**, not on a compiled-in list — a profile
whose route kind is absent cannot be claimed, because the suite would create
that kind and fail:

| Profile | Requires | Description |
|---------|----------|-------------|
| `GATEWAY-HTTP` | always | HTTPRoute routing, header/path manipulation, redirects, mirroring, timeouts |
| `GATEWAY-GRPC` | `GRPCRoute` | GRPCRoute routing |
| `GATEWAY-TLS` | `TLSRoute` (v1.5+) | TLSRoute passthrough, terminate, and mixed-mode listeners |
| `GATEWAY-TCP` | `TCPRoute` (v1.6+) | TCPRoute routing |
| `GATEWAY-UDP` | `UDPRoute` (v1.6+) | UDPRoute routing |

So a run against Gateway API v1.4 claims two profiles (HTTP and GRPC — it has
no TLSRoute, TCPRoute or UDPRoute CRD) and a run against v1.6 claims all five.
See the [capability matrix](capability-matrix.md).

Extended features are listed in `conformance/features.go` (`gatedFeatures`) and kept in sync with the Rust `SUPPORTED_FEATURES` table in `crates/coxswain-controller/src/controller/gateway_class_status.rs`. The `scripts/check-supported-features.sh` script enforces this parity in CI — a mismatch is a build error. Each entry carries what the cluster must install for the declaration to be true, so both sides shrink identically on an older CRD set.

## Prerequisites

- Go toolchain (same version as `go.mod` in `conformance/`).
- A local Kubernetes cluster with `kubectl` pointing at it. See cluster-specific notes below.
- The production Docker image (`coxswain:e2e`). The setup script builds it.

## Setup

`scripts/setup-conformance.sh` resets the cluster, builds the image, installs the Helm chart with conformance-specific overrides (Ingress API surface disabled; Gateway listener ports allocated dynamically via per-Gateway VIP Services), and probes for the free in-CIDR ClusterIP needed by `GatewayStaticAddresses` tests.

```bash
bash scripts/setup-conformance.sh --reset '<cluster-reset-command>'
```

Run the command from the repository root. The `--reset` argument is a shell string that is evaluated to tear down and recreate the cluster.

### Cluster-specific reset commands

| Cluster | Reset command |
|---------|---------------|
| OrbStack | `orb delete -f k8s && orb start k8s` |
| kind | `kind delete cluster --name kind && kind create cluster --name kind` |
| minikube | `minikube delete && minikube start` |

### VIP Service type

Each conformance Gateway gets its own per-Gateway VIP Service. The type must match what the cluster's LoadBalancer controller supports:

| Cluster | Required setting | Why |
|---------|-----------------|-----|
| OrbStack | `VIP_SERVICE_TYPE=ClusterIP` | OrbStack uses k3s klipper-lb (host-port binding). Two Services on the same port collide and stay `<pending>`. OrbStack routes ClusterIPs to the host, so ClusterIP works. |
| kind (CI) | _(default)_ `LoadBalancer` | cloud-provider-kind assigns a distinct external IP per Service. |
| minikube | `VIP_SERVICE_TYPE=ClusterIP` | Same klipper-lb issue as OrbStack on single-node clusters. |

Set the variable before the setup script:

```bash
# OrbStack
VIP_SERVICE_TYPE=ClusterIP bash scripts/setup-conformance.sh --reset 'orb delete -f k8s && orb start k8s'

# kind (CI default — no override needed)
bash scripts/setup-conformance.sh --reset 'kind delete cluster --name kind && kind create cluster --name kind'
```

!!! warning
    Forgetting `VIP_SERVICE_TYPE=ClusterIP` on OrbStack causes all per-test Gateway Services to stay `<pending>`, leaving Gateways without IP addresses. Every conformance test that opens a connection then times out waiting for the address — the suite takes hours instead of minutes and all traffic tests fail.

### Skip reset (iterate on a running cluster)

Pass `SKIP_RESET=1` to reuse the current cluster and skip the image build if `coxswain:e2e` is already current:

```bash
SKIP_RESET=1 COXSWAIN_E2E_SKIP_BUILD=1 bash scripts/setup-conformance.sh
```

## Running the suite

After setup completes, the script prints the exact command to run, including the probed `CONFORMANCE_USABLE_ADDR`. Copy and run it:

```bash
cd conformance && CONFORMANCE_USABLE_ADDR=<ip> CONFORMANCE_UNUSABLE_ADDR=192.0.2.1 \
  go test -v -timeout 60m -run TestConformance \
  -args --organization=coxswain-labs --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version="$(git describe --tags --always)" \
  --report-output=reports/local-report.yaml
```

Or use the wrapper, which resolves the upstream report path for you:

```bash
bash scripts/run-conformance.sh
```

A loose `reports/*.yaml` is gitignored. Published reports live under
`conformance/reports/<report-dir>/coxswain-coxswain/` and are tracked — see
`conformance/reports/README.md` for the layout.

A full run takes 8–15 minutes on a clean cluster.

## Running against an older Gateway API version

Coxswain supports several Gateway API versions (see the
[capability matrix](capability-matrix.md)), and publishes a report for each.
Because Gateway API CRDs are cluster-scoped singletons, **every version needs
its own fresh cluster**:

```bash
for v in $(scripts/gateway-api-versions.sh --versions); do
  kind create cluster --name coxswain-conf
  bash scripts/setup-conformance.sh --gateway-api-version "$v" --reset ''
  bash scripts/run-conformance.sh   --gateway-api-version "$v"
  kind delete cluster --name coxswain-conf
done
```

`run-conformance.sh` pins the Go suite module to the matching version in a
temporary copy of `conformance/`, so no tracked file is modified — a pinned
`go.mod` left behind would look like an intentional downgrade of the project's
own dependency.

Expect fewer profiles and a shorter `supportedFeatures` list on older versions.
That is the mechanism working. The versions come from
`.gateway-api-versions.json`, whose `"latest": true` entry is also what drives
codegen, e2e and kubeconform; `scripts/check-gateway-api-versions.sh` validates
the manifest.

The same matrix runs in CI via the `Conformance reports (all Gateway API versions)`
workflow, which is `workflow_dispatch` only and emits one combined,
repo-tree-shaped artifact.

### Running a subset of tests

Pass a `-test.run` filter to run only the tests matching a pattern:

```bash
# Only TLSRoute tests
cd conformance && go test -v -timeout 10m -run 'TestConformance/TLSRoute' \
  -args --organization=coxswain-labs --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version="$(git describe --tags --always)"

# A single named test
go test -v -timeout 5m -run 'TestConformance/HTTPRouteRequestMirror' \
  -args --organization=coxswain-labs --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version="$(git describe --tags --always)"
```

Note: `--report-output` is optional for targeted runs.

### Verify compilation without a cluster

```bash
cd conformance && go vet ./...
```

## Reading the report

The YAML report records pass/fail/skip per test, the claimed feature set, and the Gateway API version under test. Key fields:

```yaml
results:
  - name: HTTPRouteRequestMirror
    result: passed
  - name: TLSRouteMixedTerminationSameNamespace
    result: passed
  - name: TLSRouteListenerMixedTerminationNotSupported
    result: skipped    # skipped because SupportTLSRouteModeMixed is claimed
```

A test is **skipped** (not failed) when the implementation explicitly claims the feature that supersedes it — for example, claiming `TLSRouteModeMixed` causes `TLSRouteListenerMixedTerminationNotSupported` to be skipped, since implementations that support mixed mode must accept (not reject) such configurations.

## Adding a new claimed feature

1. Add a `{name: features.SupportXxx}` entry to the `gatedFeatures` table in `conformance/features.go`, with a `requiresKind` or `requiresField` guard if the CRD kind or schema field is absent below the newest supported Gateway API version.
2. Add the bare feature name (e.g. `"TLSRouteModeTerminate"`) to the sorted `SUPPORTED_FEATURES` slice in `crates/coxswain-controller/src/controller/gateway_class_status.rs`.
3. Run `scripts/check-supported-features.sh` — it must report the feature count in sync.
4. Add or update e2e tests for the new behaviour (`crates/coxswain-e2e/tests/`).

## CI

The conformance suite runs in CI against a kind cluster with cloud-provider-kind on every PR, at the pinned latest Gateway API version. The CI job uses `Dockerfile.ci` (Linux-only fast path) and `VIP_SERVICE_TYPE=LoadBalancer` (the default).

Reports for every supported version are produced by the `Conformance reports (all Gateway API versions)` workflow (`workflow_dispatch`), which uploads one bundle laid out as the repo tree.

Nothing in CI commits reports back to this repository. Run that workflow with `publish_release: true` and the bundle is attached to a GitHub release instead — release assets never expire, whereas Actions artifacts are capped at 90 days on a public repo. Publishing upstream is then: download the release asset, unpack at the root of a `kubernetes-sigs/gateway-api` checkout, open a PR.

Every report is traceable to its source tree. `implementation.version` and the report filename both carry a `git describe --tags --always --long` string, so the commit ref is present even for a build on an exact release tag, and the release body names the full source commit.

The release workflow separately attaches the latest-version report to each product release, where conformance also acts as a **gate** — a build that fails conformance is never published.
