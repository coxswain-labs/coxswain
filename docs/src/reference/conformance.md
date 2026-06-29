# Gateway API Conformance

Coxswain is tested against the official [Gateway API conformance suite](https://gateway-api.sigs.k8s.io/concepts/conformance/) on every release. This page explains what is claimed, how to run the suite locally, and how to interpret the report.

## Claimed profiles and features

Coxswain claims three conformance profiles:

| Profile | Description |
|---------|-------------|
| `GATEWAY-HTTP` | HTTPRoute routing, header/path manipulation, redirects, mirroring, timeouts |
| `GATEWAY-GRPC` | GRPCRoute routing |
| `GATEWAY-TLS` | TLSRoute passthrough, terminate, and mixed-mode listeners |

Extended features are listed in `conformance/main_test.go` (`opts.SupportedFeatures`) and kept in sync with the Rust `SUPPORTED_FEATURES` constant in `crates/coxswain-controller/src/controller/gateway_class_status.rs`. The `scripts/check-supported-features.sh` script enforces this parity in CI — a mismatch is a build error.

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

`reports/local-report.yaml` is gitignored. A CI-generated report for each release is published to `conformance/reports/`.

A full run takes 8–15 minutes on a clean cluster.

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

1. Add the `features.SupportXxx` constant to `opts.SupportedFeatures` in `conformance/main_test.go`.
2. Add the bare feature name (e.g. `"TLSRouteModeTerminate"`) to the sorted `SUPPORTED_FEATURES` slice in `crates/coxswain-controller/src/controller/gateway_class_status.rs`.
3. Run `scripts/check-supported-features.sh` — it must report the feature count in sync.
4. Add or update e2e tests for the new behaviour (`crates/coxswain-e2e/tests/`).

## CI

The conformance suite runs in CI against a kind cluster with cloud-provider-kind on every PR. The CI job uses `Dockerfile.ci` (Linux-only fast path) and `VIP_SERVICE_TYPE=LoadBalancer` (the default). Reports for merged releases are committed to `conformance/reports/`.
