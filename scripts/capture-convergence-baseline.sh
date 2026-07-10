#!/usr/bin/env bash
# Capture the #513 real full-rebuild convergence baseline from a live cluster.
#
# This is Layer 2 of the #513 convergence benchmark (see DEVELOPMENT.md
# "Convergence benchmarks"): Layer 1 (criterion, `cargo bench -p
# coxswain-reflector --bench convergence` / `-p coxswain-core --bench
# routing`) sweeps synthetic cluster-size curves; this script instead scrapes
# the per-stage histograms — `reconcile_debounce_seconds`,
# `routing_table_rebuild_duration_seconds`, `snapshot_build_seconds`,
# `snapshot_apply_seconds`, `ack_latency_seconds` — off a REAL running
# controller + proxy, after a real workload (a conformance run is the
# canonical driver: the largest realistic Gateway API route set this repo
# exercises; an e2e run works too, just against a smaller topology).
#
# Deliberately prints to stdout only — it does NOT write into the repo.
# Captured numbers are environment-dependent (OrbStack vs CI kind, machine
# noise); committing a snapshot would go stale and mislead the moment
# hardware or cluster state changes. Post the output as a comment on the
# tracking issue (#513) instead — #511/#512/#383 cite that comment as the
# baseline reference, not a repo file.
#
# Usage:
#   1. Run a workload against the cluster (the conformance suite, or an e2e
#      suite) so the controller/proxy have processed real reconciles.
#   2. scripts/capture-convergence-baseline.sh
#
# Requires: kubectl pointed at the target cluster, coxswain installed in the
# coxswain-system namespace (Helm release name `coxswain` — the default from
# charts/coxswain).
#
# The controller runs 2 replicas under leader election, and the discovery
# server's Stream RPC is leader-gated (#531) -- a standby replica's
# build_snapshot()/handle_ack() never run, so snapshot_build_seconds and
# ack_latency_seconds are only ever observed on the LEADER. Port-forwarding
# `svc/coxswain-controller` lands on whichever replica the Service picks,
# non-deterministically -- so this script finds the leader pod explicitly
# rather than trusting the Service to route there.

set -euo pipefail

NAMESPACE="coxswain-system"
LEADER_LABEL="app.kubernetes.io/component=controller,discovery.coxswain-labs.dev/leader=true"
PROXY_SVC="svc/coxswain-shared-proxy-internal"
ADMIN_PORT=8082

controller_pf_port=""
proxy_pf_port=""
controller_pf_pid=""
proxy_pf_pid=""

cleanup() {
  [[ -n "$controller_pf_pid" ]] && kill "$controller_pf_pid" 2>/dev/null || true
  [[ -n "$proxy_pf_pid" ]] && kill "$proxy_pf_pid" 2>/dev/null || true
}
trap cleanup EXIT

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

port_forward() {
  local target="$1" local_port="$2"
  kubectl port-forward -n "$NAMESPACE" "$target" "${local_port}:${ADMIN_PORT}" \
    >/dev/null 2>&1 &
  echo $!
}

wait_for_port() {
  local port="$1"
  for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:${port}/metrics" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "timed out waiting for port-forward on :${port}" >&2
  return 1
}

leader_pod="$(kubectl get pods -n "$NAMESPACE" -l "$LEADER_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
if [[ -z "$leader_pod" ]]; then
  echo "could not find a controller pod labelled discovery.coxswain-labs.dev/leader=true -- is coxswain deployed and healthy?" >&2
  exit 1
fi

controller_pf_port="$(free_port)"
proxy_pf_port="$(free_port)"
controller_pf_pid="$(port_forward "pod/${leader_pod}" "$controller_pf_port")"
proxy_pf_pid="$(port_forward "$PROXY_SVC" "$proxy_pf_port")"
wait_for_port "$controller_pf_port"
wait_for_port "$proxy_pf_port"

# `name_count`/`name_sum` -> mean seconds per observation. `awk` prints
# nothing (silent zero) if the series was never emitted (e.g. no ack yet).
extract_histogram_mean() {
  local body="$1" name="$2"
  awk -v name="$name" '
    $0 ~ "^" name "_count" { count = $NF }
    $0 ~ "^" name "_sum"   { sum = $NF }
    END {
      if (count != "" && count+0 > 0) {
        printf "%s: mean=%.6fs  n=%d\n", name, sum/count, count
      } else {
        printf "%s: no observations yet\n", name
      }
    }
  ' <<<"$body"
}

echo "# Convergence baseline captured $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# Cluster: $(kubectl config current-context 2>/dev/null || echo unknown)"
echo "# Leading controller replica: ${leader_pod}"
echo

controller_metrics="$(curl -sf "http://127.0.0.1:${controller_pf_port}/metrics")"
proxy_metrics="$(curl -sf "http://127.0.0.1:${proxy_pf_port}/metrics")"

echo "## Controller stages (coxswain_controller_*, coxswain_discovery_*)"
extract_histogram_mean "$controller_metrics" "coxswain_controller_reconcile_debounce_seconds"
extract_histogram_mean "$controller_metrics" "coxswain_controller_routing_table_rebuild_duration_seconds"
extract_histogram_mean "$controller_metrics" "coxswain_discovery_snapshot_build_seconds"
extract_histogram_mean "$controller_metrics" "coxswain_discovery_ack_latency_seconds"
echo
echo "## Proxy stage (coxswain_discovery_*)"
extract_histogram_mean "$proxy_metrics" "coxswain_discovery_snapshot_apply_seconds"
