#!/usr/bin/env bash
# Bring a local Kubernetes cluster to the state the Gateway API conformance
# suite expects: production coxswain image built and loaded, Gateway API
# CRDs at the pinned version installed, and the Helm release deployed with
# the conformance-specific overrides (Ingress API surface disabled; Gateway
# listener ports are allocated dynamically via per-Gateway VIP Services).
#
# After this script returns, run the conformance suite from the repo root:
#
#   cd conformance && go test -v -timeout 60m -run TestConformance \
#     -args --organization=coxswain-labs --project=coxswain \
#     --url=https://github.com/coxswain-labs/coxswain \
#     --version="$(git describe --tags --always)" \
#     --report-output=reports/local-report.yaml
#
# Usage:
#   scripts/setup-conformance.sh --reset '<cluster-reset-command>'
#
# Examples:
#   scripts/setup-conformance.sh --reset 'orb delete -f k8s && orb start k8s'
#   scripts/setup-conformance.sh --reset 'kind delete cluster --name kind && kind create cluster --name kind'
#   scripts/setup-conformance.sh --reset 'minikube delete && minikube start'
#
# The reset command is passed as one shell-evaluated string so the script
# stays cluster-agnostic. Pass an empty string to skip the reset (useful when
# iterating on Helm values against an already-clean cluster).
#
# Exits non-zero if any step fails. Conformance must validate the artifact
# published to GHCR, so this script ALWAYS builds with the production
# `Dockerfile` — never `Dockerfile.ci`.

set -euo pipefail

RESET_CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset)
      RESET_CMD="$2"
      shift 2
      ;;
    -h|--help)
      sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "${RESET_CMD-}" ] && [ -z "${SKIP_RESET-}" ]; then
  echo "error: --reset <cmd> is required (or set SKIP_RESET=1 to skip)" >&2
  echo "see scripts/setup-conformance.sh --help" >&2
  exit 2
fi

if [ ! -f .gateway-api-version ]; then
  echo "error: .gateway-api-version not found; run from the repo root" >&2
  exit 1
fi
GATEWAY_API_VERSION=$(cat .gateway-api-version)

if [ -n "$RESET_CMD" ]; then
  echo ">>> reset cluster: $RESET_CMD"
  bash -c "$RESET_CMD"

  # Wait for the apiserver to come back up.
  echo ">>> wait for node Ready"
  until kubectl get nodes 2>/dev/null | grep -q " Ready "; do
    sleep 2
  done
fi

echo ">>> build production Docker image (tag coxswain:e2e)"
docker build -t coxswain:e2e .

echo ">>> install Gateway API CRDs $GATEWAY_API_VERSION"
kubectl apply -f \
  "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

# Per-Gateway VIP Service type (#472). Each conformance Gateway gets its own VIP
# whose advertised listener port maps to a distinct internal port on the shared
# proxy — this is what makes cross-Gateway isolation (TLSRouteHostnameIntersection)
# pass. Default LoadBalancer suits CI (kind + cloud-provider-kind assigns a
# distinct IP per Service). On host-port-binding LBs (k3s/OrbStack klipper-lb)
# two VIPs sharing a port collide and stay <pending>, so run with
# VIP_SERVICE_TYPE=ClusterIP locally (OrbStack routes ClusterIPs to the host).
VIP_SERVICE_TYPE="${VIP_SERVICE_TYPE:-LoadBalancer}"
echo ">>> helm install coxswain (conformance overrides, vipServiceType=$VIP_SERVICE_TYPE)"
helm install coxswain charts/coxswain \
  --namespace coxswain-system --create-namespace \
  --set image.repository=coxswain \
  --set image.tag=e2e \
  --set image.pullPolicy=IfNotPresent \
  --set "proxy.shared.vipServiceType=$VIP_SERVICE_TYPE" \
  --set controller.ingress.enabled=false

echo ">>> wait for rollouts (timeout 180s)"
kubectl -n coxswain-system rollout status \
  deployment/coxswain-controller \
  deployment/coxswain-shared-proxy \
  --timeout=180s

# GatewayStaticAddresses (#260): the conformance test needs a "usable" IP that
# coxswain can actually bind. coxswain honors a requested IPAddress by provisioning
# that Gateway's VIP as a ClusterIP pinned to it (regardless of the global VIP
# type), so the usable address must be a free in-CIDR clusterIP. We probe one by
# creating a throwaway ClusterIP Service, reading its assigned clusterIP, and
# deleting it. The "unusable" IP is TEST-NET-1, outside any Service CIDR.
echo ">>> probing a free in-CIDR ClusterIP for GatewayStaticAddresses (#260)"
PROBE_SVC="coxswain-static-addr-probe"
kubectl -n coxswain-system create service clusterip "$PROBE_SVC" --tcp=80:80 >/dev/null
USABLE_ADDR=$(kubectl -n coxswain-system get svc "$PROBE_SVC" \
  -o jsonpath='{.spec.clusterIP}')
kubectl -n coxswain-system delete service "$PROBE_SVC" >/dev/null
echo ">>> usable=$USABLE_ADDR unusable=192.0.2.1"
STATIC_ADDR_ENV="CONFORMANCE_USABLE_ADDR=$USABLE_ADDR CONFORMANCE_UNUSABLE_ADDR=192.0.2.1 "

echo ">>> ready. Run conformance now:"
echo "    cd conformance && ${STATIC_ADDR_ENV}go test -v -timeout 60m -run TestConformance \\"
echo "      -args --organization=coxswain-labs --project=coxswain \\"
echo "      --url=https://github.com/coxswain-labs/coxswain \\"
echo "      --version=\"\$(git describe --tags --always)\" \\"
echo "      --report-output=reports/local-report.yaml"
