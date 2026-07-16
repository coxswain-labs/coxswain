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
#     --contact=https://github.com/coxswain-labs/coxswain/issues \
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
  --set controller.coxswainImage=coxswain:e2e \
  --set "proxy.shared.vipServiceType=$VIP_SERVICE_TYPE" \
  --set controller.ingress.enabled=false

echo ">>> wait for rollouts (timeout 180s)"
kubectl -n coxswain-system rollout status \
  deployment/coxswain-controller \
  deployment/coxswain-shared-proxy \
  --timeout=180s

# GatewayStaticAddresses (#260, #558): the conformance test needs a "usable" IP
# that coxswain can actually bind. coxswain honors a requested IPAddress by
# provisioning that Gateway's VIP as a ClusterIP pinned to it (regardless of the
# global VIP type), so the usable address must be a free in-CIDR clusterIP.
#
# The IP must come from the CIDR's *static lower band*: since k8s 1.26
# (ServiceIPStaticSubrange, GA) the allocator draws random assignments from the
# upper band only, so a lower-band IP can never be stolen by the ~25 Services
# the conformance suite creates from its base manifests AFTER this probe runs.
# Probing a dynamically-assigned IP (the old approach) left exactly that window
# and flaked the test on small service CIDRs (#558; OrbStack's /25 gave a
# per-run collision chance of several percent).
#
# The first IP of the range is the `kubernetes` Service; we validate candidates
# base+2.. by creating a Service pinned to each until the apiserver accepts one
# (skipping conventional fixed IPs like kube-dns at base+10). The "unusable" IP
# is TEST-NET-1, outside any Service CIDR.
echo ">>> selecting a free static-band ClusterIP for GatewayStaticAddresses (#260, #558)"
PROBE_SVC="coxswain-static-addr-probe"
K8S_SVC_IP=$(kubectl -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}')
BASE_PREFIX="${K8S_SVC_IP%.*}"
BASE_LAST="${K8S_SVC_IP##*.}"
USABLE_ADDR=""
for off in $(seq 1 14); do
  CAND="$BASE_PREFIX.$((BASE_LAST + off))"
  if kubectl -n coxswain-system create service clusterip "$PROBE_SVC" \
       --tcp=80:80 --clusterip="$CAND" >/dev/null 2>&1; then
    kubectl -n coxswain-system delete service "$PROBE_SVC" >/dev/null
    USABLE_ADDR="$CAND"
    break
  fi
done
if [ -z "$USABLE_ADDR" ]; then
  echo "error: no free static-band clusterIP found near $K8S_SVC_IP" >&2
  exit 1
fi
echo ">>> usable=$USABLE_ADDR unusable=192.0.2.1"
STATIC_ADDR_ENV="CONFORMANCE_USABLE_ADDR=$USABLE_ADDR CONFORMANCE_UNUSABLE_ADDR=192.0.2.1 "

echo ">>> ready. Run conformance now:"
echo "    cd conformance && ${STATIC_ADDR_ENV}go test -v -timeout 60m -run TestConformance \\"
echo "      -args --organization=coxswain-labs --project=coxswain \\"
echo "      --url=https://github.com/coxswain-labs/coxswain \\"
echo "      --version=\"\$(git describe --tags --always)\" \\"
echo "      --contact=https://github.com/coxswain-labs/coxswain/issues \\"
echo "      --report-output=reports/local-report.yaml"
