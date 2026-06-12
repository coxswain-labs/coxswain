#!/usr/bin/env bash
# Bring a local Kubernetes cluster to the state the Gateway API conformance
# suite expects: production coxswain image built and loaded, Gateway API
# CRDs at the pinned version installed, and the Helm release deployed with
# the conformance-specific overrides (Ingress entry points disabled; gateway
# Service pre-declares ports 80/443/8080/8090/8443 so every listener in the
# conformance fixtures gets a reachable LB endpoint).
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
# `Dockerfile` — never `Dockerfile.e2e`.

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

echo ">>> helm install coxswain (conformance overrides)"
helm install coxswain charts/coxswain \
  --namespace coxswain-system --create-namespace \
  --set image.repository=coxswain \
  --set image.tag=e2e \
  --set image.pullPolicy=IfNotPresent \
  --set proxy.http.enabled=false \
  --set proxy.https.enabled=false \
  --set 'service.gateway.additionalPorts[0].name=gw-http,service.gateway.additionalPorts[0].port=80,service.gateway.additionalPorts[0].targetPort=80,service.gateway.additionalPorts[0].protocol=TCP' \
  --set 'service.gateway.additionalPorts[1].name=gw-https,service.gateway.additionalPorts[1].port=443,service.gateway.additionalPorts[1].targetPort=443,service.gateway.additionalPorts[1].protocol=TCP' \
  --set 'service.gateway.additionalPorts[2].name=gw-8080,service.gateway.additionalPorts[2].port=8080,service.gateway.additionalPorts[2].targetPort=8080,service.gateway.additionalPorts[2].protocol=TCP' \
  --set 'service.gateway.additionalPorts[3].name=gw-8090,service.gateway.additionalPorts[3].port=8090,service.gateway.additionalPorts[3].targetPort=8090,service.gateway.additionalPorts[3].protocol=TCP' \
  --set 'service.gateway.additionalPorts[4].name=gw-8443,service.gateway.additionalPorts[4].port=8443,service.gateway.additionalPorts[4].targetPort=8443,service.gateway.additionalPorts[4].protocol=TCP'

echo ">>> wait for LoadBalancer IP"
until [ -n "$(kubectl -n coxswain-system get svc coxswain-shared-proxy \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)" ]; do
  sleep 2
done
LB_IP=$(kubectl -n coxswain-system get svc coxswain-shared-proxy \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo ">>> LB IP: $LB_IP"

echo ">>> helm upgrade with --status-address=$LB_IP"
helm upgrade coxswain charts/coxswain --namespace coxswain-system \
  --reuse-values --set controller.statusAddress="$LB_IP"

echo ">>> wait for rollouts (timeout 180s)"
kubectl -n coxswain-system rollout status \
  deployment/coxswain-controller \
  deployment/coxswain-shared-proxy \
  --timeout=180s

echo ">>> ready. Run conformance now:"
echo "    cd conformance && go test -v -timeout 60m -run TestConformance \\"
echo "      -args --organization=coxswain-labs --project=coxswain \\"
echo "      --url=https://github.com/coxswain-labs/coxswain \\"
echo "      --version=\"\$(git describe --tags --always)\" \\"
echo "      --report-output=reports/local-report.yaml"
