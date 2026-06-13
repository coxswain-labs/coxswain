#!/usr/bin/env bash
# Recapture mock fixtures from a live controller into mock/data/.
#
# Usage: BASE=http://localhost:8082 mock/capture.sh
#   (port-forward the controller admin port first:
#    kubectl -n coxswain-system port-forward deploy/coxswain-controller 8082:8082)
#
# Enumerates pods/gateways/ingresses from the list endpoints, then snapshots
# every list + detail endpoint the UI calls. A path maps to a filename by
# replacing '/' with '_' — the same scheme mock/plugin.js uses to resolve them.
set -euo pipefail
BASE="${BASE:-http://localhost:8082}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/data"
mkdir -p "$DIR"

save() { # $1 = api path
  local f="${1//\//_}"
  curl -fsS "$BASE$1" -o "$DIR/${f}.json" && echo "  $1"
}
jqpods() { python3 -c "import sys,json;[print(x['$2']) for x in json.load(sys.stdin).get('$1',[])]"; }
jqkeys() { python3 -c "import sys,json;[print(x['namespace']+'/'+x['name']) for x in json.load(sys.stdin).get('$1',[])]"; }

echo "top-level:"
for p in cluster proxies controllers gateways ingresses problems health; do save "/api/v1/$p"; done

echo "proxies:"
curl -fsS "$BASE/api/v1/proxies" | jqpods proxies pod_name | while read -r pod; do
  save "/api/v1/proxies/$pod"; save "/api/v1/proxies/$pod/routes"; save "/api/v1/proxies/$pod/health"
done

echo "controllers:"
curl -fsS "$BASE/api/v1/controllers" | jqpods controllers pod_name | while read -r pod; do
  save "/api/v1/controllers/$pod"; save "/api/v1/controllers/$pod/health"
done

echo "gateways + attached httproutes:"
curl -fsS "$BASE/api/v1/gateways" | jqkeys gateways | while read -r g; do
  save "/api/v1/gateways/$g"
  curl -fsS "$BASE/api/v1/gateways/$g" \
    | python3 -c "import sys,json;[print(r['namespace']+'/'+r['name']) for r in json.load(sys.stdin).get('attached_routes_list',[])]" \
    | while read -r r; do save "/api/v1/routes/httproute/$r"; done
done

echo "ingresses:"
curl -fsS "$BASE/api/v1/ingresses" | jqkeys ingresses | while read -r i; do
  save "/api/v1/routes/ingress/$i"
done

echo "done → $DIR"
