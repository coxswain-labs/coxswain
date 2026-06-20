#!/usr/bin/env bash
# Start the local "headroom" proxy (ghcr.io/chopratejas/headroom) and point the
# CURRENT shell at it by exporting ANTHROPIC_BASE_URL. It does NOT launch claude
# — run `claude` yourself afterwards and it will route through headroom.
#
# Must be SOURCED, not executed: a child process cannot set env vars in your
# shell. It is written to run correctly when sourced into bash or zsh.
#
#   source scripts/use-headroom.sh            # set this terminal up
#   source scripts/use-headroom.sh --update   # force re-pull :latest + recreate
#
# Suggested alias (~/.zshrc):
#   alias headroom="source $HOME/Workspace/projects/coxswain/scripts/use-headroom.sh"
#
# Idempotent: reuses an already-running headroom container instead of starting a
# second one (which would collide on the port), and waits until the proxy
# accepts connections before exporting the URL.

_use_headroom() {
  local image="ghcr.io/chopratejas/headroom:latest"
  local container="headroom" port="8787" update=0 waited=0
  local base="http://localhost:${port}"

  [ "${1:-}" = "--update" ] && update=1

  local cyan='\033[36m' red='\033[31m' reset='\033[0m'
  log() { printf "${cyan}[headroom]${reset} %s\n" "$*" >&2; }
  err() { printf "${red}[headroom] error:${reset} %s\n" "$*" >&2; }

  command -v docker >/dev/null 2>&1 || { err "docker not found on PATH"; return 1; }
  docker info >/dev/null 2>&1 || { err "docker daemon not reachable (is it running?)"; return 1; }

  if [ "$update" = 1 ]; then
    log "pulling ${image}"
    docker pull "$image" || { err "pull failed"; return 1; }
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi

  if [ "$(docker ps --filter "name=^/${container}$" --filter "status=running" --format '{{.Names}}' 2>/dev/null)" = "$container" ]; then
    log "reusing running container '${container}' on :${port}"
  else
    docker rm -f "$container" >/dev/null 2>&1 || true
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      log "pulling ${image}"
      docker pull "$image" || { err "pull failed"; return 1; }
    fi
    log "starting '${container}' on :${port}"
    docker run -d --name "$container" -p "${port}:${port}" "$image" >/dev/null \
      || { err "failed to start (is :${port} already in use by something else?)"; return 1; }
  fi

  # curl exits 0 on any HTTP response (even 404) — that means the port is live.
  log "waiting for ${base} ..."
  while [ "$waited" -lt 30 ]; do
    if curl -s -o /dev/null --max-time 2 "$base"; then
      export ANTHROPIC_BASE_URL="$base"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  err "headroom did not become ready on ${base} within 30s (check: docker logs ${container})"
  return 1
}

# Detect sourced-vs-executed across bash and zsh.
_uh_is_sourced() {
  if [ -n "${ZSH_VERSION:-}" ]; then
    case "${ZSH_EVAL_CONTEXT:-}" in *:file*) return 0 ;; *) return 1 ;; esac
  fi
  [ -n "${BASH_VERSION:-}" ] && [ "${BASH_SOURCE[0]}" != "${0}" ]
}

if _uh_is_sourced; then
  if _use_headroom "$@"; then
    printf '\033[32m[headroom]\033[0m this terminal now routes the Anthropic API via %s — run: claude\n' \
      "${ANTHROPIC_BASE_URL}" >&2
  fi
  unset -f _use_headroom _uh_is_sourced
  # End of a sourced file returns the last status automatically; nothing to exit.
else
  printf '\033[31m[headroom] error:\033[0m this script must be SOURCED to set ANTHROPIC_BASE_URL in your shell:\n' >&2
  printf '    source %s\n' "$0" >&2
  exit 1
fi
