#!/usr/bin/env bash
# Enforce CLAUDE.md's "an MSG_PEEK retry loop waits via PeekBackoff, never
# readable()" rule (issues #614, #628).
#
# `MSG_PEEK` leaves the peeked bytes in the kernel queue, so `TcpStream::peek`
# never reports `EWOULDBLOCK` while any byte is queued — and tokio clears
# read-readiness *only* on `EWOULDBLOCK` (`runtime/io/registration.rs::async_io`).
# A successful short peek therefore leaves READABLE set, so `readable()` returns
# `Poll::Ready` instantly, forever: the loop busy-spins a core until its timeout.
# It is remotely triggerable with one byte — measured on #628, a single peer that
# sent one byte and stalled drove 1,368,449 iterations in one second, saturating a
# worker on the accept path before any routing or auth ran.
#
# This was written the obvious way twice: #614 (`passthrough.rs::peek_sni`) and
# #628 (`accept.rs::peek_and_drain_proxy_header`). `edge/peek.rs::PeekBackoff` now
# holds the wait once; this gate stops a third peek loop from reaching for
# readiness again.
#
# Scope: `crates/coxswain-proxy/src/edge` — every socket peek in the product lives
# there. The rule is per-file: a file that peeks must not also await readiness.
# `BinaryHeap::peek()` (coxswain-core) and `Peekable::peek()` (coxswain-e2e) are
# out of scope by construction, not by luck. Comment lines are skipped, since
# `peek.rs` names `readable()` deliberately to document why it is wrong.
#
# The peek pattern covers `peek_from` / `poll_peek` too, not just `peek`:
# `UdpSocket::peek_from` is `async_io(Interest::READABLE, || io.peek_from(buf))`,
# i.e. the same MSG_PEEK-never-clears-readiness shape, and `edge/udp.rs` — the
# highest-event-rate plane in the product — is in scope. It uses consuming
# `recv_from` today; this keeps it that way. `.peekable()` is deliberately not
# matched (iterator adapter, not a socket peek).
#
# A file needing a genuine `readable()` + `try_read()` loop (which *does* return
# `EWOULDBLOCK`, so readiness works there) must not also peek — split it.
#
# Run from the repo root. Exits non-zero with a list of offending sites.

set -euo pipefail

roots=(crates/coxswain-proxy/src/edge)
offenders=""

while IFS= read -r -d '' path; do
  hits=$(awk '
    /^[[:space:]]*\/\// { next }
    /\.(poll_)?peek(_from)?[[:space:]]*\(/ { peeks = 1 }
    /\.readable[[:space:]]*\(/ { readable[++n] = FILENAME ":" FNR ":" $0 }
    END {
      if (peeks)
        for (i = 1; i <= n; i++) print readable[i]
    }
  ' "$path")
  if [ -n "$hits" ]; then
    offenders+="$hits"$'\n'
  fi
done < <(find "${roots[@]}" -name '*.rs' -print0)

offenders=$(printf '%s' "$offenders" | grep -v '^$' || true)

if [ -n "$offenders" ]; then
  count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
  echo "FAIL: $count readable() wait(s) in a file that peeks:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  echo "" >&2
  echo "MSG_PEEK leaves bytes in the kernel queue, so peek never returns EWOULDBLOCK and" >&2
  echo "tokio never clears read-readiness: readable() returns instantly forever and spins a" >&2
  echo "core until the timeout — remotely triggerable with one byte. Wait via" >&2
  echo "crate::edge::peek::PeekBackoff instead. See CLAUDE.md and [[project_peek_loop_needs_readable]]." >&2
  exit 1
fi

echo "OK: no readable() waits in peeking files under ${roots[*]}."
