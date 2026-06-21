#!/usr/bin/env bash
# Enforce CLAUDE.md's rule that crate-public fallible functions carry
# `#[must_use]`. A `pub fn ... -> Result<...>` whose result is dropped silently
# discards both the success value and the error; `Result` is `#[must_use]` on its
# own, but `clippy::double_must_use` then forbids a bare `#[must_use]`, so the
# convention is the message form `#[must_use = "<why>"]` — which both documents
# the consequence and satisfies the lint.
#
# Scope: bare `pub fn` only (the crate-public API surface) in the production
# crates. `pub(crate)`/`pub(super)` fns are intentionally NOT covered — the
# footgun is cross-crate. Skips `/tests/` paths and inline `#[cfg(test)]`
# modules. Handles multi-line signatures (return type on a later line).
#
# Run from the repo root. Exits non-zero with a list of offenders.

set -euo pipefail

CRATES=(
  coxswain-core
  coxswain-discovery
  coxswain-reflector
  coxswain-proxy
  coxswain-controller
  coxswain-admin
  coxswain-health
  coxswain-bin
)

python3 - "${CRATES[@]}" <<'PY'
import re
import sys
from pathlib import Path

FN_START_RE = re.compile(r"^\s*pub fn \w")
# A return type whose final path segment is `Result` (covers `Result`,
# `anyhow::Result`, `crate::x::Result`, etc.).
RESULT_RE = re.compile(r"->\s*(?:[\w]+::)*Result\b")
ATTR_RE = re.compile(r"^\s*#\[")
DOC_RE = re.compile(r"^\s*///")
MUSTUSE_RE = re.compile(r"#\[must_use")

offenders = []
total = 0
for crate in sys.argv[1:]:
    for path in sorted(Path(f"crates/{crate}/src").rglob("*.rs")):
        if "/tests/" in str(path):
            continue
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        # Cut at the first inline test module so test helpers aren't flagged.
        cut = len(lines)
        for i, line in enumerate(lines):
            if re.match(r"\s*#\[cfg\(test\)\]", line) or re.match(r"\s*mod tests\b", line):
                cut = i
                break
        for i, line in enumerate(lines[:cut]):
            if not FN_START_RE.match(line):
                continue
            # Accumulate the signature until the body `{` or trait-decl `;`.
            sig = line
            j = i
            while "{" not in sig and ";" not in sig and j + 1 < cut:
                j += 1
                sig += " " + lines[j].strip()
            # Trim at the first body-open brace so a `Result` inside the body
            # cannot be mistaken for the return type.
            sig = sig.split("{", 1)[0]
            if not RESULT_RE.search(sig):
                continue
            total += 1
            k = i - 1
            found = False
            while k >= 0 and (ATTR_RE.match(lines[k]) or DOC_RE.match(lines[k])):
                if MUSTUSE_RE.search(lines[k]):
                    found = True
                    break
                k -= 1
            if not found:
                offenders.append((path, i + 1))

if offenders:
    print(f"FAIL: {len(offenders)} Result-returning pub fn(s) missing #[must_use]:\n")
    for path, lineno in offenders:
        print(f"  {path}:{lineno}")
    print(
        "\nCLAUDE.md requires crate-public `pub fn ... -> Result` to carry "
        '`#[must_use = "<why>"]` (the message form — a bare `#[must_use]` trips '
        "clippy::double_must_use). Add it after the `///` doc, before the fn.",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"OK: {total} Result-returning pub fns in {len(sys.argv) - 1} crates all "
    f"carry #[must_use]."
)
PY
