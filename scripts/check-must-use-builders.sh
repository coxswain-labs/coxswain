#!/usr/bin/env bash
# Enforce CLAUDE.md's rule that consumable-return helpers carry `#[must_use]`:
# chainable builder methods (`pub fn with_*(...) -> Self`) and boolean predicates
# (`pub fn is_/has_/can_(&self, ...) -> bool`). Ignoring a builder's returned
# `Self` silently drops the mutation; ignoring a predicate's bool is almost always
# a bug. Plain constructors (`new`/`parse`/`from_*`) are intentionally NOT covered
# — `#[must_use]` there is noise, not a footgun.
#
# Scope: non-test source in the production crates (excludes `coxswain-e2e`).
# Skips `/tests/` paths and inline `#[cfg(test)]` modules. Single-line signatures
# only (a builder whose `-> Self` wraps to a later line is not matched — keep
# builder/predicate signatures on one line).
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

BUILDER_RE = re.compile(
    r"^\s*pub(\(crate\)|\(super\))? fn (?P<name>with_\w+)\s*\(.*\)\s*->\s*Self\b"
)
PRED_RE = re.compile(
    r"^\s*pub(\(crate\)|\(super\))? fn (?P<name>(is|has|can)_\w+)\s*\(\s*&?\s*self\b.*\)\s*->\s*bool\b"
)
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
            m = BUILDER_RE.match(line) or PRED_RE.match(line)
            if not m:
                continue
            total += 1
            # Walk back over the contiguous attribute + doc-comment block for
            # `#[must_use]` (it may sit either side of the `///` doc).
            j = i - 1
            found = False
            while j >= 0 and (ATTR_RE.match(lines[j]) or DOC_RE.match(lines[j])):
                if MUSTUSE_RE.search(lines[j]):
                    found = True
                    break
                j -= 1
            if not found:
                offenders.append((path, i + 1, m.group("name")))

if offenders:
    print(f"FAIL: {len(offenders)} builder/predicate(s) missing #[must_use]:\n")
    for path, lineno, name in offenders:
        print(f"  {path}:{lineno}: {name}")
    print(
        "\nCLAUDE.md requires chainable `with_*(...) -> Self` builders and "
        "`is_/has_/can_(&self, ...) -> bool` predicates to carry `#[must_use]`. "
        "Add the attribute (after the `///` doc, before the fn).",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"OK: {total} builders/predicates in {len(sys.argv) - 1} crates all carry "
    f"#[must_use]."
)
PY
