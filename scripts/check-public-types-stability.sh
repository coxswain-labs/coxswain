#!/usr/bin/env bash
# Enforce CLAUDE.md's API stability annotation policy: every non-test
# `pub enum` / `pub struct` in the workspace's production crates must
# carry `#[non_exhaustive]` on the contiguous attribute block immediately
# preceding the declaration, OR a `// intentionally open: <reason>`
# comment within the three lines preceding the declaration.
#
# The "intentionally open" opt-out is reserved for types downstream
# consumers must construct via field literal (e.g. CLI-derived config
# structs `coxswain-bin/src/main.rs` assembles, or routing-table predicate
# structs `coxswain-reflector::gateway_api` assembles per HTTPRoute match).
# Every such opt-out must carry the rationale comment; the script flags
# any opt-out missing one.
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

PUB_RE = re.compile(r"^\s*pub (enum|struct) (?P<name>\w+)")
ATTR_RE = re.compile(r"^\s*#\[")
OPEN_RE = re.compile(r"^\s*//.*intentionally open")

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
        for i, line in enumerate(lines):
            m = PUB_RE.match(line)
            if not m:
                continue
            total += 1
            # Walk backwards over the contiguous block of attribute lines
            # (`#[...]`) and rationale comments (`// intentionally open: ...`)
            # immediately preceding this declaration.
            j = i - 1
            block = []
            while j >= 0 and (ATTR_RE.match(lines[j]) or OPEN_RE.match(lines[j])):
                block.append(lines[j])
                j -= 1
            has_ne = any("non_exhaustive" in a for a in block)
            has_open = any("intentionally open" in a for a in block)
            if has_ne and has_open:
                offenders.append((path, i + 1, m.group("name"),
                                  "both #[non_exhaustive] AND `// intentionally open:` present — choose one"))
            elif not has_ne and not has_open:
                offenders.append((path, i + 1, m.group("name"),
                                  "missing #[non_exhaustive] (or `// intentionally open: <reason>`)"))

if offenders:
    print(f"FAIL: {len(offenders)} public type(s) violate the API stability policy:\n")
    for path, lineno, name, msg in offenders:
        print(f"  {path}:{lineno}: {name}: {msg}")
    print(
        "\nCLAUDE.md's API stability annotations section requires every "
        "non-test `pub enum`/`pub struct` to carry `#[non_exhaustive]`, "
        "unless it is intentionally constructable downstream via field "
        "literal — in which case a `// intentionally open: <reason>` "
        "comment must accompany it. See #243 (# Errors backfill) and "
        "#244 (# Panics audit) for the related doc-coverage follow-ups.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"OK: {total} public types in {len(sys.argv) - 1} crates all carry "
      f"#[non_exhaustive] or a `// intentionally open:` rationale.")
PY
