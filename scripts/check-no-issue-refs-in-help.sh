#!/usr/bin/env bash
# Keep internal issue numbers out of the CLI's user-facing `--help` output.
#
# clap's derive API turns the `///` doc comment on a `#[arg]` field into that
# flag's help text, and the one on a `#[command]` item into the subcommand's.
# So a `(#584)` written as a note-to-self for the next maintainer is not a
# comment at all — it ships, and every operator running `coxswain serve
# --help` reads a reference to a tracker they cannot open. 26 of them had
# accumulated this way before this gate existed.
#
# The rule is only about *help text*. Issue refs remain the norm everywhere
# else: commit footers, `//!` module headers, and ordinary `///` docs on
# non-clap items all keep them, because those are read by people with the
# tracker open.
#
# Scope is therefore "every doc comment inside a type deriving `Parser`, `Args`,
# `Subcommand`, or `ValueEnum`" — not "every doc comment followed by `#[arg]`".
# The first draft of this gate used the latter and silently missed two whole
# classes of help text, both of which clap renders from docs that carry no
# attribute of their own: a `#[derive(Subcommand)]` enum's variant docs become
# that subcommand's help, and a `#[derive(ValueEnum)]` enum's variant docs become
# the per-value descriptions under its flag. The `good/`+`bad/` fixtures pin all
# of them.
#
# Run from the repo root. Exits non-zero with a list of offending lines.

set -euo pipefail

roots=()
for d in crates/*/src; do
  [ -d "$d" ] && roots+=("$d")
done

# No clap sources at all (a trimmed fixture tree) is vacuously clean.
if [ ${#roots[@]} -eq 0 ]; then
  echo "OK: no crate sources to scan for issue refs in help text."
  exit 0
fi

# awk marks a "clap region" from a `#[derive(...)]` naming Parser/Args/Subcommand
# through the item's closing brace at column 0 (rustfmt guarantees that for a
# top-level item). Every `///` inside the region is help text: field docs,
# variant docs, and the item's own doc alike. The contiguous doc block directly
# above the derive is included too — for `#[derive(Parser)]` that block becomes
# the command's `about` line.
offenders=$(find "${roots[@]}" -name '*.rs' -type f -print0 2>/dev/null \
  | xargs -0 awk '
    function report(text, lineno) {
      if (text ~ /#[0-9]+/) print file ":" lineno ":" text
    }
    function flush_pending(render,   i) {
      if (render) for (i = 1; i <= pending_n; i++) report(pending[i], pending_ln[i])
      pending_n = 0
    }
    FNR == 1 { file = FILENAME; in_clap = 0; pending_n = 0 }
    {
      line = $0
      sub(/^[ \t]+/, "", line)

      if (in_clap) {
        if (line ~ /^\/\/\//) report(line, FNR)
        # rustfmt closes a top-level item with `}` in column 0.
        if ($0 ~ /^}/) in_clap = 0
        next
      }

      if (line ~ /^#\[derive\(/ && line ~ /(Parser|Args|Subcommand|ValueEnum)/) {
        flush_pending(1)
        in_clap = 1
        next
      }

      if (line ~ /^\/\/\//)  { pending_n++; pending[pending_n] = line; pending_ln[pending_n] = FNR }
      else if (line == "")   { }
      else                   { flush_pending(0) }
    }
  ' || true)

if [ -n "$offenders" ]; then
  count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
  echo "FAIL: $count issue reference(s) in clap help text:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  echo "" >&2
  echo "A '///' on a #[arg]/#[command] field IS the --help output an operator reads." >&2
  echo "Describe the behaviour instead; keep the issue ref in the commit footer." >&2
  exit 1
fi

echo "OK: no issue references in clap help text."
