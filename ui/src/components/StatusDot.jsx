/**
 * Reachability or health status indicator: a coloured dot + label.
 *
 * `state` ∈ "ok" | "err" | "warn" | "muted"
 *
 * The `aria-label` ensures screen readers announce the state text, not the
 * invisible dot.
 */
export function StatusDot({ state = 'ok', children, label }) {
  return (
    <span
      class={`dot ${state}`}
      aria-label={label ?? (typeof children === 'string' ? children : state)}
    >
      {children}
    </span>
  );
}

/** Convenience: reachable / unreachable status dot. */
export function ReachableDot({ reachable }) {
  return reachable
    ? <StatusDot state="ok" label="reachable">reachable</StatusDot>
    : <StatusDot state="err" label="unreachable">unreachable</StatusDot>;
}
