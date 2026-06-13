/**
 * Status / category badge.
 *
 * `variant` maps to a CSS class that sets the background and foreground colour:
 *   leader | standby | shared | dedicated | ok | fail | warn | true | false |
 *   neutral | conflict | dead
 *
 * An `aria-label` is always set so screen readers announce the badge text
 * rather than relying on colour alone.
 */
export function Badge({ variant = 'neutral', children, label }) {
  return (
    <span
      class={`badge b-${variant}`}
      aria-label={label ?? (typeof children === 'string' ? children : undefined)}
      role="status"
    >
      {children}
    </span>
  );
}

/** Convenience: derive the badge variant from a `component` string. */
export function componentBadge(component) {
  if (component === 'controller')       return <Badge variant="neutral">controller</Badge>;
  if (component === 'dedicated-proxy')  return <Badge variant="dedicated">dedicated</Badge>;
  return <Badge variant="shared">shared</Badge>;
}

/** Convenience: derive the badge variant from a pool string ("shared"/"dedicated"). */
export function poolBadge(pool) {
  return pool === 'dedicated'
    ? <Badge variant="dedicated">dedicated</Badge>
    : <Badge variant="shared">shared</Badge>;
}
