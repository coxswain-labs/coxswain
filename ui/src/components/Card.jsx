/** Clickable card that links to a detail screen. */
export function Card({ onClick, error, children }) {
  const handleKey = (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && onClick) {
      e.preventDefault();
      onClick();
    }
  };
  return (
    <div
      class={`card${error ? ' err' : ''}`}
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={handleKey}
      aria-pressed="false"
    >
      {children}
    </div>
  );
}

/** Two-slot card header: left = name/meta, right = badge. */
export function CardHeader({ name, badge }) {
  return (
    <div class="card-header">
      <div class="card-name">{name}</div>
      {badge}
    </div>
  );
}

/** Card footer: left = meta text, right = status dot. */
export function CardFooter({ left, right }) {
  return (
    <div class="card-foot">
      <span style="font-size:12px;color:var(--muted)">{left}</span>
      {right}
    </div>
  );
}

/** A responsive grid of cards. */
export function CardGrid({ children }) {
  return <div class="card-grid">{children}</div>;
}
