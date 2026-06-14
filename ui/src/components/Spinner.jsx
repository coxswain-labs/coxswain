export function Spinner({ label = 'Loading…' }) {
  return (
    <div class="state-box" role="status" aria-live="polite">
      <div class="spinner" aria-hidden="true" />
      <div>{label}</div>
    </div>
  );
}

export function ErrorState({ error }) {
  return (
    <div class="state-box" role="alert">
      <div class="error-msg">⚠ {error?.message ?? String(error)}</div>
    </div>
  );
}

export function EmptyState({ message = 'Nothing here.' }) {
  return (
    <div class="empty-box" aria-live="polite">
      {message}
    </div>
  );
}
