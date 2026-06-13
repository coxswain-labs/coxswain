/** Labelled surface panel, used in two-column layouts. */
export function Panel({ title, children }) {
  return (
    <div class="panel">
      {title && <div class="panel-title">{title}</div>}
      {children}
    </div>
  );
}
