/**
 * Navigation breadcrumb trail.
 *
 * Each ancestor crumb is a link (clicking it goes up to that level); the current
 * item is plain text. Present on every page except the Dashboard home, so the
 * nav structure stays consistent as you descend — descending only appends a
 * crumb.
 *
 * @param {{ label: string, href?: string, onClick?: function }[]} items
 */
export function Breadcrumb({ items }) {
  return (
    <nav aria-label="breadcrumb" class="breadcrumb">
      {items.map((item, i) => (
        <>
          {i > 0 && <span aria-hidden="true">/</span>}
          {item.onClick ? (
            <a key={item.label} onClick={item.onClick}>{item.label}</a>
          ) : (
            <span key={item.label} style="color:var(--text)">{item.label}</span>
          )}
        </>
      ))}
    </nav>
  );
}
