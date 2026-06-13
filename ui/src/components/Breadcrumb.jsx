/**
 * Navigation breadcrumb trail.
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
