/**
 * Shared header filter dropdown. Presentational `<select>` styled to match the
 * search box and share its control row; the owning screen supplies the options,
 * current value, and change handler. Replaces the per-screen segmented pill so
 * every header control is one uniform type — three dropdowns/inputs that align
 * on desktop and stack to a full-width column on mobile with no special-casing.
 *
 * `options` is `[{ value, label }]`; `value` is the currently selected key.
 */
export function FilterSelect({ value, onChange, options, label }) {
  return (
    <select class="filter-select" aria-label={label} value={value} onChange={onChange}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}
