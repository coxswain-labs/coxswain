/**
 * Shared header search input. Presentational — the owning screen supplies the
 * value and change handler (see `useSearch`). Sits alongside the type/namespace
 * `FilterSelect` dropdowns, composing into one control cluster that stacks to a
 * full-width column on mobile.
 */
export function SearchBox({ value, onInput, placeholder = 'Search name or type…', label = 'Search by name or type' }) {
  return (
    <input
      type="search"
      class="search-box"
      placeholder={placeholder}
      aria-label={label}
      value={value}
      onInput={onInput}
    />
  );
}
