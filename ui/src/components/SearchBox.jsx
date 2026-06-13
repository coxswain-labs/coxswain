/**
 * Shared header search input. Presentational — the owning screen supplies the
 * value and change handler (see `useSearch`). Sits to the right of a screen's
 * segmented filter so the two compose into one right-aligned control cluster.
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
