import { Icon } from './Icon.jsx';

/**
 * Shared header search input with a leading magnifier icon. Presentational — the
 * owning screen supplies the value and change handler (see `useSearch`). Sits
 * alongside the type/namespace `FilterSelect` dropdowns, composing into one
 * control cluster that stacks to a full-width column on mobile.
 */
export function SearchBox({ value, onInput, placeholder = 'Search name or type…', label = 'Search by name or type' }) {
  return (
    <span class="search-wrap">
      <Icon name="search" size={15} />
      <input
        type="search"
        class="search-box"
        placeholder={placeholder}
        aria-label={label}
        value={value}
        onInput={onInput}
      />
    </span>
  );
}
