import { useState, useRef, useEffect, useMemo } from 'preact/hooks';

/** Show the search input only when the option list is long enough to need it,
 *  so low-cardinality filters (e.g. the 4-option type filter) get a plain
 *  clickable list and only longer namespace lists get a search box. */
const SEARCH_ABOVE = 5;

/**
 * Searchable single-select filter (combobox).
 *
 * A `.filter-select`-styled trigger that opens a popover with a scrollable,
 * filtered option list (and a search input once the list passes `SEARCH_ABOVE`)
 * — the single filter control across the app, replacing the native `<select>`
 * so the open experience is consistent and scales to high-cardinality lists
 * (namespaces). Closes on select, Escape, or an outside click. `onChange`
 * receives the selected **value** directly (not a DOM event).
 *
 * When a non-default option is selected (any value other than `clearValue`,
 * which defaults to the first option — typically the "All …" entry), a small
 * `×` button appears to clear the filter in one click.
 *
 * @param {{value:string,label:string}[]} options
 * @param {string} value                  currently-selected option value
 * @param {(value:string)=>void} onChange
 * @param {string} label                  aria-label for the trigger
 * @param {string} [clearValue]           value the `×` resets to (default: first option)
 */
export function ComboFilter({ options, value, onChange, label, clearValue }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const rootRef = useRef(null);
  const inputRef = useRef(null);

  const searchable = options.length > SEARCH_ABOVE;
  const selected = options.find((o) => o.value === value) ?? options[0];
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle ? options.filter((o) => o.label.toLowerCase().includes(needle)) : options;
  }, [q, options]);

  // While open: focus the search (when present), and close on Escape or an
  // outside click.
  useEffect(() => {
    if (!open) return undefined;
    if (searchable) inputRef.current?.focus();
    const onKey = (e) => {
      if (e.key === 'Escape') setOpen(false);
    };
    const onOutside = (e) => {
      if (!rootRef.current?.contains(e.target)) setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onOutside);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onOutside);
    };
  }, [open]);

  const resetTo = clearValue ?? options[0]?.value;
  const clearable = resetTo != null && value !== resetTo;

  const pick = (v) => {
    onChange(v);
    setOpen(false);
    setQ('');
  };

  return (
    <div class="combo" ref={rootRef}>
      <button
        type="button"
        class={`filter-select combo-trigger${clearable ? ' clearable' : ''}`}
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        {selected?.label ?? ''}
      </button>
      {clearable && (
        <button
          type="button"
          class="combo-clear"
          aria-label={`Clear ${label}`}
          onClick={(e) => {
            e.stopPropagation();
            onChange(resetTo);
            setOpen(false);
            setQ('');
          }}
        >
          ×
        </button>
      )}
      {open && (
        <div class="combo-popover" role="listbox" aria-label={label}>
          {searchable && (
            <input
              ref={inputRef}
              type="search"
              class="combo-search"
              placeholder="Filter…"
              value={q}
              onInput={(e) => setQ(e.currentTarget.value)}
              aria-label={`${label} search`}
            />
          )}
          <div class="combo-list">
            {filtered.length === 0 ? (
              <div class="combo-empty">No matches</div>
            ) : (
              filtered.map((o) => (
                <button
                  type="button"
                  key={o.value}
                  role="option"
                  aria-selected={o.value === value}
                  class={`combo-option${o.value === value ? ' active' : ''}`}
                  onClick={() => pick(o.value)}
                >
                  {o.label}
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
