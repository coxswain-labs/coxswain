import { useState } from 'preact/hooks';
import { replaceQuery } from '../router.js';

/**
 * Search-box state for a screen: local text (drives filtering immediately)
 * mirrored to `?q=` via replaceState, so the search is shareable without
 * flooding back-button history with one entry per keystroke. Returns the raw
 * `search` value (for the input), the normalised `q` (for matching), and the
 * `onSearch` input handler.
 */
export function useSearch(query) {
  const [search, setSearch] = useState(() => query?.q ?? '');
  const onSearch = (e) => {
    const v = e.currentTarget.value;
    setSearch(v);
    replaceQuery({ q: v.trim() || null });
  };
  return { search, q: search.trim().toLowerCase(), onSearch };
}

/**
 * True when the query is empty, or is a substring of the entity's name or its
 * type label — so a name fragment or a type word ("controller", "gateway", …)
 * both narrow a list. `q` is expected already lower-cased; `typeLabel` must be
 * a lower-case literal.
 */
export function matchesSearch(name, typeLabel, q) {
  return q === '' || name.toLowerCase().includes(q) || typeLabel.includes(q);
}
