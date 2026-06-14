import { useState, useEffect, useCallback, useRef } from 'preact/hooks';

/**
 * Fetch data from `fetcher()` on mount and whenever `deps` change.
 *
 * Returns `{ data, loading, error, refetch }`.
 * - `data`    — the resolved value, or `null` before the first successful fetch.
 * - `loading` — `true` during an in-flight request.
 * - `error`   — the last Error, or `null` on success.
 * - `refetch` — call to manually re-trigger the fetch.
 *
 * Stale responses are discarded: if the component unmounts or `deps` change
 * before a response arrives, the result is ignored.
 */
export function useApi(fetcher, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  // Increment to trigger a re-fetch without changing deps.
  const [rev, setRev] = useState(0);

  const refetch = useCallback(() => setRev((r) => r + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetcher()
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setError(null);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err);
          setLoading(false);
        }
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, rev]);

  return { data, loading, error, refetch };
}
