import { useEffect, useRef, useState } from 'preact/hooks';

/**
 * Track an element's pixel height in state via a `ResizeObserver`.
 *
 * Used to dock a scrolling table's sticky header directly below a pinned
 * controls bar: the bar's height isn't fixed — it grows when filters wrap and
 * shrinks when the tab bar or pager are absent — so a measured value beats a
 * hard-coded offset. Feed the returned height into a CSS variable the header's
 * `top` reads.
 *
 * @returns {[import('preact').RefObject<HTMLElement>, number]} `[ref, heightPx]`
 */
export function useElementHeight() {
  const ref = useRef(null);
  const [height, setHeight] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const update = () => setHeight(el.offsetHeight);
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, height];
}
