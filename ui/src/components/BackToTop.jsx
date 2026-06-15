import { useState, useEffect } from 'preact/hooks';
import { Icon } from './Icon.jsx';

/**
 * Floating "back to top" button, shown once the page has scrolled past
 * `threshold` px; clicking smooth-scrolls to the top. Rendered once at the app
 * root so any long screen (the per-proxy route table especially) gets it — it's
 * a no-op on short pages (never crosses the threshold) and on the bounded-scroll
 * routing tabs (the window itself doesn't scroll there).
 */
export function BackToTop({ threshold = 600 }) {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const onScroll = () => setShow(window.scrollY > threshold);
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, [threshold]);

  if (!show) return null;
  return (
    <button
      type="button"
      class="back-to-top"
      aria-label="Back to top"
      title="Back to top"
      onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
    >
      <Icon name="chevron-up" size={20} />
    </button>
  );
}
