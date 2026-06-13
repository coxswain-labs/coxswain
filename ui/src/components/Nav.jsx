import { useState, useEffect, useRef } from 'preact/hooks';
import { nav, navKeyFor } from '../router.js';

/**
 * Top navigation bar.
 *
 * On wide viewports the links are inline in the bar. On narrow viewports
 * (< 640 px) a hamburger button toggles a drop-down menu. The menu closes
 * automatically on navigation (hash change) and on Escape.
 *
 * Links are plain hash anchors so they're keyboard-navigable without custom
 * handlers; `activeScreen` is derived by the router so this component is
 * otherwise stateless with respect to routing.
 */
export function Nav({ activeScreen }) {
  const active    = navKeyFor(activeScreen);
  const [open, setOpen] = useState(false);
  const menuRef   = useRef(null);
  const btnRef    = useRef(null);

  // Close the menu on any hash navigation.
  useEffect(() => {
    const onHash = () => setOpen(false);
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  // Close on Escape, return focus to the hamburger button.
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => {
      if (e.key === 'Escape') {
        setOpen(false);
        btnRef.current?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);

  // Close when clicking outside the menu.
  useEffect(() => {
    if (!open) return;
    const onOutside = (e) => {
      if (!menuRef.current?.contains(e.target) && !btnRef.current?.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onOutside);
    return () => document.removeEventListener('mousedown', onOutside);
  }, [open]);

  const links = [
    { href: '#/fleet',    key: 'fleet',    label: 'Fleet' },
    { href: '#/health',   key: 'health',   label: 'Health' },
    { href: '#/events',   key: 'events',   label: 'Events' },
    { href: '#/problems', key: 'problems', label: 'Problems' },
  ];

  return (
    <header class="nav" role="banner">
      <a
        class="nav-brand"
        href="#/fleet"
        aria-label="Coxswain home"
        onClick={() => setOpen(false)}
      >
        <span class="nav-logo" aria-hidden="true">⛵</span>
        <span class="nav-name">Coxswain</span>
      </a>

      {/* Inline links — visible on wide screens */}
      <nav class="nav-links nav-links-inline" aria-label="Main navigation">
        {links.map((l) => (
          <NavLink key={l.key} href={l.href} active={active === l.key} label={l.label} />
        ))}
      </nav>

      {/* Hamburger — visible on narrow screens */}
      <button
        ref={btnRef}
        class="nav-hamburger"
        aria-label="Toggle navigation menu"
        aria-expanded={open}
        aria-controls="nav-dropdown"
        onClick={() => setOpen((o) => !o)}
      >
        <span class={`hamburger-icon${open ? ' open' : ''}`} aria-hidden="true" />
      </button>

      {/* Drop-down — shown when open on narrow screens */}
      {open && (
        <nav
          id="nav-dropdown"
          class="nav-dropdown"
          ref={menuRef}
          aria-label="Main navigation"
        >
          {links.map((l) => (
            <NavLink
              key={l.key}
              href={l.href}
              active={active === l.key}
              label={l.label}
              onClick={() => setOpen(false)}
              dropdown
            />
          ))}
        </nav>
      )}
    </header>
  );
}

function NavLink({ href, active, label, onClick, dropdown }) {
  return (
    <a
      href={href}
      class={`nav-link${active ? ' active' : ''}${dropdown ? ' nav-link-dropdown' : ''}`}
      aria-current={active ? 'page' : undefined}
      onClick={onClick}
    >
      {label}
    </a>
  );
}
