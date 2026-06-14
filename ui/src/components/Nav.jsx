import { useState, useEffect, useRef } from 'preact/hooks';
import { nav, navKeyFor } from '../router.js';
import { useSSE } from '../hooks/useSSE.js';
import { useApi } from '../hooks/useApi.js';
import { getHealth, getCluster } from '../api/endpoints.js';
import { VersionInfo } from './VersionInfo.jsx';

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
  const { connected } = useSSE('/api/v1/events');
  // Deployment versions surfaced in the nav's info popover (and the drawer foot
  // on mobile). One-time fetches — they don't change at runtime. Coxswain's
  // version comes from the serving controller's /health; the Kubernetes server
  // version from /cluster.
  // Normalize to a bare version (no leading "v") at the source — Coxswain's
  // /health reports "0.1.0" while Kubernetes' GitVersion is "v1.31.2"; the
  // display adds exactly one "v" prefix, so values must not already carry one.
  const stripV = (s) => (s ? String(s).replace(/^v/i, '') : s);
  const version    = stripV(useApi(getHealth).data?.version);
  const k8sVersion = stripV(useApi(getCluster).data?.kubernetes_version);
  const versionRows = [
    { label: 'Coxswain', value: version },
    { label: 'Kubernetes', value: k8sVersion },
  ];
  const [open, setOpen] = useState(false);
  const menuRef   = useRef(null);
  const btnRef    = useRef(null);

  // Lock body scroll while drawer is open.
  useEffect(() => {
    document.body.style.overflow = open ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [open]);

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
    { href: '#/dashboard', key: 'dashboard', label: 'Dashboard' },
    { href: '#/fleet',     key: 'fleet',     label: 'Fleet' },
    { href: '#/routing',   key: 'routing',   label: 'Routing' },
    { href: '#/events',    key: 'events',    label: 'Events' },
  ];

  return (
    <header class="nav" role="banner">
      <a
        class="nav-brand"
        href="#/dashboard"
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

      {/* Version info popover + stream status — inline on wide screens, the info
          icon sits just left of the live indicator. */}
      <VersionInfo rows={versionRows} class="version-info-inline" />
      <SSEStatus connected={connected} class="nav-status-inline" />

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

      {/* Full-screen drawer — shown when open on narrow screens */}
      {open && (
        <div class="nav-drawer-backdrop" onClick={() => setOpen(false)} aria-hidden="true" />
      )}
      <nav
        id="nav-drawer"
        class={`nav-drawer${open ? ' open' : ''}`}
        ref={menuRef}
        aria-label="Main navigation"
        aria-hidden={!open}
      >
        <div class="nav-drawer-header">
          <span class="nav-brand" style="pointer-events:none">
            <span class="nav-logo" aria-hidden="true">⛵</span>
            <span class="nav-name">Coxswain</span>
          </span>
          <button
            class="nav-drawer-close"
            aria-label="Close navigation menu"
            onClick={() => setOpen(false)}
          >
            <span class="hamburger-icon open" aria-hidden="true" />
          </button>
        </div>
        <div class="nav-drawer-links">
          {links.map((l) => (
            <NavLink
              key={l.key}
              href={l.href}
              active={active === l.key}
              label={l.label}
              onClick={() => setOpen(false)}
              drawer
            />
          ))}
        </div>
        {/* On mobile the drawer has room, so versions show inline (no popover);
            the stream status sits to the right. */}
        <div class="nav-drawer-footer">
          <div class="drawer-versions">
            {versionRows.filter((r) => r.value).map((r) => (
              <div class="drawer-version" key={r.label}>
                <span class="drawer-version-label">{r.label}</span>
                <code>v{r.value}</code>
              </div>
            ))}
          </div>
          <SSEStatus connected={connected} />
        </div>
      </nav>
    </header>
  );
}

/** Single global stream-connection indicator: Live (green) / Disconnected
 *  (red). Rendered in the nav bar on wide screens and in the drawer foot on
 *  narrow ones — never repeated per screen. */
function SSEStatus({ connected, class: className = '' }) {
  return (
    <span
      class={`nav-status ${connected ? 'live' : 'offline'} ${className}`}
      role="status"
      aria-label={connected ? 'Live — receiving events' : 'Disconnected from event stream'}
      title={connected ? 'Live — receiving events' : 'Disconnected'}
    >
      <span class="nav-status-dot" aria-hidden="true" />
      {connected ? 'Live' : 'Disconnected'}
    </span>
  );
}

function NavLink({ href, active, label, onClick, drawer }) {
  return (
    <a
      href={href}
      class={`nav-link${active ? ' active' : ''}${drawer ? ' nav-link-drawer' : ''}`}
      aria-current={active ? 'page' : undefined}
      onClick={onClick}
    >
      {label}
    </a>
  );
}
