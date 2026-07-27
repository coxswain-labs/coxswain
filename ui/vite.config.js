import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { mockApi } from './mock/plugin.js';

export default defineConfig({
  // `mockApi` only adds a dev middleware, so it's inert in `vite build`; the
  // production bundle never includes fixtures.
  plugins: [preact(), mockApi()],
  build: {
    // Stable, unhashed output filenames: `coxswain-admin` embeds them at fixed
    // paths via `include_str!` (`UI_HTML`/`UI_JS`/`UI_CSS` in `lib.rs`), and
    // serves them at fixed routes (`/`, `/app.js`, `/app.css`). A content hash
    // in the filename would break both — the whole bundle is already rebuilt
    // and redeployed atomically on every release, so cache-busting via
    // filename buys nothing the deploy doesn't already give for free (see the
    // `no-store` reasoning on the served responses in `aggregator/mod.rs`).
    //
    // No `viteSingleFile` here (deliberately, #669): CSP can only authorise
    // `script-src 'self'` for a *fetched* script — an inlined one has no
    // origin to authorise, so the only escape hatch would be a content hash
    // or `'unsafe-inline'` recomputed/rechecked on every build. Emitting a
    // real `app.js`/`app.css` at a stable path makes `'self'` true by
    // construction instead: the CSP header becomes a static string with
    // nothing to keep in sync.
    cssCodeSplit: false,
    assetsInlineLimit: Infinity, // keeps the one data: SVG icon inline in the CSS
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        assetFileNames: 'app.[ext]',
      },
    },
  },
});
