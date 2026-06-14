import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { mockApi } from './mock/plugin.js';

export default defineConfig({
  // `mockApi` only adds a dev middleware, so it's inert in `vite build`; the
  // production single-file bundle never includes fixtures.
  plugins: [preact(), viteSingleFile(), mockApi()],
  build: {
    // Singlefile inlines everything; no need for a manifest.
    cssCodeSplit: false,
    assetsInlineLimit: Infinity,
  },
});
