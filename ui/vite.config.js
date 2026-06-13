import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  plugins: [preact(), viteSingleFile()],
  build: {
    // Singlefile inlines everything; no need for a manifest.
    cssCodeSplit: false,
    assetsInlineLimit: Infinity,
  },
});
