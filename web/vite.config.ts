import { fileURLToPath } from 'node:url';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';
import { app } from './vite-plugin-app';
import { integrity } from './vite-plugin-integrity';

const wasm = fileURLToPath(new URL('./src/lib/wasm/sigylo_wasm_bg.wasm', import.meta.url));

export default defineConfig({
  plugins: [svelte(), app(), integrity(wasm)],
  build: {
    target: 'es2022',
    // The polyfill would be an inline script, which the CSP forbids.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8787' },
  },
  test: {
    include: ['tests/**/*.test.ts'],
  },
});
