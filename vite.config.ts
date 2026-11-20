import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
import { dashboardControl } from './cloud/gcp/dashboard-control.mjs';

/**
 * Standalone Vite config for the Deception Lab. It is deliberately separate
 * from the World Monitor config: no PWA, no analytics, no proxies, and it is
 * not part of the production build or the Vercel deployment.
 */
export default defineConfig({
  plugins: [dashboardControl()],
  root: fileURLToPath(new URL('.', import.meta.url)),
  base: './',
  publicDir: false,
  server: {
    host: '127.0.0.1',
    port: 3100,
    strictPort: true,
    open: false,
    // Same-origin bridge to the swarm hub (SSE + state) so the dashboard never
    // needs cross-origin access to another local port. Loopback only.
    proxy: {
      // One loopback tunnel port per lab VM (see LABS in cloud/gcp/dashboard-control.mjs).
      '/hub/vm1': { target: 'http://127.0.0.1:18092', changeOrigin: false, ws: false, rewrite: (p) => p.replace(/^\/hub\/vm1/, '') },
      '/hub/vm2': { target: 'http://127.0.0.1:18093', changeOrigin: false, ws: false, rewrite: (p) => p.replace(/^\/hub\/vm2/, '') },
      '^/hub(?=/|$)': { target: 'http://127.0.0.1:18092', changeOrigin: false, ws: false, rewrite: (p) => p.replace(/^\/hub/, '') },
    },
  },
  preview: { host: '127.0.0.1', port: 3101, strictPort: true },
  build: { outDir: 'dist', emptyOutDir: true, target: 'es2022', sourcemap: true },
});
