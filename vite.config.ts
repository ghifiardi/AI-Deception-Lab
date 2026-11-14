import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

/**
 * Standalone Vite config for the Deception Lab. It is deliberately separate
 * from the World Monitor config: no PWA, no analytics, no proxies, and it is
 * not part of the production build or the Vercel deployment.
 */
export default defineConfig({
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
      '/hub': { target: 'http://127.0.0.1:18092', changeOrigin: false, ws: false, rewrite: (p) => p.replace(/^\/hub/, '') },
    },
  },
  preview: { host: '127.0.0.1', port: 3101, strictPort: true },
  build: { outDir: 'dist', emptyOutDir: true, target: 'es2022', sourcemap: true },
});
