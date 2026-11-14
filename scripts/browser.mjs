// Shared helpers: start the lab's Vite server in-process and launch Chromium.
import { createServer } from 'vite';
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';

export const LAB_ROOT = fileURLToPath(new URL('..', import.meta.url));

export async function startServer() {
  const server = await createServer({
    configFile: fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
    server: { port: 3102, strictPort: false, host: '127.0.0.1' },
    logLevel: 'warn',
  });
  await server.listen();
  const url = server.resolvedUrls?.local[0];
  if (!url) throw new Error('Vite did not report a local URL');
  return { server, url };
}

/**
 * Uses Playwright's bundled Chromium; falls back to installed Google Chrome.
 * `headedFallback`: run the Chrome fallback with a visible window. Needed for
 * video: headless Chrome screencasts of pages with a viewport meta tag come
 * out ~90px short (grey band), while headed Chrome records the full frame.
 */
export async function launchBrowser({ headedFallback = false } = {}) {
  try {
    return await chromium.launch();
  } catch (err) {
    console.warn(`Bundled Chromium unavailable (${String(err).split('\n')[0]}); using installed Chrome${headedFallback ? ' (headed window)' : ''}.`);
    return chromium.launch({ channel: 'chrome', headless: !headedFallback });
  }
}

/** Fails the run if the page ever requests a non-loopback origin. */
export function guardNetwork(page, violations) {
  page.on('request', (req) => {
    const u = new URL(req.url());
    const local = ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname) || u.protocol === 'data:' || u.protocol === 'blob:';
    if (!local) violations.push(req.url());
  });
}
