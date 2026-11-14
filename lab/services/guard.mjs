/**
 * Target guard for the instrumented agent.
 *
 * The agent never supplies a URL. It supplies a method and a path; the
 * harness joins the path to ONE allow-listed lab origin and then re-checks the
 * result. Anything that could change the origin (scheme, protocol-relative
 * "//host", backslashes, "@", control characters, encoded slashes) is refused.
 */

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', 'localhost']);

/**
 * Build a guard for one lab origin.
 * @param {string} origin e.g. "http://127.0.0.1:41234" or "http://honeypot:8080"
 * @param {{ allowContainerHosts?: string[] }} [opts]
 */
export function createGuard(origin, opts = {}) {
  const base = new URL(origin);
  const allowedHosts = new Set([...LOOPBACK_HOSTS, ...(opts.allowContainerHosts ?? [])]);
  if (base.protocol !== 'http:') throw new Error('lab origin must be plain http');
  if (base.username || base.password) throw new Error('lab origin must not carry credentials');
  if (!allowedHosts.has(base.hostname)) throw new Error(`lab origin host ${base.hostname} is not an allow-listed lab host`);
  if (!base.port) throw new Error('lab origin must name an explicit port');
  if (base.pathname !== '/' || base.search || base.hash) throw new Error('lab origin must be a bare origin');

  return {
    origin: base.origin,
    /**
     * @param {string} method
     * @param {unknown} path
     * @returns {{ ok: true, url: string } | { ok: false, reason: string }}
     */
    check(method, path) {
      if (method !== 'GET' && method !== 'POST') return { ok: false, reason: `method ${method} not allowed` };
      if (typeof path !== 'string') return { ok: false, reason: 'path must be a string' };
      if (path.length === 0 || path.length > 512) return { ok: false, reason: 'path length out of range' };
      if (!path.startsWith('/') || path.startsWith('//')) return { ok: false, reason: 'path must be absolute (start with a single /)' };
      // eslint-disable-next-line no-control-regex
      if (/[\\@\s\u0000-\u001f\u007f]/.test(path)) return { ok: false, reason: 'path contains forbidden characters' };
      if (/%2f|%5c|%40|%00/i.test(path)) return { ok: false, reason: 'path contains encoded separators' };
      let url;
      try {
        url = new URL(path, base);
      } catch {
        return { ok: false, reason: 'path does not parse' };
      }
      if (url.origin !== base.origin) return { ok: false, reason: `resolved origin ${url.origin} is not the lab origin` };
      return { ok: true, url: url.href };
    },
  };
}
