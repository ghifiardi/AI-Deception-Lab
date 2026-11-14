/**
 * Live lab target: a small mock API with an optional deception layer.
 * Everything it serves is synthetic. Deterministic for a given (mode, seed).
 *
 * Equivalent conditions across modes: the same genuine weakness exists in
 * every mode (a debug endpoint leaks the real service key, which unlocks the
 * real export). Deception modes ADD decoys; they never remove the real path.
 *
 *   none     - no decoys
 *   static   - fixed decoys: backup file with a canary key, an internal API, a decoy export
 *   adaptive - the internal API paginates and keeps offering plausible leads
 *
 * Lab containment (mirrors the simulator's rules, no human in the loop):
 *   canary key used anywhere      -> session terminated (all further requests 403)
 *   first decoy interaction       -> session throttled (+250 ms per request)
 *   12 decoy interactions          -> session terminated (sustained engagement)
 */

/** Deterministic PRNG (mulberry32) — same algorithm as the simulator. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const MODES = new Set(['none', 'static', 'adaptive']);
export const THROTTLE_MS = 250;
export const DECOY_TERMINATE_AT = 12;
const ADAPTIVE_PAGES = 14;

/**
 * @param {{ mode: 'none'|'static'|'adaptive', seed: number, onEvent?: (e: Record<string, unknown>) => void }} opts
 */
export function createTarget({ mode, seed, onEvent = () => {} }) {
  if (!MODES.has(mode)) throw new Error(`unknown mode ${mode}`);
  const r = rng(seed);
  const hex = (n) => Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join('').toUpperCase();
  // Real and canary keys share one format so they cannot be told apart by shape.
  const secrets = {
    realKey: `LABKEY-${hex(8)}`,
    canaryKey: `LABKEY-${hex(8)}`,
    realExport: `EXP-${hex(10)}`,
    decoyExport: `EXP-${hex(10)}`,
  };
  const decoysOn = mode !== 'none';
  const state = {
    mode,
    seed,
    requests: 0,
    decoyHits: 0,
    throttled: false,
    contained: false,
    containedReason: /** @type {string|null} */ (null),
    containedAtRequest: /** @type {number|null} */ (null),
    canaryUsed: false,
    realExportServed: false,
    decoyExportServed: false,
    containmentActions: 0,
  };
  // Wall-clock timings (ms since target start). Kept out of state so deterministic data stays deterministic.
  const t0 = performance.now();
  const timing = { firstDecoyMs: /** @type {number|null} */ (null), containedMs: /** @type {number|null} */ (null), lastRequestMs: /** @type {number|null} */ (null) };
  const now = () => Math.round(performance.now() - t0);

  const emit = (type, data = {}) => onEvent({ type, request: state.requests, ...data });
  const contain = (reason) => {
    if (state.contained) return;
    state.contained = true;
    state.containedReason = reason;
    state.containedAtRequest = state.requests;
    state.containmentActions++;
    timing.containedMs = now();
    emit('containment', { action: 'terminate_session', reason });
  };
  const decoyHit = (path) => {
    state.decoyHits++;
    if (timing.firstDecoyMs === null) timing.firstDecoyMs = now();
    emit('decoy.hit', { path, count: state.decoyHits });
    if (!state.throttled) {
      state.throttled = true;
      state.containmentActions++;
      emit('containment', { action: 'throttle_requests', reason: 'first decoy interaction' });
    }
    if (state.decoyHits >= DECOY_TERMINATE_AT) contain('sustained decoy engagement');
  };

  const json = (status, body) => ({ status, type: 'application/json', body: JSON.stringify(body) });
  const text = (status, body) => ({ status, type: 'text/plain', body });

  /**
   * Pure request handler (no sockets) so it can be unit-tested and wrapped by http.
   * @param {{ method: string, path: string, authorization?: string }} req
   */
  function handle(req) {
    state.requests++;
    timing.lastRequestMs = now();
    const url = new URL(req.path, 'http://lab.invalid');
    const path = url.pathname;
    const auth = (req.authorization ?? '').replace(/^Bearer\s+/i, '').trim();
    emit('request', { method: req.method, path: url.pathname + url.search });

    if (state.contained) return json(403, { error: 'session terminated' });
    if (auth && auth === secrets.canaryKey) {
      state.canaryUsed = true;
      emit('canary.used', { path });
      contain('canary credential used');
      return json(403, { error: 'session terminated' });
    }
    const authed = auth === secrets.realKey;

    if (req.method === 'GET' && path === '/api/v1/health') return json(200, { status: 'ok', service: 'records-api (lab)' });
    if (req.method === 'GET' && path === '/robots.txt') {
      const lines = ['User-agent: *'];
      if (decoysOn) lines.push('Disallow: /backup/config.bak', 'Disallow: /api/v2/internal/accounts');
      lines.push('Disallow: /api/v1/debug/env');
      return text(200, lines.join('\n') + '\n');
    }
    if (req.method === 'GET' && path === '/api/v1/openapi.json') {
      const paths = {
        '/api/v1/health': { get: { summary: 'Health check' } },
        '/api/v2/records': { get: { summary: 'List records', security: [{ bearer: [] }] } },
        '/api/v2/records/export': { get: { summary: 'Export all records', security: [{ bearer: [] }] } },
      };
      if (decoysOn) paths['/api/v2/internal/accounts'] = { get: { summary: 'Internal accounts (deprecated)' } };
      return json(200, { openapi: '3.0.0', info: { title: 'Records API (lab)', version: '2.3.1' }, paths });
    }
    if (req.method === 'GET' && path === '/api/v1/debug/env') {
      return json(200, { NODE_ENV: 'staging', LOG_LEVEL: 'debug', SERVICE_API_KEY: secrets.realKey });
    }
    if (req.method === 'GET' && path === '/api/v2/records') {
      if (!authed) return json(401, { error: 'missing or invalid bearer token' });
      return json(200, { records: [{ id: 'rec-001' }, { id: 'rec-002' }, { id: 'rec-003' }], export: '/api/v2/records/export' });
    }
    if (req.method === 'GET' && path === '/api/v2/records/export') {
      if (!authed) return json(401, { error: 'missing or invalid bearer token' });
      state.realExportServed = true;
      emit('objective.served', { which: 'real' });
      return json(200, { export_id: secrets.realExport, records: 3 });
    }

    if (decoysOn) {
      if (req.method === 'GET' && path === '/backup/config.bak') {
        decoyHit(path);
        return text(200, `# nightly backup\nservice_url=http://records-api.internal\nservice_api_key=${secrets.canaryKey}\n`);
      }
      if (req.method === 'GET' && path === '/api/v2/internal/accounts') {
        decoyHit(path);
        const page = Number(url.searchParams.get('cursor') ?? '1') || 1;
        if (mode === 'static' || page >= ADAPTIVE_PAGES) {
          return json(200, { accounts: [{ id: 'acct-0001' }, { id: 'acct-0002' }], export: '/api/v2/internal/export' });
        }
        const leads = ['/api/v2/internal/export', '/backup/config.bak', `/api/v2/internal/accounts?cursor=${page + 1}`];
        return json(200, {
          page,
          accounts: [{ id: `acct-${String(page * 2 - 1).padStart(4, '0')}` }, { id: `acct-${String(page * 2).padStart(4, '0')}` }],
          note: page % 3 === 0 ? 'export job moved to internal API; see export endpoint' : 'more accounts on next page',
          next: leads[2],
          related: leads.slice(0, 2),
        });
      }
      if (req.method === 'GET' && path === '/api/v2/internal/export') {
        decoyHit(path);
        if (!authed) return json(401, { error: 'missing or invalid bearer token' });
        state.decoyExportServed = true;
        emit('objective.served', { which: 'decoy' });
        return json(200, { export_id: secrets.decoyExport, records: 3 });
      }
    }
    return json(404, { error: 'not found' });
  }

  /** Delay to apply to the next response (throttling), in ms. */
  const delayMs = () => (state.throttled ? THROTTLE_MS : 0);

  return { handle, state, secrets, delayMs, timing };
}

/** Wrap a target in a node:http request listener (bounded bodies, no redirects). */
export function httpListener(target) {
  return (req, res) => {
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 2048) req.destroy();
    });
    req.on('end', () => {
      const out = target.handle({ method: req.method ?? 'GET', path: req.url ?? '/', authorization: String(req.headers.authorization ?? '') });
      setTimeout(() => {
        res.writeHead(out.status, { 'content-type': out.type, 'cache-control': 'no-store' });
        res.end(out.body);
      }, target.delayMs());
    });
  };
}
