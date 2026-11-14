import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createDefense, eventMac, digest } from '../lab/services/defense/gateway.mjs';
import { verifyRecords } from '../scripts/verify-log.ts';
import { createTarget } from '../lab/services/target.mjs';

const key = 'control-test-key-'.repeat(4);
async function lab(mode: string, fn: (d: any, get: any, event: any) => Promise<void>) {
  const d = createDefense({ mode, controlKey: key });
  const servers = [createServer(d.publicHandler), createServer(d.controlHandler)];
  for (const s of servers) await new Promise<void>((r) => s.listen(0, '::', r));
  const send = (index: number, path: string, headers = {}, body = '', client = '127.0.0.1') => new Promise<any>((resolve, reject) => {
    const req = request({ host: client === '::1' ? '::1' : '127.0.0.1', port: (servers[index]!.address() as any).port, path, method: index ? 'POST' : 'GET', localAddress: client, headers }, (res) => {
      let data = ''; res.on('data', (c) => data += c); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data) }));
    });
    req.on('error', reject); req.end(body);
  });
  const get = (path: string, token?: string, client?: string, extra = {}) => send(0, path, { ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra }, '', client);
  const event = (overrides = {}, signed = true) => {
    const body = JSON.stringify({ source: 'opencanary', nodeId: 'lab-opencanary-1', kind: 'http.login-attempt', srcHost: '127.0.0.1', issuedAt: Date.now(), eventId: digest(overrides), ...overrides });
    return send(1, '/events', { 'x-lab-signature': signed ? eventMac(key, body) : '0'.repeat(64) }, body);
  };
  try { await fn(d, get, event); }
  finally { for (const s of servers) { s.closeAllConnections(); await new Promise<void>((r) => s.close(() => r())); } }
}

test('V2: exact previous debug-key bypass succeeds at baseline, fails after hardening, and triggers canary containment in defended mode', async () => {
  for (const mode of ['baseline', 'hardened', 'defended']) await lab(mode, async (d, get) => {
    const env = await get('/api/v1/debug/env');
    if (mode === 'hardened') { assert.equal(env.status, 404); return; }
    const stolen = env.body.SERVICE_API_KEY;
    const result = await get('/api/v2/records/export', stolen);
    assert.equal(result.status, mode === 'baseline' ? 200 : 403);
    assert.equal(d.target.state.realExportServed, mode === 'baseline');
    if (mode === 'defended') assert.ok(d.log.records.some((e: any) => e.type === 'defense.revoked'));
  });
});

test('V2: authentic alert revokes even a valid credential for the triggering peer; a different legitimate peer retains access', async () => {
  await lab('defended', async (d, get, event) => {
    assert.equal((await get('/api/v2/records/export', d.target.secrets.realKey)).status, 200);
    assert.equal((await event()).status, 202);
    assert.equal((await get('/api/v2/records/export', d.target.secrets.realKey)).status, 403);
    assert.equal((await get('/api/v2/records/export', d.target.secrets.realKey, '::1')).status, 200);
    assert.ok(verifyRecords(d.log.records).ok);
  });
});

test('V2: forged, malformed, stale, wrong-sensor and replayed control events cannot revoke other clients', async () => {
  await lab('defended', async (d, get, event) => {
    assert.equal((await event({}, false)).status, 401);
    assert.equal((await event({ source: 'attacker' })).status, 400);
    assert.equal((await event({ issuedAt: Date.now() - 60000 })).status, 400);
    assert.equal((await event({ srcHost: {} })).status, 400);
    assert.equal((await event({ nodeId: 'other' })).status, 400);
    assert.equal((await get('/api/v2/records/export', d.target.secrets.realKey)).status, 200);
    const id = digest('one-event');
    assert.equal((await event({ eventId: id })).status, 202);
    assert.equal((await event({ eventId: id, srcHost: '::1' })).status, 409);
    assert.equal((await get('/api/v2/records/export', d.target.secrets.realKey, '::1')).status, 200);
  });
});

test('V2: changing forwarded client identity cannot evade a block', async () => {
  await lab('defended', async (d, get, event) => {
    await event();
    assert.equal((await get('/api/v2/records/export', d.target.secrets.realKey, undefined, { 'x-forwarded-for': '127.0.0.2', 'x-client-id': 'legitimate' })).status, 403);
  });
});

test('V2: hardening ablation does not claim alert enforcement; genuine service remains available', async () => {
  await lab('hardened', async (d, get, event) => {
    const response = await event();
    assert.equal(response.body.enforced, false);
    assert.equal((await get('/api/v2/records/export', d.target.secrets.realKey)).status, 200);
    assert.equal((await get('/api/v2/records/export')).status, 401);
  });
});

test('V2: encoded and query variants do not leak the genuine key', async () => {
  await lab('defended', async (d, get) => {
    for (const path of ['/api/v1/debug/env?x=1', '/api/v1/debug/%65nv', '/api/v1/debug/env/', '/backup/config.bak', '//api/v1/debug/env']) {
      const r = await get(path);
      assert.ok(!JSON.stringify(r.body).includes(d.target.secrets.realKey));
    }
    for (const [url, method, expected] of [['http://[', 'GET', 400], ['/api/v2/records/export', 'POST', 405]] as const) {
      let status = 0;
      let body = '';
      const res: any = { writeHead(s: number) { status = s; }, end(value: string) { body = value; } };
      d.publicHandler({ socket: { remoteAddress: '127.0.0.1' }, url, method, headers: {} }, res);
      assert.equal(status, expected);
      assert.ok(!body.includes(d.target.secrets.realKey));
    }
  });
});

test('V2: a known V1 seeded canary cannot globally deny service to legitimate clients', async () => {
  await lab('defended', async (d, get) => {
    const oldCanary = createTarget({ mode: 'none', seed: 42 }).secrets.canaryKey;
    assert.equal((await get('/api/v2/records/export', oldCanary)).status, 401);
    assert.equal(d.target.state.contained, false);
    assert.equal((await get('/api/v2/records/export', d.target.secrets.realKey, '::1')).status, 200);
  });
});

test('V2: weak supplied credentials fail closed at startup', () => {
  assert.throws(() => createDefense({ controlKey: key, legitimateKey: '' }), /legitimate key/);
  assert.throws(() => createDefense({ controlKey: 'short' }), /control key/);
});

test('V2: a fresh alert after an expired inactive revocation renews denial instead of accidentally allowing access', async () => {
  let clock = Date.now();
  const d = createDefense({ controlKey: key, now: () => clock });
  const apply = (id: string) => new Promise<number>(resolve => {
    const body = JSON.stringify({ source: 'opencanary', kind: 'http.login-attempt', nodeId: 'lab-opencanary-1', srcHost: '127.0.0.1', issuedAt: clock, eventId: digest(id) });
    const handlers: any = {};
    const req = { method: 'POST', url: '/events', headers: { 'x-lab-signature': eventMac(key, body) }, setEncoding() {}, on(name: string, fn: any) { handlers[name] = fn; } };
    let status = 0;
    const res: any = { writeHead(s: number) { status = s; return res; }, end() { resolve(status); } };
    d.controlHandler(req, res); handlers.data(body); handlers.end();
  });
  assert.equal(await apply('first'), 202);
  const firstExpiry = d.denied.get('127.0.0.1').expires;
  clock += 16 * 60000;
  assert.equal(await apply('after-expiry'), 202);
  assert.ok(d.denied.get('127.0.0.1').expires > firstExpiry);
  assert.equal(d.denied.get('127.0.0.1').expires, clock + 15 * 60000);
});
