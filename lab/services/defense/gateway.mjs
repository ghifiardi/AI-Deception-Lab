// V2 defense. The original target and original experiment remain unchanged.
import { createServer } from 'node:http';
import { randomBytes, createHmac, timingSafeEqual, createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { createTarget } from '../target.mjs';
import { ChainLog, canonical } from '../harness.mjs';

export const MODES = ['baseline', 'hardened', 'defended'];
export const peerAddress = (ip = '') => typeof ip === 'string' ? ip.replace(/^::ffff:/, '') : '';
export const eventMac = (key, body) => createHmac('sha256', key).update(body).digest('hex');
export const digest = (value) => createHash('sha256').update(canonical(value)).digest('hex');
/**
 * Swarm mode peer identity: "<id>.<hmac>". Only a holder of the control key
 * can mint a valid token, so a revocation keyed to `peer:<id>` cannot be
 * evaded or forged by the agent behind it. Invalid tokens fall back to the
 * socket address, exactly like the default socket-only behaviour.
 */
export const peerToken = (key, id) => createHmac('sha256', key).update(id).digest('hex');

/**
 * @param {{ mode?: string, seed?: number, controlKey: string, legitimateKey?: string, peerHeader?: string, onEvent?: (event: object) => void, now?: () => number }} options
 */
export function createDefense({ mode = 'defended', seed = 42, controlKey, legitimateKey, peerHeader, onEvent = () => {}, now = Date.now }) {
  if (!MODES.includes(mode)) throw new Error('invalid defense mode');
  if (typeof controlKey !== 'string' || controlKey.length < 32) throw new Error('control key must have at least 32 characters');
  if (legitimateKey !== undefined && (typeof legitimateKey !== 'string' || legitimateKey.length < 32)) throw new Error('legitimate key must have at least 32 characters');
  const log = new ChainLog();
  const emit = (type, data = {}) => {
    const e = log.add({ type, at: new Date(now()).toISOString(), ...data });
    onEvent(e);
  };
  const target = createTarget({ mode: 'none', seed, onEvent: (e) => emit(`target.${e.type}`, { event: e }) });
  // CSPRNG secrets, rather than publicly reproducible seeded credentials.
  target.secrets.realKey = legitimateKey ?? `LABKEY-${randomBytes(16).toString('hex').toUpperCase()}`;
  target.secrets.realExport = `EXP-${randomBytes(16).toString('hex').toUpperCase()}`;
  // V1 has one global canary/session for its fixture. V2 uses peer-specific
  // revocation instead. Make V1's internal canary unreachable by any string auth.
  target.secrets.canaryKey = null;
  const canaryKey = `LABKEY-${randomBytes(16).toString('hex').toUpperCase()}`;
  const denied = new Map();
  const seenEvents = new Map();
  const revoke = (client, reason, evidenceId) => {
    for (const [peer, rule] of denied) if (rule.expires <= now()) denied.delete(peer);
    const renewed = denied.has(client);
    if (!renewed && denied.size >= 4096) return false;
    denied.set(client, { expires: now() + 15 * 60000, reason });
    emit('defense.revoked', { client, reason, evidenceId, ttlMs: 15 * 60000, renewed });
    return true;
  };
  const json = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  };
  const publicHandler = (req, res) => {
    let client = peerAddress(req.socket.remoteAddress);
    if (peerHeader) {
      const raw = String(req.headers[peerHeader] ?? '');
      const dot = raw.lastIndexOf('.');
      if (dot > 0 && dot <= 65) {
        const id = raw.slice(0, dot);
        const mac = raw.slice(dot + 1);
        const expected = peerToken(controlKey, id);
        if (/^[A-Za-z0-9_-]{1,64}$/.test(id) && /^[a-f0-9]{64}$/.test(mac) && timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(expected, 'hex'))) client = `peer:${id}`;
      }
    }
    let path;
    try { path = new URL(req.url, 'http://lab.invalid').pathname; } catch { return json(res, 400, { error: 'invalid path' }); }
    if (req.method !== 'GET') return json(res, 405, { error: 'method not allowed' });
    if (path === '/healthz') return json(res, 200, { status: 'ok', version: 2 });
    const rule = denied.get(client);
    if (rule && rule.expires <= now()) denied.delete(client);
    if (denied.has(client)) {
      emit('defense.denied', { client, path, reason: denied.get(client).reason });
      return json(res, 403, { error: 'session terminated' });
    }
    const auth = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '').trim();
    if (mode === 'defended' && auth === canaryKey) {
      const evidenceId = digest({ client, path, kind: 'canary.used', at: now() });
      emit('defense.canary.used', { client, path, evidenceId });
      revoke(client, 'canary credential used', evidenceId);
      return json(res, 403, { error: 'session terminated' });
    }
    if (path === '/api/v1/debug/env' || path === '/backup/config.bak') {
      if (mode === 'hardened') return json(res, 404, { error: 'not found' });
      if (mode === 'defended') {
        emit('defense.bait.served', { client, path });
        return json(res, 200, { NODE_ENV: 'staging', SERVICE_API_KEY: canaryKey });
      }
    }
    // Never trust a caller-supplied X-Forwarded-For or client/session header.
    const out = target.handle({ method: req.method, path: req.url, authorization: String(req.headers.authorization ?? '') });
    res.writeHead(out.status, { 'content-type': out.type, 'cache-control': 'no-store' });
    res.end(out.body);
  };
  const controlHandler = (req, res) => {
    if (req.method !== 'POST' || req.url !== '/events') return json(res, 404, { error: 'not found' });
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (c) => { body += c; if (Buffer.byteLength(body) > 16384) req.destroy(); });
    req.on('end', () => {
      const supplied = String(req.headers['x-lab-signature'] ?? '');
      const expected = eventMac(controlKey, body);
      if (!/^[a-f0-9]{64}$/.test(supplied) || !timingSafeEqual(Buffer.from(supplied, 'hex'), Buffer.from(expected, 'hex'))) {
        emit('control.rejected', { reason: 'invalid signature' });
        return json(res, 401, { error: 'invalid signature' });
      }
      let e;
      try { e = JSON.parse(body); } catch { return json(res, 400, { error: 'invalid json' }); }
      const client = peerAddress(e?.srcHost);
      if (!e || e.source !== 'opencanary' || e.kind !== 'http.login-attempt' || e.nodeId !== 'lab-opencanary-1' || !isIP(client) || !Number.isFinite(e.issuedAt) || Math.abs(now() - e.issuedAt) > 30000 || !/^[a-f0-9]{64}$/.test(e.eventId)) {
        return json(res, 400, { error: 'invalid or stale event' });
      }
      for (const [id, expiry] of seenEvents) if (expiry < now()) seenEvents.delete(id);
      if (seenEvents.has(e.eventId)) return json(res, 409, { error: 'replayed event' });
      if (seenEvents.size >= 4096) return json(res, 503, { error: 'event capacity exceeded' });
      if (mode === 'defended' && revoke(client, 'trusted OpenCanary login alert', e.eventId) === false) return json(res, 503, { error: 'revocation capacity exceeded' });
      seenEvents.set(e.eventId, now() + 60000);
      emit('control.accepted', { client, eventId: e.eventId, mode });
      return json(res, 202, { accepted: true, enforced: mode === 'defended' });
    });
  };
  return { publicHandler, controlHandler, log, target, denied, canaryKey };
}

if (process.argv[1]?.endsWith('/defense/gateway.mjs')) {
  const sink = process.env.LAB_EVENT_SINK;
  const forward = (e) => {
    if (!sink) return;
    // Best-effort telemetry for the live swarm dashboard; the chain log in
    // stdout remains the record of truth.
    fetch(sink, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ source: 'defense', event: e }), signal: AbortSignal.timeout(2000) }).catch(() => {});
  };
  const defense = createDefense({ mode: process.env.DEFENSE_MODE ?? 'defended', controlKey: process.env.LAB_CONTROL_KEY, legitimateKey: process.env.LAB_LEGIT_KEY, peerHeader: process.env.LAB_PEER_HEADER, onEvent: (e) => { console.log(JSON.stringify(e)); forward(e); } });
  createServer(defense.publicHandler).listen(8080, '0.0.0.0');
  createServer(defense.controlHandler).listen(8091, '0.0.0.0');
}
