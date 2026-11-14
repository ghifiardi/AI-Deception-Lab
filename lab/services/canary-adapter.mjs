/**
 * OpenCanary -> lab adapter (optional, profile "opencanary", disabled by default).
 *
 * OpenCanary posts each event to this service over the internal lab network
 * (WebhookHandler). The adapter normalises it into lab evidence and forwards it
 * to the in-lab collector. Nothing leaves the lab network.
 *
 * Privacy: credentials submitted to the fake login page are NEVER stored or
 * forwarded. Only a SHA-256 of the username and the password length are kept.
 */
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

const COLLECTOR = process.env.COLLECTOR_URL ?? 'http://collector:4318/v1/events';

export const LOGTYPES = {
  1000: 'boot',
  1001: 'message',
  1002: 'debug',
  1003: 'error',
  1004: 'ping',
  1005: 'config-save',
  1006: 'example',
  3000: 'http.get',
  3001: 'http.login-attempt',
};

const clip = (v, n = 200) => (v === undefined || v === null ? null : String(v).slice(0, n));
const sha = (v) => createHash('sha256').update(String(v), 'utf8').digest('hex');

/** Normalise one OpenCanary event (object or JSON string). Returns null for unparseable input. */
export function normalizeOpenCanary(raw) {
  let ev = raw;
  if (typeof raw === 'string') {
    try {
      ev = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!ev || typeof ev !== 'object' || typeof ev.logtype !== 'number') return null;
  const data = ev.logdata && typeof ev.logdata === 'object' ? ev.logdata : {};
  const kind = LOGTYPES[ev.logtype] ?? `logtype-${ev.logtype}`;
  const out = {
    source: 'opencanary',
    nodeId: clip(ev.node_id, 64),
    logtype: ev.logtype,
    kind,
    evidenceType: ev.logtype === 3000 || ev.logtype === 3001 ? 'decoy-interaction' : null,
    srcHost: clip(ev.src_host, 64),
    dstPort: typeof ev.dst_port === 'number' ? ev.dst_port : null,
    path: clip(data.PATH, 300),
    method: ev.logtype === 3001 ? 'POST' : ev.logtype === 3000 ? 'GET' : null,
    userAgent: clip(data.USERAGENT, 160),
    localTime: clip(ev.local_time, 40),
  };
  if (ev.logtype === 3001) {
    out.credentials = {
      usernameSha256: data.USERNAME !== undefined ? sha(data.USERNAME) : null,
      passwordLength: data.PASSWORD !== undefined ? String(data.PASSWORD).length : null,
      redacted: true,
    };
  }
  return out;
}

if (process.argv[1]?.endsWith('canary-adapter.mjs')) {
  createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== '/opencanary') {
      res.writeHead(404).end();
      return;
    }
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (c) => {
      body += c;
      if (body.length > 16384) req.destroy();
    });
    req.on('end', () => {
      let msg = null;
      try {
        msg = JSON.parse(body).message;
      } catch {}
      const ev = normalizeOpenCanary(msg);
      if (!ev) {
        res.writeHead(400).end();
        return;
      }
      const line = JSON.stringify({ sensor: 'opencanary-adapter', ...ev });
      console.log(line);
      fetch(COLLECTOR, { method: 'POST', headers: { 'content-type': 'application/json' }, body: line, signal: AbortSignal.timeout(2000) }).catch(() =>
        console.log(JSON.stringify({ sensor: 'opencanary-adapter', warn: 'collector unreachable' })),
      );
      res.writeHead(202).end();
    });
  }).listen(4319, () => console.log(JSON.stringify({ sensor: 'opencanary-adapter', listening: 4319 })));
}
