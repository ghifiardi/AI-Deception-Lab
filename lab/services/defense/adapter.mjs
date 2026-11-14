// Dedicated V2 adapter: source validation precedes redaction and authenticated enforcement.
import { createServer } from 'node:http';
import { lookup } from 'node:dns/promises';
import { normalizeOpenCanary } from '../canary-adapter.mjs';
import { eventMac, digest, peerAddress } from './gateway.mjs';

const key = process.env.LAB_CONTROL_KEY;
if (!key || key.length < 32) throw new Error('LAB_CONTROL_KEY required');
const CONTROL = 'http://defense:8091/events';
const COLLECTOR = 'http://collector:4318/v1/events';
const send = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body, signal: AbortSignal.timeout(3000), redirect: 'error' });

createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/opencanary') return res.writeHead(404).end();
  let trusted;
  try { trusted = await lookup('opencanary', { all: true }); } catch { return res.writeHead(503).end(); }
  if (!trusted.some((p) => p.address === peerAddress(req.socket.remoteAddress))) return res.writeHead(403).end();
  let raw = '';
  req.setEncoding('utf8');
  req.on('data', (c) => { raw += c; if (Buffer.byteLength(raw) > 16384) req.destroy(); });
  req.on('end', async () => {
    let e;
    try { e = normalizeOpenCanary(JSON.parse(raw).message); } catch { return res.writeHead(400).end(); }
    if (!e || e.nodeId !== 'lab-opencanary-1') return res.writeHead(400).end();
    // Source-provided identity and raw credentials never leave the normalizer.
    const evidence = { ...e, issuedAt: Date.now(), eventId: digest(e) };
    try {
      if (e.kind === 'http.login-attempt') {
        const body = JSON.stringify(evidence);
        const response = await send(CONTROL, body, { 'x-lab-signature': eventMac(key, body) });
        if (response.status !== 202 && response.status !== 409) throw new Error(`control ${response.status}`);
        console.log(JSON.stringify({ type: 'adapter.enforced', eventId: evidence.eventId, client: e.srcHost, status: response.status }));
      }
      const body = JSON.stringify({ sensor: 'opencanary-v2', ...evidence });
      const r = await send(COLLECTOR, body);
      if (!r.ok) throw new Error(`collector ${r.status}`);
      console.log(body);
      res.writeHead(202).end();
    } catch (err) {
      console.error(JSON.stringify({ type: 'adapter.delivery.failed', error: String(err.message) }));
      res.writeHead(503).end();
    }
  });
}).listen(4319, '0.0.0.0');
