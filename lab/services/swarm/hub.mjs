/**
 * Swarm hub: the live-telemetry edge of an isolated engagement.
 *
 * It sits between the tunnel (loopback on the lab host) and the internal lab
 * network. It does three things, all bounded:
 *   POST /v1/events   ingest one lab/agent event (collector + defense + orchestrator all use this)
 *   GET  /state       JSON snapshot of the engagement (dashboard reconnects)
 *   GET  /stream      SSE: replayed ring buffer, then live events, with heartbeats
 *   ANY  /lab/*       reverse proxy to the defense gateway, so every swarm agent
 *                     can carry its own signed peer identity through one tunnel
 *
 * The hub keeps events in memory only. It stores nothing on disk, reaches only
 * the gateway, and holds no secrets.
 */
import { createServer } from 'node:http';
import { installEgressGuard } from '../egress-guard.mjs';

const MAX_BODY = 16384;
const RING_MAX = 500;
const MAX_CLIENTS = 16;
const HEARTBEAT_MS = 10000;

/**
 * @param {{ upstream?: string, ringMax?: number, now?: () => number }} [opts]
 */
export function createHub({ upstream = process.env.LAB_UPSTREAM, ringMax = RING_MAX, now = Date.now } = {}) {
  let seq = 0;
  /** @type {any[]} */
  const ring = [];
  /** @type {Set<import('node:http').ServerResponse>} */
  const clients = new Set();
  /** @type {Map<string, any>} agent id -> last state */
  const agents = new Map();
  const engagement = { status: 'idle', startedAt: null, completedAt: null };

  const readBody = (req) =>
    new Promise((resolve, reject) => {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (c) => {
        body += c;
        if (body.length > MAX_BODY) {
          req.destroy();
          reject(new Error('body too large'));
        }
      });
      req.on('end', () => resolve(body));
      req.on('error', reject);
    });

  const json = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  };

  const ingest = (payload) => {
    const e = payload?.event ?? payload;
    if (!e || typeof e !== 'object' || typeof e.type !== 'string') return null;
    const event = { hub_seq: ++seq, at: new Date(now()).toISOString(), source: typeof payload?.source === 'string' ? payload.source : 'unknown', ...e };
    // A new engagement starts from a clean live view: agent IDs repeat across
    // engagements, and stale outcomes must never carry over.
    if (event.type === 'engagement.started') {
      agents.clear();
      engagement.completedAt = null;
    }
    // Derived live state for /state; every field optional.
    if (event.agentId && (event.type === 'agent.started' || event.type === 'agent.state' || event.type === 'agent.done')) {
      const prev = agents.get(event.agentId) ?? {};
      agents.set(event.agentId, { ...prev, ...event.agent ?? {}, agentId: event.agentId, role: event.role ?? prev.role, lastType: event.type, lastAt: event.at, state: event.state ?? prev.state, outcome: event.outcome ?? prev.outcome, toolCalls: event.toolCalls ?? prev.toolCalls, tokens: event.tokens ?? prev.tokens, note: event.note ?? prev.note });
    }
    if (event.type === 'engagement.started') {
      engagement.status = 'running';
      engagement.startedAt = event.at;
      engagement.id = event.engagementId ?? null;
    }
    if (event.type === 'engagement.completed') {
      engagement.status = 'completed';
      engagement.completedAt = event.at;
    }
    ring.push(event);
    if (ring.length > ringMax) ring.splice(0, ring.length - ringMax);
    for (const res of clients) res.write(`id: ${event.hub_seq}\nevent: lab\ndata: ${JSON.stringify(event)}\n\n`);
    return event;
  };

  const proxy = async (req, res, body) => {
    if (!upstream) return json(res, 502, { error: 'no upstream configured' });
    // Pin every request to the upstream origin. Resolving the raw path against
    // the upstream would let '/lab//other-host/x' (protocol-relative) escape it.
    const origin = new URL(upstream).origin;
    const path = req.url.slice('/lab'.length);
    const target = new URL(origin + path);
    if (!path.startsWith('/') || target.origin !== origin) return json(res, 400, { error: 'proxy target outside the lab upstream' });
    const headers = { ...req.headers, host: target.host };
    delete headers.connection;
    delete headers['content-length'];
    try {
      const out = await fetch(target, { method: req.method, headers, body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body, redirect: 'manual', signal: AbortSignal.timeout(10000) });
      res.writeHead(out.status, { 'content-type': out.headers.get('content-type') ?? 'application/json', 'cache-control': 'no-store' });
      res.end(Buffer.from(await out.arrayBuffer()));
    } catch (err) {
      json(res, 502, { error: `upstream failed: ${err instanceof Error ? err.name : 'error'}` });
    }
  };

  const handler = async (req, res) => {
    const url = req.url ?? '/';
    // The dashboard runs on a different loopback port; allow that origin only.
    const origin = req.headers.origin;
    if (typeof origin === 'string' && /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(origin)) {
      res.setHeader('access-control-allow-origin', origin);
      res.setHeader('vary', 'origin');
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'content-type' });
      return res.end();
    }
    if (req.method === 'GET' && url === '/healthz') return json(res, 200, { status: 'ok', role: 'swarm-hub' });
    if (req.method === 'GET' && url === '/state') {
      return json(res, 200, { format: 'gatra/swarm-hub-state@1', engagement, agents: [...agents.values()], events: ring.length, liveClients: clients.size });
    }
    if (req.method === 'GET' && url === '/stream') {
      if (clients.size >= MAX_CLIENTS) return json(res, 503, { error: 'stream capacity reached' });
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
      res.write(`retry: 2000\n\n`);
      for (const e of ring) res.write(`id: ${e.hub_seq}\nevent: lab\ndata: ${JSON.stringify(e)}\n\n`);
      clients.add(res);
      const beat = setInterval(() => {
        if (!clients.has(res)) return;
        res.write(`: heartbeat ${Date.now()}\n\n`);
      }, HEARTBEAT_MS);
      req.on('close', () => {
        clearInterval(beat);
        clients.delete(res);
      });
      return;
    }
    if (url.startsWith('/lab/')) return proxy(req, res, req.method === 'GET' ? undefined : await readBody(req));
    if (req.method === 'POST' && url === '/v1/events') {
      let payload;
      try { payload = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'invalid json' }); }
      const event = ingest(payload);
      return event ? json(res, 202, { hub_seq: event.hub_seq }) : json(res, 400, { error: 'invalid event' });
    }
    json(res, 404, { error: 'not found' });
  };

  const server = createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(400).end();
      else res.end();
    });
  });

  return {
    server,
    ingest,
    state: () => ({ engagement: { ...engagement }, agents: [...agents.values()], events: ring.length }),
    /** Test/inspection access to the ring; never used for serving. */
    snapshot: () => [...ring],
    clients: () => clients.size,
  };
}

if (process.argv[1]?.endsWith('/swarm/hub.mjs')) {
  // The hub sits on the edge bridge so its port can be published; it must
  // still only ever connect to the defense gateway. Network-level masquerade
  // settings are not enforced on every Docker runtime (Docker Desktop ignores
  // them), so deny everything else in-process as well.
  const up = process.env.LAB_UPSTREAM ? new URL(process.env.LAB_UPSTREAM) : null;
  const guard = installEgressGuard({ allowHosts: up ? [{ host: up.hostname, port: Number(up.port || (up.protocol === 'https:' ? 443 : 80)) }] : [] });
  const hub = createHub();
  const port = Number(process.env.LAB_HUB_PORT ?? 8092);
  hub.server.listen(port, '0.0.0.0', () => console.log(JSON.stringify({ swarmHub: 'listening', port, upstream: process.env.LAB_UPSTREAM ?? null, egress: guard.policy })));
}
