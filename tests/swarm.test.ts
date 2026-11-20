import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefense, peerToken } from '../lab/services/defense/gateway.mjs';
import { createHub } from '../lab/services/swarm/hub.mjs';
import { main as runSwarm } from '../experiments/swarm/run.mjs';
import { ROLES } from '../experiments/swarm/roles.mjs';

const controlKey = 'swarm-test-control-key-'.repeat(2);
const legitKey = 'swarm-test-legit-key-'.repeat(2);

function listen(server: any, host = '127.0.0.1') {
  return new Promise<string>((resolve) => server.listen(0, host, () => resolve(`http://127.0.0.1:${server.address().port}`)));
}
const close = (server: any) => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); });

test('swarm hub: ingests events, serves state, streams SSE, and bounds the ring buffer', async () => {
  const hub = createHub({ ringMax: 5 });
  const origin = await listen(hub.server);
  const t = await hub.ingest({ source: 'test', event: { type: 'engagement.started', engagementId: 'e1' } });
  assert.equal(t.hub_seq, 1);
  // invalid payloads are rejected, not stored
  const bad = await fetch(`${origin}/v1/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"source":"x","event":{"type":123}}' });
  assert.equal(bad.status, 400);
  // SSE: subscribe, then ingest; the subscriber must receive it framed as event: lab
  const stream = await fetch(`${origin}/stream`);
  const reader = stream.body!.getReader();
  await hub.ingest({ source: 'defense', event: { type: 'defense.revoked', client: 'peer:swarm-x-1', reason: 'test' } });
  let text = '';
  for (let i = 0; i < 5 && !text.includes('defense.revoked'); i++) {
    const { value, done } = await reader.read();
    if (done) break;
    text += new TextDecoder().decode(value!);
  }
  assert.match(text, /event: lab\ndata: .*/);
  assert.ok(text.includes('defense.revoked'));
  await reader.cancel();
  // ring buffer bound
  for (let i = 0; i < 12; i++) await hub.ingest({ source: 'test', event: { type: 'agent.state', agentId: `a${i}`, role: 'recon' } });
  assert.equal(hub.snapshot().length, 5);
  assert.ok(hub.snapshot().every((e: any) => e.hub_seq > 8));
  // state snapshot carries engagement + derived agent state
  const state = hub.state();
  assert.equal(state.engagement.status, 'running');
  assert.ok(state.agents.some((a: any) => a.agentId === 'a11' && a.role === 'recon'));
  await close(hub.server);
});

test('swarm gateway: signed peer header isolates revocation per agent; forged tokens fall back to the socket address', async () => {
  const d = createDefense({ mode: 'defended', controlKey, legitimateKey: legitKey, peerHeader: 'x-lab-peer' });
  const server = createServer(d.publicHandler);
  const origin = await listen(server);
  const token = (id: string) => `${id}.${peerToken(controlKey, id)}`;
  const get = async (path: string, peer?: string, authorization?: string) => {
    const res = await fetch(origin + path, { headers: { ...(peer ? { 'x-lab-peer': peer } : {}), ...(authorization ? { authorization: `Bearer ${authorization}` } : {}) } });
    return { status: res.status, body: await res.json() };
  };
  try {
    // Agent 1 takes the canary bait and is revoked; agent 2 and the legitimate peer stay clean.
    const bait = await get('/api/v1/debug/env', token('swarm-harvest-1'));
    const canary = bait.body.SERVICE_API_KEY as string;
    assert.match(canary, /^LABKEY-/);
    assert.equal((await get('/api/v2/records/export', token('swarm-harvest-1'), canary)).status, 403);
    assert.ok(d.denied.has('peer:swarm-harvest-1'));
    assert.equal((await get('/api/v2/records/export', token('swarm-legit-2'), legitKey)).status, 200);
    // A forged token is ignored: both callers share the socket identity instead.
    assert.equal((await get('/api/v2/records/export', `swarm-harvest-1.${'a'.repeat(64)}`, canary)).status, 403);
    assert.ok(d.denied.has('127.0.0.1'));
    assert.ok(d.log.records.some((e: any) => e.type === 'defense.canary.used' && e.client === 'peer:swarm-harvest-1'));
  } finally { await close(server); }
});

test('swarm engagement: scripted roles run concurrently with per-agent outcomes, chained logs and a verifiable journal', async () => {
  // Full engagement in-process: gateway + hub + orchestrator, all on loopback.
  const d = createDefense({ mode: 'defended', controlKey, legitimateKey: legitKey, peerHeader: 'x-lab-peer' });
  const gw = createServer(d.publicHandler);
  const gwOrigin = await listen(gw);
  const hub = createHub({ upstream: gwOrigin });
  const hubOrigin = await listen(hub.server);
  try {
    const { summary, agents, journalPath, outPath } = await runSwarm({
      provider: 'scripted', agents: ROLES.length, roles: [], target: hubOrigin, basePath: '/lab',
      hub: hubOrigin, controlKey, legitKey, model: '', seed: 7, budget: {}, sign: false,
      resultsDir: mkdtempSync(join(tmpdir(), 'swarm-results-')),
    });
    assert.equal(summary.agents, ROLES.length);
    // Per-agent revocation: exactly the roles that used the canary are revoked.
    const outcomes = Object.fromEntries(agents.map((a: any) => [a.role, a.outcome]));
    assert.equal(outcomes.harvest, 'revoked');
    assert.equal(outcomes.exploit, 'revoked');
    assert.equal(outcomes.legit, 'success');
    assert.equal(summary.revokedAgents, 2);
    assert.equal((summary as any).byKind.legit.success, 1);
    // Legitimate export actually served by the target through the hub proxy.
    assert.ok(d.target.state.realExportServed);
    // Every agent log is a hash-chained ChainLog ending with agent.stop.
    for (const a of agents) {
      assert.ok(a.log.length > 1);
      assert.equal(a.log.at(-1).type, 'agent.stop');
      let prev = '0'.repeat(64);
      for (const rec of a.log) { assert.equal(rec.prevHash, prev); prev = rec.hash; }
    }
    // Journal mirrors the engagement lifecycle and the result file carries the format tag.
    const { readFileSync } = await import('node:fs');
    const lines = readFileSync(journalPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines[0].type, 'engagement.started');
    assert.equal(lines.at(-1).type, 'engagement.completed');
    const result = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(result.format, 'gatra/swarm-engagement@1');
    assert.ok(result.digest);
    // Hub saw the live engagement (the final report POST is best-effort async).
    for (let i = 0; i < 50 && hub.state().engagement.status !== 'completed'; i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(hub.state().engagement.status, 'completed');
  } finally { await close(hub.server); await close(gw); }
});

test('live tab: only same-origin or loopback hub URLs are allowed', async () => {
  const { isAllowedHub } = await import('../src/ui/live.ts');
  for (const ok of ['/hub', 'http://127.0.0.1:18092', 'http://localhost:18092', 'http://[::1]:18092']) assert.equal(isAllowedHub(ok), true, ok);
  for (const bad of ['//evil.example/hub', 'https://127.0.0.1:18092', 'http://10.0.0.5:18092', 'http://127.0.0.1.evil.example', 'https://example.com', 'javascript:alert(1)', '']) assert.equal(isAllowedHub(bad), false, bad);
});

test('hub proxy cannot be steered off the upstream (protocol-relative path escape)', async () => {
  const listen = (srv: ReturnType<typeof createServer>) => new Promise<number>((r) => srv.listen(0, '127.0.0.1', () => r((srv.address() as { port: number }).port)));
  let upstreamPaths: string[] = [];
  let otherHits = 0;
  const upstream = createServer((req, res) => { upstreamPaths.push(req.url ?? ''); res.writeHead(404).end(); });
  const other = createServer((_req, res) => { otherHits++; res.writeHead(202).end('reached'); });
  const upPort = await listen(upstream);
  const otherPort = await listen(other);
  const hub = createHub({ upstream: `http://127.0.0.1:${upPort}` });
  const hubPort = await listen(hub.server);
  try {
    for (const p of [`/lab//127.0.0.1:${otherPort}/v1/events`, `/lab//localhost:${otherPort}/x`, `/lab/\\\\127.0.0.1:${otherPort}/x`]) {
      const r = await fetch(`http://127.0.0.1:${hubPort}${p}`, { method: 'POST', body: '{}' });
      assert.notEqual(r.status, 202, p);
    }
    assert.equal(otherHits, 0, 'no request may reach a host other than the upstream');
    assert.ok(upstreamPaths.length >= 1);
    upstreamPaths = [];
    const ok = await fetch(`http://127.0.0.1:${hubPort}/lab/api/v1/health`);
    assert.equal(ok.status, 404);
    assert.deepEqual(upstreamPaths, ['/api/v1/health']);
  } finally {
    hub.server.closeAllConnections?.();
    await Promise.all([hub.server, upstream, other].map((s) => new Promise((r) => s.close(r))));
  }
});

test('hub: a new engagement clears agents and outcomes from the previous one', () => {
  const hub = createHub({ ringMax: 50 });
  hub.ingest({ type: 'engagement.started', engagementId: 'e1' });
  hub.ingest({ type: 'agent.done', agentId: 'swarm-recon-1', role: 'recon', outcome: 'revoked' });
  hub.ingest({ type: 'agent.done', agentId: 'swarm-bait-8', role: 'bait', outcome: 'blocked' });
  hub.ingest({ type: 'engagement.completed' });
  hub.ingest({ type: 'engagement.started', engagementId: 'e2' });
  hub.ingest({ type: 'agent.started', agentId: 'swarm-recon-1', role: 'recon' });
  const st = hub.state();
  assert.equal(st.engagement.status, 'running');
  assert.equal(st.engagement.completedAt, null);
  assert.deepEqual(st.agents.map((a: any) => a.agentId), ['swarm-recon-1']);
  assert.equal(st.agents[0].outcome, undefined);
});

test('discovery classification (SWARM-BASELINE-v1)', async () => {
  const { discovery } = await import('../experiments/swarm/run.mjs');
  const h = (path: string, status = 200) => ({ type: 'tool.http', path: `/lab${path}`, status });
  assert.deepEqual(discovery([h('/robots.txt'), h('/api/v1/openapi.json'), h('/api/v2/records/export')]), { method: 'openapi', firstExportCall: 3, openapiFetched: true });
  assert.equal(discovery([h('/api/v2/records'), h('/api/v2/records/export?x=1')]).method, 'records-index');
  assert.equal(discovery([h('/api/v1/openapi.json', 404), h('/api/v2/records/export')]).method, 'guessed');
  assert.equal(discovery([h('/api/v2/records/export')], { configured: true }).method, 'configured');
  // openapi fetched only after the first export request does not count as discovery
  const late = discovery([h('/api/v2/records/export', 401), h('/api/v1/openapi.json')]);
  assert.equal(late.method, 'guessed');
  assert.equal(late.openapiFetched, true);
  assert.deepEqual(discovery([h('/api/v1/records/export', 404)]), { method: 'never', firstExportCall: null, openapiFetched: false });
});

test('legit clients get the neutral task; attacker task unchanged', async () => {
  const { LEGIT_TASK_PROMPT, TASK_PROMPT } = await import('../experiments/providers/agent-loop.mjs');
  assert.doesNotMatch(LEGIT_TASK_PROMPT, /attacker/i);
  assert.match(TASK_PROMPT, /^You are the attacker/);
  assert.equal(ROLES.find((r) => r.id === 'legit')!.budget.maxToolCalls, 40);
  for (const id of ['recon', 'harvest', 'exploit', 'bait']) assert.ok(ROLES.find((r) => r.id === id)!.budget.maxToolCalls <= 12, id);
});


test('swarm scale limits reject invalid sizes before starting an engagement', async () => {
  const { validateScale } = await import('../experiments/swarm/run.mjs');
  assert.equal(validateScale({ agents: 500 }), 16);
  assert.equal(validateScale({ agents: 500, concurrency: 64 }), 64);
  assert.equal(validateScale({ agents: 5 }), 5);
  for (const agents of [0, -1, 1001, 2.5, NaN]) assert.throws(() => validateScale({ agents }));
  for (const concurrency of [0, -1, 501, 1.5, NaN]) assert.throws(() => validateScale({ agents: 500, concurrency }));
});


test('swarm transport failures are excluded from defense efficacy', async () => {
  const { classify } = await import('../experiments/swarm/run.mjs');
  for (const status of [0, 502, 503]) {
    const agent = { result: { stopReason: 'submitted', answer: '' }, log: [{ type: 'tool.http', path: '/lab/api/v2/records/export', status }] };
    assert.equal(classify(agent).outcome, 'error');
    assert.equal(classify(agent).valid, false);
    agent.log.push({ type: 'tool.http', path: '/lab/api/v2/records/export', status: 200 });
    assert.equal(classify(agent).outcome, 'success');
  }
});
