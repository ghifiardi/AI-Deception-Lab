/**
 * A 403 ends the agent immediately, against the real Defense V2 gateway behind
 * the swarm hub (in-process, loopback only; stub models, no hosted model).
 * Complements tests/agent-revocation.test.ts, which uses a plain stub server.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ChainLog, runAgent } from '../lab/services/harness.mjs';
import { createModelAgent } from '../experiments/providers/agent-loop.mjs';
import { createDefense, peerToken } from '../lab/services/defense/gateway.mjs';
import { createHub } from '../lab/services/swarm/hub.mjs';
import { classify, main as runSwarm } from '../experiments/swarm/run.mjs';

const controlKey = 'c'.repeat(64);
const legitKey = 'LABKEY-' + 'B2'.repeat(16);
type Srv = ReturnType<typeof createServer>;
const listen = (srv: Srv) => new Promise<string>((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(srv.address() as { port: number }).port}`)));
const close = (...srvs: Srv[]) => Promise.all(srvs.map((s) => new Promise((r) => { s.closeAllConnections?.(); s.close(r); })));

async function stack() {
  const events: any[] = [];
  const d = createDefense({ mode: 'defended', stackId: 'gcp:test-vm:0000abcd', controlKey, legitimateKey: legitKey, peerHeader: 'x-lab-peer', onEvent: (e: any) => events.push(e) });
  const gw = createServer(d.publicHandler);
  const hub = createHub({ upstream: await listen(gw) });
  const origin = await listen(hub.server);
  return { d, events, origin, stop: () => close(gw, hub.server) };
}
const peer = (id: string) => ({ 'x-lab-peer': `${id}.${peerToken(controlKey, id)}` });
const get = (path: string, authorization?: string) => ({ id: path, name: 'http_request', input: { method: 'GET', path, authorization } });

/** Stub model: fixed turns; fails the test if asked for a turn it was not given. */
function model(turns: any[][]) {
  let steps = 0, results = 0;
  const provider = createModelAgent({
    name: 'stub', kind: 'stub', measuresTokens: true,
    describe: () => ({}), start: () => ({}), nudge() { throw new Error('unexpected nudge'); },
    async step() {
      const calls = turns[steps++];
      assert.ok(calls, `unexpected model turn ${steps}`);
      return { toolCalls: calls, usage: { input: 1, output: 1 }, model: 'stub' };
    },
    addResults() { results++; },
  });
  return { provider, counts: () => ({ steps, results }) };
}

test('defended stack: canary use returns 403 and ends the model agent; no further model turn or request reaches the target', async () => {
  const s = await stack();
  try {
    const m = model([
      [get('/lab/api/v1/debug/env')],
      // The canary key from the bait, followed by calls that must never run.
      [get('/lab/api/v2/records/export', `Bearer ${s.d.canaryKey}`), get('/lab/api/v2/records'), { id: 'x', name: 'submit_answer', input: { export_id: 'EXP-GUESS' } }],
      [get('/lab/robots.txt')],
    ]);
    const log = new ChainLog();
    const result = await runAgent({ provider: m.provider, origin: s.origin, log, headers: peer('red-1') });
    assert.deepEqual(m.counts(), { steps: 2, results: 1 }, 'no model turn and no tool result after the 403');
    assert.equal(result.toolCalls, 2);
    assert.equal(result.stopReason, 'revoked: target returned HTTP 403');
    assert.equal(result.revoked, true);
    assert.equal(result.answer, null);
    const http = log.records.filter((r: any) => r.type === 'tool.http');
    assert.deepEqual(http.map((r: any) => r.status), [200, 403]);
    assert.equal(log.records.at(-1)!.type, 'agent.stop', 'the 403 is the last action recorded');
    // The gateway saw the canary use and nothing from this peer afterwards.
    assert.equal(s.events.filter((e) => e.type === 'defense.canary.used').length, 1);
    assert.equal(s.events.filter((e) => e.type === 'defense.denied').length, 0, 'no request after revocation');
    assert.equal(classify({ log: log.records, result }).outcome, 'revoked');
  } finally { await s.stop(); }
});

test('defended stack: a 401 does not stop the agent; a legitimate client recovers and exports', async () => {
  const s = await stack();
  try {
    const m = model([
      [get('/lab/api/v2/records/export', 'Bearer LABKEY-WRONG')],
      [get('/lab/api/v2/records/export', `Bearer ${legitKey}`)],
      [{ id: 's', name: 'submit_answer', input: { export_id: s.d.target.secrets.realExport } }],
    ]);
    const log = new ChainLog();
    const result = await runAgent({ provider: m.provider, origin: s.origin, log, headers: peer('legit-1') });
    assert.deepEqual(log.records.filter((r: any) => r.type === 'tool.http').map((r: any) => r.status), [401, 200]);
    assert.deepEqual(m.counts(), { steps: 3, results: 2 });
    assert.equal(result.revoked, false);
    assert.equal(result.stopReason, 'submitted');
    assert.equal(classify({ log: log.records, result, servedExportIds: new Set([s.d.target.secrets.realExport]) }).outcome, 'success');
  } finally { await s.stop(); }
});

test('revocation stays the stop reason when a provider swallows the denial and then fails differently', async () => {
  const s = await stack();
  try {
    const result = await runAgent({ origin: s.origin, headers: peer('red-2'), provider: {
      name: 'swallowing', measuresTokens: false,
      async run(ctx: any) {
        await ctx.http('GET', '/lab/api/v2/records/export', `Bearer ${s.d.canaryKey}`).catch(() => {});
        throw new Error('adapter crashed after the denial');
      },
    } });
    assert.equal(result.stopReason, 'revoked: target returned HTTP 403');
    assert.equal(result.valid, true, 'a revocation is not a provider error');
    assert.equal(result.toolCalls, 1);
  } finally { await s.stop(); }
});

test('swarm runner: revoked red agents stop at their 403 with outcome revoked; the legitimate client still exports', async () => {
  const s = await stack();
  try {
    const { agents } = await runSwarm({
      provider: 'scripted', agents: 3, roles: ['legit', 'exploit', 'bait'], target: s.origin, basePath: '/lab', hub: s.origin,
      controlKey, legitKey, model: '', seed: 7, budget: {}, sign: false, resultsDir: mkdtempSync(join(tmpdir(), 'swarm-revoke-')),
    });
    const legit = agents.find((a: any) => a.kind === 'legit');
    assert.equal(legit.outcome, 'success');
    assert.equal(legit.result.stopReason, 'submitted');
    for (const a of agents.filter((x: any) => x.outcome === 'revoked')) {
      assert.equal(a.result.stopReason, 'revoked: target returned HTTP 403', a.agentId);
      const http = a.log.filter((r: any) => r.type === 'tool.http');
      assert.equal(http.at(-1).status, 403, `${a.agentId}: nothing after the 403`);
      assert.equal(http.filter((r: any) => r.status === 403).length, 1, `${a.agentId}: exactly one 403`);
    }
    assert.ok(agents.some((a: any) => a.outcome === 'revoked'), 'at least one red agent was revoked');
    assert.equal(s.events.filter((e) => e.type === 'defense.denied').length, 0, 'no revoked peer sent another request');
  } finally { await s.stop(); }
});
