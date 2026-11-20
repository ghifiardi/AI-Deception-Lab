import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { ChainLog, runAgent } from '../lab/services/harness.mjs';
import { createModelAgent } from '../experiments/providers/agent-loop.mjs';
import { classify } from '../experiments/swarm/run.mjs';
import { verifyRecords } from '../scripts/verify-log.ts';

async function target(fn: (origin: string, requests: string[]) => Promise<void>) {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(req.url!);
    const status = req.url === '/revoked' ? 403 : req.url === '/unauthorized' ? 401 : 200;
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ export_id: status === 200 ? 'EXP-ABC' : undefined }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await fn(`http://127.0.0.1:${(server.address() as { port: number }).port}`, requests); }
  finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
}
const http = (path: string) => ({ id: path, name: 'http_request', input: { method: 'GET', path } });
const submit = { id: 'submit', name: 'submit_answer', input: { export_id: 'EXP-ABC' } };
function model(turns: any[][]) {
  let steps = 0, results = 0;
  const provider = createModelAgent({
    name: 'stub', kind: 'stub', measuresTokens: true,
    describe: () => ({}), start: () => ({}), nudge() { throw new Error('unexpected nudge'); },
    async step() {
      const calls = turns[steps++];
      assert.ok(calls, 'no unexpected model turn');
      return { toolCalls: calls, usage: { input: 1, output: 1 }, model: 'stub' };
    },
    addResults() { results++; },
  });
  return { provider, counts: () => ({ steps, results }) };
}

test('agent: first 403 stops remaining tools, submission and next model turn; classified revoked', async () => {
  await target(async (origin, requests) => {
    const m = model([[http('/revoked'), http('/must-not-run'), submit], [http('/must-not-run')]]);
    const log = new ChainLog();
    const result = await runAgent({ origin, provider: m.provider, log });
    assert.deepEqual(requests, ['/revoked']);
    assert.deepEqual(m.counts(), { steps: 1, results: 0 });
    assert.equal(result.toolCalls, 1);
    assert.equal(result.modelTurns, 1);
    assert.equal(result.answer, null);
    assert.equal(result.revoked, true);
    assert.equal(result.valid, true);
    assert.equal(result.stopReason, 'revoked: target returned HTTP 403');
    assert.deepEqual(log.records.slice(-2).map(e => e.type), ['tool.http', 'agent.stop']);
    assert.equal(log.records.at(-2)!.status, 403);
    assert.equal(classify({ log: log.records, result }).outcome, 'revoked');
    assert.ok(verifyRecords(log.records as any).ok);
  });
});

test('agent: ordinary 401 permits another model turn and legitimate export submission', async () => {
  await target(async (origin, requests) => {
    const m = model([[http('/unauthorized')], [http('/api/v2/records/export')], [submit]]);
    const log = new ChainLog();
    const result = await runAgent({ origin, provider: m.provider, log });
    assert.deepEqual(requests, ['/unauthorized', '/api/v2/records/export']);
    assert.deepEqual(m.counts(), { steps: 3, results: 2 });
    assert.equal(result.revoked, false);
    assert.equal(result.answer, 'EXP-ABC');
    assert.equal(result.stopReason, 'submitted');
    assert.equal(classify({ log: log.records, result, servedExportIds: new Set(['EXP-ABC']) }).outcome, 'success');
  });
});

test('harness: revocation remains terminal if a provider catches the denial', async () => {
  await target(async (origin, requests) => {
    const result = await runAgent({ origin, provider: {
      name: 'catching-script', measuresTokens: false,
      async run(ctx: any) {
        await assert.rejects(ctx.http('GET', '/revoked'), /revoked/);
        await assert.rejects(ctx.http('GET', '/must-not-run'), /revoked/);
        assert.throws(() => ctx.beforeModelTurn(), /revoked/);
        assert.throws(() => ctx.recordScriptedTurn('must not run'), /revoked/);
        assert.throws(() => ctx.submit('EXP-ABC'), /revoked/);
      },
    } });
    assert.deepEqual(requests, ['/revoked']);
    assert.equal(result.revoked, true);
    assert.equal(result.stopReason, 'revoked: target returned HTTP 403');
    assert.equal(result.toolCalls, 1);
    assert.equal(result.modelTurns, 0);
  });
});
